"""Offline PCAP watcher, graph API, and Server-Sent Events server (loopback only)."""
from __future__ import annotations

import argparse
import hashlib
import itertools
import ipaddress
import json
import os
import queue
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

try:
    from . import backup_vault
except ImportError:
    import backup_vault

ROOT = Path(__file__).resolve().parent
CACHE_DIR = ROOT / "cache"
GRAPH_PATH = ROOT / "Vault" / "graph_state.json"
DASHBOARD_PATH = ROOT / "index.html"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8766
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_PACKETS = 100_000
MAX_PACKET_BYTES = 2 * 1024 * 1024
POLL_SECONDS = 1.0
STABLE_POLLS = 2
MAX_SSE_CLIENTS = 16
MAX_SSE_QUEUE = 32
MAX_WATCHED_FILES = 4096
STOP = threading.Event()


def authorized_capture_path(path: str | Path, cache_dir: Path = CACHE_DIR) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(cache_dir) / candidate
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(Path(cache_dir).resolve())
    except ValueError as exc:
        raise PermissionError("capture is outside the designated local cache directory") from exc
    if not resolved.is_file() or resolved.suffix.casefold() != ".pcap":
        raise ValueError("only regular .pcap files in the local cache are accepted")
    if resolved.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError("capture exceeds the 128 MiB processing limit")
    return resolved


def _read_exact(stream, length: int) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("truncated PCAP record")
    return data


def _ipv4_from_frame(frame: bytes, link_type: int) -> tuple[str, str] | None:
    if link_type == 1:  # Ethernet, including 802.1Q VLAN tags
        if len(frame) < 14:
            return None
        offset = 14
        ether_type = struct.unpack("!H", frame[12:14])[0]
        while ether_type in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return None
            ether_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
        if ether_type != 0x0800:
            return None
    elif link_type in (101, 228):  # DLT_RAW / DLT_IPV4
        offset = 0
    elif link_type == 113:  # Linux cooked capture v1
        if len(frame) < 16 or struct.unpack("!H", frame[14:16])[0] != 0x0800:
            return None
        offset = 16
    elif link_type == 276:  # Linux cooked capture v2
        if len(frame) < 20 or struct.unpack("!H", frame[0:2])[0] != 0x0800:
            return None
        offset = 20
    else:
        return None
    if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        return None
    ihl = (frame[offset] & 0x0F) * 4
    if ihl < 20 or len(frame) < offset + ihl:
        return None
    total_length = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
    if total_length < ihl or total_length > len(frame) - offset:
        return None
    try:
        src = str(ipaddress.IPv4Address(frame[offset + 12:offset + 16]))
        dst = str(ipaddress.IPv4Address(frame[offset + 16:offset + 20]))
    except ipaddress.AddressValueError:
        return None
    return src, dst


def parse_capture(path: str | Path, max_packets: int = MAX_PACKETS,
                  cache_dir: Path = CACHE_DIR) -> list[dict]:
    """Parse supported classic PCAP headers and return unique IPv4 endpoint pairs."""
    pcap_path = authorized_capture_path(path, cache_dir)
    pairs = set()
    with pcap_path.open("rb") as stream:
        magic = _read_exact(stream, 4)
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", False),
            b"\xa1\xb2\xc3\xd4": (">", False),
            b"\x4d\x3c\xb2\xa1": ("<", True),
            b"\xa1\xb2\x3c\x4d": (">", True),
        }
        if magic not in formats:
            raise ValueError("unsupported PCAP magic or pcapng format")
        endian, _nanosecond = formats[magic]
        rest = _read_exact(stream, 20)
        major, minor, _zone, _sigfigs, snaplen, link_type = struct.unpack(endian + "HHIIII", rest)
        if major != 2 or minor not in (2, 3, 4):
            raise ValueError(f"unsupported PCAP version {major}.{minor}")
        if snaplen < 1 or snaplen > MAX_PACKET_BYTES:
            raise ValueError("invalid or excessive PCAP snap length")
        if link_type not in (1, 101, 113, 228, 276):
            raise ValueError(f"unsupported link-layer type {link_type}")
        count = 0
        while True:
            header = stream.read(16)
            if not header:
                break
            if len(header) != 16:
                raise ValueError("truncated packet header")
            _seconds, _fraction, included, original = struct.unpack(endian + "IIII", header)
            if included > snaplen or included > MAX_PACKET_BYTES or included > MAX_CAPTURE_BYTES:
                raise ValueError("packet length exceeds configured limits")
            if included > original:
                raise ValueError("captured packet length exceeds original packet length")
            frame = _read_exact(stream, included)
            count += 1
            if count > max_packets:
                raise ValueError("capture exceeds packet processing limit")
            endpoints = _ipv4_from_frame(frame, link_type)
            if endpoints:
                pairs.add(endpoints)
    return [{"source": src, "target": dst} for src, dst in sorted(pairs)]


class EventHub:
    def __init__(self, max_clients: int = MAX_SSE_CLIENTS, queue_size: int = MAX_SSE_QUEUE):
        self.max_clients = max_clients
        self.queue_size = queue_size
        self._clients: set[queue.Queue] = set()
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        with self._lock:
            if len(self._clients) >= self.max_clients:
                raise RuntimeError("SSE client limit reached")
            client = queue.Queue(maxsize=self.queue_size)
            self._clients.add(client)
            return client

    def unsubscribe(self, client: queue.Queue) -> None:
        with self._lock:
            self._clients.discard(client)

    def publish(self, event: dict) -> None:
        payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            clients = tuple(self._clients)
        for client in clients:
            try:
                client.put_nowait(payload)
            except queue.Full:
                try:
                    client.get_nowait()
                    client.put_nowait(payload)
                except (queue.Empty, queue.Full):
                    pass


HUB = EventHub()
_GRAPH_LOCK = threading.RLock()


def load_graph(path: Path = GRAPH_PATH) -> dict:
    if not path.exists():
        return {"nodes": [], "links": []}
    return backup_vault.read_graph(path)


def apply_capture_to_graph(pairs: list[dict], graph_path: Path = GRAPH_PATH) -> dict:
    with _GRAPH_LOCK, backup_vault.graph_transaction(graph_path):
        graph = load_graph(graph_path)
        nodes = {node["id"]: node for node in graph["nodes"]}
        links = {(edge["source"], edge["target"]): edge for edge in graph["links"]}
        added_nodes, added_links = [], []
        for pair in pairs:
            src, dst = "ipv4:" + pair["source"], "ipv4:" + pair["target"]
            if src not in nodes:
                node = {"id": src, "type": "ipv4", "label": pair["source"]}
                nodes[src] = node
                added_nodes.append(node)
            if dst not in nodes:
                node = {"id": dst, "type": "ipv4", "label": pair["target"]}
                nodes[dst] = node
                added_nodes.append(node)
            if (src, dst) not in links:
                edge = {"source": src, "target": dst, "type": "observed-traffic"}
                links[(src, dst)] = edge
                added_links.append(edge)
        updated = {
            "nodes": [nodes[key] for key in sorted(nodes, key=str.casefold)],
            "links": [links[key] for key in sorted(links)],
        }
        if updated != graph:
            if graph_path.exists():
                backup_vault.execute_pre_mutation_backup(graph_path, graph_path.parent / "Backups")
            backup_vault.atomic_write_graph(updated, graph_path)
            backup_vault.enforce_retention_rotation(graph_path.parent / "Backups")
        return {"nodes": added_nodes, "links": added_links, "snapshot": updated}


class CaptureWatcher(threading.Thread):
    def __init__(self, directory: Path = CACHE_DIR, hub: EventHub = HUB,
                 poll_seconds: float = POLL_SECONDS, graph_path: Path = GRAPH_PATH):
        super().__init__(name="pcap-watcher", daemon=True)
        self.directory = Path(directory).resolve()
        self.hub = hub
        self.poll_seconds = poll_seconds
        self.graph_path = Path(graph_path)
        self.stop_event = threading.Event()
        self._observed: dict[Path, tuple[int, int, int]] = {}
        self._processed: set[str] = set()
        self.errors: list[str] = []
        self._graph_signature = None

    def scan_once(self) -> list[dict]:
        self.directory.mkdir(parents=True, exist_ok=True)
        events = []
        paths = sorted(itertools.islice(self.directory.glob("*.pcap"), MAX_WATCHED_FILES))
        present = set(paths)
        self._observed = {path: value for path, value in self._observed.items() if path in present}
        for path in paths:
            try:
                stat = path.stat()
                signature = (stat.st_size, stat.st_mtime_ns)
                previous = self._observed.get(path)
                stable = (previous is not None and previous[:2] == signature)
                cycles = previous[2] + 1 if stable else 1
                self._observed[path] = (signature[0], signature[1], cycles)
                if cycles < STABLE_POLLS or stat.st_size == 0 or stat.st_size > MAX_CAPTURE_BYTES:
                    continue
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                key = digest.hexdigest()
                if key in self._processed:
                    continue
                if len(self._processed) >= MAX_WATCHED_FILES:
                    raise ValueError("capture session limit reached; archive processed captures and restart")
                pairs = parse_capture(path, cache_dir=self.directory)
                after = path.stat()
                if (after.st_size, after.st_mtime_ns) != signature:
                    self._observed.pop(path, None)
                    continue
                update = apply_capture_to_graph(pairs, self.graph_path)
                event = {"type": "graph_update", "capture_id": key[:16],
                         "nodes": update["nodes"], "links": update["links"]}
                self.hub.publish(event)
                self._processed.add(key)
                events.append(event)
            except (OSError, ValueError, PermissionError) as exc:
                message = f"{path.name}: {type(exc).__name__}: {exc}"
                self.errors.append(message)
                if len(self.errors) > 100:
                    del self.errors[:-100]
                self._observed.pop(path, None)
        return events

    def run(self) -> None:
        while not self.stop_event.wait(self.poll_seconds):
            self.scan_once()
            try:
                stat = self.graph_path.stat()
                signature = (stat.st_mtime_ns, stat.st_size)
                if signature != self._graph_signature:
                    self.hub.publish({"type": "graph_snapshot", **load_graph(self.graph_path)})
                    self._graph_signature = signature
            except (OSError, ValueError) as exc:
                self.errors = (self.errors + [f"graph: {type(exc).__name__}"])[-100:]


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False) + "\n").encode("utf-8")


class GraphHandler(BaseHTTPRequestHandler):
    server_version = "JackMartyLocal/1.0"

    def log_message(self, fmt, *args):
        print(f"[pcap-dashboard] {self.command} {self.path.split('?')[0]}")

    def _allowed_origin(self) -> bool:
        host = self.headers.get("Host", "").split(":", 1)[0].casefold()
        if host not in {"127.0.0.1", "localhost"}:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin.casefold() == f"http://{self.headers.get('Host', '').casefold()}"

    def _json(self, data: dict, status: int = 200):
        body = _json_bytes(data)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._allowed_origin():
            self._json({"error": "invalid host or origin"}, 403)
            return
        path = urlsplit(self.path).path
        if path == "/health":
            self._json({"ok": True, "service": "jack-marty-local", "host": DEFAULT_HOST,
                        "port": self.server.server_port, "watcher_errors": len(self.server.watcher.errors)})
        elif path == "/graph":
            try:
                self._json(load_graph(self.server.graph_path))
            except (OSError, ValueError, json.JSONDecodeError):
                self._json({"error": "graph state is unavailable or malformed"}, 503)
        elif path == "/stream":
            self._stream()
        elif path in ("/", "/index.html"):
            try:
                body = (ROOT / "index.html").read_bytes()
            except OSError:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/graph.js":
            self._static(ROOT / "graph.js", "application/javascript; charset=utf-8")
        elif path == "/style.css":
            self._static(ROOT / "style.css", "text/css; charset=utf-8")
        else:
            self.send_error(404)

    def _static(self, path: Path, content_type: str):
        try:
            body = path.read_bytes()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _stream(self):
        try:
            client = self.server.hub.subscribe()
        except RuntimeError:
            self._json({"error": "too many SSE clients"}, 503)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while not self.server.stop_event.is_set():
                try:
                    payload = client.get(timeout=15)
                    self.wfile.write(("event: graph\ndata: " + payload + "\n\n").encode("utf-8"))
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.server.hub.unsubscribe(client)

    def do_POST(self):
        self._json({"error": "operation is not available over HTTP"}, 405)


class GraphHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 32

    def __init__(self, address, handler, *, hub=HUB, graph_path=GRAPH_PATH, cache_dir=CACHE_DIR):
        self.hub = hub
        self.graph_path = Path(graph_path)
        self.stop_event = threading.Event()
        self.watcher = CaptureWatcher(cache_dir, hub, graph_path=graph_path)
        super().__init__(address, handler)


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, graph_path: Path = GRAPH_PATH,
          start_watcher: bool = True, cache_dir: Path = CACHE_DIR) -> GraphHTTPServer:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("server must bind to loopback only")
    Path(graph_path).parent.mkdir(parents=True, exist_ok=True)
    if not Path(graph_path).exists():
        backup_vault.atomic_write_graph({"nodes": [], "links": []}, Path(graph_path))
    server = GraphHTTPServer((host, port), GraphHandler, graph_path=graph_path, cache_dir=cache_dir)
    if start_watcher:
        server.watcher.start()
    return server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Loopback-only PCAP graph dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)
    server = serve(port=args.port)
    print(f"Jack/Marty dashboard listening at http://127.0.0.1:{server.server_port}/")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        STOP.set()
        server.watcher.stop_event.set()
        server.stop_event.set()
        server.shutdown()
        server.server_close()
        if server.watcher.is_alive():
            server.watcher.join(timeout=3)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
