from __future__ import annotations

import gzip
import http.client
import json
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import agent_adapter
import backup_vault
import index_vault
import switchboard_router as router
import watch_pcap


def make_pcap(path: Path, src="192.0.2.10", dst="198.51.100.7") -> None:
    src_bytes = bytes(int(part) for part in src.split("."))
    dst_bytes = bytes(int(part) for part in dst.split("."))
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 2, 20)
    ip[8] = 64
    ip[9] = 1
    ip[12:16], ip[16:20] = src_bytes, dst_bytes
    frame = bytes.fromhex("00112233445566778899aabb0800") + bytes(ip)
    with path.open("wb") as stream:
        stream.write(b"\xd4\xc3\xb2\xa1")
        stream.write(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        stream.write(struct.pack("<IIII", 1, 0, len(frame), len(frame)))
        stream.write(frame)


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.vault = self.base / "Vault"
        self.targets = self.vault / "OSINT_Targets"
        self.targets.mkdir(parents=True)
        self.graph = self.vault / "graph_state.json"
        self.backups = self.vault / "Backups"
        backup_vault.atomic_write_graph({"nodes": [], "links": []}, self.graph)
        self.old = (index_vault.GRAPH_PATH, index_vault.TARGETS_DIR, index_vault.VAULT, index_vault.INDEX_PATH)
        index_vault.GRAPH_PATH, index_vault.TARGETS_DIR = self.graph, self.targets
        index_vault.VAULT, index_vault.INDEX_PATH = self.vault, self.vault / "Targets_Index.md"

    def tearDown(self):
        index_vault.GRAPH_PATH, index_vault.TARGETS_DIR, index_vault.VAULT, index_vault.INDEX_PATH = self.old
        self.temp.cleanup()

    def test_metadata_graph_dedup_stale_edge_and_restore(self):
        doc = self.targets / "case.md"
        doc.write_text("""id: CASE-7
#forensics #forensics
Contact test@example.invalid and 192.0.2.10. CVE-2024-12345
SHA256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
See [[secondary]] and [[secondary]].
""", encoding="utf-8")
        metadata = index_vault.parse_target_metadata(doc)
        self.assertEqual(metadata["email_indicators"], ["test@example.invalid"])
        self.assertEqual(metadata["hashtags"], ["forensics"])
        self.assertEqual(metadata["ip_indicators"], ["192.0.2.10"])
        first = index_vault.process_identity_mutations(doc)
        self.assertTrue(first["changed"])
        snapshot = sorted(self.backups.glob("graph-*.json.gz"))[-1]
        self.assertTrue(snapshot.is_file())
        graph = backup_vault.read_graph(self.graph)
        self.assertEqual(len([n for n in graph["nodes"] if n["id"] == "doc:CASE-7"]), 1)
        self.assertEqual(len(graph["links"]), len({(e["source"], e["target"]) for e in graph["links"]}))
        graph["nodes"].append({"id": "unrelated", "type": "note"})
        backup_vault.atomic_write_graph(graph, self.graph)
        doc.write_text("id: CASE-7\n#updated\n", encoding="utf-8")
        second = index_vault.process_identity_mutations(doc)
        self.assertTrue(second["changed"])
        current = backup_vault.read_graph(self.graph)
        self.assertIn("unrelated", {n["id"] for n in current["nodes"]})
        self.assertFalse(any(e["target"] == "doc:secondary" for e in current["links"]))
        restored = backup_vault.restore_backup(snapshot, self.graph)
        self.assertEqual(restored, backup_vault.read_graph(self.graph))
        self.assertIn("updated", (self.vault / "Targets_Index.md").read_text(encoding="utf-8"))

    def test_source_path_escape_and_graph_validation(self):
        outside = self.base / "outside.md"
        outside.write_text("id: outside", encoding="utf-8")
        with self.assertRaises(PermissionError):
            index_vault.parse_target_metadata(outside)
        with self.assertRaises(ValueError):
            backup_vault.validate_graph({"nodes": [], "links": "bad"})

    def test_backup_collision_safety_and_retention(self):
        paths = [backup_vault.execute_pre_mutation_backup(self.graph, self.backups) for _ in range(12)]
        self.assertEqual(len(set(paths)), 12)
        backup_vault.enforce_retention_rotation(self.backups)
        self.assertEqual(len(list(self.backups.glob("graph-*.json.gz"))), 10)
        bad = self.backups / "invalid.json.gz"
        with gzip.open(bad, "wt", encoding="utf-8") as stream:
            stream.write("not graph")
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            backup_vault.restore_backup(bad, self.graph)


class CaptureAndHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.cache = self.base / "cache"
        self.cache.mkdir()
        self.graph = self.base / "Vault" / "graph_state.json"
        backup_vault.atomic_write_graph({"nodes": [], "links": []}, self.graph)

    def tearDown(self):
        self.temp.cleanup()

    def test_parser_watcher_dedup_and_outside_path_denied(self):
        capture = self.cache / "safe.pcap"
        make_pcap(capture)
        pairs = watch_pcap.parse_capture(capture, cache_dir=self.cache)
        self.assertEqual(pairs, [{"source": "192.0.2.10", "target": "198.51.100.7"}])
        make_pcap(self.base / "outside.pcap")
        with self.assertRaises(PermissionError):
            watch_pcap.parse_capture(self.base / "outside.pcap", cache_dir=self.cache)
        hub = watch_pcap.EventHub()
        events = hub.subscribe()
        watcher = watch_pcap.CaptureWatcher(self.cache, hub, graph_path=self.graph)
        self.assertEqual(watcher.scan_once(), [])
        published = watcher.scan_once()
        self.assertEqual(len(published), 1)
        self.assertEqual(json.loads(events.get_nowait())["type"], "graph_update")
        self.assertEqual(watcher.scan_once(), [])
        self.assertEqual(len(backup_vault.read_graph(self.graph)["nodes"]), 2)
        hub.unsubscribe(events)

    def test_http_health_graph_dashboard_post_rejection_and_sse(self):
        hub = watch_pcap.EventHub()
        server = watch_pcap.serve(port=0, graph_path=self.graph, start_watcher=False,
                                  cache_dir=self.cache)
        server.hub = hub
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        try:
            base = f"http://{host}:{port}"
            with urlopen(base + "/health", timeout=3) as response:
                self.assertTrue(json.loads(response.read())["ok"])
            with urlopen(base + "/graph", timeout=3) as response:
                self.assertEqual(json.loads(response.read()), {"nodes": [], "links": []})
            with urlopen(base + "/", timeout=3) as response:
                page = response.read().decode()
                self.assertIn('id="graphCanvas"', page)
                self.assertIn("/graph.js", page)
            request = Request(base + "/danger", data=b"{}", method="POST")
            with self.assertRaises(HTTPError) as denied:
                urlopen(request, timeout=3)
            self.assertEqual(denied.exception.code, 405)
            bad_host = Request(base + "/health", headers={"Host": "example.com"})
            with self.assertRaises(HTTPError) as denied_host:
                urlopen(bad_host, timeout=3)
            self.assertEqual(denied_host.exception.code, 403)

            connection = http.client.HTTPConnection(host, port, timeout=4)
            connection.request("GET", "/stream")
            stream_response = connection.getresponse()
            self.assertEqual(stream_response.status, 200)
            self.assertIn("text/event-stream", stream_response.getheader("Content-Type"))
            first = stream_response.readline() + stream_response.readline()
            self.assertIn(b"connected", first)
            expected = {"type": "graph_update", "capture_id": "synthetic", "nodes": [{"id": "a", "type": "ipv4"}],
                        "links": [{"source": "a", "target": "b"}]}
            hub.publish(expected)
            lines = []
            while True:
                line = stream_response.readline()
                if line == b"\n": break
                lines.append(line)
            self.assertTrue(any(line.startswith(b"event: graph") for line in lines))
            data_line = next(line for line in lines if line.startswith(b"data: "))
            self.assertEqual(json.loads(data_line[6:]), expected)
            connection.close()
        finally:
            server.stop_event.set()
            server.shutdown(); server.server_close(); thread.join(timeout=2)


class RouterBoundaryTests(unittest.TestCase):
    def test_routing_abstraction_fail_closed_and_authorization(self):
        auth = router.Authorization(True, True, ("external-handoff",))
        called = []
        clean = router.evaluate_and_route_security_query(
            "Review host 192.0.2.4 safely", "marty", authorization=auth,
            gatekeeper=lambda raw: raw.replace("192.0.2.4", "<IP>"),
            target_handler=lambda text: called.append(text) or "ok")
        self.assertEqual(clean["status"], "completed")
        self.assertEqual(called, ["Review host <IP> safely"])
        failed = router.evaluate_and_route_security_query(
            "Review host 192.0.2.4", "marty", authorization=auth,
            gatekeeper=lambda _raw: (_ for _ in ()).throw(TimeoutError()),
            target_handler=lambda text: called.append(text))
        self.assertEqual(failed["status"], "blocked")
        self.assertEqual(len(called), 1)
        self.assertEqual(router.evaluate_and_route_security_query("", "marty", authorization=auth)["status"], "blocked")
        self.assertEqual(router.evaluate_and_route_security_query("hello", "jack", authorization=router.Authorization(True))["status"], "blocked")
        self.assertEqual(router.evaluate_and_route_security_query("hello", "marty", authorization=router.Authorization(True, True), marked_sensitive=True)["status"], "blocked")

    def test_private_source_and_restricted_gateway_boundary(self):
        auth = router.Authorization(True, True, ("external-handoff",))
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "family.mp4"
            source.write_bytes(b"PRIVATE_RAW_VIDEO_SENTINEL")
            recipient = []
            result = agent_adapter.process_private_source(
                source, "summarize locally", authorization=auth,
                jack_processor=lambda path, _question: f"local:{path.read_bytes().decode()}",
                sanitized_handoff="Summarize media from 192.0.2.9",
                gatekeeper=lambda text: text.replace("192.0.2.9", "<IP>"),
                marty_sender=lambda text: recipient.append(text) or "Marty summary")
            self.assertEqual(result["status"], "completed")
            self.assertIn("PRIVATE_RAW_VIDEO_SENTINEL", result["local_result"])
            self.assertNotIn("PRIVATE_RAW_VIDEO_SENTINEL", "".join(recipient))
            self.assertNotIn("192.0.2.9", "".join(recipient))
        self.assertEqual(agent_adapter.execute_restricted_tool("shell", {}, auth)["status"], "denied")
        self.assertEqual(agent_adapter.execute_restricted_tool("index_document", {"path": "x"}, auth)["status"], "denied")

    def test_existing_switchboard_import_remains_available(self):
        import switchboard
        self.assertTrue(callable(getattr(switchboard, "ask_claude_sub", None)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
