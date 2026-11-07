"""Isolated loopback console for Jack, sanitized Marty handoffs, and local graph tools."""
from __future__ import annotations

import argparse
import hmac
import json
import secrets
import threading
import time
import os
from urllib.parse import urlsplit

import agent_adapter
import backup_vault
import index_vault
import switchboard_router
import watch_pcap

MAX_BODY = 24_000


class ConsoleHandler(watch_pcap.GraphHandler):
    def do_GET(self):
        if urlsplit(self.path).path == "/console.js" and self._allowed_origin():
            self._static(watch_pcap.ROOT / "console.js", "application/javascript; charset=utf-8")
            return
        if urlsplit(self.path).path == "/api/session":
            if not self._allowed_origin():
                self._json({"error": "invalid host or origin"}, 403)
                return
            self._json({"token": self.server.local_token, "jack_model": agent_adapter.JACK_MODEL,
                        "gatekeeper_model": switchboard_router.GATEKEEPER_MODEL})
        else:
            super().do_GET()

    def do_POST(self):
        if not self._allowed_origin() or not hmac.compare_digest(
                self.headers.get("X-Local-Token", ""), self.server.local_token):
            self._json({"error": "local session authorization required"}, 403)
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self._json({"error": "JSON content type required"}, 415)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > MAX_BODY:
                raise ValueError("request size is outside the allowed range")
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise ValueError("request must be an object")
        except (ValueError, UnicodeError):
            self._json({"error": "invalid or oversized request"}, 400)
            return
        path = urlsplit(self.path).path
        if path not in {"/api/chat", "/api/handoff", "/api/index", "/api/shutdown"}:
            self._json({"error": "operation is not allowlisted"}, 404)
            return
        if not self.server.operation_lock.acquire(blocking=False):
            self._json({"error": "a local operation is already running"}, 409)
            return
        try:
            if path == "/api/chat":
                text, target = value.get("text"), value.get("target")
                if not isinstance(text, str) or not text.strip() or len(text) > 6000 or target not in {"jack", "marty"}:
                    self._json({"error": "provide task text (1 to 6000 characters) and a valid target"}, 400)
                    return
                # Raw files, attachments, and prior Jack results cannot enter this request.
                if set(value) - {"text", "target", "handoff_authorized"}:
                    self._json({"error": "attachments and extra fields are not accepted"}, 400)
                    return
                if target == "marty" and not self.server.allow_external_handoff:
                    self._json({"error": "external handoff is disabled by server policy"}, 403)
                    return
                permissions = ("external-handoff",) if target == "marty" else ()
                auth = switchboard_router.Authorization(True, True, permissions)
                if target == "jack":
                    result = agent_adapter.process_security_message(text, target,
                        authorization=auth, marked_sensitive=True)
                else:
                    result = switchboard_router.evaluate_and_route_security_query(
                        text, target, authorization=auth, marked_sensitive=True)
                    if result["status"] == "ready":
                        now = time.monotonic()
                        self.server.pending_handoffs = {key: entry for key, entry in
                            self.server.pending_handoffs.items() if now - entry[0] < 600}
                        if len(self.server.pending_handoffs) >= 8:
                            self._json({"error": "too many pending handoffs; wait for expiry"}, 409)
                            return
                        handoff_id = secrets.token_urlsafe(24)
                        self.server.pending_handoffs[handoff_id] = (now, result["text"])
                        self._json({"status": "prepared", "preview": result["text"], "handoff_id": handoff_id})
                        return
                self._json(result, 200 if result["status"] == "completed" else 503)
            elif path == "/api/handoff":
                handoff_id = value.get("handoff_id")
                if not self.server.allow_external_handoff or set(value) != {"handoff_id"} or not isinstance(handoff_id, str):
                    self._json({"error": "handoff is not authorized"}, 403)
                    return
                entry = self.server.pending_handoffs.pop(handoff_id, None)
                if not entry or time.monotonic() - entry[0] >= 600:
                    self._json({"error": "handoff expired or was already sent; prepare it again"}, 409)
                    return
                answer = agent_adapter.existing_marty_subscription_handoff(entry[1])
                self._json({"status": "completed", "target": "marty", "text": answer})
            elif path == "/api/shutdown":
                if value != {"action": "stop-console"}:
                    self._json({"error": "invalid shutdown request"}, 400)
                    return
                self._json({"status": "stopping"})
                self.server.stop_event.set()
                self.server.watcher.stop_event.set()
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                if value != {"action": "index-local-documents"}:
                    self._json({"error": "invalid index operation"}, 400)
                    return
                results = index_vault.reindex_all()
                graph = backup_vault.read_graph()
                self.server.hub.publish({"type": "graph_snapshot", **graph})
                self._json({"status": "completed", "documents": len(results),
                            "changed": sum(result["changed"] for result in results)})
        except Exception as exc:
            # Never include request text or a subprocess's output in a browser error.
            self._json({"status": "failed", "error": type(exc).__name__}, 503)
        finally:
            self.server.operation_lock.release()


def serve(port: int = 8766, *, start_watcher: bool = True):
    backup_vault.ensure_vault()
    server = watch_pcap.GraphHTTPServer(("127.0.0.1", port), ConsoleHandler)
    server.local_token = secrets.token_urlsafe(32)
    server.operation_lock = threading.Lock()
    server.allow_external_handoff = os.environ.get("JACK_MARTY_ALLOW_HANDOFF", "1") == "1"
    server.pending_handoffs = {}
    if start_watcher:
        server.watcher.start()
    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    server = serve(args.port)
    print(f"Jack/Marty local console: http://127.0.0.1:{server.server_port}/", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop_event.set()
        server.watcher.stop_event.set()
        server.server_close()
        server.watcher.join(timeout=3)


if __name__ == "__main__":
    main()
