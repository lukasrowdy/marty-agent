import concurrent.futures
import json
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import agent_adapter
import backup_vault
import index_vault
import local_console
import switchboard_router as router
import watch_pcap
import test_integration as fixtures


class HardeningTests(unittest.TestCase):
    def test_all_external_routes_require_permission_and_local_only_blocks(self):
        for brain in ("marty", "cloud", "claude"):
            with self.subTest(brain=brain):
                result = router.evaluate_and_route_security_query("hello", brain,
                    authorization=router.Authorization(True, True), target_handler=lambda _: self.fail("forwarded"))
                self.assertEqual(result["status"], "blocked")
        auth = router.Authorization(True, True, ("external-handoff",))
        result = router.evaluate_and_route_security_query("private sentinel", "marty", authorization=auth, local_only=True)
        self.assertEqual(result["status"], "blocked")
        for value in (None, {}, []):
            self.assertEqual(router.evaluate_and_route_security_query("test", value, authorization=auth)["status"], "blocked")
        for answer in (None, "", {}, "Avery Example"):
            result = router.evaluate_and_route_security_query("Avery Example", "marty", authorization=auth,
                sensitive_identifiers=("Avery Example",), gatekeeper=lambda _: answer)
            self.assertEqual(result["status"], "blocked")

    def test_restore_preserves_current_state_and_recovers_corrupt_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph = Path(tmp) / "graph.json"
            backups = Path(tmp) / "Backups"
            first = {"nodes": [{"id": "first", "type": "document"}], "links": []}
            second = {"nodes": [{"id": "second", "type": "document"}], "links": []}
            backup_vault.atomic_write_graph(first, graph)
            saved = backup_vault.execute_pre_mutation_backup(graph, backups)
            backup_vault.atomic_write_graph(second, graph)
            backup_vault.restore_backup(saved, graph)
            snapshots = [backup_vault._validate_snapshot(path) for path in backups.glob("graph-*.json.gz")]
            self.assertIn(second, snapshots)
            graph.write_text("broken JSON", encoding="utf-8")
            backup_vault.restore_backup(saved, graph)
            self.assertEqual(backup_vault.read_graph(graph), first)
            self.assertEqual(len(list(backups.glob("rejected-*.json"))), 1)

    def test_concurrent_graph_updates_are_not_lost(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph = Path(tmp) / "graph.json"
            backup_vault.atomic_write_graph({"nodes": [], "links": []}, graph)
            def add(number):
                watch_pcap.apply_capture_to_graph([{"source": f"192.0.2.{number}", "target": "198.51.100.1"}], graph)
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                list(executor.map(add, range(1, 9)))
            result = backup_vault.read_graph(graph)
            self.assertEqual(len(result["nodes"]), 9)
            self.assertEqual(len(result["links"]), 8)

    def test_bad_and_incomplete_pcaps_do_not_mutate_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph = root / "graph.json"
            original = {"nodes": [], "links": []}
            backup_vault.atomic_write_graph(original, graph)
            capture = root / "fixture.pcap"
            fixtures.make_pcap(capture)
            complete = capture.read_bytes()
            capture.write_bytes(complete[:-1])
            watcher = watch_pcap.CaptureWatcher(root, watch_pcap.EventHub(), graph_path=graph)
            watcher.scan_once(); self.assertEqual(watcher.scan_once(), [])
            self.assertTrue(watcher.errors)
            self.assertEqual(backup_vault.read_graph(graph), original)
            capture.write_bytes(complete)
            watcher.scan_once(); self.assertEqual(len(watcher.scan_once()), 1)
            capture.write_bytes(b"BAD!" + complete[4:])
            with self.assertRaises(ValueError): watch_pcap.parse_capture(capture, cache_dir=root)

    def test_backup_failure_prevents_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph = Path(tmp) / "graph.json"
            original = {"nodes": [], "links": []}
            backup_vault.atomic_write_graph(original, graph)
            with patch.object(backup_vault, "execute_pre_mutation_backup", side_effect=OSError("test failure")):
                with self.assertRaises(OSError):
                    watch_pcap.apply_capture_to_graph([{"source": "192.0.2.1", "target": "192.0.2.2"}], graph)
            self.assertEqual(backup_vault.read_graph(graph), original)

    def test_console_session_policy_preview_binding_and_one_time_handoff(self):
        server = local_console.serve(0, start_watcher=False)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        base = f"http://127.0.0.1:{server.server_port}"
        def post(path, value, token=True):
            headers = {"Content-Type": "application/json"}
            if token: headers["X-Local-Token"] = server.local_token
            with urlopen(Request(base + path, data=json.dumps(value).encode(), headers=headers), timeout=4) as response:
                return json.load(response)
        try:
            with self.assertRaises(HTTPError) as rejected:
                post("/api/chat", {"target": "jack", "text": "hi"}, token=False)
            self.assertEqual(rejected.exception.code, 403)
            with self.assertRaises(HTTPError):
                post("/api/chat", {"target": "jack", "text": "hi", "source_bytes": "private"})
            server.allow_external_handoff = False
            with self.assertRaises(HTTPError): post("/api/chat", {"target": "marty", "text": "hi"})
            server.allow_external_handoff = True
            sent = []
            with patch.object(router, "call_gatekeeper", return_value="approved clean task"), patch.object(
                    agent_adapter, "existing_marty_subscription_handoff", side_effect=lambda text: sent.append(text) or "ok"):
                prepared = post("/api/chat", {"target": "marty", "text": "synthetic original"})
                self.assertEqual(prepared["preview"], "approved clean task")
                self.assertEqual(sent, [])
                with self.assertRaises(HTTPError):
                    post("/api/handoff", {"handoff_id": prepared["handoff_id"], "text": "changed content"})
                result = post("/api/handoff", {"handoff_id": prepared["handoff_id"]})
                self.assertEqual(result["status"], "completed")
                self.assertEqual(sent, ["approved clean task"])
                with self.assertRaises(HTTPError): post("/api/handoff", {"handoff_id": prepared["handoff_id"]})
        finally:
            server.stop_event.set(); server.shutdown(); server.server_close(); worker.join(timeout=2)
