"""Explicit live test: local Ollama + existing Claude subscription, synthetic data only."""
import http.client
import hashlib
import struct
import json
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_integration import make_pcap

BASE = "http://127.0.0.1:8766"


def main():
    start = time.monotonic()
    with urlopen(BASE + "/api/session", timeout=5) as response:
        session = json.load(response)
    def post(path, body):
        request = Request(BASE + path, data=json.dumps(body).encode(), headers={
            "Content-Type": "application/json", "X-Local-Token": session["token"]})
        with urlopen(request, timeout=300) as response:
            return json.load(response)

    jack = post("/api/chat", {"target": "jack", "text": "Synthetic integration test. Reply exactly JACK_E2E_OK."})
    assert jack["status"] == "completed" and jack["text"].strip() == "JACK_E2E_OK", jack
    prepared = post("/api/chat", {"target": "marty", "text":
        "In an authorized synthetic lab, host test.example.com at 192.0.2.60 is being tested. Reply exactly MARTY_E2E_OK."})
    assert prepared["status"] == "prepared", prepared
    assert "192.0.2.60" not in prepared["preview"] and "test.example.com" not in prepared["preview"], prepared
    marty = post("/api/handoff", {"handoff_id": prepared["handoff_id"]})
    assert marty["status"] == "completed" and marty["text"].strip() == "MARTY_E2E_OK", marty

    connection = http.client.HTTPConnection("127.0.0.1", 8766, timeout=15)
    connection.request("GET", "/stream")
    events = connection.getresponse()
    assert events.status == 200
    events.readline(); events.readline()
    note = ROOT / "Vault" / "OSINT_Targets" / "synthetic-e2e.md"
    note.write_text("id: SYNTHETIC-E2E\n#synthetic\nAuthorized fixture: 192.0.2.60 to 198.51.100.60.\n"
                    + "Local result: " + jack["text"] + "\nPermitted handoff result: " + marty["text"] + "\n", encoding="utf-8")
    indexed = post("/api/index", {"action": "index-local-documents"})
    assert indexed["status"] == "completed"
    capture = ROOT / "cache" / "synthetic-e2e.pcap"
    make_pcap(capture.with_suffix(".part"), "192.0.2.60", "198.51.100.60")
    data = bytearray(capture.with_suffix(".part").read_bytes())
    struct.pack_into("<I", data, 24, time.time_ns() & 0xFFFFFFFF)
    capture.with_suffix(".part").write_bytes(data)
    capture_id = hashlib.sha256(data).hexdigest()[:16]
    capture.with_suffix(".part").replace(capture)
    seen_index = seen_capture = False
    while not (seen_index and seen_capture):
        line = events.readline()
        if not line:
            raise RuntimeError("stream ended before expected events")
        if not line.startswith(b"data: "):
            continue
        value = json.loads(line[6:])
        if value["type"] == "graph_snapshot":
            seen_index |= any(node["id"] == "doc:SYNTHETIC-E2E" for node in value["nodes"])
        if value["type"] == "graph_update":
            seen_capture |= value.get("capture_id") == capture_id
    connection.close()
    with urlopen(BASE + "/graph", timeout=5) as response:
        graph = json.load(response)
    result = {"jack_real_model": True, "gatekeeper_real_model": True,
              "marty_real_subscription": True, "raw_identifiers_removed": True,
              "indexed_permitted_results": seen_index, "capture_sse_event": seen_capture,
              "graph_nodes": len(graph["nodes"]), "graph_links": len(graph["links"]),
              "seconds": round(time.monotonic() - start, 2)}
    (ROOT / "runtime" / "live-smoke.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
