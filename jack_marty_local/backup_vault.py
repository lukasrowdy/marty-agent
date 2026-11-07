"""Atomic graph snapshots and bounded retention for the isolated Jack/Marty build."""
from __future__ import annotations

import gzip
import json
import os
import tempfile
import uuid
import time
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
VAULT_DIR = ROOT / "Vault"
GRAPH_PATH = VAULT_DIR / "graph_state.json"
BACKUP_DIR = VAULT_DIR / "Backups"
MAX_SNAPSHOTS = 10
BACKUP_GLOB = "graph-*.json.gz"
_LOCAL_LOCKS = threading.local()


def validate_graph(value: Any) -> dict:
    if not isinstance(value, dict) or not isinstance(value.get("nodes"), list) or not isinstance(value.get("links"), list):
        raise ValueError("graph must be an object with nodes and links arrays")
    for node in value["nodes"]:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not isinstance(node.get("type"), str):
            raise ValueError("each graph node needs string id and type fields")
    for edge in value["links"]:
        if not isinstance(edge, dict) or not isinstance(edge.get("source"), str) or not isinstance(edge.get("target"), str):
            raise ValueError("each graph link needs string source and target fields")
    return value


def read_graph(path: Path = GRAPH_PATH) -> dict:
    return validate_graph(json.loads(path.read_text(encoding="utf-8")))


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _atomic_write_graph(graph: dict, path: Path = GRAPH_PATH) -> None:
    validated = validate_graph(graph)
    payload = (json.dumps(validated, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _atomic_write_bytes(path, payload)


def _validate_snapshot(path: Path) -> dict:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return validate_graph(json.load(stream))


def _execute_pre_mutation_backup(graph_path: Path = GRAPH_PATH, backup_dir: Path = BACKUP_DIR) -> Path:
    """Write and validate an exclusive gzip snapshot of the current graph before mutation."""
    graph_path = Path(graph_path)
    backup_dir = Path(backup_dir)
    if not graph_path.is_file():
        raise FileNotFoundError(f"graph file does not exist: {graph_path}")
    current = read_graph(graph_path)
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    final_path = backup_dir / f"graph-{stamp}-{uuid.uuid4().hex}.json.gz"
    fd, temp_name = tempfile.mkstemp(prefix=".graph-backup-", suffix=".tmp", dir=str(backup_dir))
    os.close(fd)
    try:
        with open(graph_path, "rb") as source, open(temp_name, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    compressed.write(block)
            raw.flush()
            os.fsync(raw.fileno())
        copied = _validate_snapshot(Path(temp_name))
        if copied != current:
            raise ValueError("snapshot validation did not match the source graph")
        with open(temp_name, "rb") as src, open(final_path, "xb") as dst:
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                dst.write(block)
            dst.flush()
            os.fsync(dst.fileno())
        _validate_snapshot(final_path)
    except Exception:
        try:
            final_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        try:
            Path(temp_name).unlink(missing_ok=True)
        except OSError:
            pass
    return final_path


def enforce_retention_rotation(backup_dir: Path = BACKUP_DIR, keep: int = MAX_SNAPSHOTS) -> list[Path]:
    """Keep the newest application-owned snapshots; fail loudly if a prune fails."""
    if keep < 1:
        raise ValueError("retention must keep at least one snapshot")
    backup_dir = Path(backup_dir)
    if not backup_dir.exists():
        return []
    snapshots = sorted((p for p in backup_dir.glob(BACKUP_GLOB) if p.is_file()),
                       key=lambda p: (p.stat().st_mtime_ns, p.name))
    removed = []
    for old in snapshots[:-keep]:
        old.unlink()
        removed.append(old)
    return removed


def restore_backup(backup_path: Path, graph_path: Path = GRAPH_PATH) -> dict:
    """Validate a gzip snapshot fully, then atomically replace the graph with it."""
    backup_path = Path(backup_path)
    graph_path = Path(graph_path)
    restored = _validate_snapshot(backup_path)
    payload = (json.dumps(restored, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with graph_transaction(graph_path):
        backup_dir = graph_path.parent / "Backups"
        if graph_path.exists():
            try:
                read_graph(graph_path)
            except (ValueError, UnicodeError):
                # Preserve invalid current data for recovery without treating it as a valid snapshot.
                rejected = backup_dir / f"rejected-{uuid.uuid4().hex}.json"
                _atomic_write_bytes(rejected, graph_path.read_bytes())
            else:
                execute_pre_mutation_backup(graph_path, backup_dir)
        _atomic_write_bytes(graph_path, payload)
        enforce_retention_rotation(backup_dir)
    return restored


def ensure_vault() -> None:
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    (VAULT_DIR / "OSINT_Targets").mkdir(parents=True, exist_ok=True)
    if not GRAPH_PATH.exists():
        atomic_write_graph({"nodes": [], "links": []})




@contextmanager
def graph_transaction(graph_path: Path = GRAPH_PATH, timeout: float = 20.0):
    """Serialize graph read/backup/write across threads and Python processes."""
    path = Path(graph_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = str(path.resolve()).casefold()
    held = getattr(_LOCAL_LOCKS, "held", None)
    if held is None:
        held = _LOCAL_LOCKS.held = set()
    if key in held:
        yield
        return
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+b") as handle:
        if handle.seek(0, 2) == 0:
            handle.write(b"0")
            handle.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("graph transaction lock timed out")
                time.sleep(0.05)
        held.add(key)
        try:
            yield
        finally:
            held.remove(key)
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def atomic_write_graph(graph: dict, path: Path = GRAPH_PATH) -> None:
    with graph_transaction(path):
        _atomic_write_graph(graph, path)


def execute_pre_mutation_backup(graph_path: Path = GRAPH_PATH, backup_dir: Path = BACKUP_DIR) -> Path:
    with graph_transaction(graph_path):
        result = _execute_pre_mutation_backup(graph_path, backup_dir)
        enforce_retention_rotation(backup_dir)
        return result


if __name__ == "__main__":
    ensure_vault()
    print(f"Vault ready: {VAULT_DIR}")
