"""
private_backup.py - encrypted backup of my-agent/private/ for the NAS.

Why (2026-09-24, Lukas: "start backing yourself up"): private/ holds the NAS-sort pipeline
state, private media renders, the dashboard's private chats and the outbox, and it
lived on this PC only. The NAS share is readable on the LAN, so it goes there as
ciphertext only, the same rule backup-marty.ps1 follows for the handoff vault.

Left out on purpose:
  business/            Lukas: the business folder stays on this computer. Matched case-insensitively,
                       at the top level; a build refuses to finish if any archived path starts with it.
  scratch/<folders>/   throwaway frame extracts, rebuildable from the NAS (files directly
                       in scratch/ are kept).
  */proxies/           Creator Hub's preview copies, rebuildable from the NAS.
  __pycache__/, and any directory junction or symlink (os.walk would otherwise follow a junction
  out of private/, or into business/).

Key: 32 random bytes in Windows Credential Manager, target "marty/private-backup-key",
created by `init` and read through tools/cred.py. If this PC dies, the key dies with it,
so Lukas keeps a second copy: he runs `show-key` himself, in his own PowerShell window,
and stores it in his password manager. show-key refuses to run without an interactive
terminal. That is a guard against accidents, not attacks: anything running as {{WIN_USER}} can read
the key from Credential Manager. What this protects against is people and devices on the LAN or the
NAS that can read the share. Nothing is recoverable without the offline copy of the key.

File format (".mpb", version 1):
  b"MARTYPB1" + 2-byte big-endian header length + header JSON
      {"v": 1, "key_id": first 8 bytes of sha256(key) as hex, "created": ISO time,
       "chunk": 1048576, "nonce_base": 8 random bytes as base64}
  then records: 4-byte big-endian ciphertext length + ciphertext.
  Each record is AES-256-GCM over up to 1 MB of plaintext, nonce = nonce_base + counter(4),
  AAD = header bytes + counter(4) + last flag(1). The last flag means a file cut off at a
  record boundary fails to decrypt instead of restoring short, and the header can't be
  swapped between files. Same cipher and chunking as marty-handoff/vault.py.
  The plaintext is a streamed tar. Its LAST member is .marty-manifest.json (path, size and sha256
  of every file, hashed while it was read, plus files skipped or changed mid-copy), so `drill`
  proves every file in memory without writing any plaintext to disk. The drill proves the archive
  matches what was read; the manifest's "skipped" and "changed" lists are what say whether that
  read was complete and consistent.

Usage (system Python 3.12, which has `cryptography`):
  py tools/private_backup.py init                 create the key if missing (never prints it)
  py tools/private_backup.py status               key present? prints the key id only
  py tools/private_backup.py build --out FILE     encrypt private/ into FILE
  py tools/private_backup.py drill FILE [--key-prompt]          decrypt in memory and check every file
  py tools/private_backup.py restore FILE DEST [--key-prompt]   unpack into an EMPTY folder and verify it
  py tools/private_backup.py prune DIR --keep N   keep the newest N (at least 1) private-*.mpb in DIR
  --key-prompt reads the key typed by hand (the password-manager copy) instead of Credential
  Manager, which is the dead-PC path. Drill and prune in that order: never prune before a drill passes.
  py tools/private_backup.py show-key             Lukas only, in his own terminal
"""

import argparse
import base64
import getpass
import hashlib
import io
import json
import os
import secrets
import struct
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cred  # noqa: E402  (tools/cred.py: Windows Credential Manager)

SOURCE = Path(r"C:\Users\{{WIN_USER}}\my-agent\private")
KEY_TARGET = "marty/private-backup-key"
MAGIC = b"MARTYPB1"
CHUNK = 1024 * 1024
EXCLUDE_TOP = {"business"}          # compared case-insensitively
EXCLUDE_ANY = {"__pycache__", "proxies"}
MANIFEST_NAME = ".marty-manifest.json"


# --- key -----------------------------------------------------------------------

def load_key():
    stored = cred.read(KEY_TARGET)
    if not stored:
        sys.exit(f"no key in Credential Manager ({KEY_TARGET}); run: py tools/private_backup.py init")
    key = base64.b64decode(stored)
    if len(key) != 32:
        sys.exit("the stored key is not 32 bytes; refusing to use it")
    return key


def prompt_key():
    stored = getpass.getpass("Backup key (from your password manager; nothing shows while you paste): ").strip()
    try:
        key = base64.b64decode(stored, validate=True)
    except ValueError:
        sys.exit("that isn't a valid key (expected base64 text)")
    if len(key) != 32:
        sys.exit("that key is not 32 bytes; check you copied all of it")
    return key


def get_key(args):
    return prompt_key() if getattr(args, "key_prompt", False) else load_key()


def key_id(key):
    return hashlib.sha256(key).hexdigest()[:16]


# --- encrypted stream ------------------------------------------------------------

class EncryptingWriter(io.RawIOBase):
    """File-like sink for tarfile: buffers plaintext and writes sealed records to `out`."""

    def __init__(self, out, key):
        self.out = out
        self.aes = AESGCM(key)
        self.base = secrets.token_bytes(8)
        header = json.dumps({
            "v": 1, "key_id": key_id(key), "chunk": CHUNK,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "nonce_base": base64.b64encode(self.base).decode(),
        }, separators=(",", ":")).encode()
        self.header = MAGIC + struct.pack(">H", len(header)) + header
        out.write(self.header)
        self.buf = bytearray()
        self.counter = 0
        self.sealed = False

    def writable(self):
        return True

    def _emit(self, data, last):
        ctr = struct.pack(">I", self.counter)
        ct = self.aes.encrypt(self.base + ctr, bytes(data), self.header + ctr + (b"\x01" if last else b"\x00"))
        self.out.write(struct.pack(">I", len(ct)))
        self.out.write(ct)
        self.counter += 1
        if self.counter >= 2 ** 32:
            raise OverflowError("too many records for one nonce base")

    def write(self, b):
        if self.sealed:
            raise ValueError("write after seal")
        self.buf += b
        while len(self.buf) > CHUNK:  # keep at least one byte back so the final record is never empty-by-accident
            self._emit(self.buf[:CHUNK], last=False)
            del self.buf[:CHUNK]
        return len(b)

    def seal(self):
        if not self.sealed:
            self._emit(self.buf, last=True)
            self.buf = bytearray()
            self.sealed = True


class DecryptingReader(io.RawIOBase):
    """File-like source for tarfile: reads sealed records and yields plaintext."""

    def __init__(self, f, key):
        self.f = f
        if f.read(len(MAGIC)) != MAGIC:
            raise ValueError("not a Marty private backup (bad magic)")
        (hlen,) = struct.unpack(">H", f.read(2))
        hjson = f.read(hlen)
        self.header = MAGIC + struct.pack(">H", hlen) + hjson
        meta = json.loads(hjson)
        if meta.get("v") != 1:
            raise ValueError(f"unknown format version {meta.get('v')}")
        if meta.get("key_id") != key_id(key):
            raise ValueError("this backup was made with a different key")
        self.meta = meta
        self.base = base64.b64decode(meta["nonce_base"])
        self.aes = AESGCM(key)
        self.counter = 0
        self.pending = b""
        self.done = False

    def readable(self):
        return True

    def _next(self):
        raw = self.f.read(4)
        if len(raw) < 4:
            raise ValueError("backup is cut off: the final record is missing")
        (n,) = struct.unpack(">I", raw)
        ct = self.f.read(n)
        if len(ct) != n:
            raise ValueError("backup is cut off mid-record")
        ctr = struct.pack(">I", self.counter)
        for flag in (b"\x00", b"\x01"):
            try:
                pt = self.aes.decrypt(self.base + ctr, ct, self.header + ctr + flag)
            except InvalidTag:
                continue
            self.counter += 1
            if flag == b"\x01":
                self.done = True
                if self.f.read(1):
                    raise ValueError("data after the final record")
            return pt
        raise ValueError(f"record {self.counter} failed authentication (tampered, corrupt, or wrong key)")

    def readinto(self, b):
        while not self.pending and not self.done:
            self.pending = self._next()
        if not self.pending:
            return 0
        n = min(len(b), len(self.pending))
        b[:n] = self.pending[:n]
        self.pending = self.pending[n:]
        return n


class HashingReader(io.RawIOBase):
    def __init__(self, f):
        self.f = f
        self.h = hashlib.sha256()
        self.n = 0

    def readable(self):
        return True

    def readinto(self, b):
        data = self.f.read(len(b))
        self.h.update(data)
        self.n += len(data)
        b[:len(data)] = data
        return len(data)


# --- what goes in --------------------------------------------------------------

def _walk_error(err):
    # os.walk swallows errors unless told otherwise, which silently skipped whole folders.
    raise err


def _is_link_dir(path):
    return os.path.islink(path) or (hasattr(os.path, "isjunction") and os.path.isjunction(path))


def wanted_files(root):
    for dirpath, dirnames, filenames in os.walk(root, onerror=_walk_error):
        rel = Path(dirpath).relative_to(root)
        parts = rel.parts
        if not parts:
            dirnames[:] = [d for d in dirnames if d.casefold() not in EXCLUDE_TOP]
        elif len(parts) == 1 and parts[0].casefold() == "scratch":
            dirnames[:] = []  # keep files directly in scratch/, skip its throwaway folders
        dirnames[:] = [d for d in dirnames
                       if d.casefold() not in EXCLUDE_ANY and not _is_link_dir(os.path.join(dirpath, d))]
        dirnames.sort()
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_file() and not p.is_symlink():
                yield p, (rel / name).as_posix()


# --- commands ------------------------------------------------------------------

def cmd_init(_):
    if cred.read(KEY_TARGET):
        print(f"key already present (id {key_id(load_key())}); nothing changed")
        return 0
    key = secrets.token_bytes(32)
    cred.write(KEY_TARGET, base64.b64encode(key).decode())
    if base64.b64decode(cred.read(KEY_TARGET)) != key:
        sys.exit("wrote the key but could not read it back; not using it")
    print(f"key created in Credential Manager as {KEY_TARGET} (id {key_id(key)})")
    return 0


def cmd_status(_):
    s = cred.read(KEY_TARGET)
    print(f"{KEY_TARGET}: " + (f"present (id {key_id(base64.b64decode(s))})" if s else "MISSING"))
    return 0


def cmd_build(args):
    key = load_key()
    out_path = Path(args.out)
    tmp = out_path.with_suffix(out_path.suffix + ".part")
    manifest, skipped, changed = [], [], []
    try:
        with open(tmp, "wb") as out:
            enc = EncryptingWriter(out, key)
            with tarfile.open(fileobj=enc, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                for path, arc in wanted_files(SOURCE):
                    if arc.casefold().startswith("business/"):
                        raise SystemExit(f"refusing: {arc} is inside the business folder")
                    # Open before writing the tar header: a locked or vanished file is skipped and
                    # recorded, instead of killing the whole backup.
                    try:
                        f = open(path, "rb")
                    except OSError as e:
                        skipped.append({"path": arc, "error": str(e)[:200]})
                        continue
                    with f:
                        st = os.fstat(f.fileno())
                        info = tarfile.TarInfo(arc)
                        info.size = st.st_size
                        info.mtime = int(st.st_mtime)
                        # A file that SHRINKS mid-read raises OSError; a streamed tar can't take it
                        # back, so the build fails rather than writing a short member.
                        hr = HashingReader(f)
                        tar.addfile(info, hr)
                        after = os.fstat(f.fileno())
                    entry = {"path": arc, "size": hr.n, "sha256": hr.h.hexdigest()}
                    if after.st_size != st.st_size or after.st_mtime_ns != st.st_mtime_ns:
                        entry["changed_during_copy"] = True   # grew or was rewritten while read: may be torn
                        changed.append(arc)
                    manifest.append(entry)
                body = json.dumps({"source": str(SOURCE),
                                   "excluded": sorted(EXCLUDE_TOP) + ["scratch/*/", "*/proxies/", "__pycache__/", "junctions and symlinks"],
                                   "files": manifest, "skipped": skipped, "changed_during_copy": changed},
                                  indent=1).encode()
                info = tarfile.TarInfo(MANIFEST_NAME)
                info.size = len(body)
                info.mtime = int(datetime.now().timestamp())
                tar.addfile(info, io.BytesIO(body))
            enc.seal()
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, out_path)
    total = sum(m["size"] for m in manifest)
    print(json.dumps({"out": str(out_path), "files": len(manifest), "plaintext_bytes": total,
                      "encrypted_bytes": out_path.stat().st_size, "key_id": key_id(key),
                      "skipped": len(skipped), "changed_during_copy": len(changed)}))
    for e in skipped[:10]:
        print("SKIPPED:", e["path"], "-", e["error"], file=sys.stderr)
    for a in changed[:10]:
        print("CHANGED DURING COPY (may be torn):", a, file=sys.stderr)
    return 0


def cmd_drill(args):
    key = get_key(args)
    try:
        return _drill(args.file, key)
    except Exception as e:  # any failure is a failed drill, reported the same way
        print(json.dumps({"drill": "FAILED", "error": f"{type(e).__name__}: {e}"[:300]}))
        return 1


def _drill(path, key):
    seen, manifest = {}, None
    with open(path, "rb") as f:
        dec = DecryptingReader(f, key)
        with tarfile.open(fileobj=dec, mode="r|") as tar:
            for m in tar:
                data = tar.extractfile(m) if m.isfile() else None
                if data is None:
                    continue
                if manifest is not None:
                    raise ValueError("a member follows the manifest; the manifest must be last")
                if m.name == MANIFEST_NAME:
                    manifest = json.loads(data.read())
                    continue
                h = hashlib.sha256()
                n = 0
                while True:
                    block = data.read(CHUNK)
                    if not block:
                        break
                    h.update(block)
                    n += len(block)
                seen[m.name] = (n, h.hexdigest())
        # tarfile can stop before the last record's padding; read to the end so every record,
        # including the one flagged final, is authenticated.
        while dec.read(CHUNK):
            pass
        if not dec.done:
            raise ValueError("the stream ended before the final record")
    if manifest is None:
        print("DRILL FAILED: no manifest in the backup")
        return 1
    bad = [e["path"] for e in manifest["files"]
           if seen.get(e["path"]) != (e["size"], e["sha256"])]
    extra = sorted(set(seen) - {e["path"] for e in manifest["files"]})
    business = [n for n in seen if n.casefold().startswith("business/")]
    if bad or extra or business:
        print(json.dumps({"drill": "FAILED", "mismatched": bad[:20], "unexpected": extra[:20], "business": business[:5]}))
        return 1
    print(json.dumps({"drill": "passed", "files": len(seen), "bytes": sum(s for s, _ in seen.values()),
                      "skipped_at_build": len(manifest.get("skipped", [])),
                      "changed_during_copy": len(manifest.get("changed_during_copy", [])),
                      "key_id": dec.meta["key_id"], "created": dec.meta["created"]}))
    return 0


def cmd_restore(args):
    # The dead-PC path: decrypt into an empty folder with tarfile's "data" filter (no absolute paths,
    # no ../, no links out, no device files), then check every restored file against the manifest.
    key = get_key(args)
    dest = Path(args.dest)
    if dest.exists() and any(dest.iterdir()):
        sys.exit(f"{dest} is not empty; restore only into an empty folder")
    dest.mkdir(parents=True, exist_ok=True)
    manifest = None
    try:
        with open(args.file, "rb") as f:
            dec = DecryptingReader(f, key)
            with tarfile.open(fileobj=dec, mode="r|") as tar:
                for m in tar:
                    if m.name == MANIFEST_NAME:
                        manifest = json.loads(tar.extractfile(m).read())
                        continue
                    tar.extract(m, dest, filter="data")
            while dec.read(CHUNK):
                pass
            if not dec.done:
                raise ValueError("the stream ended before the final record")
    except Exception as e:
        print(json.dumps({"restore": "FAILED", "error": f"{type(e).__name__}: {e}"[:300], "dest": str(dest)}))
        return 1
    if manifest is None:
        print(json.dumps({"restore": "FAILED", "error": "no manifest in the backup", "dest": str(dest)}))
        return 1
    bad = []
    for e in manifest["files"]:
        p = dest / e["path"]
        h = hashlib.sha256()
        try:
            with open(p, "rb") as fh:
                for block in iter(lambda: fh.read(CHUNK), b""):
                    h.update(block)
        except OSError:
            bad.append(e["path"]); continue
        if h.hexdigest() != e["sha256"]:
            bad.append(e["path"])
    ok = not bad
    print(json.dumps({"restore": "passed" if ok else "FAILED", "files": len(manifest["files"]),
                      "mismatched": bad[:20], "dest": str(dest)}))
    return 0 if ok else 1


def cmd_prune(args):
    if args.keep < 1:
        sys.exit("--keep must be at least 1; prune never deletes every backup")
    for part in Path(args.dir).glob("private-*.mpb.part"):
        part.unlink()   # a build that died mid-write
    files = sorted(Path(args.dir).glob("private-*.mpb"), key=lambda p: p.stat().st_mtime, reverse=True)
    removed = []
    for p in files[args.keep:]:
        p.unlink()
        removed.append(p.name)
    print(json.dumps({"kept": [p.name for p in files[:args.keep]], "removed": removed}))
    return 0


def cmd_show_key(_):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        sys.exit("show-key only runs in your own interactive terminal (PowerShell or Command Prompt).")
    print("This prints the key that unlocks every private backup. Store it in your password manager,")
    print("then close this window. Anyone with this key and the NAS file can read private/.")
    if input('Type SHOW to continue: ').strip() != "SHOW":
        print("cancelled")
        return 1
    print(base64.b64encode(load_key()).decode())
    return 0


def main():
    ap = argparse.ArgumentParser(description="Encrypted backup of my-agent/private/")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("status")
    b = sub.add_parser("build"); b.add_argument("--out", required=True)
    d = sub.add_parser("drill"); d.add_argument("file"); d.add_argument("--key-prompt", action="store_true")
    r = sub.add_parser("restore"); r.add_argument("file"); r.add_argument("dest"); r.add_argument("--key-prompt", action="store_true")
    p = sub.add_parser("prune"); p.add_argument("dir"); p.add_argument("--keep", type=int, default=4)
    sub.add_parser("show-key")
    args = ap.parse_args()
    return {"init": cmd_init, "status": cmd_status, "build": cmd_build, "drill": cmd_drill,
            "restore": cmd_restore, "prune": cmd_prune, "show-key": cmd_show_key}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
