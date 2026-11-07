"""
cred.py - store and check API keys in Windows Credential Manager, from a terminal.

Generic version of the key store Channel uses (channel/keys.py), so any project
can keep its keys in the OS store with no config file, no environment variable,
no .env, and nothing ever pasted into a chat.

Usage (from C:/Users/{{WIN_USER}}/my-agent):

    py tools/cred.py set itm/elevenlabs        # prompts; paste shows NOTHING, that is normal
    py tools/cred.py gen marty/phone-bridge-path   # makes a random 64-char token, stores it, shows only its length
    py tools/cred.py status itm/elevenlabs itm/openai-images
    py tools/cred.py test itm/elevenlabs       # live round-trip using the stored key
    py tools/cred.py delete itm/elevenlabs

Target names are free-form; use a project prefix so entries are obviously
yours in Control Panel > Credential Manager > Windows Credentials:
    itm/...   Interview the Machine (the show)
    channel/... is owned by channel/keys.py; do not manage those here.

Nothing here caches, logs, or prints a key. `status` prints a redacted stub only;
for marty/ and jr/ names `set`, `gen`, `status` and `test` print the length and nothing else.
"""

import ctypes
import getpass
import json
import secrets
import sys
import urllib.request
import urllib.error

_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_ERROR_NOT_FOUND = 1168


class KeyStoreError(Exception):
    pass


if sys.platform != "win32":
    sys.exit("cred.py only works on Windows (Credential Manager).")

from ctypes import wintypes


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class _CREDENTIAL_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ("Keyword", wintypes.LPWSTR),
        ("Flags", wintypes.DWORD),
        ("ValueSize", wintypes.DWORD),
        ("Value", ctypes.POINTER(ctypes.c_byte)),
    ]


class _CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", _FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.POINTER(_CREDENTIAL_ATTRIBUTE)),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


_PCREDENTIAL = ctypes.POINTER(_CREDENTIAL)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_advapi32.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(_PCREDENTIAL)]
_advapi32.CredReadW.restype = wintypes.BOOL
_advapi32.CredWriteW.argtypes = [_PCREDENTIAL, wintypes.DWORD]
_advapi32.CredWriteW.restype = wintypes.BOOL
_advapi32.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
_advapi32.CredDeleteW.restype = wintypes.BOOL
_advapi32.CredFree.argtypes = [ctypes.c_void_p]
_advapi32.CredFree.restype = None


def read(target: str) -> str | None:
    pcred = _PCREDENTIAL()
    if not _advapi32.CredReadW(target, _CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)):
        err = ctypes.get_last_error()
        if err == _ERROR_NOT_FOUND:
            return None
        raise KeyStoreError(f"CredReadW failed: {ctypes.FormatError(err).strip()}")
    try:
        cred = pcred.contents
        size = cred.CredentialBlobSize
        if size == 0:
            return ""
        return ctypes.string_at(cred.CredentialBlob, size).decode("utf-16-le")
    finally:
        _advapi32.CredFree(pcred)


def write(target: str, secret: str) -> None:
    secret = secret.strip()
    if not secret:
        raise ValueError("refusing to store an empty key")
    if "\n" in secret or "\r" in secret:
        raise ValueError("key contains a newline - probably pasted wrong")
    blob = secret.encode("utf-16-le")
    buf = (ctypes.c_byte * len(blob)).from_buffer_copy(blob)
    cred = _CREDENTIAL()
    cred.Type = _CRED_TYPE_GENERIC
    cred.TargetName = target
    cred.Comment = "API key managed by my-agent/tools/cred.py. Safe to delete to revoke."
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte))
    cred.Persist = _CRED_PERSIST_LOCAL_MACHINE
    cred.UserName = target.split("/")[0] if "/" in target else "marty"
    if not _advapi32.CredWriteW(ctypes.byref(cred), 0):
        err = ctypes.get_last_error()
        raise KeyStoreError(f"CredWriteW failed: {ctypes.FormatError(err).strip()}")


def delete(target: str) -> bool:
    if not _advapi32.CredDeleteW(target, _CRED_TYPE_GENERIC, 0):
        err = ctypes.get_last_error()
        if err == _ERROR_NOT_FOUND:
            return False
        raise KeyStoreError(f"CredDeleteW failed: {ctypes.FormatError(err).strip()}")
    return True


def redacted(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}...{secret[-4:]} ({len(secret)} chars)"


# marty/ and jr/ entries are shared secrets (websocket paths, bridge tokens):
# even a 4-character stub is too much, so they show a length only.
_LENGTH_ONLY_PREFIXES = ("marty/", "jr/")


def shown(target: str, secret: str) -> str:
    if target.startswith(_LENGTH_ONLY_PREFIXES):
        return f"({len(secret)} chars)"
    return redacted(secret)


# --- live tests: prove the key works without ever printing it ----------------

def _http(url, headers, body=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method or ("POST" if data else "GET"))
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, json.loads(r.read().decode() or "{}")


def test(target: str) -> str:
    key = read(target)
    if not key:
        return f"{target}: MISSING (run: py tools/cred.py set {target})"
    name = target.split("/")[-1]
    try:
        if name.startswith("elevenlabs"):
            st, j = _http("https://api.elevenlabs.io/v1/user/subscription", {"xi-api-key": key})
            tier = j.get("tier"); used = j.get("character_count"); lim = j.get("character_limit")
            return f"{target}: ok (tier={tier}, characters {used}/{lim})"
        if name.startswith("openai"):
            st, j = _http("https://api.openai.com/v1/models", {"Authorization": f"Bearer {key}"})
            ids = [m["id"] for m in j.get("data", [])]
            img = [i for i in ids if "image" in i]
            return f"{target}: ok ({len(ids)} models visible; image models: {', '.join(img) or 'none listed'})"
        if name.startswith("google") or name.startswith("gemini"):
            st, j = _http(f"https://generativelanguage.googleapis.com/v1beta/models?key={key}", {})
            ids = [m["name"] for m in j.get("models", [])]
            img = [i for i in ids if "image" in i or "imagen" in i or "veo" in i]
            return f"{target}: ok ({len(ids)} models visible; image/video: {', '.join(img) or 'none listed'})"
        if name.startswith("anthropic"):
            st, j = _http("https://api.anthropic.com/v1/models", {"x-api-key": key, "anthropic-version": "2023-06-01"})
            return f"{target}: ok ({len(j.get('data', []))} models visible)"
        return f"{target}: stored {shown(target, key)}; no live test defined for this provider"
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:200]
        return f"{target}: HTTP {e.code} - {detail}"
    except Exception as e:  # noqa: BLE001
        return f"{target}: error - {e}"


def main(argv):
    if len(argv) < 2:
        print(__doc__); return 2
    cmd, names = argv[0], argv[1:]
    if cmd == "set":
        if len(names) != 1:
            print("set takes exactly one name"); return 2
        print(f"Paste the key for {names[0]} and press Enter.")
        print("NOTHING will show while you paste. That is normal. In Command Prompt, right-click pastes.")
        # Terminal pastes can carry invisible control characters (a leading 0x06
        # broke the ntfy token on 2026-09-28), so keep printable characters only.
        secret = "".join(c for c in getpass.getpass("key: ") if c.isprintable()).strip()
        write(names[0], secret)
        print(f"stored {names[0]} {shown(names[0], secret)}")
        return 0
    if cmd == "gen":
        # A random token that is NEVER displayed: generated here, stored here,
        # and only its length is printed (phone bridge path secret, 2026-10-03).
        if len(names) != 1:
            print("gen takes exactly one name"); return 2
        token = secrets.token_urlsafe(48)
        write(names[0], token)
        print(f"stored {names[0]} ({len(token)} chars, generated, never displayed)")
        return 0
    if cmd == "status":
        for n in names:
            v = read(n)
            if not v:
                print(f"{n}: MISSING")
                continue
            print(f"{n}: present {shown(n, v)}")
        return 0
    if cmd == "test":
        for n in names:
            print(test(n))
        return 0
    if cmd == "delete":
        for n in names:
            print(f"{n}: {'deleted' if delete(n) else 'was not stored'}")
        return 0
    print(f"unknown command {cmd!r}"); print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
