"""Strict, read-only bootstrap for Jr's authenticated local broker pipe.

The private config is written by an elevated installer under Jr's data ACL.
The web service cannot choose a pipe, operation, VM or credential from a
request. A missing or malformed config leaves the research broker disabled.

CHANGED 2026-09-28 (Jr overnight build, helper item 2 "pipe"), from Codex's
2026-09-28 16:12 version: the row validation moved into parse_channel_row()
so jr_broker_client.py (which reads the file through a verified handle) and
read_broker_client() (the path-based reader the pipe probe uses) share one
definition of a valid channel row. Behaviour of read_broker_client() is
unchanged.

CHANGED 2026-09-28 (cloud PR #3 port, 6:40 PM), from the cloud branch
(commit ec64ddc): the version field must be the int 1; 1.0 and true compare
equal to 1 in JSON and used to be accepted.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re

from broker_ipc import BrokerPipeClient


# CHANGED 2026-09-28 evening (fix helper, skeptic item 10): the file lives in
# the Gate 1a channel folder (<Root>\channel), which carries the four-entry
# protected ACL the client verifies; data\ is the service's private folder
# and the broker (a Limited desktop token) cannot write there.
CHANNEL_PATH = Path(r"C:\ProgramData\JrIndependent\channel\broker-channel.json")
ADDRESS = re.compile(r"^\\\\\.\\pipe\\jr-broker-[0-9a-f]{24,64}$")
MIN_BYTES = 50
MAX_BYTES = 1024


class ChannelError(Exception):
    pass


def parse_channel_row(raw: bytes) -> tuple[str, bytes]:
    """Validate the channel file's bytes; return (pipe address, 32-byte key)."""
    try:
        if not isinstance(raw, (bytes, bytearray)) or not MIN_BYTES <= len(raw) <= MAX_BYTES:
            raise ValueError()
        row = json.loads(raw)
        if type(row) is not dict or set(row) != {"version", "address", "authkey"}:
            raise ValueError()
        if (type(row["version"]) is not int or row["version"] != 1 or
                type(row["address"]) is not str or not ADDRESS.fullmatch(row["address"])):
            raise ValueError()
        if type(row["authkey"]) is not str or len(row["authkey"]) != 44:
            raise ValueError()
        key = base64.b64decode(row["authkey"], validate=True)
        if len(key) != 32:
            raise ValueError()
        return row["address"], key
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ChannelError("Jr broker channel is damaged") from exc


def read_broker_client(path: Path = CHANNEL_PATH) -> BrokerPipeClient:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ChannelError("Jr broker channel is unavailable")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ChannelError("Jr broker channel is damaged") from exc
    address, key = parse_channel_row(raw)
    return BrokerPipeClient(address, key)
