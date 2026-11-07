"""Independent Jr web process.

This entrypoint never touches the VM itself. It is suitable for a
separate-account, loopback-only service once its account, ACL and
owner passphrase are provisioned. It does not import Marty's dashboard.

CHANGED 2026-09-28 (Jr overnight build, item 3 "app"), what and why:
- The broker client comes from jr_app_server.broker_from_config(root): the installer's
  broker-policy.json and app-config.json in the data root. No policy file means no broker,
  and the service says so on /api/session instead of pretending.
- The owner's never-send list (root\\never-send.json) is wired as the hosted send screen.
- --public-origin still wins when given; otherwise the installer's app-config value is used.
"""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from jr_app_server import broker_from_config, make_server
from jr_auth import JrAuth
from jr_history import JrHistory
from jr_never_send import NEVER_SEND_FILE, NeverSendScreen
from jr_private_root import create_private_root, verify_private_root
from jr_spend import JrSpend
from jr_hosted import HostedTap


DEFAULT_ROOT = Path(r"C:\ProgramData\JrIndependent\data")
DEFAULT_PORT = 8794


def safe_root(value: str) -> Path:
    candidate = Path(value)
    path = candidate.resolve()
    if (not candidate.is_absolute() or
        any(part.lower().startswith("onedrive") or part.lower() in {"my-agent", "marty-vault"}
            for part in path.parts)):
        raise ValueError("Jr data must use an independent local directory")
    return path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Independent, offline-first Jr app")
    parser.add_argument("operation", choices=("init", "check", "serve"))
    parser.add_argument("--data-root", default=str(DEFAULT_ROOT))
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--public-origin", default=None)
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("Use a nonprivileged TCP port")
    root = safe_root(args.data_root)
    auth = JrAuth(root / "identity.json")
    if args.operation == "init":
        first = getpass.getpass("New, unique Jr passphrase: ")
        second = getpass.getpass("Repeat Jr passphrase: ")
        if first != second:
            raise ValueError("Passphrases did not match")
        if not 16 <= len(first) <= 1024:
            raise ValueError("Use a unique passphrase of 16 to 1024 characters")
        create_private_root(root)
        auth.provision(first)
        print("Jr's separate identity was created. No VM access was granted.")
        return 0
    if not auth.configured():
        print("Jr identity is not provisioned; offline app is not started.")
        return 2
    verify_private_root(root)
    history = JrHistory(root / "history")
    spend = JrSpend(root)
    hosted = HostedTap(spend)
    setup = broker_from_config(root)
    broker_line = ("broker client configured from broker-policy.json" if setup.client is not None
                   else f"no broker: {setup.reason}")
    if args.operation == "check":
        history.list_threads()  # also detects missing/corrupt initialized history
        spend.summary()
        print(f"Jr's separate identity and encrypted history are readable; {broker_line}.")
        return 0
    server = make_server(auth, port=args.port, history=history, spend=spend,
                         hosted=hosted, broker=setup.client, broker_reason=setup.reason,
                         public_origin=args.public_origin or setup.public_origin,
                         text_allowed=NeverSendScreen(root / NEVER_SEND_FILE))
    print(f"Jr app listening on 127.0.0.1:{server.server_port}; {broker_line}")
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
