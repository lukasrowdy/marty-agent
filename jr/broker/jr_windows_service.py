"""Offline-first Windows service entrypoint for the independent Jr app.

The service never receives a VM controller. It must be installed under its
own NT SERVICE\\JrIndependent identity and can only bind 127.0.0.1.

CHANGED 2026-09-28 (wave 2 integration): this is the file the installed
service actually runs (install_jr_service.ps1 points the service at
app\\jr_windows_service.py), and the Codex original still built the server
the pre-item-3 way: no broker client, an old pipe_probe lambda, no never-send
screen. build_offline_server now wires the server exactly as jr_app_main.py's
"serve" does (item 3): the broker client from broker_from_config(root) (the
installer's broker-policy.json and app-config.json in the data root; a
missing policy file means "broker not installed" on /api/session, never a
crash), the owner's never-send list as the hosted send screen, and the
public origin from app-config. The admin token file stays as before.
Video (item 8) stays unwired here and in jr_app_main until Gate 5 provides
video-tools.json; make_server's video argument is left None.
"""

from __future__ import annotations

from pathlib import Path
import secrets

from jr_app_main import DEFAULT_PORT, DEFAULT_ROOT
from jr_app_server import broker_from_config, make_server
from jr_auth import JrAuth
from jr_history import JrHistory
from jr_hosted import HostedTap
from jr_never_send import NEVER_SEND_FILE, NeverSendScreen
from jr_private_root import create_private_root, verify_private_root
from jr_spend import JrSpend

import servicemanager
import win32service
import win32serviceutil


SERVICE_NAME = "JrIndependent"


def build_offline_server(root: Path = DEFAULT_ROOT, port: int = DEFAULT_PORT):
    root = Path(root)
    if not root.exists():
        create_private_root(root)
    verify_private_root(root)
    token_path = root / "admin.token"
    if not token_path.exists():
        with open(token_path, "x", encoding="ascii") as stream:
            stream.write(secrets.token_urlsafe(48))
            stream.flush()
    admin_token = token_path.read_text(encoding="ascii")
    if len(admin_token) < 48 or len(admin_token) > 128:
        raise ValueError("Jr administration token is damaged")
    auth = JrAuth(root / "identity.json")
    history = JrHistory(root / "history")
    spend = JrSpend(root)
    history.list_threads()
    spend.summary()
    setup = broker_from_config(root)
    return make_server(auth, port=port, history=history, spend=spend,
                       hosted=HostedTap(spend), admin_token=admin_token,
                       broker=setup.client, broker_reason=setup.reason,
                       public_origin=setup.public_origin,
                       text_allowed=NeverSendScreen(root / NEVER_SEND_FILE))


class JrWindowsService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = "Jr Independent App"
    _svc_description_ = "Jr-only offline-first app; no VirtualBox control"

    def __init__(self, args):
        super().__init__(args)
        self.server = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.server is not None:
            self.server.shutdown()

    def SvcDoRun(self):
        try:
            self.server = build_offline_server()
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            self.server.serve_forever(poll_interval=0.5)
        except Exception:
            servicemanager.LogErrorMsg("Jr independent service initialization failed")
            raise
        finally:
            if self.server is not None:
                self.server.server_close()


if __name__ == "__main__":
    # CHANGED 2026-09-29 (Gate 2, approved 12:09 PM): the wave 2 rewrite dropped
    # the dispatcher call. PrepareToHostSingle only fills the dispatch table;
    # StartServiceCtrlDispatcher is the call that connects to the Service
    # Control Manager. Without it the process exits at once and the SCM logs
    # event 7009 after 30 s, which is exactly how the first Apply failed.
    servicemanager.PrepareToHostSingle(JrWindowsService)
    servicemanager.StartServiceCtrlDispatcher()
