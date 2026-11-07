"""
Marty Status Dashboard - device enrollment CLI.

  py setup_dashboard_auth.py enroll lukas [label]   add a device
  py setup_dashboard_auth.py enroll lukas [label] --qr [--path /tonight]
                                                    same, plus a QR code the phone
                                                    scans to log itself in
  py setup_dashboard_auth.py devices                list devices: active (and when
                                                    it ends), expired, or revoked
  py setup_dashboard_auth.py revoke <device_id>      revoke one

Tokens are shown exactly once, here, and only a SHA-256 hash is written to
dashboard-devices.jsonl. If a token is lost, revoke that device and enroll
again.

Since 2026-09-26 a device login ends on the server after 30 days without
use or 90 days after enrollment (dashboard_auth.IDLE_DAYS / MAX_AGE_DAYS).
An ended device is not revoked, it just stops working; enroll again (or
sign in with the passkey) to get a fresh one.

Do not paste a token into any chat, voice session, or cloud AI. Type it
into the dashboard's own login box once and let the browser keep the
session cookie. Same rule as the Channel and marty-portal device tokens.

--qr (added 2026-09-21, ported from Channel's qr.py): a 43-character token
is miserable to type on a phone, so this renders a QR code of the login URL
and opens it on this screen; the phone's camera scans it and lands on the
dashboard already logged in. The token goes in the URL FRAGMENT (#token=),
which a browser never sends to the server, so it cannot reach the dashboard
log, the tailscale serve proxy, or any request line; the login page reads
it, posts it to /api/session, and scrubs it from the address bar and
history before reloading. The PNG is deleted as soon as you press Enter.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

import dashboard_auth

TAILSCALE = r"C:\Program Files\Tailscale\tailscale.exe"
FALLBACK_ORIGIN = "https://{{TAILNET_HOST}}"


def tailnet_origin() -> str:
    """The HTTPS name tailscale serve publishes this PC under, read from the
    running node so a rename cannot leave a stale name here."""
    try:
        out = subprocess.run([TAILSCALE, "status", "--json"], capture_output=True, text=True, timeout=10).stdout
        name = (json.loads(out).get("Self") or {}).get("DNSName", "").rstrip(".")
        if name:
            return "https://" + name
    except Exception:
        pass
    return FALLBACK_ORIGIN


def login_url(token: str, path: str = "/") -> str:
    if not path.startswith("/"):
        path = "/" + path
    return "%s%s#token=%s" % (tailnet_origin(), path, token)


def show_qr(url: str, label: str) -> None:
    """Render the login URL as a QR PNG in the temp folder, open it, wait,
    delete it. The file exists only while you are looking at it."""
    import qrcode  # Python312 has it (installed for Channel); imported here so
    # the plain enroll path never depends on it.
    path = os.path.join(tempfile.gettempdir(), "dashboard-login-%s.png" % (label or "device"))
    qrcode.make(url).save(path)
    os.startfile(path)
    print("QR code opened on this screen. Point the phone camera at it; the")
    print("dashboard opens already logged in. Press Enter here when done and")
    print("the image is deleted.")
    try:
        input()
    except EOFError:
        pass
    try:
        os.remove(path)
        print("QR image deleted.")
    except OSError:
        print("Could not delete %s (still open?). Delete it yourself; it contains the token." % path)


def cmd_enroll(args):
    token = dashboard_auth.enroll(args.handle, args.label)
    print("")
    print("device token for %s (%s):" % (args.handle, args.label or "unlabelled"))
    print("")
    print(token)
    print("")
    print("Shown once. Open the dashboard and paste it into the login box.")
    print("If you lose it, revoke the device and enroll again.")
    print("This login ends after %d days without use, and %d days from now at the latest."
          % (dashboard_auth.IDLE_DAYS, dashboard_auth.MAX_AGE_DAYS))
    print("")
    if getattr(args, "qr", False):
        show_qr(login_url(token, args.path), args.label)


def passkey_parents() -> dict:
    """{device id: [passkey ids]} for every passkey not revoked, read from passkeys.jsonl beside
    the devices file (passkeys.py keeps it). Read only; missing or damaged means no marks.
    passkeys.py refuses a passkey whose parent device is REVOKED; an expired parent is fine."""
    parents = {}
    try:
        lines = (dashboard_auth.ROOT / "passkeys.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return parents
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and not row.get("revoked_at") and row.get("device_id") is not None:
            parents.setdefault(row.get("device_id"), []).append(row.get("id"))
    return parents


def _passkey_words(ids) -> str:
    names = ", ".join(str(i) for i in ids)
    return ("passkey %s" % names) if len(ids) == 1 else ("passkeys %s" % names)


def cmd_devices(args):
    rows = dashboard_auth.list_devices()
    if not rows:
        print("no devices enrolled")
        return
    parents = passkey_parents()
    for r in rows:
        state = dashboard_auth.device_state(r)
        state = state.upper() if state != "active" else state
        seen = r.get("last_seen_at") or "never"
        ends = dashboard_auth.ends_at(r)
        print("  %3d  %-8s %-16s %-17s last seen %s%s" % (
            r.get("id", 0), r.get("handle", "?"), r.get("label") or "-", state, seen,
            ("  ends " + ends) if ends else ""
        ))
        kids = parents.get(r.get("id"))
        if kids and not r.get("revoked_at"):
            # An ended parent still lets its passkey sign in; revoking it does not. Say so, so a
            # tidy-up of expired rows never takes the fingerprint sign-in with it.
            print("        parent of %s: revoking this device ends that passkey too (leave it; expired is harmless)"
                  % _passkey_words(kids))


def cmd_revoke(args):
    kids = passkey_parents().get(args.device_id)
    if dashboard_auth.revoke(args.device_id):
        print("revoked device %d" % args.device_id)
        if kids:
            print("it was the parent of %s, which will no longer sign in; set a passkey up again from a "
                  "signed-in device (More > Fingerprint sign-in)" % _passkey_words(kids))
    else:
        print("no live device with id %d" % args.device_id)


def main():
    ap = argparse.ArgumentParser(
        prog="setup_dashboard_auth.py",
        description="Enroll and revoke dashboard devices (tokens shown once, hashed at rest).",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    en = sub.add_parser("enroll", help="add a device and print its token once")
    en.add_argument("handle", choices=dashboard_auth.HANDLES)
    en.add_argument("label", nargs="?", default=None)
    en.add_argument("--qr", action="store_true", help="also show a QR code the phone scans to log in")
    en.add_argument("--path", default="/", help="page the QR lands on, e.g. /tonight (default /)")
    en.set_defaults(fn=cmd_enroll)

    sub.add_parser("devices", help="list enrolled devices").set_defaults(fn=cmd_devices)

    rv = sub.add_parser("revoke", help="revoke a device by id")
    rv.add_argument("device_id", type=int)
    rv.set_defaults(fn=cmd_revoke)

    args = ap.parse_args()
    try:
        args.fn(args)
    except TimeoutError:
        # dashboard_auth takes a cross-process lock on the devices file (2026-09-25). If the
        # dashboard or passkeys.py holds it past the timeout, say so instead of a traceback.
        print("The device list is busy: the dashboard or passkeys.py is holding its lock.\n"
              "Nothing was changed. Try again in a few seconds.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
