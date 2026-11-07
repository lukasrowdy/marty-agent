"""Cuts a cable the broker connected when the broker can no longer cut it.

CHANGED 2026-09-28 late (wave 3f, skeptic wave 3e finding 4): the default
stale limit rises from 45 s to 60 s, derived from the loop's worst healthy
heartbeat gap instead of a literal: poll_seconds (3) + the gate bridge
(jr_broker_main.gate_bridge_seconds: 30 s driver bound + 2 s gap + 3 s
slack = 35) + one guest status call (15) = 53 s, plus a 7 s margin. At 45
a healthy batch whose loop waited out a long driver call (about 47 s, and
about 50 s for the first gap after approve) could be cut. The mirrors below
are pinned to their sources by test_wave3f_fixes (this process stays light
and does not import the broker at module level).

NEW 2026-09-28 (Jr overnight build, item 1 "broker"). Third and last line of
defence, after the guest's own lease cap and the per-batch network_watchdog
child (whose stdin closes when the broker dies). This one reads the broker's
heartbeat file and acts ONLY on cables the broker itself connected:

  * no heartbeat file, or connected_by_broker false (and cable_unverified
    not true): nothing to do
  * connected_by_broker true and the broker process is dead (pid gone, or a
    recycled pid with a different start time), or the heartbeat is older
    than stale_seconds (the poll loop wedged): cut through
    network_watchdog.cut_network(), which verifies the cable off and only
    escalates to poweroff when it cannot; then rewrite the heartbeat with
    connected_by_broker false and a cut_by_watchdog record so the next pass
    is idle.
  * cable_unverified true (CHANGED 2026-09-28 evening, fix helper, skeptic
    finding B): the broker itself could not verify its last cut (phase
    "fault"). That counts as connected whatever the pid says, so the cut is
    attempted on every pass until it verifies. A live broker in fault keeps
    rewriting the flag, so the cut repeats every interval until the broker
    exits; the cut is idempotent (setlinkstate off on a cable that is off).

A live, fresh broker with a verified cable is never second-guessed: its own
poll loop owns the cable. A heartbeat with vm_mode "fake" is never acted on
by the real cutter.

CHANGED 2026-09-28 evening (fix helper, skeptic finding A): this process now
has a launcher. jr_broker_main spawns it after the broker's first heartbeat
write, detached (its own process group, no console, breakaway from the
caller's job when the job allows it) so it OUTLIVES the broker; it is never
pinned to the broker's pid. It leaves on its own only when
  * the heartbeat says final, the broker pid is gone and the cable is
    verified off (a normal broker exit), or
  * its max lifetime (watchdog_max_lifetime_seconds, default 24 h) has
    passed and the cable is verified off.
While a cable is on or unverified it never leaves. One instance at a time:
its own named lock (watchdog_lock_name, default "<lock_name>-watchdog"); a
second copy exits 2. It writes a status file next to the heartbeat
(watchdog_status_path, default "<heartbeat folder>\\watchdog.json": pid,
process start time, last action, and "exited" with the reason when it
leaves) that the broker reads before spawning, so a watchdog that outlived
one broker serves the next. "Verified off" is read from the VM itself
(showvminfo: cableconnected1 off, or the VM powered off) in real mode; a
fake heartbeat is verified off when it reports neither connected nor
unverified.

Runs from the broker's launch, or by hand with --once. Config keys used:
heartbeat_path, vboxmanage, vm_uuid, log_path, lock_name,
watchdog_lock_name, watchdog_status_path, watchdog_interval_seconds
(default 5), watchdog_stale_seconds (default 60, see DEFAULT_STALE_SECONDS;
wave 3f), watchdog_max_lifetime_seconds (default 86400).
"""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
from pathlib import Path
import sys
import threading
import time

import network_watchdog

log = logging.getLogger("jr.broker.watchdog")
# Wave 3f F4: the loop's worst healthy heartbeat gap, from the same
# constants the loop runs on, plus a margin.
POLL_SECONDS = 3.0             # jr_broker_main.DEFAULTS["poll_seconds"]
GATE_BRIDGE_SECONDS = 35.0     # jr_broker_main.gate_bridge_seconds(2.0)
GUEST_STATUS_SECONDS = 15.0    # research_broker.GUEST_CALL_SECONDS
STALE_MARGIN_SECONDS = 7.0
DEFAULT_STALE_SECONDS = POLL_SECONDS + GATE_BRIDGE_SECONDS + GUEST_STATUS_SECONDS + STALE_MARGIN_SECONDS
DEFAULT_INTERVAL_SECONDS = 5.0
DEFAULT_MAX_LIFETIME_SECONDS = 86400.0
DEFAULT_LOCK_NAME = "Local\\jr-broker-watchdog"
STATUS_NAME = "watchdog.json"
STILL_ACTIVE = 259
EXIT_REFUSED = 2


def read_heartbeat(path):
    """The heartbeat dict, or None when absent or not the expected shape."""
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
            return None
        row = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None
    if type(row) is not dict or row.get("version") != 1:
        return None
    if type(row.get("pid")) is not int or type(row.get("connected_by_broker")) is not bool:
        return None
    if isinstance(row.get("written_at"), bool) or not isinstance(row.get("written_at"), (int, float)):
        return None
    if "cable_unverified" in row and type(row["cable_unverified"]) is not bool:
        return None
    return row


def process_alive(pid, process_start=None):
    """Windows: the pid is open, still active, and (when known) has the same
    creation time as the heartbeat recorded. Elsewhere: os.kill(pid, 0)."""
    if sys.platform != "win32":
        try:
            os.kill(int(pid), 0)
            return True
        except OSError:
            return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    try:
        code = ctypes.c_uint32(0)
        if not kernel32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code)):
            return False
        if code.value != STILL_ACTIVE:
            return False
        if process_start is not None:
            times = [ctypes.c_uint64() for _ in range(4)]
            if kernel32.GetProcessTimes(ctypes.c_void_p(handle), *[ctypes.byref(t) for t in times]):
                if int(times[0].value) != int(process_start):
                    return False
        return True
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def check_once(heartbeat_path, *, cut, process_alive=process_alive, now=None,
               stale_seconds=DEFAULT_STALE_SECONDS, log=log):
    """One pass. Returns {"action": "none"|"cut", "reason": ..., "result": ...}."""
    now = time.time() if now is None else now
    row = read_heartbeat(heartbeat_path)
    if row is None:
        return {"action": "none", "reason": "no readable heartbeat"}
    unverified = row.get("cable_unverified") is True
    if not row["connected_by_broker"] and not unverified:
        return {"action": "none", "reason": "broker reports no cable of its own"}
    alive = process_alive(row["pid"], row.get("process_start"))
    age = now - row["written_at"]
    if unverified:
        reason = "broker reports its cable unverified"
    elif alive and age <= stale_seconds:
        return {"action": "none", "reason": f"broker alive, heartbeat {age:.0f}s old"}
    else:
        reason = ("broker process is dead" if not alive else
                  f"heartbeat stale ({age:.0f}s > {stale_seconds:.0f}s)")
    log.warning("%s with cable connected (batch %s); cutting", reason, row.get("batch_id"))
    try:
        result = cut()
    except Exception as exc:  # noqa: BLE001 - the cutter is the last line; never raise past it
        log.exception("cut failed")
        result = {"network_off_confirmed": False, "poweroff_requested": True, "error": exc.__class__.__name__}
    confirmed = result.get("network_off_confirmed") is True
    log.warning("cut %s (poweroff requested: %s)", "verified" if confirmed else "NOT verified",
                result.get("poweroff_requested"))
    if confirmed:
        updated = dict(row)
        updated["connected_by_broker"] = False
        updated["cable_unverified"] = False
        updated["cut_by_watchdog"] = {"at": now, "reason": reason, "result": result}
        try:
            from jr_broker_main import write_json_atomic
            write_json_atomic(heartbeat_path, updated)
        except Exception:  # noqa: BLE001
            log.exception("heartbeat rewrite failed")
    return {"action": "cut", "reason": reason, "result": result}


# ---------------- the long-lived loop ----------------

def exit_reason(row, *, alive, elapsed, max_lifetime, verified_off):
    """Why this watchdog may leave now, or None. verified_off is asked only
    when a rule could otherwise match (it may run VBoxManage)."""
    finished = (row is not None and row.get("final") is True and not alive and
                not row["connected_by_broker"] and row.get("cable_unverified") is not True)
    if finished and verified_off():
        return "broker finished, cable verified off"
    if elapsed >= max_lifetime and verified_off():
        return f"max lifetime {max_lifetime:.0f}s reached, cable verified off"
    return None


def lock_name(config):
    if config.get("watchdog_lock_name"):
        return str(config["watchdog_lock_name"])
    if config.get("lock_name"):
        return str(config["lock_name"]) + "-watchdog"
    return DEFAULT_LOCK_NAME


def status_path(config):
    if config.get("watchdog_status_path"):
        return Path(config["watchdog_status_path"])
    return Path(config["heartbeat_path"]).with_name(STATUS_NAME)


def read_watchdog_status(path):
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
            return None
        row = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None
    if type(row) is not dict or row.get("version") != 1 or type(row.get("pid")) is not int:
        return None
    return row


def watchdog_alive(path, *, process_alive=process_alive):
    """True when the status file names a watchdog process that is still that
    live process and has not recorded its exit. The broker asks this before
    spawning; the lock is the hard guarantee, this is the cheap check."""
    row = read_watchdog_status(path)
    if row is None or "exited" in row:
        return False
    return process_alive(row["pid"], row.get("process_start"))


def _real_cutter(config):
    """The cutter for a config. A fake-vm heartbeat (the QA harness and the
    tests; that broker's config names no VBoxManage) gets a verified fake
    cut so the heartbeat is rewritten; a real heartbeat needs vboxmanage and
    vm_uuid in the config, or the cut stays unverified and is logged."""
    configured = bool(config.get("vboxmanage") and config.get("vm_uuid"))
    if configured:
        network_watchdog.configure(config["vboxmanage"], config["vm_uuid"])

    def cut():
        row = read_heartbeat(config["heartbeat_path"])
        if row is not None and row.get("vm_mode") == "fake":
            log.info("fake-vm heartbeat; nothing real to cut")
            return {"network_off_confirmed": True, "poweroff_requested": False, "fake": True}
        if not configured:
            log.error("no vboxmanage/vm_uuid in config; cannot cut")
            return {"network_off_confirmed": False, "poweroff_requested": False}
        return network_watchdog.cut_network()
    return cut


def _real_verifier(config):
    """verified_off(row) -> bool. Real mode reads the VM; a fake heartbeat is
    off when it reports neither connected nor unverified; unconfigured with
    no fake heartbeat can prove nothing, so it answers False and the
    watchdog stays."""
    configured = bool(config.get("vboxmanage") and config.get("vm_uuid"))

    def verified_off(row):
        if row is not None and row.get("vm_mode") == "fake":
            return not row["connected_by_broker"] and row.get("cable_unverified") is not True
        if not configured:
            return False
        state = network_watchdog.vm_state()
        return bool(state and (state.get("VMState") == "poweroff" or
                               state.get("cableconnected1") == "off"))
    return verified_off


def serve(config, *, cut, verified_off, process_alive=process_alive, once=False,
          monotonic=time.monotonic, wait=None, now=time.time, log=log):
    """The loop. Every pass: check_once, then the exit rules, then the status
    file. Returns the last outcome plus "exit" (0 or 1 for --once) and, when
    a rule ended it, "reason". wait(interval) returning True stops it (a
    threading.Event.wait in production; a fake in tests)."""
    from jr_broker_main import process_start_time, write_json_atomic
    heartbeat_path = config["heartbeat_path"]
    stale = float(config.get("watchdog_stale_seconds", DEFAULT_STALE_SECONDS))
    interval = float(config.get("watchdog_interval_seconds", DEFAULT_INTERVAL_SECONDS))
    max_lifetime = float(config.get("watchdog_max_lifetime_seconds", DEFAULT_MAX_LIFETIME_SECONDS))
    status_file = status_path(config)
    status = {"version": 1, "pid": os.getpid(), "process_start": process_start_time(),
              "started_at": now(), "max_lifetime_seconds": max_lifetime,
              "interval_seconds": interval, "heartbeat_path": str(heartbeat_path)}
    if wait is None:
        wait = threading.Event().wait
    started = monotonic()
    passes = 0

    def record(outcome, exited=None):
        status.update(written_at=now(), passes=passes, last_action=outcome.get("action"),
                      last_reason=outcome.get("reason"))
        if exited is not None:
            status["exited"] = exited
        try:
            write_json_atomic(status_file, status)
        except Exception:  # noqa: BLE001 - the status file is a courtesy, never the cut
            log.exception("watchdog status write failed")

    while True:
        passes += 1
        outcome = check_once(heartbeat_path, cut=cut, process_alive=process_alive,
                             now=now(), stale_seconds=stale, log=log)
        if once:
            ok = outcome["action"] == "none" or outcome["result"].get("network_off_confirmed") is True
            outcome["exit"] = 0 if ok else 1
            record(outcome, exited="--once")
            return outcome
        row = read_heartbeat(heartbeat_path)
        alive = row is not None and process_alive(row["pid"], row.get("process_start"))
        reason = exit_reason(row, alive=alive, elapsed=monotonic() - started,
                             max_lifetime=max_lifetime, verified_off=lambda: verified_off(row))
        if reason is not None:
            log.info("leaving: %s", reason)
            outcome.update(exit=0, reason=reason)
            record(outcome, exited=reason)
            return outcome
        record(outcome)
        if wait(interval):
            outcome.update(exit=0, reason="stop requested")
            record(outcome, exited="stop requested")
            return outcome


def main(argv=None):
    parser = argparse.ArgumentParser(prog="jr_broker_watchdog")
    parser.add_argument("config")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"refused: config unreadable ({exc.__class__.__name__})", file=sys.stderr)
        return EXIT_REFUSED
    if type(config) is not dict or not isinstance(config.get("heartbeat_path"), str):
        print("refused: config needs heartbeat_path", file=sys.stderr)
        return EXIT_REFUSED
    from jr_broker_main import InstanceLock
    lock = InstanceLock(lock_name(config), lock_dir=Path(config["heartbeat_path"]).parent)
    if not lock.acquire():
        print("refused: another heartbeat watchdog holds the lock", file=sys.stderr)
        return EXIT_REFUSED
    try:
        handlers = [logging.StreamHandler(sys.stderr)]
        if config.get("log_path"):
            handlers.append(logging.FileHandler(config["log_path"], encoding="utf-8"))
        logging.basicConfig(level=logging.INFO, handlers=handlers,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        log.info("heartbeat watchdog started (pid %s)", os.getpid())
        outcome = serve(config, cut=_real_cutter(config), verified_off=_real_verifier(config),
                        once=args.once)
        if args.once:
            print(json.dumps(outcome, default=str))
        return outcome.get("exit", 0)
    finally:
        lock.release()


if __name__ == "__main__":
    sys.exit(main())
