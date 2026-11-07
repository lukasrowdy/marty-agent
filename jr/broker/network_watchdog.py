"""Staged independent cable cutoff for the fixed Jr VM.

Intended to run only during an approved online batch. Closing its stdin,
missing a heartbeat, or reaching its deadline removes the virtual cable.
If cable removal cannot be verified, it requests hard poweroff. This staged
file is not installed or launched by the current dashboard.

CHANGED 2026-09-28 (Jr overnight build, item 1 "broker"):
  * The VBoxManage path and VM UUID are no longer hard-coded. They come from
    configure() or from the --config JSON file given on the command line
    (keys "vboxmanage" and "vm_uuid"). Unconfigured, every VBoxManage call
    raises, so a misconfigured watchdog can never claim a cutoff it did not
    verify (cut_network then reports network_off_confirmed=False).
  * max_lease is a per-batch command-line argument (--max-lease SECONDS,
    default 120) so the short lease keeps its 120 s backstop and the long
    lease is not cut at 120 s. The launcher (fixed_vm_adapter) passes it.
  * cut_network/_state/_poweroff take an explicit vm argument (defaulting
    to the configured one) so tests never rely on a module constant.
  Behaviour of watch() and cut_network() is otherwise unchanged.

CHANGED 2026-09-28 (wave 2 integration, OpenRouter review item): _state()
logs why it answered None, "showvminfo returncode N" against "showvminfo
raised <Exception>", on logger jr.network_watchdog. The fail-safe behaviour
(None forces the poweroff fallback) is unchanged; only the log tells the two
apart afterwards. The child runs with stderr discarded by its launcher, so
the line reaches a log only where logging is configured (tests, and any
future launcher that keeps stderr).

CHANGED 2026-09-28 evening (fix helper, skeptic finding A): the heartbeat
timeout and the loop-stale threshold live here, in one place, so the child
and its launcher (fixed_vm_adapter) cannot drift apart:
  * HEARTBEAT_TIMEOUT 20 s (was 12): one 15 s guest-control call plus one
    3 s pulse interval must not trip the child. --heartbeat-timeout on the
    command line overrides it for tests only; the launcher never passes it.
  * LOOP_STALE_SECONDS 15 s: the launcher's pulse thread keeps the child
    alive only while the broker's poll loop has ticked this recently. A
    wedged broker stops pulsing and the child cuts at most
    LOOP_STALE_SECONDS + HEARTBEAT_TIMEOUT after the last real tick.
"""

from __future__ import annotations

import argparse
import json
import logging
import queue
import subprocess
import sys
import threading
import time


# Filled by configure(); None means "not configured, refuse to run VBoxManage".
VBOX = None
VM = None
DEFAULT_MAX_LEASE = 120.0
HARD_MAX_LEASE = 300.0  # the longest any batch may keep the cable on
# Heartbeat contract between this child and fixed_vm_adapter's pulse thread.
HEARTBEAT_TIMEOUT = 20.0     # seconds without a heartbeat before the child cuts
LOOP_STALE_SECONDS = 15.0    # the launcher pulses only while the broker loop ticked this recently
MAX_HEARTBEAT_TIMEOUT = 60.0
log = logging.getLogger("jr.network_watchdog")


class WatchdogConfigError(Exception):
    pass


def configure(vboxmanage, vm_uuid):
    """Set the VBoxManage path and VM identifier for this process. Either may be
    None, which leaves the watchdog unable to run VBoxManage (fake-VM mode)."""
    global VBOX, VM
    if vboxmanage is not None and (not isinstance(vboxmanage, str) or not vboxmanage.strip()):
        raise WatchdogConfigError("vboxmanage must be a non-empty path or None")
    if vm_uuid is not None and (not isinstance(vm_uuid, str) or not vm_uuid.strip()):
        raise WatchdogConfigError("vm_uuid must be a non-empty string or None")
    VBOX, VM = vboxmanage, vm_uuid


def load_config(path):
    """Read the broker's JSON config and configure this module from it."""
    with open(path, "r", encoding="utf-8") as stream:
        row = json.load(stream)
    if type(row) is not dict:
        raise WatchdogConfigError("Watchdog config must be a JSON object")
    configure(row.get("vboxmanage"), row.get("vm_uuid"))
    return row


def _run(args, timeout):
    if VBOX is None or VM is None:
        raise WatchdogConfigError("VBoxManage path or VM id not configured")
    return subprocess.run([VBOX, *args], capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _state(run, vm=None):
    vm = VM if vm is None else vm
    try:
        result = run(["showvminfo", vm, "--machinereadable"], timeout=3)
        if result.returncode:
            log.warning("VM state unknown: showvminfo returncode %s", result.returncode)
            return None
        rows = {}
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if key in rows:
                    log.warning("VM state unknown: showvminfo repeated key %s", key[:40])
                    return None
                rows[key] = value.strip('"')
        return rows
    except Exception as exc:
        log.warning("VM state unknown: showvminfo raised %s", type(exc).__name__)
        return None


def vm_state(run=None, vm=None):
    """Public read of the VM's machine-readable state, or None when unknown."""
    return _state(run or _run, vm)


def _poweroff(run, vm=None):
    vm = VM if vm is None else vm
    try:
        run(["controlvm", vm, "poweroff"], timeout=5)
    except Exception:
        pass
    state = _state(run, vm)
    if not state or state.get("VMState") != "poweroff":
        try:
            run(["controlvm", vm, "pause"], timeout=2)
        except Exception:
            pass
        for index in range(1, 9):
            try:
                run(["controlvm", vm, f"setlinkstate{index}", "off"], timeout=1)
            except Exception:
                pass
        try:
            run(["controlvm", vm, "poweroff"], timeout=5)
        except Exception:
            pass
        state = _state(run, vm)
    return {"poweroff_confirmed": bool(state and state.get("VMState") == "poweroff")}


def cut_network(run=None, poweroff=None, vm=None):
    run = run or _run
    vm = VM if vm is None else vm
    if poweroff is None:
        poweroff = lambda: _poweroff(run, vm)
    try:
        run(["controlvm", vm, "setlinkstate1", "off"], timeout=5)
    except Exception:
        pass
    state = _state(run, vm)
    if state and (state.get("VMState") == "poweroff" or state.get("cableconnected1") == "off"):
        return {"network_off_confirmed": True, "poweroff_requested": False}
    try:
        result = poweroff()
        confirmed = result.get("poweroff_confirmed") is True
    except Exception:
        confirmed = False
    return {"network_off_confirmed": confirmed, "poweroff_requested": True}


def watch(input_stream, *, monotonic=time.monotonic, timeout=HEARTBEAT_TIMEOUT,
          max_lease=DEFAULT_MAX_LEASE, cutoff=cut_network):
    max_lease = min(float(max_lease), HARD_MAX_LEASE)
    events = queue.Queue()

    def read():
        try:
            for line in input_stream:
                if line == b"heartbeat\n":
                    events.put(monotonic())
        finally:
            events.put(None)

    threading.Thread(target=read, daemon=True).start()
    started = last = monotonic()
    while monotonic() - started < max_lease:
        remain = min(1.0, timeout - (monotonic() - last), max_lease - (monotonic() - started))
        try:
            stamp = events.get(timeout=max(0.01, remain))
        except queue.Empty:
            if monotonic() - last >= timeout:
                break
            continue
        if stamp is None:
            break
        last = stamp
    return cutoff()


MAX_LEASE = HARD_MAX_LEASE
DEFAULT_LEASE = DEFAULT_MAX_LEASE


def lease_from_argv(argv):
    """Item 6's strict form: --max-lease SECONDS only, default 120, refused
    outside 1 to 300. parse_args() below is the full entry point (it also
    takes --config); this stays for callers and tests that use the strict one."""
    if not argv:
        return DEFAULT_LEASE
    if len(argv) != 2 or argv[0] != "--max-lease":
        raise ValueError("usage: network_watchdog.py [--max-lease SECONDS]")
    try:
        value = float(argv[1])
    except ValueError:
        raise ValueError("--max-lease must be a number") from None
    if not 1.0 <= value <= MAX_LEASE:
        raise ValueError("--max-lease must be 1 to 300 seconds")
    return value


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="network_watchdog", add_help=True)
    parser.add_argument("--config", required=False, default=None,
                        help="broker JSON config with vboxmanage and vm_uuid")
    parser.add_argument("--max-lease", type=float, default=DEFAULT_MAX_LEASE,
                        help="seconds before the cable is cut regardless of heartbeats")
    parser.add_argument("--heartbeat-timeout", type=float, default=HEARTBEAT_TIMEOUT,
                        help="seconds without a heartbeat before the cut (tests only)")
    args = parser.parse_args(argv)
    if not (1.0 <= args.max_lease <= HARD_MAX_LEASE):
        parser.error(f"--max-lease must be 1 to {HARD_MAX_LEASE:.0f} seconds")
    if not (1.0 <= args.heartbeat_timeout <= MAX_HEARTBEAT_TIMEOUT):
        parser.error(f"--heartbeat-timeout must be 1 to {MAX_HEARTBEAT_TIMEOUT:.0f} seconds")
    return args


def main(argv=None, input_stream=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.config:
        load_config(args.config)
    result = watch(input_stream if input_stream is not None else sys.stdin.buffer,
                   max_lease=args.max_lease, timeout=args.heartbeat_timeout)
    return 0 if result["network_off_confirmed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
