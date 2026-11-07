"""Staged narrow VM adapter for the fixed Jr-Computer-Lab instance.

CHANGED 2026-09-28 late (wave 3 follow-up, skeptic wave 3 fix item 2):
tick()'s docstring states the real driver bound (30 s, not 20) and how the
broker bridges it: stamps during its bounded gate wait and again inside poll.

CHANGED 2026-09-28 evening (fix helper, skeptic item 6b): _Watchdog.tick()
stamps the loop tick without a heartbeat, for the broker loop to call before
it waits on the guest gate.

CHANGED 2026-09-28 (Jr overnight build, helper item "guest"):
- arm_guest_quota takes the batch shape (page_limit, request_cap, byte_cap)
  and passes it to the guest CLI; the host refuses values above the same
  maxima the guest enforces (MAX_PAGE_LIMIT 30, MAX_REQUEST_CAP 1500,
  MAX_BYTE_CAP 150 MB). test_fixed_vm_adapter checks these equal the guest's.
- The guest status stdout cap rises from 4096 to MAX_STATUS_BYTES (256 KiB):
  a 30-page batch of search results with 8 links each is about 206 KiB in the
  worst case (guest_page_quota.max_status_bytes()), and a test pins that the
  largest possible status fits under this cap.
- start_network_watchdog takes the batch lease and passes it to the watchdog
  as --max-lease (1 to 300 s), so a long batch is not cut at 120 s.

CHANGED 2026-09-28 (Jr overnight build, item 1 "broker"), merged onto item
6's copy; these are item 1's hunks:
- The watchdog child no longer has a hard-coded VBoxManage path or VM id, so
  start_network_watchdog also passes "--config PATH" (the broker config,
  given as watchdog_config=... at construction). The config is mandatory:
  an unconfigured watchdog cannot verify a cutoff, so the adapter refuses to
  start one and the batch is refused, which is the safe direction.
- _Watchdog pulses the heartbeat from its own daemon thread every
  PULSE_SECONDS, independent of the broker's poll. Before this, the only
  pulse was inside ResearchBroker.poll(), which holds the broker lock across
  a guest-control call with a 15 s timeout while the watchdog's heartbeat
  timeout is 12 s: one slow guest call cut the cable. The thread never
  touches guest control or the broker lock. close() stops it and closes
  stdin (which is what makes the watchdog cut).

CHANGED 2026-09-28 evening (fix helper, skeptic finding A): the pulse thread
alone let a wedged-but-alive broker keep the cable on until --max-lease. Now
pulse() from the broker's poll loop is the loop's tick, and the thread only
bridges the gaps while that tick is younger than LOOP_STALE_SECONDS (15 s,
from network_watchdog so it sits next to the child's HEARTBEAT_TIMEOUT of
20 s). A loop that stops ticking stops the pulses; the child cuts.
- modify_cable_off(): "modifyvm --cable-connected1=off" through the
  controller, for a VM found saved at broker startup (skeptic finding D).
  Verified by re-reading cableconnected1; never raises.

The future privileged broker imports the already-tested jr_computer module and
passes it here. The independent Jr web service must never import this adapter
or receive VirtualBox credentials. This code is not installed or run against
the VM by the staging shell.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time

from network_watchdog import LOOP_STALE_SECONDS


GUEST_CLI = "/opt/jr-computer/guest_quota_cli.py"
GUEST_PYTHON = "/usr/bin/python3"
BATCH_RE = re.compile(r"^[A-Za-z0-9_-]{24,80}$")
# Must equal guest_page_quota's maxima (a test cross-checks without importing).
MAX_PAGE_LIMIT = 30
MAX_REQUEST_CAP = 1500
MAX_BYTE_CAP = 150 * 1024 * 1024
MAX_LEASE_SECONDS = 300
MAX_STATUS_BYTES = 262144
PULSE_SECONDS = 3.0


class VmAdapterError(Exception):
    pass


class _Watchdog:
    def __init__(self, process, *, pulse_seconds=PULSE_SECONDS,
                 loop_stale_seconds=LOOP_STALE_SECONDS, monotonic=time.monotonic):
        self.process = process
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.pulse_seconds = pulse_seconds
        self.loop_stale_seconds = loop_stale_seconds
        self.monotonic = monotonic
        self.last_tick = monotonic()
        self.thread = None

    def pulse(self):
        """The broker's poll loop calls this: it is the loop's tick and a
        heartbeat in one."""
        self.last_tick = self.monotonic()
        self._send()

    def tick(self):
        """The loop's tick alone, no heartbeat sent (ADDED 2026-09-28, fix
        helper, skeptic item 6b). A navigator driver call can hold the guest
        gate for up to 30 s (jr_computer's guest-control timeout), longer
        than LOOP_STALE_SECONDS, so the broker loop stamps this before and
        during its gate wait (bounded by jr_broker_main.gate_bridge_seconds)
        and ResearchBroker.poll stamps it again before its guest status
        call (CORRECTED 2026-09-28 late, skeptic wave 3 item 2). The pulse
        thread keeps bridging a healthy wait; a wedged loop, or a driver call
        wedged past the bridge, stops the stamps and goes stale."""
        self.last_tick = self.monotonic()

    def _send(self):
        with self.lock:
            if self.stopped.is_set():
                raise VmAdapterError("Network watchdog was closed")
            if self.process.poll() is not None:
                raise VmAdapterError("Network watchdog exited")
            self.process.stdin.write(b"heartbeat\n")
            self.process.stdin.flush()

    def loop_is_fresh(self):
        return self.monotonic() - self.last_tick <= self.loop_stale_seconds

    def start_pulsing(self):
        """Heartbeat from a thread of its own so a slow guest-control call in the
        broker's poll cannot starve the watchdog into cutting the cable. The
        thread pulses only while the broker's loop has ticked recently; a
        wedged loop goes silent and the child's timeout cuts the cable."""
        if self.thread is not None:
            return self
        self.thread = threading.Thread(target=self._pulse_loop, name="jr-watchdog-pulse",
                                       daemon=True)
        self.thread.start()
        return self

    def _pulse_loop(self):
        while not self.stopped.wait(self.pulse_seconds):
            if not self.loop_is_fresh():
                continue  # the broker's loop is stale: let the child time out
            try:
                self._send()
            except Exception:
                # The watchdog is gone or closed: nothing more to keep alive.
                # The broker notices on its next pulse() or poll().
                return

    def close(self):
        self.stopped.set()
        with self.lock:
            try:
                self.process.stdin.close()
            except Exception:
                pass


def validate_caps(page_limit, request_cap, byte_cap):
    for name, value, maximum in (("page limit", page_limit, MAX_PAGE_LIMIT),
                                 ("request cap", request_cap, MAX_REQUEST_CAP),
                                 ("byte cap", byte_cap, MAX_BYTE_CAP)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise VmAdapterError(f"Batch {name} must be an integer from 1 to {maximum}")


class FixedVmAdapter:
    def __init__(self, controller, *, watchdog_path=None, popen=subprocess.Popen,
                 watchdog_config=None):
        self.controller = controller
        self.popen = popen
        self.watchdog_path = Path(watchdog_path or Path(__file__).with_name("network_watchdog.py"))
        self.watchdog_config = None if watchdog_config is None else str(watchdog_config)

    def _machine_rows(self):
        result = self.controller._host(["showvminfo", self.controller.VM, "--machinereadable"], 5)
        if result.returncode:
            raise VmAdapterError("Fixed VM state unavailable")
        rows = {}
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if key in rows:
                    raise VmAdapterError("Duplicate VM state key")
                rows[key] = value.strip('"')
        return rows

    def isolated_running_cable_off(self):
        try:
            if self.controller.isolation(True) != "running":
                return False
            if self._machine_rows().get("cableconnected1") != "off":
                return False
            self.controller._attest_guard()
            return True
        except Exception:
            return False

    def _guest_quota(self, command, batch_id=None, expires_at=None, caps=None):
        if command not in {"arm", "status", "close"}:
            raise VmAdapterError("Unknown fixed guest operation")
        if command == "arm":
            if not isinstance(batch_id, str) or not BATCH_RE.fullmatch(batch_id):
                raise VmAdapterError("Invalid generated batch id")
            if type(expires_at) not in {int, float}:
                raise VmAdapterError("Invalid lease deadline")
            if type(caps) is not dict or set(caps) != {"page_limit", "request_cap", "byte_cap"}:
                raise VmAdapterError("Invalid batch caps")
            validate_caps(caps["page_limit"], caps["request_cap"], caps["byte_cap"])
            tail = [command, batch_id, str(expires_at), str(caps["page_limit"]),
                    str(caps["request_cap"]), str(caps["byte_cap"])]
        else:
            tail = [command]
        root = self.controller.ROOT
        fd, filename = tempfile.mkstemp(prefix="jr-quota-auth-", dir=root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(self.controller._password("admin-password.dpapi"))
            arguments = ["guestcontrol", self.controller.VM, "run", "--username=kali",
                         "--passwordfile=" + filename, "--exe=/usr/bin/sudo",
                         "--wait-stdout", "--wait-stderr", "--timeout=12000", "--",
                         "-n", GUEST_PYTHON, GUEST_CLI, *tail]
            result = self.controller._host(arguments, 15)
            if result.returncode or len(result.stdout) > MAX_STATUS_BYTES:
                raise VmAdapterError("Guest page quota command failed")
            row = json.loads(result.stdout)
            if (type(row) is not dict or type(row.get("used")) is not int or
                row["used"] not in range(MAX_PAGE_LIMIT + 1)):
                raise VmAdapterError("Guest page quota returned invalid status")
            return row
        except (OSError, ValueError, TypeError) as exc:
            raise VmAdapterError("Guest page quota unavailable") from exc
        finally:
            Path(filename).unlink(missing_ok=True)

    def arm_guest_quota(self, batch_id, deadline, *, page_limit, request_cap, byte_cap):
        if not self.isolated_running_cable_off():
            raise VmAdapterError("Cannot arm a guest batch while cable or guard is unverified")
        return self._guest_quota("arm", batch_id, deadline,
                                 {"page_limit": page_limit, "request_cap": request_cap,
                                  "byte_cap": byte_cap})

    def guest_quota_status(self):
        return self._guest_quota("status")

    def close_guest_quota(self):
        return self._guest_quota("close")

    def connect_cable(self):
        if not self.isolated_running_cable_off():
            return False
        try:
            self.controller._cable(True)
            return self._machine_rows().get("cableconnected1") == "on"
        except Exception:
            return False

    def disconnect_cable(self):
        try:
            self.controller._cable(False)
            return self._machine_rows().get("cableconnected1") == "off"
        except Exception:
            return False

    def hard_poweroff(self):
        try:
            return self.controller.cut_off()["poweroff_confirmed"] is True
        except Exception:
            return False

    def modify_cable_off(self):
        """Cable off in the VM's stored configuration (a saved VM has no
        running link to cut). True only when re-read as off."""
        try:
            result = self.controller._host(["modifyvm", self.controller.VM,
                                            "--cable-connected1=off"], 10)
            if result.returncode:
                return False
            return self._machine_rows().get("cableconnected1") == "off"
        except Exception:
            return False

    def start_network_watchdog(self, max_lease=120):
        if type(max_lease) not in {int, float} or not 1 <= max_lease <= MAX_LEASE_SECONDS:
            raise VmAdapterError(f"Watchdog lease must be 1 to {MAX_LEASE_SECONDS} seconds")
        if not self.watchdog_path.is_file():
            raise VmAdapterError("Network watchdog file missing")
        if self.watchdog_config is None or not Path(self.watchdog_config).is_file():
            raise VmAdapterError("Network watchdog config missing; refusing an unverifiable cutoff")
        process = self.popen([sys.executable, "-B", str(self.watchdog_path),
                              "--config", self.watchdog_config,
                              "--max-lease", str(int(max_lease))],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        watchdog = _Watchdog(process)
        watchdog.pulse()  # prove the pipe is live before connecting internet
        return watchdog.start_pulsing()
