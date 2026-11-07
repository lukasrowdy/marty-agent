"""Jr's durable VM broker process.

CHANGED 2026-09-28 late (wave 3g, skeptic wave 3f finding 1): the facade's
approve passes the pipe's received_at through to ResearchBroker.approve (the
budget clock starts when the request arrived), and after a successful
approve it asks client_alive once more: a client that gave up while the
cable was being connected gets the batch stopped (cable off, guest batch
closed, no navigator) instead of an online batch nobody is watching.

CHANGED 2026-09-28 late (wave 3f, skeptic wave 3e finding 2): the facade's
approve takes the pipe's optional client_alive check and hands it to
ResearchBroker.approve, which refuses before the cable goes on when the
app's client has already given up.

CHANGED 2026-09-28 late (wave 3e, skeptic wave 3d findings 1, 3b and 6):
- F1: the facade writes the heartbeat only after a successful approve, stop
  or emergency, or after a failure that left the cable unverified (phase
  "fault" or cable_unverified: that write can only make jr_broker_watchdog
  cut, never hold a cut off). begin never writes: it changes nothing the
  watchdog acts on, and the loop writes every poll_seconds anyway. Before,
  a failed begin or approve during a wedge refreshed written_at and held
  off the heartbeat watchdog's stale cut. approve still writes on success
  because the cable has just gone on and the loop may be a tick away.
- F3b: run() builds the GuestGate before the broker and hands the broker
  that same gate, so approve's arm and status calls and stop's guest close
  share it with the loop and the navigator.
- F6: the facade passes cut_after (stale_after + LOOP_STALE_SECONDS) to
  snapshot() and to status(), which then report phase "cutting" with reason
  "loop_stale" or "deadline_passed" (see ResearchBroker.snapshot).
- F3: status() is non-blocking now (ResearchBroker.status).
- F3b follow-on: approve checks the old navigator BEFORE the broker arms.
  With approve now waiting on the gate, a navigator stuck inside a guest
  call (holding the gate) turned the second approval into a generic
  refusal after 15 s. Now a valid approval (check_approval) that finds the
  old navigator alive after the bounded join is spent through the stop
  path and refused "navigator_busy" with the cable never put on.

CHANGED 2026-09-28 late (wave 3c pulse fix, skeptic wave 3c pulse verdict):
- The pipe's poll op is read-only. The web app's watch_batch polls it every
  3 s; BrokerFacade.poll called ResearchBroker.poll() outside the GuestGate,
  which stamped the watchdog tick, pulsed the child, rewrote the heartbeat
  and made a guest status call while the loop sat blocked behind a wedged
  navigator driver call. Both watchdogs stayed fed until the host deadline
  or the child's --max-lease (120 s short, 300 s long), and the pipe poll's
  guest call could land inside a typing sequence. BrokerFacade.poll now
  returns ResearchBroker.snapshot(): the last public status, no tick, no
  pulse, no heartbeat write, no guest-control call, no deadline evaluation,
  never waiting on the broker lock, plus "stale_seconds" when the loop's
  last real poll of an online batch is older than stale_after (2 x
  poll_seconds + gate_bridge_seconds). The loop's poll through the gate is
  the only thing that ticks, pulses, writes the loop heartbeat, checks the
  deadline and presence, and cuts. status() was checked: it neither ticks
  nor pulses, and is unchanged.
- The GuestGate clock is time.monotonic (run() passed the wall clock), so a
  backward wall-clock step cannot lengthen the gate bridge.

CHANGED 2026-09-28 late (wave 3 follow-up, skeptic wave 3 fix list):
- item 1: when the previous batch's navigator is still inside a driver call
  after the bounded join, NavigatorRunner.start raises NavigatorBusy and the
  facade stops the new batch through the stop path (cable off, guest batch
  closed, phase stopped) and refuses approve with the typed pipe refusal
  "navigator_busy". Before, the batch stayed online for its whole lease with
  nothing driving it.
- item 2: a guest-control driver call can hold the gate for up to 30 s
  (jr_computer's guest-control subprocess timeout), not 20. The poll loop
  now keeps stamping the watchdog tick WHILE it waits on the gate, bounded by
  gate_bridge_seconds() (the 30 s driver bound plus the gate's gap plus
  slack), and ResearchBroker.poll stamps it again once the gate is held,
  before its own guest status call. A navigator wedged past that bound, or a
  wedged loop, stops the stamps and the pulses end within LOOP_STALE_SECONDS.

CHANGED 2026-09-28 evening (fix helper, skeptic integrated verdict):
- item 2: the real-mode link picker is JrModel(think=False) (navigator_model
  below), so a pick fits the lease budget instead of thinking past it;
- item 6a: NavigatorRunner.start joins the previous batch's thread (bounded)
  before launching the next one;
- item 6b: the poll loop stamps the network watchdog's tick before it waits
  on the guest gate (_tick_watchdog), so a long driver call holding the gate
  does not silence the pulse thread;
- item 10: --check-config validates a real-mode config and exits 0 or 2
  without touching the VM, the lock, the pipe or any file.

NEW 2026-09-28 (Jr overnight build, item 1 "broker"). Runs as the desktop
user from a scheduled task (Interactive, Limited; logon trigger plus a
5-minute repetition), because the VirtualBox registration and the DPAPI
blobs the VM adapter needs are user-scoped. It is the ONE thing that touches
the VM cable once installed.

Startup, in this order, and nothing serves before all of it passes:
  1. Instance lock. A second copy exits with code 2 while the first holds it
     (a named mutex on Windows, released by the kernel if the broker dies).
  2. VM state, then the cable, in that order (CHANGED 2026-09-28 evening,
     fix helper, skeptic finding D):
       running  cut the cable FIRST, through network_watchdog.cut_network,
                before any other step can depend on it. Hard poweroff is
                only the escalation when the cut cannot be verified; if
                that also fails, exit 4 (fault).
       paused   the same cut (a paused VM with the cable on resumes live),
                then exit 3: it is not running and this broker does not
                resume VMs.
       saved    no running link to cut; the stored cable state is set off
                through the adapter (modifyvm --cable-connected1=off,
                verified by re-reading it); exit 3, or exit 4 when that
                cannot be verified.
       other    exit 3. Expected after a reboot until the VM starts; the
                task's repetition retries it. Not a crash, not a loop the
                supervisor should escalate.
  3. Isolation check through the adapter (running, cable off, guard attested).
     Fails: exit 5, with the cable already off.
  4. Serve the authenticated named pipe (BrokerPipeServer from broker_ipc.py,
     ops fixed: begin, approve, status, stop, emergency, poll) pinned to the
     Jr service SID from the config, backed by ResearchBroker. Publish the
     pipe address and key in the channel file (version 1, the shape
     jr_broker_channel.read_broker_client() reads). Write the first
     heartbeat, then launch the heartbeat watchdog (below).

While serving: a poll tick every poll_seconds (3) drives ResearchBroker.poll()
when a batch is online, re-checks that the VM is still running when idle
(exit 3 if it is not), and writes the heartbeat file: pid, process start
time, connected_by_broker, cable_unverified, poweroff_confirmed, batch_id,
lease_seconds, presence, phase, used, limit, deadline. The heartbeat is
written from the poll loop on purpose, so it goes stale when the poll loop
wedges; jr_broker_watchdog.py reads it and cuts a cable this broker
connected if this broker is dead or stale. The pipe watchdog heartbeat (the
network_watchdog child) is pulsed from a thread in fixed_vm_adapter that
follows the poll loop's ticks, so a slow guest-control call never starves
it but a wedged loop does not keep it alive either. The pipe's poll op
reads a snapshot and feeds neither watchdog (wave 3c pulse fix).

Heartbeat truth (CHANGED 2026-09-28 evening, fix helper, skeptic finding B):
connected_by_broker is true while a batch is online AND whenever the cable
is unverified: phase "fault", or the last disconnect could not be verified
(cable_unverified true; poweroff_confirmed records what the escalation
said). It never goes false on this broker's word alone after a failed cut;
jr_broker_watchdog verifies the cable from the VM and clears it.

Heartbeat watchdog launch (CHANGED 2026-09-28 evening, fix helper, skeptic
finding A): after the first heartbeat write the broker launches
jr_broker_watchdog.py as a detached process (own process group, no console,
breakaway from the caller's job where allowed) that must OUTLIVE this
broker; it is never given this broker's pid. Before launching, and every
watchdog_check_seconds (60) while serving, the broker reads the watchdog's
status file (watchdog.json next to the heartbeat): a live watchdog (pid and
process start time still that live process, no "exited" note) is left
alone; a missing or finished one is launched again. The watchdog's own lock
makes a duplicate exit 2 harmlessly. A launch failure is logged and the
broker keeps serving: the per-batch child and the guest cap still stand.

Shutdown (SIGINT, SIGTERM, SIGBREAK, or the run() stop event): an online
batch is disconnected and verified, the heartbeat is rewritten as final
(connected_by_broker false only when that cut verified), the pipe closes,
the channel file is removed, the lock is released.

--fake-vm: the fake VM from test_research_broker.py stands in for the
adapter. That mode installs an import guard that refuses jr_computer,
jr_emergency_stop and jr_vm_watchdog, refuses a config that names a
VBoxManage path, VM id or controller, leaves network_watchdog unconfigured
and refuses to run if any VBoxManage path is resolved or if any module in
sys.modules was loaded from the dashboard folder (CHANGED 2026-09-28
evening, fix helper, skeptic finding 7: these are ConfigError raises, not
asserts, so PYTHONOPTIMIZE cannot strip them, and a module loaded through
spec_from_file_location or runpy is caught by its __file__). The dashboard
folder is config "dashboard_dir" or, absent that, the "dashboard" folder
holding jr_computer.py found by walking up from this file; nothing from it
is imported or added to sys.path. It is for the QA harness and the tests;
it never touches VirtualBox.

Config (JSON file, the only argument besides the flags): see
broker-config.example.json. The VBoxManage path, VM UUID, service SID and
every folder come from it; nothing here is hard-coded to this PC. No secret
lives in the config: the pipe key is generated per start, the grant key is
read from Credential Manager by jr_presence.

Exit codes (the supervisor, deploy/run-jr-broker.ps1, reads these):
  0  stopped cleanly (signal, stop event, or the supervisor died: see below).
  1  crash: an unhandled exception. Restart with backoff.
  2  refused: lock held by another broker, bad config, or a fake-mode
     refusal. DO NOT RESTART; nothing changes until a person fixes it.
  3  VM not running (at start, or it stopped while idle). Quiet exit; the
     task's repetition retries it. Not a crash.
  4  the startup cable cut could not be verified (poweroff was attempted).
  5  isolation failed after the cut (cable is off).
  2 and 3 are the quiet exits; 4 and 5 are faults the supervisor may retry
  with backoff like a crash, since the cable is off either way.

Navigator (CHANGED 2026-09-28, wave 2 integration): every approved batch
whose plan is a JSON object runs jr_navigator.Navigator on its own thread
under this broker. The poller and the navigator share one GuestGate
(config guest_min_gap_seconds between guest-control calls, default 2), so
a poll never lands inside a typing sequence. The navigator gets the plan
(json.loads of the stored plan text; a plan that is not a JSON object,
such as the harness's "plan text", leaves the navigator idle and the batch
runs as before), the question (the plan's "question" when the app sends
one, else its "objective"), the broker's own deadline and the profile's
page limit, and it asks the model outside the gate. Real mode drives the
guest through the controller module's _driver (the Cua driver in
jr_computer, loaded by RealVmRuntime through the configured
controller_path) and picks links with jr_model.JrModel (Ollama);
--fake-vm uses FakeGuestDriver, which charges a slot in the fake VM's
guest state per typed page, and FakeLinkPicker, which picks the first two
results and never opens a socket. stop, emergency, the batch leaving
"online" and shutdown all signal the navigator's stop event; shutdown
joins it briefly after the cable is cut. Config: guest_min_gap_seconds
(0 to 10), navigator_receipt_poll_seconds (0.01 to 30, default 3),
navigator_log_path (optional JSONL of navigator events).

Parent death: the supervisor is killed by Task Scheduler with
TerminateProcess, so it gets no finally block. Given --parent-pid N (or the
JR_BROKER_PARENT_PID environment variable), the broker records that
process's creation time at startup and checks it is still that live process
on every poll tick; when it is gone the broker runs the same shutdown as
SIGTERM (cut the cable first, final heartbeat, channel removed) and exits 0
within one poll interval. A pid that is not alive at startup is refused
(exit 2): a broker with no supervisor must not start.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import importlib.abc
import importlib.util
import json
import logging
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time

import network_watchdog
from broker_ipc import BrokerPipeServer, BrokerRefusal
from jr_navigator import DDG_LITE, DRIVER_CALL_BOUND_SECONDS, GuestGate, Navigator, NavigatorError
from research_broker import BrokerError, ResearchBroker

EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_VM_NOT_RUNNING = 3
EXIT_CUT_UNVERIFIED = 4
EXIT_ISOLATION = 5

FORBIDDEN_IMPORTS = ("jr_computer", "jr_emergency_stop", "jr_vm_watchdog")
FORBIDDEN_FAKE_KEYS = ("vboxmanage", "vm_uuid", "controller_path")
REQUIRED_REAL_KEYS = ("vboxmanage", "vm_uuid", "client_sid", "controller_path", "deps_dir")
DEFAULTS = {"poll_seconds": 3.0, "vm_check_seconds": 30.0, "lock_name": "Local\\jr-broker",
            "heartbeat_version": 1, "watchdog_check_seconds": 60.0,
            "guest_min_gap_seconds": 2.0, "navigator_receipt_poll_seconds": 3.0}
NAVIGATOR_JOIN_SECONDS = 5.0
GATE_BRIDGE_SLACK_SECONDS = 3.0   # on top of the driver bound and the gate gap
PIPE_PREFIX = r"\\.\pipe\jr-broker-"
HERE = Path(__file__).resolve().parent
WATCHDOG_SCRIPT = HERE / "jr_broker_watchdog.py"
DASHBOARD_MARKER = "jr_computer.py"
# Windows process creation flags for the detached heartbeat watchdog.
DETACHED_PROCESS = 0x00000008
CREATE_BREAKAWAY_FROM_JOB = 0x01000000

log = logging.getLogger("jr.broker")


class ConfigError(Exception):
    pass


# ---------------- parent process ----------------

def parent_alive_check(pid):
    """A callable that answers whether the given process is still the same
    live process it was when this was built (creation time pinned, so a
    recycled pid does not count). None when pid is None."""
    if pid is None:
        return None
    from jr_broker_watchdog import process_alive
    pid = int(pid)
    if pid <= 0 or pid == os.getpid():
        raise ConfigError("parent pid must be another live process")
    start = process_start_time(pid)
    if not process_alive(pid, start):
        raise ConfigError(f"parent process {pid} is not alive; refusing to start")
    return lambda: process_alive(pid, start)


# ---------------- fake-mode import guard ----------------

class ImportGuard(importlib.abc.MetaPathFinder):
    """Refuses the dashboard's VM modules by name, before any finder runs."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in FORBIDDEN_IMPORTS:
            raise ImportError(f"{fullname} is refused in --fake-vm mode")
        return None


def install_import_guard():
    for entry in sys.meta_path:
        if isinstance(entry, ImportGuard):
            return entry
    guard = ImportGuard()
    sys.meta_path.insert(0, guard)
    for name in FORBIDDEN_IMPORTS:
        if name in sys.modules:
            raise ImportError(f"{name} is already imported; refusing --fake-vm")
    return guard


def remove_import_guard(guard):
    try:
        sys.meta_path.remove(guard)
    except ValueError:
        pass


def find_dashboard_dir(start=HERE):
    """The "dashboard" folder holding jr_computer.py, from the broker's known
    place in the tree: the broker runs from <root>\\jr\\broker (staged:
    <root>\\jr\\.staged-build\\broker) and the dashboard is <root>\\dashboard,
    so the nearest ancestor named "jr" gives the root. Only is_file() is
    asked of it; nothing there is imported. None when there is no such
    ancestor or no jr_computer.py there (then config dashboard_dir is the
    only source)."""
    folder = Path(start).resolve()
    for ancestor in (folder, *folder.parents):
        if ancestor.name == "jr":
            candidate = ancestor.parent / "dashboard"
            if (candidate / DASHBOARD_MARKER).is_file():
                return candidate
            return None
    return None


def dashboard_dir(config, start=HERE):
    if config.get("dashboard_dir"):
        return Path(config["dashboard_dir"])
    return find_dashboard_dir(start)


def loaded_dashboard_modules(folder):
    """Names of sys.modules entries whose __file__ lies under folder. Catches
    what the name-based import guard cannot: spec_from_file_location, runpy,
    and anything already loaded before the guard went in."""
    if folder is None:
        return []
    try:
        root = Path(folder).resolve()
    except OSError:
        return []
    found = []
    for name, module in list(sys.modules.items()):
        file = getattr(module, "__file__", None)
        if not isinstance(file, str):
            continue
        try:
            Path(file).resolve().relative_to(root)
        except (OSError, ValueError):
            continue
        found.append(name)
    return sorted(found)


def refuse_fake_mode_leaks(config):
    """Explicit raises (never asserts, so -O cannot strip them): no VBoxManage
    path resolved, no VM key in the config, no dashboard module loaded."""
    if network_watchdog.VBOX is not None or network_watchdog.VM is not None:
        raise ConfigError("fake-vm mode must never resolve a VBoxManage path")
    present = [key for key in FORBIDDEN_FAKE_KEYS if config.get(key) is not None]
    if present:
        raise ConfigError("fake-vm refuses a config naming " + ", ".join(present))
    folder = dashboard_dir(config)
    loaded = loaded_dashboard_modules(folder)
    if loaded:
        raise ConfigError("--fake-vm refuses to run with dashboard modules loaded: " +
                          ", ".join(loaded))


# ---------------- single instance ----------------

class InstanceLock:
    """One broker per config. Windows: a named mutex, released by the kernel
    when the holder dies. Elsewhere: an flock on a lock file (for the Linux
    test lane)."""

    def __init__(self, name, lock_dir=None):
        self.name = name
        self.lock_dir = lock_dir
        self.handle = None
        self.stream = None

    def acquire(self):
        if sys.platform == "win32":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.restype = ctypes.c_void_p
            kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
            handle = kernel32.CreateMutexW(None, True, self.name)
            error = ctypes.get_last_error()
            if not handle:
                return False
            if error == 183:  # ERROR_ALREADY_EXISTS: another instance holds it
                kernel32.CloseHandle(ctypes.c_void_p(handle))
                return False
            self.handle = handle
            return True
        import fcntl  # noqa: WPS433 - POSIX only
        path = Path(self.lock_dir or ".") / (self.name.replace("\\", "_") + ".lock")
        stream = open(path, "a+")
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            stream.close()
            return False
        self.stream = stream
        return True

    def release(self):
        if self.handle is not None:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.ReleaseMutex(ctypes.c_void_p(self.handle))
            kernel32.CloseHandle(ctypes.c_void_p(self.handle))
            self.handle = None
        if self.stream is not None:
            self.stream.close()
            self.stream = None


# ---------------- config ----------------

def load_config(path, *, fake_vm):
    path = Path(path)
    try:
        row = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"config unreadable: {exc.__class__.__name__}") from exc
    if type(row) is not dict:
        raise ConfigError("config must be a JSON object")
    config = dict(DEFAULTS)
    config.update(row)
    config["_path"] = str(path)
    for key in ("heartbeat_path", "channel_path", "grants_dir"):
        if not isinstance(config.get(key), str) or not config[key].strip():
            raise ConfigError(f"config needs a string {key}")
    for key in ("poll_seconds", "vm_check_seconds"):
        value = config[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.5 <= value <= 60:
            raise ConfigError(f"{key} must be a number between 0.5 and 60")
    value = config["watchdog_check_seconds"]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.5 <= value <= 3600:
        raise ConfigError("watchdog_check_seconds must be a number between 0.5 and 3600")
    if not isinstance(config["lock_name"], str) or not config["lock_name"]:
        raise ConfigError("lock_name must be a non-empty string")
    value = config["guest_min_gap_seconds"]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 10:
        raise ConfigError("guest_min_gap_seconds must be a number between 0 and 10")
    value = config["navigator_receipt_poll_seconds"]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.01 <= value <= 30:
        raise ConfigError("navigator_receipt_poll_seconds must be a number between 0.01 and 30")
    if config.get("navigator_log_path") is not None and (
            not isinstance(config["navigator_log_path"], str) or not config["navigator_log_path"].strip()):
        raise ConfigError("navigator_log_path must be a non-empty string when given")
    if config.get("dashboard_dir") is not None and (
            not isinstance(config["dashboard_dir"], str) or not config["dashboard_dir"].strip()):
        raise ConfigError("dashboard_dir must be a non-empty string when given")
    if fake_vm:
        present = [key for key in FORBIDDEN_FAKE_KEYS if config.get(key) is not None]
        if present:
            raise ConfigError("--fake-vm refuses a config naming " + ", ".join(present))
    else:
        missing = [key for key in REQUIRED_REAL_KEYS
                   if not isinstance(config.get(key), str) or not config[key].strip()]
        if missing:
            raise ConfigError("real mode needs " + ", ".join(missing))
        if not config["client_sid"].startswith("S-1-"):
            raise ConfigError("client_sid must be a SID string")
    return config


# ---------------- files ----------------

REPLACE_ATTEMPTS = 50
REPLACE_BACKOFF = 0.01


def write_json_atomic(path, row):
    """Write row to a temporary file and swap it into place. On Windows the
    swap fails with access denied while another process (the heartbeat
    watchdog, a status reader) holds the target open, so it is retried for
    about half a second; a heartbeat must not be skipped because someone was
    reading the previous one. The temporary is a fresh mkstemp name per
    write (CHANGED 2026-09-28 evening, fix helper, skeptic finding 10): the
    broker and jr_broker_watchdog both write this file, and one shared name
    let a half-written temporary be swapped into place."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(row, stream, allow_nan=False)
        for attempt in range(REPLACE_ATTEMPTS):
            try:
                os.replace(temporary, path)
                return
            except PermissionError:
                if attempt == REPLACE_ATTEMPTS - 1:
                    raise
                time.sleep(REPLACE_BACKOFF)
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass  # already swapped into place


def process_start_time(pid=None):
    """Creation time of a process as a FILETIME integer (Windows), used with the
    pid so a recycled pid is not mistaken for a live broker. None elsewhere."""
    if sys.platform != "win32":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = (kernel32.GetCurrentProcess() if pid is None else
              kernel32.OpenProcess(0x1000, False, int(pid)))  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    times = [ctypes.c_uint64() for _ in range(4)]
    try:
        if not kernel32.GetProcessTimes(ctypes.c_void_p(handle), *[ctypes.byref(t) for t in times]):
            return None
        return int(times[0].value)
    finally:
        if pid is not None:
            kernel32.CloseHandle(ctypes.c_void_p(handle))


class Heartbeat:
    def __init__(self, path, *, vm_mode, clock=time.time):
        self.path = Path(path)
        self.vm_mode = vm_mode
        self.clock = clock
        self.pid = os.getpid()
        self.process_start = process_start_time()
        self.lock = threading.Lock()

    def write(self, broker, *, final=False):
        with broker.lock:
            online = broker.phase == "online" and not final
            # An unverified cable is a connected cable until the watchdog
            # proves otherwise from the VM itself.
            cable_unverified = (broker.phase == "fault" or
                                getattr(broker, "cable_unverified", False) is True)
            row = {"version": DEFAULTS["heartbeat_version"], "pid": self.pid,
                   "process_start": self.process_start, "written_at": self.clock(),
                   "vm_mode": self.vm_mode,
                   "connected_by_broker": online or cable_unverified,
                   "cable_unverified": cable_unverified,
                   "poweroff_confirmed": getattr(broker, "poweroff_confirmed", None),
                   "batch_id": broker.batch_id if online else None,
                   "lease_seconds": broker.profile.lease_seconds, "presence": broker.presence,
                   "phase": broker.phase, "used": broker.used,
                   "limit": broker.profile.page_limit,
                   "deadline": broker.deadline if online else None,
                   "final": final}
        with self.lock:
            write_json_atomic(self.path, row)
        return row


def write_channel(path, address, authkey):
    row = {"version": 1, "address": address,
           "authkey": base64.b64encode(authkey).decode("ascii")}
    write_json_atomic(path, row)


def remove_channel(path):
    try:
        Path(path).unlink()
    except OSError:
        pass


# ---------------- VM runtimes ----------------

class FakeGuestDriver:
    """--fake-vm stand-in for the Cua guest driver (wave 2). One Chromium
    window; hotkey, type_text and press_key answer the global_input route
    the navigator demands; a Return after a typed URL "loads" it: while the
    fake guest batch is open and under its limit it charges one slot in
    vm.guest (used, current_url, an evidence receipt), a DuckDuckGo Lite
    search page carries two result links, and the batch closes at the
    limit. Nothing here touches a VM or a socket."""

    LINKS = [{"url": "https://example.com/result-1", "title": "Result one"},
             {"url": "https://example.org/result-2", "title": "Result two"}]

    def __init__(self, vm):
        self.vm = vm
        self.calls = []
        self.typed = []
        self.title = "Chromium"
        self._pending = None

    def __call__(self, tool, args):
        self.calls.append((tool, dict(args)))
        if tool == "list_windows":
            return {"windows": [{"app_name": "Chromium", "is_on_screen": True, "pid": 1,
                                 "window_id": "w1", "title": self.title}]}
        if tool == "bring_to_front":
            return {"ok": True}
        if tool == "hotkey":
            return {"route": "global_input"}
        if tool == "type_text":
            self._pending = str(args.get("text", ""))
            return {"route": "global_input"}
        if tool == "press_key":
            url, self._pending = self._pending, None
            if url is not None and args.get("key") == "Return":
                self._navigate(url)
            return {"route": "global_input"}
        raise ValueError(f"fake guest driver has no tool {tool!r}")

    def _navigate(self, url):
        self.typed.append(url)
        if url == "about:blank":
            self.title = "about:blank - Chromium"
            return
        self.title = "Chromium"
        guest = self.vm.guest
        limit = guest.get("limit")
        if guest.get("phase") != "open" or type(limit) is not int:
            return  # the proxy refuses it: no slot
        number = guest.get("used", 0) + 1
        row = {"number": number, "url": url.encode("utf-8")[:200].decode("utf-8", "ignore"),
               "status": 200, "text": f"Fake page {number}"}
        if url.startswith(DDG_LITE):
            row["links"] = [dict(item) for item in self.LINKS]
        guest.setdefault("evidence", []).append(row)
        guest["used"] = number
        guest["current_url"] = row["url"]
        if number >= limit:
            guest["phase"] = "closed"


def navigator_model(transport=None):
    """The real-mode link picker (CHANGED 2026-09-28, fix helper, skeptic
    item 2): JrModel with thinking OFF. pick_links runs inside the lease
    budget, and this model's thinking can run past it; the payload carries
    "think": false so Ollama is told, not left to its default. `transport`
    is for tests; None means the module's Ollama transport."""
    from jr_model import JrModel
    if transport is None:
        return JrModel(think=False)
    return JrModel(transport, think=False)


# 2026-09-29 Gate 1 fix (approved 10:38 AM): run()'s keyword parameter
# navigator_model=None (the test injection hook) shadows this function, so
# real mode called None and the broker crashed on every start. run() calls
# the module-level function through this alias instead.
_real_navigator_model = navigator_model


class FakeLinkPicker:
    """--fake-vm stand-in for JrModel.pick_links (wave 2): the first two
    offered links, then stop. Deterministic; never opens a socket."""

    def __init__(self):
        self.asked = []

    def pick_links(self, *, question, objective, links, think=None, timeout=None):
        self.asked.append({"question": question, "objective": objective, "links": list(links)})
        return {"picks": [item["url"] for item in links[:2]], "stop": True,
                "why": "fake model: the first two results"}


class FakeVmRuntime:
    """The fake VM from test_research_broker.py, plus the three startup calls
    and the fake guest driver the navigator types through."""

    def __init__(self, vm=None):
        if vm is None:
            from test_research_broker import VM
            vm = VM()
        self.vm = vm
        self.driver = FakeGuestDriver(vm)

    def state(self):
        return "running" if self.vm.running else "poweroff"

    def cut(self):
        self.vm.cable = False
        return {"network_off_confirmed": True, "poweroff_requested": False}

    def isolated(self):
        return self.vm.isolated_running_cable_off() is True

    def saved_cable_off(self):
        return self.vm.modify_cable_off() is True


class RealVmRuntime:
    """network_watchdog for the startup cut, FixedVmAdapter for everything else.
    Constructed only in real mode; the tests never build one."""

    def __init__(self, config):
        network_watchdog.configure(config["vboxmanage"], config["vm_uuid"])
        controller_path = Path(config["controller_path"])
        if not controller_path.is_file():
            raise ConfigError("controller_path is not a file")
        folder = str(controller_path.parent)
        if folder not in sys.path:
            sys.path.insert(0, folder)
        spec = importlib.util.spec_from_file_location(controller_path.stem, controller_path)
        controller = importlib.util.module_from_spec(spec)
        sys.modules[controller_path.stem] = controller
        spec.loader.exec_module(controller)
        from fixed_vm_adapter import FixedVmAdapter
        self.vm = FixedVmAdapter(controller, watchdog_config=config["_path"])
        # The navigator types through the controller's guest driver (wave 2).
        driver = getattr(controller, "_driver", None)
        if not callable(driver):
            raise ConfigError("controller module has no callable _driver for the navigator")
        self.driver = driver

    def state(self):
        rows = network_watchdog.vm_state()
        return None if rows is None else rows.get("VMState")

    def cut(self):
        return network_watchdog.cut_network()

    def isolated(self):
        return self.vm.isolated_running_cable_off() is True

    def saved_cable_off(self):
        return self.vm.modify_cable_off() is True


# ---------------- heartbeat watchdog launch ----------------

def spawn_heartbeat_watchdog(config, *, popen=subprocess.Popen):
    """Launch jr_broker_watchdog.py against this config as a process that
    outlives this broker: detached, its own process group, no inherited
    stdio, and out of the caller's job when the job allows breakaway (Task
    Scheduler and taskkill /T reach the job or the tree; the watchdog must
    survive both). Returns the new pid. Never passes this broker's pid."""
    argv = [sys.executable, "-B", str(WATCHDOG_SCRIPT), str(config["_path"])]
    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
              "stderr": subprocess.DEVNULL, "close_fds": True}
    if sys.platform == "win32":
        base = DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            process = popen(argv, creationflags=base | CREATE_BREAKAWAY_FROM_JOB, **kwargs)
        except OSError:
            log.warning("heartbeat watchdog: job breakaway refused; launching inside the job")
            process = popen(argv, creationflags=base, **kwargs)
    else:
        process = popen(argv, start_new_session=True, **kwargs)
    return process.pid


def ensure_heartbeat_watchdog(config, spawn=None):
    """Launch the heartbeat watchdog unless one is already alive. Returns
    "running", "spawned" or "failed"; a failure never stops the broker."""
    from jr_broker_watchdog import read_watchdog_status, status_path, watchdog_alive
    path = status_path(config)
    if watchdog_alive(path):
        log.info("heartbeat watchdog already running (pid %s)", read_watchdog_status(path)["pid"])
        return "running"
    spawn = spawn_heartbeat_watchdog if spawn is None else spawn
    try:
        pid = spawn(config)
    except Exception:
        log.exception("heartbeat watchdog could not be launched; the per-batch child "
                      "and the guest lease cap still stand")
        return "failed"
    log.info("heartbeat watchdog spawned (pid %s)", pid)
    return "spawned"


def add_deps(deps_dir):
    deps = Path(deps_dir)
    entries = [str(deps), str(deps / "win32"), str(deps / "win32" / "lib")]
    sys.path[:0] = [entry for entry in entries if entry not in sys.path]
    dll = deps / "pywin32_system32"
    if dll.is_dir() and hasattr(os, "add_dll_directory"):
        os.add_dll_directory(str(dll))


def secure_pipe_factory(config, *, fake_vm):
    """A SecurePipeListener factory pinned to the service SID (real) or to the
    broker's own SID (fake). Fake mode without pywin32 falls back to the
    authkey-only listener and says so loudly; real mode never falls back."""
    if config.get("deps_dir"):
        add_deps(config["deps_dir"])
    try:
        from secure_pipe import SecurePipeListener, current_user_sid
    except ImportError:
        if not fake_vm:
            raise
        log.warning("pywin32 unavailable: fake-vm pipe has no ACL (authkey only)")
        return None
    client_sid = current_user_sid() if fake_vm else config["client_sid"]

    def factory(address, authkey):
        return SecurePipeListener(address, authkey=authkey, client_sid=client_sid)
    return factory


# ---------------- navigator ----------------

class NavigatorBusy(Exception):
    """The previous batch's navigator outlived the bounded join (ADDED
    2026-09-28 late, skeptic wave 3 item 1); no second navigator starts."""


class NavigatorRunner:
    """One jr_navigator.Navigator thread per approved batch (wave 2).

    start(state) is called by the facade with approve's result; it reads the
    plan, deadline, batch id and page limit under the broker lock, parses
    the plan and launches the thread. stop() signals the running batch's
    stop event (the navigator checks it before every typing sequence and
    every receipt poll) and optionally joins. A plan that is not a JSON
    object leaves the navigator idle: the batch still runs, the poller
    still polls."""

    def __init__(self, broker, *, driver, model, gate, clock=time.time,
                 receipt_poll=3.0, log_path=None):
        self.broker = broker
        self.driver = driver
        self.model = model
        self.gate = gate
        self.clock = clock
        self.receipt_poll = float(receipt_poll)
        self.log_path = log_path
        self.thread = None
        self.stop_event = None
        self.navigator = None
        self.batch_id = None
        self.last = None       # summary of the most recent finished run
        self._lock = threading.Lock()

    def active(self):
        thread = self.thread
        return thread is not None and thread.is_alive()

    def start(self, state):
        if type(state) is not dict or state.get("phase") != "online":
            return None
        with self._lock:
            # CHANGED 2026-09-28 (fix helper, skeptic item 6a): the previous
            # batch's thread is signalled AND joined (bounded) before the next
            # one starts, so two navigators never type into the guest at once.
            self.stop(timeout=NAVIGATOR_JOIN_SECONDS)
            if self.active():
                log.warning("navigator for batch %s still running after %.1f s; not starting another",
                            self.batch_id, NAVIGATOR_JOIN_SECONDS)
                raise NavigatorBusy("previous navigator still running")
            with self.broker.lock:
                if self.broker.phase != "online":
                    return None
                plan_text = self.broker.plan
                deadline = self.broker.deadline
                batch_id = self.broker.batch_id
                page_limit = self.broker.profile.page_limit
            try:
                plan = json.loads(plan_text)
            except ValueError:
                plan = None
            if type(plan) is not dict:
                log.info("navigator idle for batch %s: the plan is not a JSON object", batch_id)
                return None
            question = plan.get("question")
            if not isinstance(question, str) or not question.strip():
                question = plan.get("objective")
            stop_event = threading.Event()
            try:
                navigator = Navigator(driver=self.driver, quota_status=self.broker.vm.guest_quota_status,
                                      model=self.model, guest_gate=self.gate, clock=self.clock,
                                      receipt_poll=self.receipt_poll, log_path=self.log_path,
                                      stop_event=stop_event, session_id=None)
            except NavigatorError as exc:
                log.warning("navigator not started for batch %s: %s", batch_id, exc)
                return None
            thread = threading.Thread(target=self._run, name="jr-navigator", daemon=True,
                                      args=(navigator, plan, question, deadline, page_limit, batch_id))
            self.thread, self.stop_event, self.navigator, self.batch_id = (
                thread, stop_event, navigator, batch_id)
            thread.start()
            return thread

    def _run(self, navigator, plan, question, deadline, page_limit, batch_id):
        try:
            summary = navigator.run(plan, question, deadline, page_limit=page_limit)
            log.info("navigator finished batch %s: %s, %s typed, %s pages",
                     batch_id, summary["stop_reason"], len(summary["typed"]), summary["pages_used"])
        except Exception as exc:
            log.warning("navigator stopped on %s for batch %s", type(exc).__name__, batch_id)
        finally:
            self.last = navigator.summary()

    def stop(self, timeout=None):
        event, thread = self.stop_event, self.thread
        if event is not None:
            event.set()
        if timeout and thread is not None and thread.is_alive():
            thread.join(timeout)


# ---------------- pipe facade ----------------

class BrokerFacade:
    """The six fixed operations. approve, stop and emergency are followed by
    a heartbeat write when they succeed (or leave the cable unverified), so
    the connected flag is on disk within milliseconds of the cable going on
    (wave 3e F1: never after begin, never after a plain failure). approve also starts the navigator
    for the new batch; stop and emergency signal it first (wave 2). poll is
    read-only (wave 3c pulse fix): a snapshot, no heartbeat write."""

    def __init__(self, broker, heartbeat, navigator=None, stale_after=None):
        self.broker = broker
        self.heartbeat = heartbeat
        self.navigator = navigator
        if stale_after is None:
            stale_after = (2 * DEFAULTS["poll_seconds"] +
                           gate_bridge_seconds(DEFAULTS["guest_min_gap_seconds"]))
        self.stale_after = float(stale_after)

    @property
    def cut_after(self):
        """Loop age past which the snapshot reports "cutting" / "loop_stale"
        (wave 3e F6): stale, plus the window after which the cable
        watchdog's pulse thread stops feeding the child."""
        return self.stale_after + network_watchdog.LOOP_STALE_SECONDS

    def _write_heartbeat(self):
        try:
            self.heartbeat.write(self.broker)
        except OSError:
            log.exception("heartbeat write failed")

    def _after(self, succeeded):
        """Wave 3e F1: write after a success, or after a failure that left
        the cable unverified (a write jr_broker_watchdog can only answer
        with a cut). Any other failure leaves the file to the loop, so an
        owner action during a wedge cannot hold off the stale-heartbeat cut."""
        if (succeeded or getattr(self.broker, "phase", None) == "fault" or
                getattr(self.broker, "cable_unverified", False) is True):
            self._write_heartbeat()

    def _op(self, fn, *args):
        succeeded = False
        try:
            result = fn(*args)
            succeeded = True
            return result
        finally:
            self._after(succeeded)

    def begin(self, owner, thread, plan):
        # No heartbeat write (wave 3e F1): begin never touches the cable,
        # and the loop rewrites the file every poll_seconds.
        return self.broker.begin(owner, thread, plan)

    def approve(self, owner, thread, nonce, client_alive=None, received_at=None):
        if self.navigator is not None and self.navigator.active():
            # Wave 3e: refuse before arming, never after the cable is on.
            self.broker.check_approval(owner, thread, nonce)
            self.navigator.stop(timeout=NAVIGATOR_JOIN_SECONDS)
            if self.navigator.active():
                self._op(self.broker.stop, owner, thread)
                raise BrokerRefusal("navigator_busy")
        # Wave 3f F2: the pipe's check that the app is still waiting; the
        # broker refuses before the cable when it has gone. Wave 3g F1: and
        # when the pipe received the request, where the budget clock starts.
        extra = {key: value for key, value in (("client_alive", client_alive),
                                               ("received_at", received_at))
                 if value is not None}
        if not extra:
            state = self._op(self.broker.approve, owner, thread, nonce)
        else:
            state = self._op(lambda: self.broker.approve(owner, thread, nonce, **extra))
        if client_alive is not None and client_alive() is not True:
            # Wave 3g F1: the client gave up while connect_cable ran. Never
            # leave the cable on for nobody: the stop path cuts it and
            # closes the guest batch; no navigator is started.
            self._op(self.broker.stop, owner, thread)
            raise BrokerError("The app stopped waiting; the batch was stopped")
        if self.navigator is not None:
            try:
                self.navigator.start(state)
            except NavigatorBusy:
                # CHANGED 2026-09-28 late (skeptic wave 3 item 1): never leave
                # the batch online with nothing driving it. Same path as the
                # stop op: cable off, guest batch closed, phase stopped. A cut
                # that cannot be verified raises from stop (fault) as it would
                # for the stop op itself.
                self._op(self.broker.stop, owner, thread)
                raise BrokerRefusal("navigator_busy")
            except Exception:
                log.exception("navigator start failed; the batch runs without it")
        return state

    def status(self, owner, thread):
        """Never waits on the broker lock (wave 3e F3); reports "cutting" as
        the pipe poll does (wave 3e F6)."""
        return self.broker.status(owner, thread, stale_after=self.stale_after,
                                  cut_after=self.cut_after)

    def stop(self, owner, thread):
        if self.navigator is not None:
            self.navigator.stop()
        return self._op(self.broker.stop, owner, thread)

    def emergency(self):
        if self.navigator is not None:
            self.navigator.stop()
        return self._op(self.broker.emergency)

    def poll(self):
        """Read-only (CHANGED 2026-09-28 late, wave 3c pulse fix): the broker's
        last public status. It must not call broker.poll(): that ticks the
        watchdog, pulses the child and calls the guest outside the gate, so
        the app's 3 s polling kept a wedged batch's cable on. No heartbeat
        write either: the heartbeat file must go stale with the loop."""
        return self.broker.snapshot(stale_after=self.stale_after, cut_after=self.cut_after)


# ---------------- presence ----------------

def build_presence(config, *, fake_vm, fake_presence):
    if fake_vm:
        value = fake_presence if fake_presence in {"console", "grant", "none"} else "none"
        return lambda stage: value
    import jr_presence
    hands = config.get("hands_grant_path") or jr_presence.default_hands_grant_path()
    return jr_presence.Presence(grants_dir=config["grants_dir"], hands_grant_path=hands,
                                log=log.info)


# ---------------- run ----------------

def run(config, *, fake_vm, stop_event=None, runtime=None, presence=None,
        listener_factory=None, allow_insecure_test=False, fake_presence="none",
        fake_auto_pages=False, ready_event=None, clock=time.time, parent_alive=None,
        watchdog_spawn=None, navigator_driver=None, navigator_model=None):
    """The whole lifecycle. Returns the exit code. Everything a test needs to
    inject is a keyword: the runtime, the presence callable, the listener,
    parent_alive (a callable answering whether the supervisor lives),
    watchdog_spawn (config -> pid; the real launcher when None), and the
    navigator's driver and model (defaults: the runtime's driver, and
    FakeLinkPicker in fake mode or JrModel in real mode)."""
    stop_event = stop_event or threading.Event()
    lock = InstanceLock(config["lock_name"], lock_dir=Path(config["heartbeat_path"]).parent)
    if not lock.acquire():
        log.error("another broker holds %s; refusing to start", config["lock_name"])
        return EXIT_REFUSED
    guard = None
    try:
        if fake_vm:
            guard = install_import_guard()
            network_watchdog.configure(None, None)
            refuse_fake_mode_leaks(config)
            if runtime is None:
                runtime = FakeVmRuntime()
            if presence is None:
                presence = build_presence(config, fake_vm=True, fake_presence=fake_presence)
        else:
            if runtime is None:
                runtime = RealVmRuntime(config)
            if presence is None:
                presence = build_presence(config, fake_vm=False, fake_presence=None)

        # 2. VM state, then the cable. Running and paused VMs have a live
        # link to cut; a saved one has only its stored setting.
        state = runtime.state()
        if state in ("running", "paused"):
            cut = runtime.cut()
            if cut.get("network_off_confirmed") is not True:
                log.error("startup cable cut could not be verified (poweroff requested: %s)",
                          cut.get("poweroff_requested"))
                return EXIT_CUT_UNVERIFIED
            log.info("cable off, verified%s",
                     " (poweroff was requested)" if cut.get("poweroff_requested") else "")
            if state == "paused":
                log.warning("VM is paused with its cable now off; exit 3, retry later")
                return EXIT_VM_NOT_RUNNING
        elif state == "saved":
            if runtime.saved_cable_off() is not True:
                log.error("saved VM: stored cable state could not be set off; exit 4")
                return EXIT_CUT_UNVERIFIED
            log.warning("VM is saved; stored cable state set off; exit 3, retry later")
            return EXIT_VM_NOT_RUNNING
        else:
            log.warning("VM is not running (state %s); exit 3, retry later", state)
            return EXIT_VM_NOT_RUNNING
        # 3. Isolation.
        if not runtime.isolated():
            log.error("isolation check failed after the cut; not serving")
            return EXIT_ISOLATION

        # 4. Serve.
        # Monotonic, never the wall clock (wave 3c pulse fix): a backward
        # wall step must not lengthen the gate bridge. Built first so the
        # broker's approve and stop share it (wave 3e F3b).
        gate = GuestGate(min_gap=float(config["guest_min_gap_seconds"]), clock=time.monotonic)
        broker = ResearchBroker(runtime.vm, presence=presence, log=log.info, clock=clock, gate=gate)
        heartbeat = Heartbeat(config["heartbeat_path"], vm_mode="fake" if fake_vm else "real",
                              clock=clock)
        runner = None
        if not fake_auto_pages:
            driver = navigator_driver if navigator_driver is not None else getattr(runtime, "driver", None)
            if not callable(driver):
                raise ConfigError("the VM runtime has no guest driver for the navigator")
            model = navigator_model
            if model is None:
                if fake_vm:
                    model = FakeLinkPicker()
                else:
                    model = _real_navigator_model()
            runner = NavigatorRunner(broker, driver=driver, model=model, gate=gate, clock=clock,
                                     receipt_poll=config["navigator_receipt_poll_seconds"],
                                     log_path=config.get("navigator_log_path"))
        facade = BrokerFacade(broker, heartbeat, navigator=runner,
                              stale_after=2 * float(config["poll_seconds"]) +
                              gate_bridge_seconds(gate.min_gap))
        if listener_factory is None and not allow_insecure_test:
            listener_factory = secure_pipe_factory(config, fake_vm=fake_vm)
            if listener_factory is None:
                allow_insecure_test = True
        server = BrokerPipeServer(facade, listener_factory=listener_factory,
                                  allow_insecure_test=allow_insecure_test)
        server.start()
        try:
            write_channel(config["channel_path"], server.address, server.authkey)
            heartbeat.write(broker)
            ensure_heartbeat_watchdog(config, watchdog_spawn)
            log.info("serving; cable off, waiting")
            if ready_event is not None:
                ready_event.set()
            exit_code = _loop(config, broker, heartbeat, runtime, stop_event, fake_auto_pages,
                              parent_alive, watchdog_spawn, gate=gate, runner=runner)
        finally:
            if runner is not None:
                runner.stop()
            with broker.lock:
                if broker.phase == "online":
                    try:
                        broker._disconnect()
                        log.info("shutdown: cable cut and verified")
                    except BrokerError:
                        log.error("shutdown: cable cut unverified; poweroff requested")
            try:
                heartbeat.write(broker, final=True)
            except OSError:
                log.exception("final heartbeat write failed")
            remove_channel(config["channel_path"])
            server.close()
            if runner is not None:
                runner.stop(timeout=NAVIGATOR_JOIN_SECONDS)
                if runner.active():
                    log.warning("navigator thread still running at shutdown; abandoned (daemon)")
        return exit_code
    finally:
        if guard is not None:
            remove_import_guard(guard)
        lock.release()


def _loop(config, broker, heartbeat, runtime, stop_event, fake_auto_pages,
          parent_alive=None, watchdog_spawn=None, gate=None, runner=None):
    if gate is None:
        gate = GuestGate(min_gap=float(config["guest_min_gap_seconds"]), clock=time.monotonic)
    next_vm_check = 0.0
    watchdog_check = float(config["watchdog_check_seconds"])
    next_watchdog_check = time.monotonic() + watchdog_check  # run() just ensured one
    while not stop_event.is_set():
        started = time.monotonic()
        if started >= next_watchdog_check:
            next_watchdog_check = started + watchdog_check
            try:
                ensure_heartbeat_watchdog(config, watchdog_spawn)
            except Exception:
                log.exception("heartbeat watchdog check failed")
        if parent_alive is not None:
            try:
                alive = parent_alive() is True
            except Exception:
                log.exception("parent liveness check failed; treating the parent as gone")
                alive = False
            if not alive:
                # Same path as SIGTERM: the caller's finally cuts an online
                # cable, writes the final heartbeat and removes the channel.
                log.warning("supervisor process is gone; shutting down")
                stop_event.set()
                break
        try:
            if broker.phase == "online":
                if fake_auto_pages:
                    _advance_fake_pages(runtime.vm, broker)
                _tick_watchdog(broker)   # the loop is alive; the gate wait that follows is not a wedge
                # Shared with the navigator's typing. The wait keeps stamping
                # the tick for at most the bridge (one driver call plus the
                # gap); poll stamps it again once the gate is held.
                gate.call_ticking(broker.poll, tick=lambda: _tick_watchdog(broker),
                                  bridge_seconds=gate_bridge_seconds(gate.min_gap))
            elif started >= next_vm_check:
                next_vm_check = started + float(config["vm_check_seconds"])
                state = runtime.state()
                if state != "running":
                    log.warning("VM stopped running (state %s); exit 3", state)
                    return EXIT_VM_NOT_RUNNING
        except BrokerError as exc:
            log.warning("poll: %s", exc)
        except Exception:
            log.exception("poll tick failed")
        if runner is not None and runner.active() and broker.phase != "online":
            runner.stop()   # the batch ended under the navigator; it bails at its next check
        try:
            heartbeat.write(broker)
        except OSError:
            log.exception("heartbeat write failed")
        stop_event.wait(max(0.05, float(config["poll_seconds"]) - (time.monotonic() - started)))
    log.info("stop requested")
    return EXIT_OK


def gate_bridge_seconds(min_gap):
    """How long the poll loop keeps stamping the tick while it waits on the
    guest gate (ADDED 2026-09-28 late, skeptic wave 3 item 2): one driver
    call at its bound, the gate's gap after it, and slack for the step."""
    return DRIVER_CALL_BOUND_SECONDS + float(min_gap) + GATE_BRIDGE_SLACK_SECONDS


def _tick_watchdog(broker):
    """Stamp the network watchdog's loop tick without sending a heartbeat.

    ADDED 2026-09-28 (fix helper, skeptic item 6b). The poll pulses the
    watchdog only once it holds the guest gate; while the navigator holds
    the gate for a long driver call (up to 30 s, jr_computer's guest-control
    timeout; CORRECTED 2026-09-28 late from "20 s", skeptic wave 3 item 2)
    the last tick ages past LOOP_STALE_SECONDS and the pulse thread goes
    quiet, so the child could cut the cable under a healthy loop. One stamp
    before the wait bridged only 15 s of it, so the loop now also stamps
    during the wait (GuestGate.call_ticking, bounded by gate_bridge_seconds)
    and ResearchBroker.poll stamps once more when it holds the gate. A
    watchdog without a tick() (an older fake) is simply skipped."""
    with broker.lock:
        watchdog = broker.watchdog
    tick = getattr(watchdog, "tick", None)
    if callable(tick):
        try:
            tick()
        except Exception:
            log.exception("watchdog tick failed")


def _advance_fake_pages(vm, broker):
    """--fake-auto-pages: the fake guest reports one more page per tick and
    closes at the limit, so a harness sees a batch run to its checkpoint."""
    guest = vm.guest
    limit = broker.profile.page_limit
    if guest.get("phase") == "open":
        guest["used"] = min(limit, guest.get("used", 0) + 1)
        guest["current_url"] = f"https://example.com/page{guest['used']}"
        if guest["used"] >= limit:
            guest["phase"] = "closed"


# ---------------- entry point ----------------

def parse_args(argv):
    parser = argparse.ArgumentParser(prog="jr_broker_main")
    parser.add_argument("config", help="path to the broker JSON config")
    parser.add_argument("--fake-vm", action="store_true",
                        help="use the fake VM from test_research_broker.py; never VirtualBox")
    parser.add_argument("--fake-presence", choices=["console", "grant", "none"], default="none",
                        help="fake-vm only: the presence every batch sees")
    parser.add_argument("--fake-auto-pages", action="store_true",
                        help="fake-vm only: report one page per tick until the limit")
    parser.add_argument("--parent-pid", type=int, default=None,
                        help="supervisor pid; exit like SIGTERM when it dies "
                             "(default: JR_BROKER_PARENT_PID when set)")
    parser.add_argument("--check-config", action="store_true",
                        help="validate the config as real mode would and exit 0 (ok) or 2 "
                             "(refused); touches no VM, lock, pipe or file")
    args = parser.parse_args(argv)
    if args.parent_pid is None:
        raw = os.environ.get("JR_BROKER_PARENT_PID", "").strip()
        if raw:
            try:
                args.parent_pid = int(raw)
            except ValueError:
                parser.error("JR_BROKER_PARENT_PID must be an integer pid")
    return args


def _configure_logging(config):
    handlers = [logging.StreamHandler(sys.stderr)]
    if config.get("log_path"):
        Path(config["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(config["log_path"], encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def check_config(path):
    """--check-config (ADDED 2026-09-28, fix helper, skeptic item 10): the
    Gate 1d config check. Real-mode validation only; nothing else runs."""
    try:
        config = load_config(path, fake_vm=False)
    except ConfigError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    print(f"config ok: {config['_path']} (channel {config['channel_path']}; "
          f"heartbeat {config['heartbeat_path']})")
    return EXIT_OK


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.check_config:
        return check_config(args.config)
    if args.fake_vm:
        install_import_guard()
    try:
        config = load_config(args.config, fake_vm=args.fake_vm)
    except ConfigError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    _configure_logging(config)
    if not args.fake_vm and (args.fake_presence != "none" or args.fake_auto_pages):
        print("refused: --fake-presence and --fake-auto-pages need --fake-vm", file=sys.stderr)
        return EXIT_REFUSED
    try:
        parent_alive = parent_alive_check(args.parent_pid)
    except ConfigError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    stop_event = threading.Event()

    def _stop(signum, frame):
        log.info("signal %s", signum)
        stop_event.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stop)
    try:
        return run(config, fake_vm=args.fake_vm, stop_event=stop_event,
                   fake_presence=args.fake_presence, fake_auto_pages=args.fake_auto_pages,
                   parent_alive=parent_alive)
    except ConfigError as exc:
        log.error("refused: %s", exc)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
