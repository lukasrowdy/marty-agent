"""Staged host coordinator for Jr's owner-approved page batches.

CHANGED 2026-09-29 (wave 3h, skeptic wave 3g findings 1 to 3; constants and
notes only, nothing structural):
- F1: CABLE_CALL_SECONDS 10 to 15, the real disconnect_cable ceiling
  (setlinkstate 5 s, jr_computer's showvminfo re-read 5 s, then
  fixed_vm_adapter's own showvminfo 5 s). The re-read and the duplicate
  isolation check in approve stay until Gate 1 measures them.
- F2 and F3: a note by STOP_INLINE_CLOSE_BY_SECONDS on the two stop cases
  its budget does not bound (the unverified-cut branch, and a stop queued
  behind an approve still in progress).

CHANGED 2026-09-28 late (wave 3g, skeptic wave 3f findings 1, 2 and 4):
- F1: approve takes an optional received_at (time.monotonic() when the pipe
  received the request, passed by broker_ipc through the facade), so a wait
  for a pipe slot or the facade's navigator join counts against
  APPROVE_CONNECT_BY_SECONDS.
- F2: stop closes the guest batch inline only when it holds the gate by
  STOP_INLINE_CLOSE_BY_SECONDS after it was called; otherwise (a long wait on
  the lock behind the loop's disconnect-plus-close cut) the close is deferred
  at once, so the stop op's worst case no longer grows with that hold.
- F4: every approve failure after the guest arm sets _close_pending, so the
  batch it armed is closed by the next stop, deferred closer or approve.

CHANGED 2026-09-28 late (wave 3f, skeptic wave 3e findings 1 and 2):
- F1: stop records a pending guest close (_close_pending). The deferred
  closer now closes whenever that close is still pending, no batch is
  online and batch_id is None (was: only while phase == "stopped", so a
  begin in between flipped phase to "paused" and left the old guest batch
  open, and the guest refused every approve until its lease ran out). The
  check runs with the gate held, right before the close, and only an
  approve holding that same gate can arm, so it never closes a new batch.
  approve, which holds the gate, performs a pending close itself before it
  arms, so whichever of the two takes the gate first closes the old batch,
  exactly once.
- F2: approve's time budget fits the app's approve client timeout
  (jr_app_server.BROKER_OP_TIMEOUTS, pinned by test_wave3f_fixes).
  GATE_WAIT_SECONDS drops from 15 to 10; approve refuses before the cable
  goes on when it reaches connect_cable more than APPROVE_CONNECT_BY_SECONDS
  after it was called, or when the pipe says its client has already gone
  (optional client_alive callable, passed by broker_ipc). Either refusal
  closes the guest batch it armed and leaves the cable off.

CHANGED 2026-09-28 late (wave 3e, skeptic wave 3d findings 2, 3, 3b, 6):
- F6: snapshot() evaluates the host deadline and the loop's staleness
  itself, read-only (no lock wait, no guest call, no cut). An online row
  whose deadline has passed, or whose last loop poll is older than
  `cut_after` (the facade passes stale_after + LOOP_STALE_SECONDS, when the
  cable watchdog's pulses have stopped), is reported as phase "cutting" with
  "reason" "loop_stale" (checked first: that loop will never cut) or
  "deadline_passed". The cut itself stays with the loop's poll, the per-batch
  child and jr_broker_watchdog.
- F3: status() never waits on the lock: the identity check, then the same
  read-only snapshot. The emergency op's queueing is fixed in broker_ipc.
- F3b: with a GuestGate (`gate`, the one the broker loop and the navigator
  share), approve's arm and status calls and stop's close_guest_quota run
  under the gate. approve takes the gate before the lock (the loop's order:
  gate, then lock) after a lock-only check of owner and nonce, and waits at
  most GATE_WAIT_SECONDS (under the pipe client's 20 s): a gate that stays
  busy refuses the approval with the nonce unspent and the cable off. stop
  cuts the cable under the lock first, then closes the guest batch under
  the gate: inline when the gate frees within STOP_GATE_WAIT_SECONDS,
  otherwise (a navigator stuck in a guest call) on a daemon thread that
  waits up to CLOSE_DEFER_SECONDS for the gate, so the close never overlaps
  that call and the stop op still returns at once. Skipped when a new batch
  was armed meanwhile. check_approval() is the lock-only owner and nonce
  check, exposed so the facade can refuse a second approval while the old
  navigator is stuck without putting the cable on.
- F2: begin, _disconnect (both outcomes), the receipt-failure and
  approve-failure cuts and emergency refresh the cached public row, so a
  snapshot that falls back to the cache never shows a pre-cut "online" row
  or a spent nonce.

CHANGED 2026-09-28 late (wave 3c pulse fix, skeptic wave 3c pulse verdict):
snapshot() is the read-only status the broker pipe's poll op now returns.
The pipe poll used to call poll(), outside the guest gate: it stamped the
watchdog tick, pulsed the child and made a guest status call while the
broker loop sat blocked behind a wedged navigator driver call, so both
watchdogs stayed fed until the host deadline or --max-lease. snapshot()
returns the last public status (fresh when the lock is free, the cached one
when a poll or approve holds it, never waiting), with no tick, no pulse, no
guest-control call and no deadline or presence evaluation. poll() records
last_poll_at on `monotonic` (time.monotonic unless a test replaces it) so
snapshot(stale_after=...) can add "stale_seconds" when the loop's last real
poll of an online batch is older than that. poll() itself is unchanged: the
broker's own loop, through the gate, is the only caller that ticks, pulses,
checks the deadline and presence, and cuts.

CHANGED 2026-09-28 late (wave 3 follow-up, skeptic wave 3 fix list): poll()
stamps the watchdog's loop tick (tick(), when the watchdog has one) before
its guest status call, so the pulse thread bridges that call (up to 15 s)
even after a long wait for the guest gate (item 2); and the owner's name in
the profile note below is now "the owner" (item 4).

CHANGED 2026-09-28 evening (fix helper, skeptic item 8): emergency() records
poweroff_confirmed and cable_unverified under the lock.

CHANGED 2026-09-28 (Jr overnight build, helper item "guest"):
- Two batch profiles replace the fixed five pages. SHORT: 110 s host lease,
  120 s watchdog, 5 pages, 400 requests, 30 MB. LONG: 290 s host lease, 300 s
  watchdog, 30 pages, 1500 requests, 150 MB (the owner: "move for 5 MINS
  uninterrupted if I am at the PC or I EXPRESSLY give permission"). The guest
  caps every lease at 300 s on its own clock, so the host stays 10 s under it
  exactly as the short profile does (skeptic, 2026-09-28: a host deadline of
  300 would be refused by the guest after any skew or a slow round trip).
  approve() asks an injected `presence` callable (item 1 supplies the real
  one: "console", "grant" or "none"; the default answers "none") and picks
  LONG only for "console" or "grant". The profile is passed to the guest at
  arm time and its watchdog seconds to the cable watchdog.
- Status dicts gain `lease_seconds` (110 or 290), `presence`, and `receipts`
  (the validated per-page list, so the navigator can read each page's url,
  status and, on a search results page, its `links`). `limit` now reports
  the active profile's page limit.
- poll() validates the new receipt shape {number, url <= 200 bytes, status,
  text} with optional links (<= 8 of {https url <= 200 bytes, title <= 80})
  and builds observed_text as "Page N (<url>): text" lines, capped at
  MAX_OBSERVED_TEXT (12,000 chars, the synopsis input cap in jr_model).
- Redirects: the guest charges a slot per 3xx reply as before; the 30-page
  long limit absorbs it. Nothing here changes that accounting.

CHANGED 2026-09-28 (Jr overnight build, item 1 "broker"), merged onto item
6's copy above; these are item 1's hunks:
- Lease clock fix in approve(). The guest deadline is computed immediately
  before the arm call (the last guest-side step before the cable), and the
  HOST deadline is computed only after connect_cable() is confirmed, as
  clock() + lease. Before, both were one number taken before two guest-control
  round trips (up to 15 s each), which ate into the lease. The guest's own
  deadline, set a few seconds earlier and 10 s inside its cap, still binds
  first. The watchdog spawn sits between the guest arm and the connect on
  purpose: it takes well under a second and its clock must start as close to
  cable-on as possible.
- Presence is re-checked on every poll during a LONG batch with stage
  "poll" (a looser idle threshold than "approve"; see jr_presence). If it
  comes back "none" (lock, idle past the poll threshold, grant revoked) the
  cable is cut and the batch ends paused; the next approval gets whatever
  lease presence then allows. SHORT batches never re-check.
- The presence callable may take a stage argument ("approve" / "poll") or
  none at all (item 6's shape); its signature decides at each call, so a
  test may swap presence_check after construction.
- approve() and stop() return the public status dict (frozen interface for
  item 2: "approve(...) -> status dict"). begin() still returns the nonce.
- An optional log callable and `last_event` record why a batch ended.
  Never part of the status dict (the frozen fields stay as item 6 set them).

CHANGED 2026-09-28 (cloud PR #3 port, 6:40 PM): approve() refuses a watchdog
handle without callable pulse() and close(), not just None (commit a74fdc2).

CHANGED 2026-09-28 evening (fix helper, skeptic findings B and C):
- _disconnect records what it could prove: cable_unverified (True after an
  unconfirmed cut, False after a confirmed one) and poweroff_confirmed (the
  hard_poweroff result on an unconfirmed cut, None otherwise). The heartbeat
  writer reads both, and reports the cable as connected while unverified.
- The presence-loss cut in poll() also closes the guest batch (best effort)
  and sets presence to "none": the real guest refuses to re-arm while its
  batch is open and unexpired, so the next approval was refused until the
  guest lease ran out. The fake VM now refuses the same way.

CHANGED 2026-09-28 (wave 2 integration):
- poll()'s deadline branch closes the guest batch best effort after the cut,
  exactly as the presence-loss branch does: the guest refuses to re-arm while
  its batch is open and unexpired, and its clock can lag the host's, so
  without the close the next approval after a lease expiry could be refused.
- emergency() powers the VM off BEFORE taking the broker lock (Grok review):
  poll() holds the lock through guest-control calls that can run to their
  subprocess timeout, and the emergency button must never wait behind one.
  The state update (phase fault, nonce cleared, watchdog closed) follows
  under the lock, and the result of the poweroff is raised from there.

The actual VM adapter is injected and has not been installed. None of these
methods is a model tool. Owner authentication and one-use approval belong to
the separate Jr web service; guest quota receipts are the page authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import inspect
import secrets
import threading
import time


@dataclass(frozen=True)
class BatchProfile:
    name: str
    lease_seconds: int
    watchdog_seconds: int
    page_limit: int
    request_cap: int
    byte_cap: int


# The guest enforces a hard 300-second maximum using its own clock. Both
# profiles keep the host deadline 10 s under the watchdog, and the watchdog
# at or under the guest cap, for clock skew and the GuestControl round trip.
GUEST_LEASE_CAP = 300
SHORT = BatchProfile("short", 110, 120, 5, 400, 30 * 1024 * 1024)
LONG = BatchProfile("long", 290, 300, 30, 1500, 150 * 1024 * 1024)
PROFILES = {SHORT.name: SHORT, LONG.name: LONG}
LONG_PRESENCE = {"console", "grant"}
PRESENCE_VALUES = {"console", "grant", "none"}
MAX_OBSERVED_TEXT = 12000
MAX_RECEIPT_URL_BYTES = 200
MAX_LINKS = 8
MAX_LINK_URL_BYTES = 200
MAX_LINK_TITLE = 80
# The longest approve waits for the shared guest gate (wave 3e F3b; wave 3f
# F2: 10 s, so the gate wait plus the arm and status calls fit inside
# APPROVE_CONNECT_BY_SECONDS and the whole approve inside the app's approve
# client timeout, jr_app_server.BROKER_OP_TIMEOUTS["approve"]).
GATE_WAIT_SECONDS = 10.0
# Wave 3f F2 budget constants (test_wave3f_fixes pins their sums):
# approve refuses, cable off, when it reaches connect_cable later than
# APPROVE_CONNECT_BY_SECONDS after it was called; CONNECT_CALL_SECONDS is the
# allowance for the connect call itself (showvminfo, guard attest,
# setlinkstate, re-read: a second or two in practice; their subprocess
# ceilings are longer, see the note before connect_cable);
# GUEST_CALL_SECONDS is one guest quota call's subprocess ceiling
# (fixed_vm_adapter passes 15) and CABLE_CALL_SECONDS one cut (wave 3h: 15 s,
# setlinkstate 5 s, jr_computer._cable's showvminfo re-read 5 s, then
# fixed_vm_adapter._machine_rows' showvminfo 5 s).
APPROVE_CONNECT_BY_SECONDS = 18.0
CONNECT_CALL_SECONDS = 5.0
GUEST_CALL_SECONDS = 15.0
CABLE_CALL_SECONDS = 15.0
# stop's inline wait for the gate, then the deferred close's (wave 3e F3b).
STOP_GATE_WAIT_SECONDS = 3.0
CLOSE_DEFER_SECONDS = 120.0
# Wave 3g F2: stop closes inline only with the gate held by this many seconds
# after it was called, so inline it ends by this plus one GUEST_CALL_SECONDS;
# past it the close is deferred and stop ends after the lock wait and its cut
# (test_wave3g_fixes pins both sums under the app's stop client timeout).
STOP_INLINE_CLOSE_BY_SECONDS = 20.0
# Wave 3h (skeptic wave 3g findings 2 and 3), what this budget does NOT bound:
# - The unverified-cut branch: when a cut cannot be verified, _disconnect
#   escalates to the emergency cut_off (up to about 26 s), so stop's own
#   _disconnect can run about 41 s after a 25 to 30 s wait on the lock, past
#   any client timeout. Accepted overrun; it fails safe: the phase goes to
#   fault, cable_unverified is set and the heartbeat watchdog keeps cutting.
# - A stop queued behind an approve still in progress: approve checks its
#   budget once, after its calls, so nothing bounds how long it holds the
#   lock. Gate 1 measures approve on this PC.
# Kept for callers that still read the short defaults by their old names.
LIMIT = SHORT.page_limit
LEASE_SECONDS = SHORT.lease_seconds


class BrokerError(Exception):
    pass


class _ApproveAbandoned(BrokerError):
    """Approve stopped before the cable (wave 3f F2): the client gave up or
    the budget ran out. The guest batch it armed is closed."""


def select_profile(presence) -> BatchProfile:
    return LONG if presence in LONG_PRESENCE else SHORT


def _control(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def _valid_link(item) -> bool:
    return (type(item) is dict and set(item) == {"url", "title"} and
            type(item["url"]) is str and item["url"].startswith("https://") and
            len(item["url"].encode("utf-8")) <= MAX_LINK_URL_BYTES and
            not _control(item["url"]) and not any(c.isspace() for c in item["url"]) and
            type(item["title"]) is str and len(item["title"]) <= MAX_LINK_TITLE and
            not _control(item["title"]))


def valid_receipt(item, used: int) -> bool:
    if type(item) is not dict or not {"number", "url", "status", "text"} <= set(item):
        return False
    if set(item) - {"number", "url", "status", "text", "links"}:
        return False
    if (type(item["number"]) is not int or not 1 <= item["number"] <= used or
        type(item["url"]) is not str or len(item["url"].encode("utf-8")) > MAX_RECEIPT_URL_BYTES or
        _control(item["url"]) or
        not (item["status"] is None or (type(item["status"]) is int and 100 <= item["status"] <= 599)) or
        type(item["text"]) is not str or len(item["text"]) > 300 or
        len(item["text"].encode("utf-8")) > 256 or _control(item["text"])):
        return False
    links = item.get("links")
    if links is not None and (type(links) is not list or not 1 <= len(links) <= MAX_LINKS or
                              not all(map(_valid_link, links))):
        return False
    return True


def build_observed_text(receipts, used: int) -> str:
    """"Page N (<url>): text" per page with text, then the missing-page line, <= 12,000 chars."""
    lines = [f"Page {item['number']} ({item['url']}): {item['text']}"
             for item in receipts if item["text"]]
    have = {item["number"] for item in receipts if item["text"]}
    missing = sorted(set(range(1, used + 1)) - have)
    tail = ""
    if missing:
        tail = ("No page text was captured for page(s) " + ", ".join(map(str, missing)) +
                "; do not infer their contents.")
    body = "\n".join(lines)
    budget = MAX_OBSERVED_TEXT - (len(tail) + 1 if tail else 0)
    if len(body) > budget:
        marker = "\n[evidence cut at the synopsis input limit]"
        body = body[:max(0, budget - len(marker))] + marker
    return body + ("\n" + tail if tail else "") if body else tail


def _takes_stage(callable_):
    """True when the presence callable accepts a positional stage argument."""
    try:
        parameters = inspect.signature(callable_).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.VAR_POSITIONAL)
               for p in parameters)


class ResearchBroker:
    def __init__(self, vm, *, clock=time.time, presence=None, log=None, gate=None):
        self.vm = vm
        self.gate = gate      # the shared GuestGate (wave 3e F3b); None calls the guest directly
        self.clock = clock
        self.presence_check = presence or (lambda: "none")
        self.log = log or (lambda message: None)
        self.lock = threading.RLock()
        self.owner = None
        self.thread = None
        self.plan = None
        self.phase = "idle"
        self.nonce = None
        self.batch_id = None
        self.deadline = 0.0
        self.guest_expires_at = None
        self.used = 0
        self.current_url = None
        self.observed_text = ""
        self.evidence_count = 0
        self.receipts = []
        self.watchdog = None
        self.profile = SHORT
        self.presence = "none"
        self.last_event = None
        # What the last cut could prove (fix helper, skeptic B). The
        # heartbeat reports both; an unverified cable counts as connected.
        self.cable_unverified = False
        self.poweroff_confirmed = None
        # Read-only pipe poll support (wave 3c pulse fix): the loop's last
        # real poll on the monotonic clock, and the last public status.
        self.monotonic = time.monotonic
        self.last_poll_at = None
        self._last_public = None
        self._close_pending = False   # wave 3f F1: a stopped batch's guest close not yet done
        self._public()

    def _identity(self, owner, thread):
        if not owner or owner != self.owner or not thread or thread != self.thread:
            raise BrokerError("This owner or conversation cannot control this research session")

    def _presence(self, stage="approve") -> str:
        check = self.presence_check
        try:
            value = check(stage) if _takes_stage(check) else check()
        except Exception:
            return "none"
        return value if value in PRESENCE_VALUES else "none"

    def _event(self, message):
        self.last_event = message
        try:
            self.log(message)
        except Exception:
            pass

    def _disconnect(self):
        try:
            confirmed = self.vm.disconnect_cable() is True
        except Exception:
            confirmed = False
        if not confirmed:
            self.phase = "fault"
            self.nonce = None
            self.cable_unverified = True
            try:
                self.poweroff_confirmed = self.vm.hard_poweroff() is True
            except Exception:
                self.poweroff_confirmed = False
            self._event("cable disconnect unconfirmed; emergency poweroff " +
                        ("confirmed" if self.poweroff_confirmed else "NOT confirmed"))
            self._public()   # wave 3e F2: the cached row shows the fault
            raise BrokerError("Cable disconnect was not confirmed; emergency poweroff requested")
        self.cable_unverified = False
        self.poweroff_confirmed = None
        self.phase = "paused"
        if self.watchdog is not None:
            try:
                self.watchdog.close()
            except Exception:
                pass
            self.watchdog = None
        self._public()       # wave 3e F2: never a pre-cut "online" row in the cache

    def _gate_enter(self, timeout=None) -> bool:
        """Take the shared guest gate for an owner op, bounded (wave 3e F3b).
        The default is read at call time, so GATE_WAIT_SECONDS stays patchable."""
        if self.gate is None:
            return True
        return self.gate.enter_within(GATE_WAIT_SECONDS if timeout is None else timeout)

    def _gate_leave(self):
        if self.gate is not None:
            self.gate.leave_quiet()

    def begin(self, owner: str, thread: str, plan: str) -> str:
        if not owner or not thread or not isinstance(plan, str) or not plan.strip():
            raise ValueError("Owner, conversation and offline plan are required")
        with self.lock:
            if self.phase not in {"idle", "stopped"}:
                raise BrokerError("Stop the existing research session first")
            if self.vm.isolated_running_cable_off() is not True:
                raise BrokerError("Dedicated VM is not running with its cable off and guard intact")
            self.owner, self.thread, self.plan = owner, thread, plan.strip()
            self.used = 0
            self.current_url = None
            self.observed_text = ""
            self.evidence_count = 0
            self.receipts = []
            self.batch_id = None
            self.profile = SHORT
            self.presence = "none"
            self.nonce = secrets.token_urlsafe(24)
            self.phase = "paused"
            self._public()   # wave 3e F2
            return self.nonce

    def approve(self, owner: str, thread: str, nonce: str, *, client_alive=None,
                received_at=None) -> dict:
        # Wave 3e F3b: a lock-only check first, so a stranger or a stale
        # nonce is refused at once; then the gate BEFORE the lock (the
        # loop's order), bounded; the nonce is spent only once both are held.
        # Wave 3f F2: the budget clock starts here; client_alive (optional,
        # from broker_ipc) says whether the pipe client is still waiting.
        # Wave 3g F1: or at received_at, when the pipe received the request.
        entered = time.monotonic() if received_at is None else received_at
        self.check_approval(owner, thread, nonce)
        if not self._gate_enter():
            self._event("approve refused: guest gate busy; approval not used")
            raise BrokerError("Guest control is busy; the approval was not used, try again")
        try:
            return self._approve(owner, thread, nonce, entered=entered, client_alive=client_alive)
        finally:
            self._gate_leave()

    def check_approval(self, owner: str, thread: str, nonce: str) -> None:
        """Lock-only: raise BrokerError unless `nonce` is this owner's live
        approval. Spends nothing and calls no guest (wave 3e F3b)."""
        with self.lock:
            self._identity(owner, thread)
            if self.phase != "paused" or not self.nonce or nonce != self.nonce:
                raise BrokerError("Approval is missing, spent or stale")

    def _approve(self, owner: str, thread: str, nonce: str, *, entered=None, client_alive=None) -> dict:
        if entered is None:
            entered = time.monotonic()
        with self.lock:
            self._identity(owner, thread)
            if self.phase != "paused" or not self.nonce or nonce != self.nonce:
                raise BrokerError("Approval is missing, spent or stale")
            self.nonce = None  # consumed before any network operation
            if self._close_pending:
                # Wave 3f F1: a stopped batch's guest close is still pending
                # (deferred behind a long driver call). This approve holds
                # the gate, so it closes the old guest batch itself; the
                # deferred closer then finds nothing pending.
                try:
                    self.vm.close_guest_quota()
                    self._close_pending = False
                except Exception:
                    pass  # the arm below verifies guest state
            if self.vm.isolated_running_cable_off() is not True:
                raise BrokerError("VM guard or cable state changed")
            presence = self._presence("approve")
            profile = select_profile(presence)
            batch_id = secrets.token_urlsafe(24)
            armed = False
            try:
                # Arm the root-owned proxy state while there is no internet.
                # This is the last guest-side step before the cable; its
                # deadline is taken right here, immediately before the call.
                guest_expires_at = self.clock() + profile.lease_seconds
                self.vm.arm_guest_quota(batch_id, guest_expires_at, page_limit=profile.page_limit,
                                        request_cap=profile.request_cap, byte_cap=profile.byte_cap)
                armed = True
                guest = self.vm.guest_quota_status()
                if (guest.get("batch_id") != batch_id or guest.get("phase") != "open" or
                    guest.get("used") != 0 or guest.get("limit") != profile.page_limit):
                    raise BrokerError("Guest quota arm was not verified")
                watchdog = self.vm.start_network_watchdog(profile.watchdog_seconds)
                if (watchdog is None or not callable(getattr(watchdog, "pulse", None)) or
                        not callable(getattr(watchdog, "close", None))):
                    raise BrokerError("Independent cable watchdog did not start")
                self.watchdog = watchdog
                # Wave 3f F2: never put the cable on for an app that has
                # stopped waiting, or past the budget that keeps approve
                # inside the app's client timeout. The connect call itself
                # is the one step that can still outlast a client (its
                # subprocess ceilings exceed CONNECT_CALL_SECONDS); the lease
                # and both watchdogs bound that cable.
                if client_alive is not None and client_alive() is not True:
                    raise _ApproveAbandoned("The app stopped waiting for this approval")
                if time.monotonic() - entered > APPROVE_CONNECT_BY_SECONDS:
                    raise _ApproveAbandoned("Approval ran past its time budget")
                if self.vm.connect_cable() is not True:
                    raise BrokerError("Virtual cable connection was not verified")
            except Exception as exc:
                if armed:
                    # Wave 3g F4: the guest batch armed above is open; the
                    # next stop, deferred closer or approve closes it.
                    self._close_pending = True
                try:
                    self._disconnect()
                    self._event(f"batch could not start ({profile.name} lease)")
                    if isinstance(exc, _ApproveAbandoned):
                        # Wave 3f F2: close the batch this approve armed
                        # (the gate is held), so the next arm is not refused.
                        try:
                            self.vm.close_guest_quota()
                            self._close_pending = False
                        except Exception:
                            pass
                finally:
                    self._public()   # wave 3e F2: no spent nonce in the cache
                raise BrokerError("Batch could not start; VM remains offline") from exc
            # The host deadline starts only now, with the cable confirmed on.
            self.deadline = self.clock() + profile.lease_seconds
            self.guest_expires_at = guest_expires_at
            self.batch_id = batch_id
            self.profile = profile
            self.presence = presence
            self.used = 0
            self.observed_text = ""
            self.evidence_count = 0
            self.receipts = []
            self.phase = "online"
            self.last_poll_at = self.monotonic()   # the loop's polls run from here
            self._event(f"batch online: {profile.name} lease, presence {presence}, "
                        f"limit {profile.page_limit}")
            return self._public()

    def poll(self) -> dict:
        """Called by a host timer, not by the model, throughout an online batch.
        Only the broker's own poll loop calls this (through the guest gate);
        the pipe's poll op reads snapshot() instead (wave 3c pulse fix)."""
        with self.lock:
            self.last_poll_at = self.monotonic()
            if self.phase != "online":
                return self._public()
            if self.clock() >= self.deadline:
                self._disconnect()
                self.nonce = secrets.token_urlsafe(24)
                # Close the guest batch too (wave 2, symmetry with the
                # presence-loss cut): best effort, the cable is already off
                # and the next arm verifies guest state.
                try:
                    self.vm.close_guest_quota()
                except Exception:
                    pass
                self._event("lease ended; cable cut")
                return self._public()
            if self.profile is LONG and self._presence("poll") == "none":
                # Lock, idle past the poll threshold, or a revoked grant: the
                # uninterrupted window is over. Cut now; the next approval is
                # short unless presence is back.
                try:
                    self._disconnect()
                finally:
                    self.nonce = secrets.token_urlsafe(24)
                    self.presence = "none"
                # Close the guest batch too (fix helper, skeptic C): the
                # guest refuses to re-arm while its batch is open and
                # unexpired, so without this the next approval was refused
                # until the guest lease ran out. Best effort: the cable is
                # already off, and the next arm verifies guest state.
                try:
                    self.vm.close_guest_quota()
                except Exception:
                    pass
                self._event("presence lost during long lease; cable cut")
                return self._public()
            try:
                # The loop is alive and holds the guest gate now; the status
                # call below can take up to 15 s (skeptic wave 3 item 2).
                tick = getattr(self.watchdog, "tick", None)
                if callable(tick):
                    tick()
                guest = self.vm.guest_quota_status()
                limit = self.profile.page_limit
                if (guest.get("batch_id") != self.batch_id or
                    type(guest.get("used")) is not int or not self.used <= guest["used"] <= limit or
                    guest.get("phase") not in {"open", "draining", "closed"}):
                    raise BrokerError("Guest page receipts changed unexpectedly")
                self.used = guest["used"]
                self.current_url = guest.get("current_url")
                receipts = guest.get("evidence", [])
                if (type(receipts) is not list or len(receipts) > limit or
                    any(not valid_receipt(item, self.used) for item in receipts) or
                    len({item["number"] for item in receipts}) != len(receipts)):
                    raise BrokerError("Guest page evidence is invalid")
                self.receipts = [dict(item) for item in receipts]
                self.evidence_count = sum(1 for item in receipts if item["text"])
                self.observed_text = build_observed_text(receipts, self.used)
                if guest["phase"] == "closed":
                    self._disconnect()
                    self.nonce = secrets.token_urlsafe(24)
                    self._event("guest closed the batch; cable cut")
                elif self.watchdog is not None:
                    self.watchdog.pulse()
            except Exception as exc:
                try:
                    self._disconnect()
                    self.nonce = secrets.token_urlsafe(24)
                    self._event("guest receipt check failed; cable cut")
                finally:
                    self._public()   # wave 3e F2: the cache carries the cut and its nonce
                raise BrokerError("Guest receipt check failed; internet disconnected") from exc
            return self._public()

    def stop(self, owner: str, thread: str) -> dict:
        called = time.monotonic()   # wave 3g F2: the inline close's budget clock
        with self.lock:
            self._identity(owner, thread)
            self.nonce = None
            self._disconnect()
            self.phase = "stopped"
            self.batch_id = None
            self._close_pending = True   # wave 3f F1
            self._event("stopped by owner")
            row = self._public()
        # Wave 3e F3b: the cable is already off; the guest close waits for the
        # shared gate outside the broker lock, so it never lands inside a
        # navigator's typing call and never inverts the loop's gate-then-lock
        # order. A gate still busy after STOP_GATE_WAIT_SECONDS (a stuck
        # navigator call) hands the close to a daemon thread. Wave 3g F2: so
        # does a stop left with no room for the gate wait and the close
        # before STOP_INLINE_CLOSE_BY_SECONDS (a long wait on the lock).
        room = STOP_INLINE_CLOSE_BY_SECONDS - (time.monotonic() - called)
        if room > 0 and self._gate_enter(min(STOP_GATE_WAIT_SECONDS, room)):
            self._close_if_stopped()
        else:
            self._event("stop: guest gate busy; guest close deferred until it frees")
            threading.Thread(target=self._deferred_close, name="jr-guest-close",
                             daemon=True).start()
        return row

    def _close_if_stopped(self):
        """Gate held by the caller; closes the guest batch unless a new batch
        was armed meanwhile, then releases the gate.

        CHANGED 2026-09-28 late (wave 3f F1): the test was phase == "stopped",
        which a begin (phase "paused") in between defeated. Now: the stop's
        close is still pending, no batch is online and batch_id is None,
        checked under the lock with the gate held, right before the close.
        Only an approve holding this same gate can arm, so a new batch can
        never be closed here; claiming the pending close under the lock
        means it happens once."""
        try:
            with self.lock:
                still_stopped = (self._close_pending and self.batch_id is None and
                                 self.phase != "online")
                if still_stopped:
                    self._close_pending = False
            if still_stopped:
                try:
                    self.vm.close_guest_quota()
                except Exception:
                    with self.lock:
                        self._close_pending = True   # the next approve tries again
        finally:
            self._gate_leave()

    def _deferred_close(self):
        if self._gate_enter(CLOSE_DEFER_SECONDS):
            self._close_if_stopped()
        else:
            self._event("stop: guest gate stayed busy; guest batch left to its own lease")

    def emergency(self) -> None:
        """Separate authenticated UI button; allowed even when Jr is locked.

        The poweroff runs before the lock is taken (wave 2, Grok review): a
        poll inside a slow guest-control call must not delay it. hard_poweroff
        is a VBoxManage controlvm call that is safe beside a guest-control
        call; the state update follows under the lock."""
        failure = None
        try:
            confirmed = self.vm.hard_poweroff() is True
        except Exception as exc:
            confirmed, failure = False, exc
        with self.lock:
            self.nonce = None
            self.phase = "fault"
            # CHANGED 2026-09-28 (fix helper, skeptic item 8): recorded under
            # the lock like _disconnect does, so the heartbeat reports the
            # poweroff result and treats the cable as unverified until the
            # watchdog proves it off from the VM itself.
            self.cable_unverified = True
            self.poweroff_confirmed = confirmed
            if self.watchdog is not None:
                try:
                    self.watchdog.close()
                except Exception:
                    pass
                self.watchdog = None
            self._event("emergency poweroff requested; " +
                        ("confirmed" if confirmed else "NOT confirmed"))
            self._public()   # wave 3e F2: the cached row shows the fault at once
            if failure is not None:
                raise failure
            if not confirmed:
                raise BrokerError("VM poweroff could not be confirmed")

    def status(self, owner: str, thread: str, *, stale_after=None, cut_after=None) -> dict:
        """The owner's status, never waiting on the lock (CHANGED 2026-09-28
        late, wave 3e F3): the stage polls it every second and it used to
        queue behind the loop's guest call. owner and thread are plain
        attribute reads, so the identity check needs no lock."""
        self._identity(owner, thread)
        return self.snapshot(stale_after=stale_after, cut_after=cut_after)

    def snapshot(self, stale_after=None, cut_after=None) -> dict:
        """The last public status, read-only (ADDED 2026-09-28 late, wave 3c
        pulse fix). Never waits on the lock: when poll() or approve() holds
        it (a guest-control call can take 15 s) the cached status from the
        last _public() is returned. No tick, no pulse, no guest-control call,
        no presence check. With stale_after (seconds), an online batch whose
        last loop poll is older than that carries "stale_seconds", the age
        of that poll.

        CHANGED 2026-09-28 late (wave 3e F6): an online row is reported as
        phase "cutting" with "reason" "loop_stale" when that age exceeds
        cut_after (the cable watchdog's pulses have stopped and the child is
        cutting), else "deadline_passed" once the host deadline has passed
        (the loop's own poll cuts on its next turn). Read-only: nothing here
        cuts, and the broker's own phase stays "online" until something does."""
        if self.lock.acquire(blocking=False):
            try:
                row = self._public()
            finally:
                self.lock.release()
        else:
            row = self._last_public
            row = dict(row, receipts=[dict(item) for item in row["receipts"]])
        if row["phase"] != "online":
            return row
        last = self.last_poll_at
        age = None if last is None else self.monotonic() - last
        if stale_after is not None and age is not None and age > stale_after:
            row["stale_seconds"] = round(age, 3)
        if cut_after is not None and age is not None and age > cut_after:
            row["phase"], row["reason"] = "cutting", "loop_stale"
        elif self.clock() >= self.deadline:
            row["phase"], row["reason"] = "cutting", "deadline_passed"
        return row

    def _public(self):
        row = self._public_row()
        self._last_public = row
        return dict(row, receipts=[dict(item) for item in row["receipts"]])

    def _public_row(self):
        return {"phase": self.phase, "used": self.used, "limit": self.profile.page_limit,
                "lease_seconds": self.profile.lease_seconds, "presence": self.presence,
                "current_url": self.current_url, "plan": self.plan,
                "observed_text": self.observed_text,
                "evidence_count": self.evidence_count,
                "receipts": [dict(item) for item in self.receipts],
                "approval_nonce": self.nonce if self.phase == "paused" else None}
