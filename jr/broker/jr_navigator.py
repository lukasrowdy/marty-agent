"""Jr navigator: turns an approved plan into page loads inside the lab VM.

CHANGED 2026-09-28 late (wave 3e, skeptic wave 3d finding 3b):
GuestGate.enter_within(timeout) and leave_quiet() let the broker's approve
and stop take the shared gate for their guest-control calls (arm, status,
close) with a bounded wait, so a wedged holder refuses an owner op instead
of hanging it. leave_quiet() stamps the gap like __exit__ but does not
count the hold in max_call_s: the broker's hold spans an owner op (up to
two guest calls and the cable), not one driver call, and the navigator
prices a typing sequence from max_call_s.

CHANGED 2026-09-28 late (wave 3c pulse fix, skeptic wave 3c pulse verdict):
GuestGate's default clock is time.monotonic (was time.time). The gate only
measures gaps, call durations and the broker loop's bridge, so a backward
wall-clock step must not stretch any of them. A Navigator built with a
private gate (guest_lock) still hands the gate its own clock, as before.

CHANGED 2026-09-28 late (wave 3 follow-up, skeptic wave 3 fix list):
- item 2: DRIVER_CALL_BOUND_SECONDS (30 s, jr_computer's guest-control
  subprocess timeout) names the longest one gated call may hold the gate,
  and GuestGate.call_ticking() lets the broker's poll loop keep stamping the
  watchdog tick while it waits for the gate, for a bounded time only.
- item 5: every driver call is timed; a typing_abandoned row carries the
  call that was in flight when the stop arrived ("in_flight", its tool, and
  "in_flight_s", its duration), and a typed row whose Return completed after
  a stop carries "stop_during" and "in_flight_s", so a stray page in the next
  batch can be attributed to the old one.

CHANGED 2026-09-28 evening (fix helper, skeptic item 6a): _type_url re-reads
the stop event before each of its four gated driver calls and abandons the
sequence (NavigatorStopped, stop_reason "stop_requested") instead of sending
the remaining keystrokes.

New file (navigator item, 2026-09-28). Runs inside the broker process after
approve. It owns no VM handle and opens no network of its own: every action is
a call to an injected `driver(tool, args)` (the real broker passes the guest
control driver from the dashboard's jr_computer module; tests pass a fake) and
an injected `quota_status()` (the guest page-quota receipt; the real broker
passes the adapter's guest status). It never imports jr_computer.

CHANGED 2026-09-28 (fix helper, after the skeptic's item 7 verdict), why:
- The lease guard covered starting a page, not finishing its keystrokes: a
  typing sequence is four driver calls, each a gap plus a guest-control
  round trip that can hang toward jr_computer's 30 s subprocess timeout, so
  the Return could land past the host deadline. Now nothing is typed unless
  `lease_guard + type_cost()` seconds remain, where type_cost is
  4 x (min_gap + the running maximum guest call duration, floor 3 s), and
  every call's duration is measured by the gate.
- "incomplete" let the navigator type the next URL over a page still in
  flight (Chromium cancels the load, the filter finishes the slot with status
  None, and that receipt is logged as the next pick's page). A slot that is
  still in flight after receipt_timeout now stops the batch with "page_stuck".
- A 3xx reply finishes its slot milliseconds before the browser reserves the
  follow-up GET; a status poll in that window looked like a finished page.
  A newest receipt with a 3xx status and nothing in flight must now hold on
  two consecutive polls before it counts as the receipt.
- The min-gap timestamp lived in the navigator, so the broker's 3 s poller
  was not spaced. GuestGate below wraps the lock and spaces every party that
  goes through it; it sleeps outside the lock. The broker constructs one and
  passes it as `guest_gate`; `guest_lock` still works and gets a private gate.
- session_id defaulted to the constant "jr-navigator"; it now defaults to a
  fresh secrets.token_hex(8) per navigator, as the trial and dashboard do.
- URLs typed into the guest are ASCII only: a non-ASCII host is IDNA-encoded
  and non-ASCII or unsafe path, query and fragment characters are
  percent-encoded when a link is admitted, so the model is offered, and the
  driver is typed, the same ASCII string. MAX_URL is 2000, jr_computer's
  text cap. A URL with userinfo (user@host) is refused.
- After each typed page, the first receipt's URL is compared to the typed
  URL (the guest cuts receipt URLs to 200 bytes; Chromium adds the root
  slash; a 3xx chain compares only its first slot). A difference is logged
  as url_mismatch with both URLs.
- Docstring: captured DuckDuckGo links are already the decoded uddg targets,
  so a pick never bounces through duckduckgo.com; a page's own 3xx still
  spends a second slot.

Flow, per `search_queries` entry in the plan: type the DuckDuckGo Lite URL
into the guest browser (ctrl+L, type_text, Return), wait for the guest receipt
for that page, take the receipt's `links`, ask the local model which links to
read (`JrModel.pick_links`, validated against the offered list), type each
pick in turn waiting for its receipt, and continue until the model says stop,
the page limit is reached, the guest reports the gate closed or expired, the
lease deadline is within `lease_guard + type_cost()` seconds, a page sticks in
flight, or the broker sets the stop event.

Guest control discipline (from the live trials): every guest-control call goes
through one GuestGate shared with the broker's 3-second poller, which holds
the one lock per call and spaces consecutive calls from any party by at least
`min_gap` seconds (default 2), because hammering guest control leaves the
guest unresponsive. Every URL typed is logged with a timestamp, in memory and
optionally to a JSON-lines file the checkpoint can attach. The model call
(pick_links) runs outside the lock so the poller keeps going while the model
thinks. The watchdog heartbeat is the broker's business: the navigator never
sends or waits on it.

Outbound channel rule (coordinator, 2026-09-28): with no allowlist the URL bar
is an outbound channel, so only two kinds of URL may ever reach the driver:
the DuckDuckGo Lite search URL built from a validated `search_queries` entry,
and the ASCII form of a URL that appeared in a captured `links` list of this
batch (about:blank during prepare() is the one fixed exception). `_type_url`
asserts membership in that per-batch set before any driver call; a string
from any other source raises NavigatorError and is never typed.

Batch parameters come from the batch, not from this file: the lease deadline
is passed to run() by the broker (110 s short, 290 s long host lease, guest
cap 300), and the page limit is read from the guest status's `limit` field
(5 short, 30 long); a `page_limit` argument is an optional cross-check and the
smaller of the two wins.

Guest status shape (item 6, guest_page_quota._public): {batch_id, phase,
used, limit, request_cap, byte_cap, inflight, current_url, evidence: [
{number, url, status, text, links?}], expired}. `links` is up to 8
{url, title} entries captured only on DuckDuckGo Lite results pages, and each
url is the decoded result target (the guest strips the /l/?uddg= wrapper), so
a pick loads the target directly. The broker's own status dict carries the
same list under `receipts`; both keys are accepted here.
"""

from __future__ import annotations

import datetime
import json
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit, urlunsplit

from jr_model import JrModel, ModelError, MAX_QUERY_CHARS, MAX_SEARCH_QUERIES


DDG_LITE = "https://lite.duckduckgo.com/lite/?q="
BROWSER_APP = "Chromium"
MAX_URL = 2000                 # jr_computer's type_text cap (2000 characters)
MAX_RECEIPT_URL_BYTES = 200    # the guest cuts receipt URLs to this many bytes
TYPING_CALLS = 4               # bring_to_front, hotkey, type_text, press_key
DEFAULT_CALL_S = 3.0           # floor for the running max guest call duration
DRIVER_CALL_BOUND_SECONDS = 30.0  # jr_computer's guest-control timeout: the longest one gated call runs
# RFC 3986 characters left alone when a link's path, query or fragment is
# percent-encoded; everything else, non-ASCII included, is escaped.
_PATH_SAFE = "/:@!$&'()*+,;=-._~%"
_QUERY_SAFE = _PATH_SAFE + "?"


class NavigatorError(Exception):
    pass


class NavigatorStopped(NavigatorError):
    """The stop event was set inside a typing sequence (ADDED 2026-09-28, fix
    helper, skeptic item 6a): the remaining keystrokes are not sent and run()
    ends with stop_reason "stop_requested" instead of "error"."""


def search_url(query: str) -> str:
    if (not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY_CHARS or
        any(ord(c) < 32 or ord(c) == 127 for c in query)):
        raise NavigatorError("Search query must be 1 to 160 printable characters")
    return DDG_LITE + quote_plus(query)


def ascii_url(url) -> str:
    """The ASCII form of an https URL, or raise NavigatorError.

    Host: IDNA-encoded when it is not already ASCII. Path, query, fragment:
    percent-encoded, existing escapes kept. A clean ASCII URL comes back
    unchanged, byte for byte. Userinfo, control characters, non-https and
    anything over MAX_URL after encoding are refused.
    """
    if (not isinstance(url, str) or not url.startswith("https://") or len(url) > MAX_URL or
        any(ord(c) < 32 or ord(c) == 127 for c in url)):
        raise NavigatorError("URL is not a typeable https address")
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise NavigatorError("URL is not a typeable https address")
    if (parts.scheme != "https" or not host or "@" in parts.netloc or
        any(not label for label in host.split("."))):
        raise NavigatorError("URL is not a typeable https address")
    if url.isascii() and quote(url, safe=_QUERY_SAFE + "#") == url:
        return url   # already clean ASCII: verbatim, byte for byte
    netloc = parts.netloc
    if not netloc.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise NavigatorError("URL host cannot be encoded")
        netloc = host + (":" + str(port) if port is not None else "")
    result = urlunsplit(("https", netloc, quote(parts.path, safe=_PATH_SAFE),
                         quote(parts.query, safe=_QUERY_SAFE),
                         quote(parts.fragment, safe=_QUERY_SAFE)))
    if not result.isascii() or len(result) > MAX_URL:
        raise NavigatorError("URL is not a typeable https address")
    return result


class GuestGate:
    """One lock and one minimum gap for every guest-control call, any party.

    The navigator and the broker's poller share a gate. `call(fn, *args)` or
    `with gate:` waits until `min_gap` seconds have passed since the previous
    call ended (sleeping with the lock released, so the other party is never
    blocked by a sleeper), then runs under the lock and stamps the clock on
    release. The longest call seen is kept in `max_call_s`; the navigator
    prices a typing sequence from it.
    """

    def __init__(self, *, lock=None, min_gap=2.0, clock=time.monotonic, sleep=time.sleep):
        if lock is None:
            lock = threading.Lock()
        if not (hasattr(lock, "__enter__") and hasattr(lock, "__exit__")):
            raise NavigatorError("GuestGate needs a context-manager lock")
        self.lock = lock
        self.min_gap = float(min_gap)
        self.clock = clock
        self.sleep = sleep
        self.max_call_s = 0.0
        self._last = None      # clock stamp of the previous call's end; lock-protected
        self._started = None   # clock stamp of the running call; lock-protected

    def __enter__(self):
        while True:
            self.lock.__enter__()
            wait = 0.0 if self._last is None else self.min_gap - (self.clock() - self._last)
            if wait <= 0:
                self._started = self.clock()
                return self
            self.lock.__exit__(None, None, None)
            self.sleep(wait)

    def __exit__(self, *exc):
        ended = self.clock()
        self._last = ended
        self.max_call_s = max(self.max_call_s, ended - self._started)
        self._started = None
        return self.lock.__exit__(*exc)

    def call(self, fn, *args):
        with self:
            return fn(*args)

    def enter_within(self, timeout):
        """__enter__ bounded by `timeout` real seconds (ADDED 2026-09-28
        late, wave 3e): True with the gate held (release it with
        leave_quiet), False when it stayed busy. A lock without
        acquire(timeout=...) is waited on unbounded, as __enter__ does."""
        acquire = getattr(self.lock, "acquire", None)
        if acquire is None:
            self.__enter__()
            return True
        end = time.monotonic() + float(timeout)
        while True:
            left = end - time.monotonic()
            if left <= 0 or not acquire(timeout=left):
                return False
            wait = 0.0 if self._last is None else self.min_gap - (self.clock() - self._last)
            if wait <= 0:
                self._started = self.clock()
                return True
            self.lock.__exit__(None, None, None)
            if time.monotonic() + wait > end:
                return False
            self.sleep(wait)

    def leave_quiet(self):
        """Release a hold taken by enter_within: the gap is stamped, the
        hold is not counted in max_call_s (ADDED 2026-09-28 late, wave 3e)."""
        self._last = self.clock()
        self._started = None
        self.lock.__exit__(None, None, None)

    def call_ticking(self, fn, *args, tick, bridge_seconds, step=1.0):
        """call(fn, *args), but the WAIT for the gate calls tick() about every
        `step` seconds while it has lasted at most `bridge_seconds` (ADDED
        2026-09-28 late, skeptic wave 3 item 2). The broker's poll loop uses
        it to show it is alive while a navigator driver call (up to
        DRIVER_CALL_BOUND_SECONDS) holds the gate. Past the bridge it waits
        without ticking, so a holder wedged beyond the driver bound lets the
        watchdog's pulses go stale. Only the waiting thread ticks. A lock
        without acquire(timeout=...) is waited on without ticking."""
        begun = self.clock()
        acquire = getattr(self.lock, "acquire", None)
        while True:
            bridging = self.clock() - begun <= bridge_seconds
            if bridging:
                tick()
            if bridging and acquire is not None:
                if not acquire(timeout=step):
                    continue
            else:
                self.lock.__enter__()
            wait = 0.0 if self._last is None else self.min_gap - (self.clock() - self._last)
            if wait <= 0:
                self._started = self.clock()
                break
            self.lock.__exit__(None, None, None)
            self.sleep(wait)
        try:
            return fn(*args)
        finally:
            self.__exit__(None, None, None)


class Navigator:
    def __init__(self, *, driver, quota_status, model: JrModel, guest_lock=None, guest_gate=None,
                 log_path=None, clock=time.time, sleep=time.sleep,
                 min_gap=2.0, receipt_poll=3.0, slot_timeout=15.0,
                 receipt_timeout=30.0, lease_guard=20.0, driver_call_s=DEFAULT_CALL_S,
                 stop_event=None, session_id=None):
        if not callable(driver) or not callable(quota_status):
            raise NavigatorError("driver and quota_status must be callables")
        if guest_gate is not None:
            if not isinstance(guest_gate, GuestGate):
                raise NavigatorError("guest_gate must be a GuestGate")
            self.gate = guest_gate
        elif guest_lock is not None:
            if not (hasattr(guest_lock, "__enter__") and hasattr(guest_lock, "__exit__")):
                raise NavigatorError("guest_lock must be a context-manager lock")
            self.gate = GuestGate(lock=guest_lock, min_gap=min_gap, clock=clock, sleep=sleep)
        else:
            raise NavigatorError("A shared guest_gate (or a guest_lock) is required")
        self.driver = driver
        self.quota_status = quota_status
        self.model = model
        self.log_path = Path(log_path) if log_path else None
        self.clock = clock
        self.sleep = sleep
        self.min_gap = self.gate.min_gap
        self.page_limit = None      # batch parameter, set by run()
        self.receipt_poll = max(float(receipt_poll), self.min_gap)
        self.slot_timeout = float(slot_timeout)
        self.receipt_timeout = float(receipt_timeout)
        self.lease_guard = float(lease_guard)
        self.driver_call_s = float(driver_call_s)
        self.stop_event = stop_event or threading.Event()
        self.session_id = secrets.token_hex(8) if session_id is None else str(session_id)
        self.log = []          # every event, in order; typed URLs carry "url"
        self.typed = []        # {"time", "url", "kind", "query_index", "page_before"}
        self.window = None     # {"pid", "window_id"} once prepare() has run
        self._last_status = None
        self.stop_reason = None
        self.lease_deadline = None  # batch parameter, set by run()
        self._allowed = set()       # URLs that may reach the driver this batch
        self._last_call = None      # (tool, seconds) of the latest driver call in a typing sequence

    # ----- logging -----------------------------------------------------------

    def _event(self, event, **fields):
        row = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
               "event": event, **fields}
        self.log.append(row)
        if self.log_path is not None:
            with open(self.log_path, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        return row

    # ----- guest control, serialised and rate limited ------------------------

    def _guest(self, call, *args):
        """Run one guest-control call through the shared gate (lock plus gap)."""
        return self.gate.call(call, *args)

    def _status(self):
        status = self._guest(self.quota_status)
        if (type(status) is not dict or type(status.get("used")) is not int or
            status.get("phase") not in {"open", "draining", "closed"} or
            ("limit" in status and (type(status["limit"]) is not int or
                                    not 1 <= status["limit"] <= 30))):
            raise NavigatorError("Guest quota status is invalid")
        self._last_status = status
        return status

    def _timed_driver(self, tool, args):
        # Times the driver call itself, inside the gate (not the gate wait).
        started = self.clock()
        try:
            return self.driver(tool, args)
        finally:
            self._last_call = (tool, self.clock() - started)

    def _drive(self, tool, args):
        result = self._guest(self._timed_driver, tool, args)
        if type(result) is not dict:
            raise NavigatorError("Guest driver did not return a result")
        return result

    def type_cost(self) -> float:
        """Seconds a whole typing sequence may take: four gated calls, each the
        gap plus the longest guest call seen so far (never under driver_call_s)."""
        return TYPING_CALLS * (self.min_gap + max(self.driver_call_s, self.gate.max_call_s))

    # ----- preparation (may run before the lease, cable off) -----------------

    def prepare(self):
        """Find the one visible guest browser window and clear it to about:blank.

        Safe to call before approve: it needs no network. run() calls it if the
        broker did not, but that spends lease time on window discovery.
        """
        rows = self._drive("list_windows", {}).get("windows", [])
        browsers = [row for row in rows if type(row) is dict and row.get("app_name") == BROWSER_APP
                    and row.get("is_on_screen") and type(row.get("pid")) is int
                    and row.get("window_id") is not None]
        if len(browsers) != 1:
            raise NavigatorError("Expected exactly one visible guest browser window")
        self.window = {"pid": browsers[0]["pid"], "window_id": browsers[0]["window_id"]}
        self._event("window", **self.window)
        self._type_url("about:blank", kind="blank", query_index=None, page_before=None)
        # Prove the browser took the keys before any lease time is spent on it.
        for _ in range(3):
            rows = self._drive("list_windows", {}).get("windows", [])
            if any(type(row) is dict and row.get("window_id") == self.window["window_id"] and
                   row.get("title") == "about:blank - " + BROWSER_APP for row in rows):
                break
        else:
            raise NavigatorError("Could not verify the browser's offline blank page")
        return self.window

    def _target(self):
        return {**self.window, "session": self.session_id, "delivery_mode": "background"}

    def _allow(self, url):
        """Admit the ASCII form of a URL to this batch's typeable set and return it."""
        url = ascii_url(url)
        self._allowed.add(url)
        return url

    def _type_url(self, url, *, kind, query_index, page_before):
        # Outbound channel guard: nothing reaches the driver unless it is the
        # blank page during prepare(), a search URL built here from a validated
        # query, or the ASCII form of a URL captured in this batch's links lists.
        if kind == "blank":
            if url != "about:blank":
                raise NavigatorError("Only about:blank may be typed as the blank page")
        elif kind not in {"search", "pick"} or url not in self._allowed:
            raise NavigatorError("Refused to type a URL that was not searched or captured")
        # CHANGED 2026-09-28 (fix helper, skeptic item 6a): the stop event is
        # re-read before every gated call, not just before the sequence. A
        # stop that lands between the hotkey and the text leaves the address
        # bar focused and empty; one between the text and the Return leaves
        # the URL unsent. Nothing after the stop reaches the driver.
        self._last_call = None
        self._stop_typing_if_requested(url)
        self._drive("bring_to_front", dict(self.window))
        target = self._target()
        for tool, args in (("hotkey", {**target, "keys": ["ctrl", "l"]}),
                           ("type_text", {**target, "text": url}),
                           ("press_key", {**target, "key": "Return"})):
            self._stop_typing_if_requested(url, before=tool)
            result = self._drive(tool, args)
            if result.get("route") != "global_input":
                raise NavigatorError("Guest driver did not confirm an input route")
        extra = {}
        if self.stop_event.is_set() and self._last_call is not None:
            # The stop arrived while the Return was in flight: the page loads
            # anyway, and this row says so (skeptic wave 3 item 5).
            extra = {"stop_during": self._last_call[0], "in_flight_s": round(self._last_call[1], 3)}
        row = self._event("typed", url=url, kind=kind, query_index=query_index,
                          page_before=page_before, **extra)
        if kind != "blank":
            self.typed.append({k: row[k] for k in ("time", "url", "kind", "query_index", "page_before")})

    # ----- stop conditions ---------------------------------------------------

    def _stop_typing_if_requested(self, url, *, before="bring_to_front"):
        if self.stop_event.is_set():
            self.stop_reason = "stop_requested"
            # The call in flight when the stop arrived, and how long it ran
            # (skeptic wave 3 item 5); None before a sequence's first call.
            tool, seconds = self._last_call if self._last_call is not None else (None, None)
            self._event("typing_abandoned", url=url, before=before, in_flight=tool,
                        in_flight_s=None if seconds is None else round(seconds, 3))
            raise NavigatorStopped("Stop requested inside a typing sequence")

    def _remaining(self):
        return self.lease_deadline - self.clock()

    def _check_stop(self, status=None, *, typing=False):
        """Return a stop reason if navigation must end now, else None.

        With typing=True the lease must also hold a whole typing sequence
        (type_cost) inside the guard, since the Return is the last of four
        gated calls, not the first.
        """
        if self.stop_event.is_set():
            return "stop_requested"
        need = self.lease_guard + (self.type_cost() if typing else 0.0)
        if self._remaining() <= need:
            return "lease_deadline"
        status = status or self._last_status
        if status is not None:
            if status["phase"] == "closed":
                return "gate_closed"
            if status.get("expired"):
                return "lease_expired"
            if status["used"] >= self.page_limit:
                return "page_limit"
        return None

    # ----- receipts ----------------------------------------------------------

    def _wait_receipt(self, page_before):
        """Wait for the typed page's guest receipt. Returns (outcome, status).

        outcome is "receipt" (slots charged and nothing in flight; a newest
        3xx receipt must hold on two consecutive polls, because the browser's
        follow-up GET is reserved milliseconds after the 3xx slot finishes),
        "no_slot" (the proxy refused it before any slot: nothing loaded),
        "page_stuck" (a slot was charged but the load was still in flight at
        receipt_timeout; the caller stops, it never types over it) or a stop
        reason.
        """
        started = self.clock()
        redirect_seen = None   # `used` seen with a newest 3xx receipt and nothing in flight
        while True:
            reason = self._check_stop()
            if reason:
                return reason, self._last_status
            self.sleep(self.receipt_poll)
            status = self._status()
            if status["phase"] == "closed" and status["used"] > page_before:
                return "receipt", status
            reason = self._check_stop(status)
            if reason and reason != "page_limit":
                return reason, status
            if status["used"] > page_before and status.get("inflight", 0) == 0:
                if not self._newest_is_redirect(status, page_before):
                    return "receipt", status
                if redirect_seen == status["used"]:
                    return "receipt", status
                redirect_seen = status["used"]
                self._event("redirect_wait", used=status["used"])
                continue
            redirect_seen = None
            elapsed = self.clock() - started
            if status["used"] == page_before and elapsed >= self.slot_timeout:
                return "no_slot", status
            if elapsed >= self.receipt_timeout:
                return "page_stuck", status

    @staticmethod
    def _receipts(status):
        rows = status.get("evidence")
        if rows is None:
            rows = status.get("receipts")
        return rows if type(rows) is list else []

    def _receipt_rows(self, status, page_before):
        """(number, url, status) for the pages charged since page_before, for the log."""
        return sorted((item["number"], item.get("url"), item.get("status"))
                      for item in self._receipts(status)
                      if type(item) is dict and type(item.get("number")) is int and item["number"] > page_before)

    def _newest_is_redirect(self, status, page_before):
        rows = self._receipt_rows(status, page_before)
        if not rows:
            return False
        code = rows[-1][2]
        return type(code) is int and 300 <= code <= 399

    def _check_receipt_url(self, status, page_before, typed_url):
        """Log url_mismatch when the first receipt after a typed page is not that page.

        The guest cuts receipt URLs to 200 bytes and Chromium adds the root
        slash to a bare host; both are the same page. Later slots in a 3xx
        chain are the redirect targets and are not compared.
        """
        rows = self._receipt_rows(status, page_before)
        if not rows:
            return
        received = rows[0][1]
        if received == typed_url:
            return
        if isinstance(received, str):
            if (typed_url.startswith(received) and
                len(received.encode("utf-8")) >= MAX_RECEIPT_URL_BYTES - 3):
                return
            if received == typed_url + "/" and not urlsplit(typed_url).path:
                return
        self._event("url_mismatch", typed=typed_url, received=received, number=rows[0][0])

    def _links_for(self, status, page_before):
        """Links captured on the pages charged since page_before (search pages only).

        Every https URL in a captured list is admitted to the typeable set
        here in its ASCII form, which is also what the model is offered;
        malformed entries are dropped so they can never be picked.
        """
        links = []
        for item in self._receipts(status):
            if (type(item) is dict and type(item.get("number")) is int and
                item["number"] > page_before and type(item.get("links")) is list):
                for entry in item["links"]:
                    if len(links) >= 8:
                        break
                    if (type(entry) is dict and isinstance(entry.get("url"), str) and
                        isinstance(entry.get("title"), str)):
                        try:
                            url = self._allow(entry["url"])
                        except NavigatorError:
                            continue
                        links.append({"url": url, "title": entry["title"]})
        return links

    # ----- the flow ----------------------------------------------------------

    def run(self, plan: dict, question: str, lease_deadline: float, page_limit=None) -> dict:
        """Drive one batch. lease_deadline is the broker's batch deadline (110 s
        short, 290 s long host lease); the page limit comes from the guest
        status's `limit` (5 or 30), with page_limit as an optional cross-check."""
        if type(plan) is not dict:
            raise NavigatorError("Plan must be the validated plan dict")
        queries = plan.get("search_queries")
        if (type(queries) is not list or not 1 <= len(queries) <= MAX_SEARCH_QUERIES or
            any(not isinstance(q, str) for q in queries)):
            raise NavigatorError("Plan has no valid search_queries")
        objective = plan.get("objective")
        if not isinstance(objective, str) or not objective.strip():
            raise NavigatorError("Plan has no objective")
        if not isinstance(question, str) or not question.strip():
            raise NavigatorError("Question is required")
        if page_limit is not None and (type(page_limit) is not int or not 1 <= page_limit <= 30):
            raise NavigatorError("page_limit must be an int from 1 to 30")
        if type(lease_deadline) not in {int, float}:
            raise NavigatorError("lease_deadline must be a clock value")
        self.lease_deadline = float(lease_deadline)
        self.page_limit = page_limit
        self.stop_reason = None
        self._allowed = set()
        self._event("start", queries=len(queries), page_limit_arg=page_limit,
                    lease_remaining_s=round(self._remaining(), 1),
                    type_cost_s=round(self.type_cost(), 1))
        try:
            self._run(queries, objective, question)
        except NavigatorStopped:
            self.stop_reason = "stop_requested"
        except Exception as exc:
            self.stop_reason = self.stop_reason or "error"
            self._event("error", error=type(exc).__name__)
            raise
        finally:
            self._event("stop", reason=self.stop_reason,
                        pages_used=(self._last_status or {}).get("used"),
                        typed=len(self.typed), max_guest_call_s=round(self.gate.max_call_s, 3))
        return self.summary()

    def _load(self, url, *, kind, query_index):
        """Type one admitted URL, wait for its receipt, log it. Returns (outcome, status)."""
        page_before = self._last_status["used"]
        self._type_url(url, kind=kind, query_index=query_index, page_before=page_before)
        outcome, status = self._wait_receipt(page_before)
        self._event("receipt", outcome=outcome, query_index=query_index,
                    used=status["used"] if status else None,
                    pages=self._receipt_rows(status, page_before) if status else [])
        if status is not None and outcome == "receipt":
            self._check_receipt_url(status, page_before, url)
        return outcome, status, page_before

    def _run(self, queries, objective, question):
        if self.window is None:
            self.prepare()
        status = self._status()
        guest_limit = status.get("limit")
        if guest_limit is None and self.page_limit is None:
            raise NavigatorError("Guest status carries no page limit and none was given")
        if guest_limit is not None and self.page_limit is not None and guest_limit != self.page_limit:
            self._event("limit_mismatch", guest=guest_limit, broker=self.page_limit)
            self.page_limit = min(guest_limit, self.page_limit)
        elif guest_limit is not None:
            self.page_limit = guest_limit
        self._event("page_limit", page_limit=self.page_limit)
        reason = self._check_stop(status)
        if reason:
            self.stop_reason = reason
            return
        for index, query in enumerate(queries, 1):
            reason = self._check_stop(typing=True)
            if reason:
                self.stop_reason = reason
                return
            outcome, status, page_before = self._load(self._allow(search_url(query)),
                                                      kind="search", query_index=index)
            if outcome not in {"receipt", "no_slot"}:
                self.stop_reason = outcome
                return
            links = self._links_for(status, page_before) if outcome == "receipt" else []
            if not links:
                self._event("no_links", query_index=index)
                continue
            reason = self._check_stop(status)
            if reason:
                self.stop_reason = reason
                return
            picks, stop = self._ask(question, objective, links, index)
            for pick in picks:
                reason = self._check_stop(typing=True)
                if reason:
                    self.stop_reason = reason
                    return
                outcome, status, _ = self._load(pick, kind="pick", query_index=index)
                if outcome not in {"receipt", "no_slot"}:
                    self.stop_reason = outcome
                    return
            if stop:
                self.stop_reason = "model_stop"
                return
        self.stop_reason = "queries_exhausted"

    def _ask(self, question, objective, links, index):
        """Ask the local model which links to read; runs outside the guest lock.

        The model's time budget is what is left after the guard and one
        typing sequence, so a pick it returns can still be typed."""
        budget = self._remaining() - self.lease_guard - self.type_cost()
        if budget <= 1:
            return [], False
        try:
            choice = self.model.pick_links(question=question, objective=objective,
                                           links=links, timeout=budget)
        except (ModelError, ValueError) as exc:
            self._event("pick_failed", query_index=index, error=type(exc).__name__)
            return [], False
        picks = list(choice["picks"])
        self._event("picked", query_index=index, picks=picks, stop=bool(choice["stop"]),
                    why=str(choice["why"])[:200])
        return picks, bool(choice["stop"])

    def summary(self) -> dict:
        return {"stop_reason": self.stop_reason,
                "typed": list(self.typed),
                "pages_used": (self._last_status or {}).get("used"),
                "log": list(self.log),
                "log_path": str(self.log_path) if self.log_path else None}
