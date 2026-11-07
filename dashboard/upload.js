/*
  upload.js: chunked, resumable file intake for the Marty dashboard.

  Used by /app.js (the chat pane's Attach button). It does not depend on the
  page: no el() helper, no page globals, no modules, no libraries. It exposes
  exactly one thing, window.MartyIntake, and draws nothing itself; the page
  renders its own card from the state objects this file hands it.

  WIRE FORMAT (POST /api/upload, one request per slice)
    Headers:
      X-Filename        encodeURIComponent(file.name), as the legacy path sends it
      X-Upload-Id       64 hex chars, the fingerprint described below
      X-Upload-Offset   byte offset of this slice within the file
      X-Upload-Total    file.size in bytes
      X-Chunk-SHA256    optional, hex SHA-256 of this slice's bytes
      Content-Type      application/octet-stream
    Body: a fixed-length Blob slice (file.slice(offset, offset + n)). Never a
    ReadableStream and never chunked transfer: the server reads bodies only by
    Content-Length. Slices start at 8 MiB, halve to a 1 MiB floor on any network
    failure, and double back after three clean slices.
    Responses:
      200 {ok:true, done:false, bytes:N}     N = bytes the PC has committed, i.e.
                                             the next offset to send
      200 {ok:true, done:true, path, name, bytes, sha256}
      409 {error:"chunk in flight", bytes:N} the previous slice is still being
                                             written: wait 2 s, then continue at N
      409 {bytes:N}                          wrong offset: continue at N
      422                                    slice hash mismatch: re-send the slice
      401                                    session expired: stop, log in again
      507                                    PC disk nearly full: wait 30 s, re-send
      413 / 400 / 403                        stop and show the server's error text
      anything else, network error, non-JSON body: a dropped connection. Back off
      1, 2, 4, 8, 16, 30, 30... seconds with no cap while the page lives, retry
      at once on window "online" and on the tab becoming visible, and before
      every retry re-read GET /api/upload/status so a lost 200 never re-sends
      bytes the PC already has.
    GET  /api/upload/status?id=  -> {bytes, total, done, path, sha256, transcript}
         transcript is null or {state:"queued"|"running"|"done"|"failed", parts, dir, error}
    POST /api/upload/abort?id=       drops the partial file on the PC
    POST /api/upload/note?id=        JSON {note}: a line for Marty in the manifest
    POST /api/upload/transcribe?id=  starts the detached transcribe worker

  WHY THE ID IS A FINGERPRINT
    X-Upload-Id is computed here, not issued by the server: SHA-256 over
    UTF-8(file.name) | "|" | String(size) | "|" | String(lastModified) | "|" |
    first 1 MiB | "|" | last 1 MiB, via crypto.subtle. The same file therefore
    produces the same id from any browser, any tab, and an Incognito window, so
    an interrupted upload resumes by simply picking the file again: the first
    request is the status GET, the bar starts where the PC left off, and no
    localStorage is involved. Two different files that merely share a name and
    a size get different ids. A file already on the PC answers "done" from the
    status GET and no bytes move. Both origins the dashboard is served from
    (the https tailnet name and http://127.0.0.1) are secure contexts, so
    crypto.subtle exists; if it does not, start() fails with a plain message.

  PUBLIC API (window.MartyIntake)
    start(file, {lane, onState, onDone, onError}) -> {cancel}
    saveNote(id, text) -> Promise
    transcribe(id, opts) -> Promise        opts.remember (boolean) stores the
                                           "transcribe by default" preference
    pollStatus(id, cb) -> {stop}           GET status every 5 s while the
                                           transcript is queued or running
    fmtBytes(n), fmtEta(seconds), fingerprint(file) -> Promise<hex>

  STATE OBJECTS handed to onState:
    {state, id, name, lane, done, total, rate, eta, chunk, attempt, message, cancel}
    state is one of hashing | confirm-cellular | uploading | retrying |
    waiting-disk | done | failed | cancelled. done/total are bytes, rate is
    bytes per second smoothed over the last few seconds, eta is seconds or null.
    confirm-cellular also carries proceed(), and the card must render Upload and
    Cancel buttons for it: there is no window.confirm on this page. retrying and
    waiting-disk carry retryIn (seconds) and are re-emitted once a second as the
    countdown runs. done carries result (the same object onDone receives).
    onDone receives the server's done payload plus id, duplicate (true when the
    status GET said the file was already on the PC) and transcribeDefault.
    onError receives one message string.
*/

(function () {
  "use strict";

  var CHUNK_MAX = 8 * 1024 * 1024;        // first and largest slice
  var CHUNK_MIN = 1 * 1024 * 1024;        // floor after network failures
  var CLEAN_SLICES_TO_DOUBLE = 3;         // clean slices before the size doubles back
  var EDGE_BYTES = 1024 * 1024;           // head and tail bytes folded into the fingerprint
  var BACKOFF_SECONDS = [1, 2, 4, 8, 16, 30];
  var BACKOFF_CEILING = 30;
  var IN_FLIGHT_WAIT_MS = 2000;           // 409 "chunk in flight"
  var DISK_FULL_WAIT_SECONDS = 30;        // 507
  var POLL_MS = 5000;                     // transcript status poll
  var STALL_MS = 60000;                   // no upload progress for this long: drop the slice
  var RESPONSE_MS = 300000;               // slice fully sent, no reply for this long: drop it
  var RATE_WINDOW_MS = 5000;              // smoothing window for the rate
  var PROGRESS_EMIT_MS = 150;             // throttle for uploading states
  var TOGGLE_KEY = "marty.intake.transcribe";
  var ID_RE = /^[a-f0-9]{64}$/;
  var SESSION_MSG = "Session expired. Log in again, then pick the same file to resume.";
  var NO_SUBTLE_MSG = "This browser cannot hash files here (crypto.subtle is unavailable). " +
    "Open the dashboard over https or http://127.0.0.1, both of which are secure contexts.";

  var active = null;                      // the one running job on this page

  // ---------- small helpers ----------

  function now() { return Date.now(); }
  function noop() {}
  function logErr(e) { try { console.error("MartyIntake:", e); } catch (ignore) {} }

  function parseJson(text) {
    if (typeof text !== "string" || !text) return null;
    try {
      var v = JSON.parse(text);
      return (v && typeof v === "object") ? v : null;
    } catch (e) { return null; }
  }

  function clampInt(v, lo, hi) {
    v = Number(v);
    if (!isFinite(v)) return lo;
    return Math.max(lo, Math.min(hi, Math.floor(v)));
  }

  function backoffSeconds(attempt) {
    attempt = Math.max(0, Math.floor(attempt || 0));
    return attempt < BACKOFF_SECONDS.length ? BACKOFF_SECONDS[attempt] : BACKOFF_CEILING;
  }

  function backoffSequence(n) {
    var out = [];
    for (var i = 0; i < n; i++) out.push(backoffSeconds(i));
    return out;
  }

  function isCellular() {
    try {
      return !!(typeof navigator !== "undefined" && navigator.connection &&
        navigator.connection.type === "cellular");
    } catch (e) { return false; }
  }

  function getTranscribeDefault() {
    try { return window.localStorage.getItem(TOGGLE_KEY) === "1"; } catch (e) { return false; }
  }

  function setTranscribeDefault(on) {
    try {
      if (on) window.localStorage.setItem(TOGGLE_KEY, "1");
      else window.localStorage.removeItem(TOGGLE_KEY);
    } catch (e) { /* private window, blocked storage: the preference just does not persist */ }
  }

  // ---------- formatting (same KB/MB/GB scale the pages already use) ----------

  function fmtBytes(n) {
    n = Number(n);
    if (!isFinite(n) || n < 0) n = 0;
    if (n < 1024) return Math.round(n) + " B";
    if (n < 1048576) return (n / 1024).toFixed(0) + " KB";
    if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
    return (n / 1073741824).toFixed(2) + " GB";
  }

  function fmtEta(seconds) {
    if (typeof seconds !== "number" || !isFinite(seconds) || seconds < 0) return "";
    var s = Math.round(seconds);
    if (s < 5) return "a few seconds";
    if (s < 60) return s + " s";
    if (s < 3600) return Math.round(s / 60) + " min";
    var h, m, d;
    if (s < 86400) {
      h = Math.floor(s / 3600);
      m = Math.round((s % 3600) / 60);
      if (m === 60) { h += 1; m = 0; }
      return h + " h" + (m ? " " + m + " min" : "");
    }
    d = Math.floor(s / 86400);
    h = Math.round((s % 86400) / 3600);
    if (h === 24) { d += 1; h = 0; }
    return d + " d" + (h ? " " + h + " h" : "");
  }

  // ---------- hashing ----------

  function subtle() {
    try {
      var c = (typeof crypto !== "undefined") ? crypto : null;
      return (c && c.subtle && typeof c.subtle.digest === "function") ? c.subtle : null;
    } catch (e) { return null; }
  }

  function hex(buffer) {
    var b = new Uint8Array(buffer), s = "";
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
    return s;
  }

  function readBuffer(blob) {
    if (typeof blob.arrayBuffer === "function") return blob.arrayBuffer();
    return new Promise(function (resolve, reject) {
      var r = new FileReader();
      r.onload = function () { resolve(r.result); };
      r.onerror = function () { reject(r.error || new Error("read failed")); };
      r.readAsArrayBuffer(blob);
    });
  }

  async function sha256Hex(bytes) {
    var s = subtle();
    if (!s) throw new Error(NO_SUBTLE_MSG);
    return hex(await s.digest("SHA-256", bytes));
  }

  async function fingerprint(file) {
    if (!file || typeof file.slice !== "function" || typeof file.size !== "number") {
      throw new Error("fingerprint() needs a File or Blob");
    }
    if (!subtle()) throw new Error(NO_SUBTLE_MSG);
    var size = file.size;
    var enc = new TextEncoder();
    var sep = enc.encode("|");
    var head = new Uint8Array(await readBuffer(file.slice(0, Math.min(EDGE_BYTES, size))));
    var tail = new Uint8Array(await readBuffer(file.slice(Math.max(0, size - EDGE_BYTES), size)));
    var parts = [
      enc.encode(String(file.name == null ? "" : file.name)), sep,
      enc.encode(String(size)), sep,
      enc.encode(String(file.lastModified)), sep,
      head, sep,
      tail
    ];
    var len = 0, i;
    for (i = 0; i < parts.length; i++) len += parts[i].length;
    var buf = new Uint8Array(len), pos = 0;
    for (i = 0; i < parts.length; i++) { buf.set(parts[i], pos); pos += parts[i].length; }
    return sha256Hex(buf);
  }

  function readFailMessage(e) {
    var msg = (e && e.message) || "";
    if (msg === NO_SUBTLE_MSG) return msg;
    var name = (e && e.name) || "";
    if (name === "NotReadableError" || name === "NotFoundError") {
      return "Could not read the file: the browser lost access to it. Pick the same file again and the upload resumes where it stopped.";
    }
    return "Could not read the file" + (msg ? " (" + msg + ")" : "") + ". Pick it again to resume.";
  }

  // ---------- server calls ----------

  function httpError(message, status, fatal) {
    var e = new Error(message);
    e.status = status || 0;
    e.fatal = !!fatal;
    return e;
  }

  function checkId(id) {
    if (typeof id !== "string" || !ID_RE.test(id)) throw httpError("bad upload id", 0, true);
  }

  async function getStatus(id) {
    var res;
    try {
      res = await fetch("/api/upload/status?id=" + encodeURIComponent(id),
        { method: "GET", cache: "no-store", credentials: "same-origin" });
    } catch (e) { throw httpError("network error", 0, false); }
    var text = "";
    try { text = await res.text(); } catch (e) { throw httpError("network error", 0, false); }
    var json = parseJson(text);
    if (res.status === 401) throw httpError(SESSION_MSG, 401, true);
    if (res.status === 400 || res.status === 403) {
      throw httpError((json && json.error) || ("HTTP " + res.status), res.status, true);
    }
    if (!res.ok || !json) throw httpError("HTTP " + res.status, res.status, false);
    return json;
  }

  async function postJson(url, body) {
    var init = { method: "POST", cache: "no-store", credentials: "same-origin" };
    if (body !== undefined) {
      init.headers = { "Content-Type": "application/json" };
      init.body = JSON.stringify(body);
    }
    var res;
    try { res = await fetch(url, init); } catch (e) { throw httpError("Dashboard unreachable", 0, false); }
    var text = "";
    try { text = await res.text(); } catch (e) { text = ""; }
    var json = parseJson(text);
    if (res.status === 401) throw httpError(SESSION_MSG, 401, true);
    if (!res.ok || (json && json.error)) {
      throw httpError((json && json.error) || ("HTTP " + res.status), res.status,
        res.status >= 400 && res.status < 500);
    }
    return json || { ok: true };
  }

  function postAbort(id) {
    try {
      fetch("/api/upload/abort?id=" + encodeURIComponent(id),
        { method: "POST", cache: "no-store", credentials: "same-origin", keepalive: true })
        .catch(noop);
    } catch (e) { /* page is going away or fetch is missing; the 7-day sweep cleans up */ }
  }

  async function saveNote(id, text) {
    checkId(id);
    return postJson("/api/upload/note?id=" + encodeURIComponent(id),
      { note: String(text == null ? "" : text) });
  }

  async function transcribe(id, opts) {
    checkId(id);
    if (opts && typeof opts.remember === "boolean") setTranscribeDefault(opts.remember);
    return postJson("/api/upload/transcribe?id=" + encodeURIComponent(id));
  }

  function pollStatus(id, cb) {
    var stopped = false, timer = null, nullTicks = 0;
    var handle = {
      stop: function () { stopped = true; if (timer) { clearTimeout(timer); timer = null; } }
    };
    cb = typeof cb === "function" ? cb : noop;
    function schedule() { if (!stopped) timer = setTimeout(tick, POLL_MS); }
    async function tick() {
      timer = null;
      if (stopped) return;
      var st = null;
      try {
        checkId(id);
        st = await getStatus(id);
      } catch (e) {
        if (e && e.fatal) {
          stopped = true;
          try { cb({ error: e.message, transcript: null }); } catch (ignore) { logErr(ignore); }
          return;
        }
        schedule();                       // transient: try again next tick
        return;
      }
      if (stopped) return;
      try { cb(st); } catch (e) { logErr(e); }
      var t = st.transcript, s = t && t.state;
      if (s === "queued" || s === "running") { schedule(); return; }
      if (!t && nullTicks < 6) { nullTicks += 1; schedule(); return; }   // worker not registered yet
      stopped = true;                     // done, failed, or nothing to wait for
    }
    tick();
    return handle;
  }

  // ---------- the upload job ----------

  function emit(job, state, extra) {
    var done = (typeof job.progress === "number") ? job.progress : 0;
    var rate = state === "uploading" ? job.rate : 0;
    var eta = (state === "uploading" && rate > 0) ? Math.max(0, (job.total - done) / rate) : null;
    var o = {
      state: state, id: job.id, name: job.file.name, lane: job.lane,
      done: done, total: job.total, rate: rate, eta: eta,
      chunk: job.chunk, attempt: job.attempt, message: "", cancel: job.handle.cancel
    };
    if (extra) Object.assign(o, extra);
    try { job.onState(o); } catch (e) { logErr(e); }
  }

  function emitUploading(job, message) { emit(job, "uploading", { message: message }); }

  function resetRate(job) { job.samples = []; job.rate = 0; }

  function noteProgress(job, bytes) {
    var t = now();
    job.samples.push({ t: t, b: bytes });
    while (job.samples.length > 2 && t - job.samples[0].t > RATE_WINDOW_MS) job.samples.shift();
    var first = job.samples[0], last = job.samples[job.samples.length - 1];
    var span = last.t - first.t;
    if (span >= 500 && last.b >= first.b) job.rate = (last.b - first.b) * 1000 / span;
  }

  function shrink(job) {
    job.chunk = Math.max(CHUNK_MIN, Math.floor(job.chunk / 2));
    job.clean = 0;
    resetRate(job);
  }

  function grow(job) {
    job.clean += 1;
    if (job.clean >= CLEAN_SLICES_TO_DOUBLE && job.chunk < CHUNK_MAX) {
      job.chunk = Math.min(CHUNK_MAX, job.chunk * 2);
      job.clean = 0;
    }
  }

  // A wait the job can be pulled out of: cancel() breaks every wait, and the
  // "online" / tab-visible events break only the retry backoff. Resolves true
  // when broken early, false when the time ran out.
  function sleep(job, ms, interruptible) {
    return new Promise(function (resolve) {
      var timer = setTimeout(function () { done(false); }, ms);
      function done(early) {
        clearTimeout(timer);
        job.breakSleep = null;
        job.wakeRetry = null;
        resolve(early);
      }
      job.breakSleep = function () { done(true); };
      job.wakeRetry = interruptible ? function () { done(true); } : null;
    });
  }

  async function countdownWait(job, state, reason, seconds, interruptible) {
    var until = now() + seconds * 1000;
    while (!job.finished) {
      var leftMs = until - now();
      if (leftMs <= 0) return;
      var left = Math.ceil(leftMs / 1000);
      emit(job, state, { message: reason + ", retrying in " + left + " s", retryIn: left });
      var early = await sleep(job, Math.min(1000, leftMs), interruptible);
      if (early) return;
    }
  }

  async function retryWait(job, reason) {
    var secs = backoffSeconds(job.attempt);
    job.attempt += 1;
    await countdownWait(job, "retrying", reason, secs, true);
  }

  async function acquireWakeLock(job) {
    if (job.finished) return;
    var wl = (typeof navigator !== "undefined") ? navigator.wakeLock : null;
    if (!wl || typeof wl.request !== "function") return;
    if (job.wakeLock && !job.wakeLock.released) return;
    try { job.wakeLock = await wl.request("screen"); } catch (e) { job.wakeLock = null; }
    if (job.finished) releaseWakeLock(job);   // finished while the request was pending
  }

  function releaseWakeLock(job) {
    var w = job.wakeLock;
    job.wakeLock = null;
    if (!w) return;
    try {
      var p = w.release();
      if (p && typeof p.catch === "function") p.catch(noop);
    } catch (e) { /* already released */ }
  }

  function addListeners(job) {
    job.onOnline = function () { if (job.wakeRetry) job.wakeRetry(); };
    job.onVisible = function () {
      if (typeof document !== "undefined" && document.visibilityState === "visible") {
        acquireWakeLock(job);
        if (job.wakeRetry) job.wakeRetry();
      }
    };
    try {
      window.addEventListener("online", job.onOnline);
      document.addEventListener("visibilitychange", job.onVisible);
    } catch (e) { /* no window or document: nothing to listen to */ }
  }

  function removeListeners(job) {
    try {
      if (job.onOnline) window.removeEventListener("online", job.onOnline);
      if (job.onVisible) document.removeEventListener("visibilitychange", job.onVisible);
    } catch (e) { /* see addListeners */ }
    job.onOnline = null;
    job.onVisible = null;
  }

  function cleanup(job) {
    removeListeners(job);
    releaseWakeLock(job);
    job.xhr = null;
    if (active === job) active = null;
  }

  function succeed(job, payload) {
    if (job.finished) return;
    job.finished = true;
    cleanup(job);
    var out = Object.assign({ id: job.id, name: job.file.name }, payload,
      { transcribeDefault: getTranscribeDefault() });
    if (out.duplicate !== true) out.duplicate = false;
    if (!out.id) out.id = job.id;
    job.progress = job.total;
    emit(job, "done", {
      message: out.duplicate ? "Already on the PC" : "Saved on this PC",
      done: job.total, result: out
    });
    try { job.onDone(out); } catch (e) { logErr(e); }
  }

  function fail(job, message) {
    if (job.finished) return;
    job.finished = true;
    cleanup(job);
    emit(job, "failed", { message: message });
    try { job.onError(message); } catch (e) { logErr(e); }
  }

  function cancelJob(job) {
    if (job.finished) return;
    job.cancelled = true;
    job.finished = true;
    var xhr = job.xhr;
    if (xhr) { try { xhr.abort(); } catch (e) { /* already settled */ } }
    if (job.breakSleep) job.breakSleep();
    if (job.confirmResolve) {
      var r = job.confirmResolve;
      job.confirmResolve = null;
      r(false);
    }
    cleanup(job);
    // No id yet means nothing was ever sent (cellular confirm declined, or still
    // fingerprinting), so there is nothing on the PC to drop.
    if (job.id) postAbort(job.id);
    emit(job, "cancelled", { message: "Cancelled" });
  }

  function confirmCellular(job) {
    return new Promise(function (resolve) {
      job.confirmResolve = resolve;
      emit(job, "confirm-cellular", {
        message: "Upload " + fmtBytes(job.total) + " over mobile data?",
        proceed: function () {
          var r = job.confirmResolve;
          job.confirmResolve = null;
          if (r) r(true);
        }
      });
    });
  }

  function serverText(json, r, status) {
    if (json && json.error) return String(json.error);
    var plain = (r && r.text) ? r.text.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 200) : "";
    return "HTTP " + status + (plain ? ": " + plain : "");
  }

  // One slice, one XMLHttpRequest. Resolves {status, text}; rejects on a network
  // error, a stall (no upload progress for STALL_MS), a missing reply (all bytes
  // sent, nothing back for RESPONSE_MS) or a cancel. upload.onprogress is the
  // reason this is an XHR and not fetch: it shows movement inside a slice on a
  // slow relay, which is the phone's normal path.
  function sendSlice(job, slice, offset, sha) {
    return new Promise(function (resolve, reject) {
      var xhr = new XMLHttpRequest();
      var end = offset + slice.size;
      var lastActivity = now(), sentAt = 0, reason = "", lastEmit = 0;
      var watchdog = null;
      job.xhr = xhr;
      function settle(fn, value) {
        if (watchdog) { clearInterval(watchdog); watchdog = null; }
        if (job.xhr === xhr) job.xhr = null;
        fn(value);
      }
      xhr.open("POST", "/api/upload", true);
      xhr.setRequestHeader("X-Filename", encodeURIComponent(job.file.name));
      xhr.setRequestHeader("X-Upload-Id", job.id);
      xhr.setRequestHeader("X-Upload-Offset", String(offset));
      xhr.setRequestHeader("X-Upload-Total", String(job.total));
      if (sha) xhr.setRequestHeader("X-Chunk-SHA256", sha);
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.upload.onprogress = function (ev) {
        lastActivity = now();
        var loaded = (ev && ev.lengthComputable) ? ev.loaded : 0;
        var done = Math.min(end, offset + loaded);
        job.progress = done;
        noteProgress(job, done);
        if (now() - lastEmit >= PROGRESS_EMIT_MS) {
          lastEmit = now();
          emitUploading(job, "Uploading");
        }
      };
      xhr.upload.onload = function () {
        sentAt = now();
        lastActivity = sentAt;
        job.progress = end;
        noteProgress(job, end);
        emitUploading(job, end >= job.total
          ? "All bytes sent, the PC is verifying the checksum"
          : "Waiting for the PC to confirm the slice");
      };
      xhr.onload = function () { settle(resolve, { status: xhr.status, text: xhr.responseText || "" }); };
      xhr.onerror = function () { settle(reject, new Error("network error")); };
      xhr.ontimeout = function () { settle(reject, new Error("timeout")); };
      xhr.onabort = function () {
        settle(reject, new Error(job.cancelled ? "cancelled" : (reason || "aborted")));
      };
      watchdog = setInterval(function () {
        var t = now();
        if (!sentAt && t - lastActivity > STALL_MS) {
          reason = "stalled";
          try { xhr.abort(); } catch (e) { /* already settled */ }
        } else if (sentAt && t - sentAt > RESPONSE_MS) {
          reason = "no response";
          try { xhr.abort(); } catch (e) { /* already settled */ }
        }
      }, 5000);
      try { xhr.send(slice); } catch (e) { settle(reject, e); }
    });
  }

  async function run(job) {
    await Promise.resolve();              // let start() return before the first callback
    if (job.finished) return;
    try {
      if (job.total <= 0) return fail(job, "The file is empty (0 bytes), nothing to upload.");

      if (isCellular()) {
        var go = await confirmCellular(job);
        if (!go || job.finished) return;  // cancel() already reported it
      }

      emit(job, "hashing", { message: "Fingerprinting " + job.file.name });
      try { job.id = await fingerprint(job.file); }
      catch (e) { return fail(job, readFailMessage(e)); }
      if (job.finished) return;

      acquireWakeLock(job);               // best effort, never awaited on the hot path

      var needSync = true, initial = true;
      while (!job.finished) {
        if (needSync) {
          var st;
          try { st = await getStatus(job.id); }
          catch (e) {
            if (job.finished) return;
            if (e.fatal) return fail(job, e.message);
            await retryWait(job, "Connection dropped");
            continue;
          }
          if (job.finished) return;
          needSync = false;
          if (st.done) return succeed(job, Object.assign({}, st, { duplicate: initial }));
          var have = clampInt(st.bytes, 0, job.total);
          initial = false;
          job.offset = have;
          job.progress = have;
          resetRate(job);
          emitUploading(job, have > 0 ? "Resuming from " + fmtBytes(have) : "Uploading");
        }

        var end = Math.min(job.offset + job.chunk, job.total);
        var slice = job.file.slice(job.offset, end);
        var sha = null;
        try { sha = await sha256Hex(await readBuffer(slice)); }
        catch (e) {
          if (job.finished) return;
          return fail(job, readFailMessage(e));
        }
        if (job.finished) return;

        var r;
        try { r = await sendSlice(job, slice, job.offset, sha); }
        catch (e) {
          if (job.finished) return;
          shrink(job);
          needSync = true;
          await retryWait(job, "Connection dropped");
          continue;
        }
        if (job.finished) return;

        var json = parseJson(r.text), s = r.status;

        if (s === 200 && json && json.ok === true) {
          job.attempt = 0;
          job.bad422 = 0;
          if (json.done === true) return succeed(job, Object.assign({}, json, { duplicate: false }));
          job.offset = (typeof json.bytes === "number") ? clampInt(json.bytes, 0, job.total) : end;
          job.progress = job.offset;
          grow(job);
          continue;
        }

        if (s === 409) {
          if (json && json.error === "chunk in flight") {
            emit(job, "retrying", { message: "The PC is still writing the previous slice, retrying in 2 s", retryIn: 2 });
            await sleep(job, IN_FLIGHT_WAIT_MS, false);
            if (job.finished) return;
          }
          if (json && typeof json.bytes === "number") {
            job.offset = clampInt(json.bytes, 0, job.total);
            job.progress = job.offset;
            resetRate(job);
          } else {
            needSync = true;
          }
          continue;
        }

        if (s === 422) {
          job.bad422 += 1;
          if (job.bad422 <= 2) {
            emit(job, "retrying", { message: "Slice failed its checksum on the PC, re-sending", retryIn: 0 });
          } else {
            needSync = true;              // keep hammering off the table; re-sync, then re-send
            await retryWait(job, "Slice keeps failing its checksum on the PC");
          }
          continue;
        }

        if (s === 401) return fail(job, SESSION_MSG);

        if (s === 507) {
          await countdownWait(job, "waiting-disk", "PC disk nearly full", DISK_FULL_WAIT_SECONDS, false);
          continue;                       // same slice, same offset
        }

        if (s === 413 || s === 400 || s === 403) return fail(job, serverText(json, r, s));

        // 5xx, any other status, or a 200 whose body is not JSON: a dropped connection.
        shrink(job);
        needSync = true;
        await retryWait(job, s >= 500 ? "The PC answered HTTP " + s
          : (s === 200 ? "Garbled reply from the PC" : "Connection dropped"));
      }
    } catch (e) {
      logErr(e);
      fail(job, "Upload failed: " + ((e && e.message) || String(e)));
    }
  }

  function start(file, opts) {
    opts = opts || {};
    var handle = { cancel: noop };
    var onError = typeof opts.onError === "function" ? opts.onError : noop;
    if (!file || typeof file.slice !== "function" || typeof file.size !== "number") {
      setTimeout(function () { onError("No file to upload."); }, 0);
      return handle;
    }
    if (active && !active.finished) {
      var busyName = active.file.name;
      setTimeout(function () { onError("Still uploading " + busyName); }, 0);
      return handle;
    }
    var job = {
      file: file, total: file.size, lane: opts.lane || "",
      onState: typeof opts.onState === "function" ? opts.onState : noop,
      onDone: typeof opts.onDone === "function" ? opts.onDone : noop,
      onError: onError,
      id: null, offset: 0, progress: 0,
      chunk: CHUNK_MAX, clean: 0, attempt: 0, bad422: 0,
      rate: 0, samples: [],
      xhr: null, wakeLock: null, breakSleep: null, wakeRetry: null, confirmResolve: null,
      finished: false, cancelled: false,
      handle: handle, onOnline: null, onVisible: null
    };
    handle.cancel = function () { cancelJob(job); };
    active = job;
    addListeners(job);
    run(job);
    return handle;
  }

  // ---------- public surface ----------

  window.MartyIntake = {
    start: start,
    saveNote: saveNote,
    transcribe: transcribe,
    pollStatus: pollStatus,
    fmtBytes: fmtBytes,
    fmtEta: fmtEta,
    fingerprint: fingerprint
  };

  // ---------- self-check: never runs on its own ----------
  // In a console: window.__MARTY_INTAKE_SELFTEST__ = true, then reload or re-run
  // this script. It exercises the pure helpers only; no request is made.
  if (typeof window !== "undefined" && window.__MARTY_INTAKE_SELFTEST__) {
    (function selfTest() {
      var checks = [
        ["fmtBytes(0)", fmtBytes(0), "0 B"],
        ["fmtBytes(1023)", fmtBytes(1023), "1023 B"],
        ["fmtBytes(1536)", fmtBytes(1536), "2 KB"],
        ["fmtBytes(8 MiB)", fmtBytes(8388608), "8.0 MB"],
        ["fmtBytes(1829997405)", fmtBytes(1829997405), "1.70 GB"],
        ["fmtBytes(NaN)", fmtBytes(NaN), "0 B"],
        ["fmtEta(3)", fmtEta(3), "a few seconds"],
        ["fmtEta(59)", fmtEta(59), "59 s"],
        ["fmtEta(120)", fmtEta(120), "2 min"],
        ["fmtEta(3700)", fmtEta(3700), "1 h 2 min"],
        ["fmtEta(90000)", fmtEta(90000), "1 d 1 h"],
        ["fmtEta(NaN)", fmtEta(NaN), ""],
        ["fmtEta(Infinity)", fmtEta(Infinity), ""],
        ["fmtEta(-1)", fmtEta(-1), ""],
        ["backoff first 9", JSON.stringify(backoffSequence(9)), "[1,2,4,8,16,30,30,30,30]"],
        ["backoff attempt 100", backoffSeconds(100), 30]
      ];
      var failed = 0;
      checks.forEach(function (c) {
        var ok = c[1] === c[2];
        if (!ok) failed += 1;
        console.log((ok ? "ok   " : "FAIL ") + c[0] + " -> " + JSON.stringify(c[1]) +
          (ok ? "" : " (expected " + JSON.stringify(c[2]) + ")"));
      });
      console.log("MartyIntake selftest: " + (checks.length - failed) + "/" + checks.length + " passed");
    })();
  }
})();
