/* Durable chat turns in the browser (2026-09-23), for the dashboard's chat pane.

   A message becomes a JOB on the server (dashboard/chatjobs.py). This file starts it,
   polls it, and draws it through the page's own renderers. Nothing here depends on the
   page staying open: reload, lock the phone or switch apps, and on the next load the
   conversation is fetched back from the server and a turn still running is picked up
   where it is. That is the fix for the replies that were lost when a phone dropped a
   long-running request (ConnectionAbortedError 10053, 19 times on the morning of
   2026-09-23).

   Two conversations, kept by id in memory and in localStorage: the cloud brains' thread
   (consoleKey) and the Local lane's thread (localKey). The server never sends a Local
   turn to a cloud brain; switching between the two swaps what the pane shows.
   newConversation() starts a fresh one for the lane on screen; the server archives the
   old one on the PC and refuses (409) while a reply is still being worked on.

   The page supplies ui: clear(), user(text) -> element, working(job) -> {update, done},
   reply(job), status(text), error(msg|null), busy(bool). */
(function () {
  const TERMINAL = ["completed", "failed", "interrupted"];
  const LOCAL_BRAINS = ["local"];

  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
  function newClientId() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return Date.now().toString(16) + "-" + Math.random().toString(16).slice(2, 12);
  }
  function isLocal(brain) { return LOCAL_BRAINS.indexOf(brain) !== -1; }

  async function api(url, opts) {
    // 20 s cap: a fetch that never settles (a phone that suspended the page) would
    // otherwise hold a watch, and the Send button, forever. The turn is safe on the server.
    const ctl = window.AbortController ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), 20000) : null;
    let res;
    try {
      res = await fetch(url, Object.assign({ cache: "no-store" }, ctl ? { signal: ctl.signal } : {}, opts || {}));
    } finally {
      if (timer) clearTimeout(timer);
    }
    let data = {};
    try { data = await res.json(); } catch (e) { /* non-JSON error page */ }
    return { ok: res.ok, status: res.status, data };
  }
  function post(url, body) {
    return api(url, { method: "POST", headers: { "Content-Type": "application/json" },
                      body: JSON.stringify(body || {}) });
  }
  // A request that keeps trying through a dropped connection or a "store busy" (503),
  // up to `tries` times. Other answers come back as they are.
  async function persistent(fn, tries) {
    let last = null;
    for (let i = 0; i < tries; i++) {
      try {
        last = await fn();
        if (last.status !== 503) return last;
      } catch (e) { last = null; }
      await sleep(800 * (i + 1));
    }
    return last;
  }

  // Plain-language line for a turn that did not simply complete.
  function statusNote(job) {
    switch (job.status) {
      case "failed": return "Failed: " + (job.error || "unknown error");
      case "interrupted":
        return "The dashboard restarted while this was running. Send the message again.";
      default: return "";
    }
  }

  function progressLine(job, who) {
    const secs = typeof job.elapsed_s === "number" ? Math.round(job.elapsed_s) + "s" : "";
    const tools = (job.tools || []).map((t) => t.tool + (t.finished ? "" : "…")).join(" · ");
    return who + " is working (" + (job.progress || "working") + (secs ? ", " + secs : "") + ")" +
           (tools ? " · " + tools : "");
  }

  function controller(o) {
    const ui = o.ui;
    let current = null;          // the job being watched
    let working = null;          // its "working" bubble
    let watchToken = 0;
    let loadToken = 0;
    const ids = {                // conversation ids (storage wins when readable)
      console: o.consoleKey ? lsGet(o.consoleKey) : null,
      local: o.localKey ? lsGet(o.localKey) : null,
    };
    let shownSession = null;     // the conversation the pane is drawing
    let wake = null;             // cuts the current poll wait short
    let loading = null;          // the load() in flight, as a promise; a send waits for it
    let acting = false;          // a send is on its way to the server

    function nap(ms) {
      return new Promise((resolve) => {
        const t = setTimeout(resolve, ms);
        wake = () => { clearTimeout(t); resolve(); };
      });
    }
    // Back in view (phone unlocked, app switched back): poll a running turn at once, or,
    // when idle, redraw the conversation in case another device changed it meanwhile.
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) return;
      if (current && wake) wake();
      else if (!current && !acting) load();   // never under a send still in flight
    });

    function kindOf(brain) { return isLocal(brain) ? "local" : "console"; }
    function keyOf(kind) { return kind === "local" ? o.localKey : o.consoleKey; }
    // Storage first, so two tabs on one phone share one thread; memory when storage is
    // unavailable (private browsing).
    function sessionFor(brain) {
      const kind = kindOf(brain);
      return (keyOf(kind) && lsGet(keyOf(kind))) || ids[kind];
    }
    function adopt(job) {
      if (!job || !job.session) return;
      const kind = kindOf(job.brain);
      ids[kind] = job.session;
      if (keyOf(kind)) lsSet(keyOf(kind), job.session);
    }
    function closeWorking() { if (working) { working.done(); working = null; } }

    async function watch(job) {
      const token = ++watchToken;
      closeWorking();
      current = job;
      ui.busy(true);
      working = ui.working(job);
      const w = working;
      let missing = 0;
      let lost = false;
      while (token === watchToken) {
        await nap(document.hidden ? 5000 : 1200);
        if (token !== watchToken) return;
        let r;
        try { r = await api("/api/chat/job?id=" + encodeURIComponent(job.id)); }
        catch (e) { lost = true; ui.status("Connection lost; still waiting for the server…"); continue; }
        if (token !== watchToken) return;          // a redraw took over while this poll was out
        if (r.status === 401) {
          w.done(); if (working === w) working = null;
          ui.error("Your login has expired. Reload the page and sign in; the reply is saved on the PC.");
          break;
        }
        if (r.status === 404) {
          // Brief 404s can be a store file caught mid-save; only a steady one is real.
          if (++missing < 4) continue;
          w.done(); if (working === w) working = null;
          ui.error("That turn is no longer on the server.");
          break;
        }
        missing = 0;
        if (!r.ok) continue;       // 503 (store busy) and the like: try again
        if (lost) { ui.status(""); lost = false; }   // clear only our own "connection lost" line
        job = r.data;
        current = job;
        if (TERMINAL.includes(job.status)) {
          w.done(); if (working === w) working = null;
          adopt(job);
          ui.reply(job);
          if (o.onReply) o.onReply(job);
          break;
        }
        w.update(job);
      }
      if (token === watchToken) { current = null; ui.busy(false); }
    }

    function threadUrl(brain) {
      const sid = sessionFor(brain);
      return "/api/chat/thread?brain=" + encodeURIComponent(brain)
             + (sid ? "&session=" + encodeURIComponent(sid) : "");
    }

    function load() {
      loading = doLoad().finally(() => { loading = null; });
      return loading;
    }

    async function doLoad() {
      const token = ++loadToken;
      watchToken++;               // stop watching whatever the last thread was running
      closeWorking();
      current = null;
      ui.busy(false);
      const r = await persistent(() => api(threadUrl(o.brain())), 3);
      if (token !== loadToken) return;
      if (!r) { ui.error("Could not load the conversation (server unreachable)."); return; }
      if (!r.ok) { ui.error(r.data.error || "Could not load the conversation (HTTP " + r.status + ")."); return; }
      ui.clear();
      ui.error(null);
      shownSession = r.data.session;
      let running = null;
      (r.data.turns || []).forEach((t) => {
        ui.user(t.message);
        if (t.id === r.data.running) running = t;
        else ui.reply(t);
      });
      if (running) watch(running);
    }

    async function send(message) {
      acting = true;
      try { return await doSend(message); } finally { acting = false; }
    }

    async function doSend(message) {
      ui.error(null);
      while (loading) await loading;   // let loads in flight finish first, so none can wipe this message
      const brain = o.brain();
      const body = { message, brain, async: true, client_id: newClientId(), session_id: sessionFor(brain) };
      const bubble = ui.user(message);
      ui.busy(true);
      // Same client_id on every retry: if an earlier POST did reach the server, this
      // returns that turn instead of starting a second one.
      const r = await persistent(() => post("/api/chat", body), 3);
      const unsent = () => { if (bubble && bubble.remove) bubble.remove(); ui.busy(false); };
      if (!r) {
        // Every attempt failed on our side, but the server may still have got one: look for
        // this message's client id in the conversation before calling it unsent.
        unsent();
        await load();
        let found = null;
        try {
          const t = await api(threadUrl(brain));
          if (t.ok) found = (t.data.turns || []).find((x) => x.client_id === body.client_id) || null;
        } catch (e) { /* still offline */ }
        if (found) return true;           // load() drew it (and is watching it if it runs)
        ui.error("Could not reach the dashboard server. Your message was not sent.");
        return false;
      }
      if (r.status === 401) { unsent(); ui.error("Your login has expired. Reload the page and sign in."); return false; }
      if (r.status === 409 && r.data.running) {
        unsent();
        await load();             // shows the turn still running
        ui.error("Still working on your last message. Wait for it to finish, then send again.");
        return false;
      }
      if (!r.ok || !r.data.job) { unsent(); ui.error("Error: " + (r.data.error || "HTTP " + r.status)); return false; }
      const job = r.data.job;
      adopt(job);                 // the thread's id is kept from the first moment
      if (shownSession && job.session !== shownSession) {
        // The server put this turn in a different conversation than the one on screen
        // (the stored one was gone or belonged to another lane): show that conversation.
        await load();
        return true;
      }
      shownSession = job.session;
      if (TERMINAL.includes(job.status)) { ui.reply(job); ui.busy(false); return true; }
      watch(job);
      return true;
    }

    // New conversation for the lane on screen. Returns true when the pane now shows it.
    async function newConversation() {
      if (current || acting) {
        ui.error("A reply is still being worked on. Wait for it to finish, then start a new conversation.");
        return false;
      }
      acting = true;
      try {
        ui.error(null);
        while (loading) await loading;
        const brain = o.brain();
        const r = await persistent(() => post("/api/chat/new", { brain, session_id: sessionFor(brain) }), 3);
        if (!r) { ui.error("Could not reach the dashboard server. The conversation was not changed."); return false; }
        if (r.status === 401) { ui.error("Your login has expired. Reload the page and sign in."); return false; }
        if (r.status === 409) {
          await load();          // shows the reply still being worked on
          ui.error("A reply is still being worked on. Wait for it to finish, then start a new conversation.");
          return false;
        }
        if (!r.ok || !r.data.session) { ui.error("Error: " + (r.data.error || "HTTP " + r.status)); return false; }
        const kind = kindOf(brain);
        ids[kind] = r.data.session;
        if (keyOf(kind)) lsSet(keyOf(kind), r.data.session);
      } finally {
        acting = false;
      }
      await load();
      return true;
    }

    return { load, send, newConversation, isBusy: () => !!current };
  }

  window.MartyChat = { controller, statusNote, progressLine, TERMINAL, lsGet, lsSet };
})();
