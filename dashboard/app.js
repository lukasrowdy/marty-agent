/* Marty app shell (MJ Dashboard Phase 1).
   Public file: it is served before login, so it carries no personal text, no local
   paths and no token. Everything personal arrives from /api after the device login. */
(() => {
  "use strict";

  // QR enrollment runs first. The enrollment QR opens /#token=..., and a fragment never
  // reaches the server. Scrub it from the address bar and history before anything else,
  // then log in with it through POST /api/session, as the server's own login page does.
  // A fragment-only change on an open tab does not reload the page, so hashchange below
  // applies the same scrub-then-login.
  function takeTokenFromHash() {
    const hash = location.hash || "";
    if (hash.indexOf("token=") === -1) return null;
    try { history.replaceState(null, "", location.pathname + location.search); } catch (_) { location.hash = ""; }
    const match = /(?:^#|[#&])token=([A-Za-z0-9_-]{20,})/.exec(hash);
    return match ? match[1] : null;
  }
  const qrToken = takeTokenFromHash();

  const $ = id => document.getElementById(id);
  const VIEWS = ["talk", "chat", "jobs", "files", "more", "jr"];
  const TITLES = {talk: "Talk", chat: "Chat", jobs: "Jobs", files: "Files", more: "More", jr: "Marty Jr."};
  const LANES = {claude_sub: "Claude Max · $0", claude_sub_tools: "Max + tools · $0", codex_sub: "Codex · $0",
                 claude: "Claude tools · metered", gemini: "Gemini · metered", openrouter: "OpenRouter · metered",
                 local: "Local · $0"};
  const SPEND_NAMES = {claude: "Claude tools", claude_sub: "Claude Max", codex_sub: "Codex", gemini: "Gemini",
                       openrouter: "OpenRouter", ollama: "Local", grok: "Grok"};
  const MEDIA_EXTS = [".mp4", ".mov", ".mkv", ".webm", ".avi", ".m4v",
                      ".mp3", ".m4a", ".wav", ".aac", ".flac", ".ogg", ".opus"];
  const EMPTY_CHAT = '<div class="empty"><span class="mini-orb"></span><h2>What are we working on?</h2></div>';
  const state = {view: "talk", lane: "claude_sub_tools", job: null, source: null, recorder: null, chunks: [],
                 pressAt: 0, handsFree: false, more: "status", entered: false, upload: null, transcriptPoll: null};
  // Text handed from Marty Jr. to Marty's composer (W4): what was last checked against the
  // never-send list, what matched, and whether the SERVER said that text is clear (cleared is
  // true only on its ok:true; this page does no matching of its own). In memory only, like
  // everything else about Jr.
  const handoff = {active: false, checking: false, error: "", hits: [], cleared: false, checkedText: null, seq: 0, timer: null};
  // Hashes (not the text) of every line of Jr text handed over in this page, so text that comes
  // back into the composer (paste, undo after Clear) is checked again instead of slipping past.
  const handoffSeen = new Set();
  function lineHash(line) {
    let h = 0x811c9dc5;
    for (let i = 0; i < line.length; i++) { h ^= line.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return h;
  }
  const lineHashes = text => text.split("\n").map(line => line.trim()).filter(line => line.length >= 12).map(lineHash);

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function lsGet(key) { try { return localStorage.getItem(key); } catch (_) { return null; } }
  function lsSet(key, value) { try { if (value == null) localStorage.removeItem(key); else localStorage.setItem(key, value); } catch (_) {} }
  const sessionKey = () => state.lane === "full" ? "mj.thread.full"
    : state.lane === "local" ? "mj.thread.local" : "mj.thread.console";

  // A device login ends on the server after 30 days without use, or 90 days after it was made
  // (dashboard_auth.py, 2026-09-26). Its 401 then carries "expired": "idle" or "age", and the
  // app goes back to the lock screen and says why instead of failing request by request.
  const ENDED = {idle: "This device's sign-in ended after 30 days without use.",
                 age: "This device's sign-in reached its 90-day limit."};
  const SIGN_IN_AGAIN = " Sign in with your passkey, or scan a new QR code from the PC.";
  function signedOut(data) {
    const why = data && ENDED[data.expired];
    if (!$("lock").hidden) return;                   // already on the lock screen: keep what it says
    if (!state.entered && !why) return;              // a first visit: boot shows the plain lock screen
    showLogin(true); showPasskeyLogin();
    $("loginError").textContent = why ? why + SIGN_IN_AGAIN : "Signed out on this device. Sign in again to continue.";
  }

  async function request(url, options = {}) {
    const response = await fetch(url, Object.assign({cache: "no-store", credentials: "same-origin"}, options));
    let data = null;
    if (response.status !== 204) { try { data = await response.json(); } catch (_) {} }
    if (!response.ok) {
      // Any data route answering 401 means this device is signed out (ended, revoked, logged out
      // elsewhere). The sign-in routes answer 401/403 for a refused attempt, and keep their own text.
      if (response.status === 401 && !/^\/api\/(session|passkey\/)/.test(url)) signedOut(data);
      const error = new Error((data && data.error) || `Request failed (${response.status})`);
      error.status = response.status;
      error.data = data;
      throw error;
    }
    return data;
  }

  // ---------- login and boot ----------

  function showLogin(show) { $("lock").hidden = !show; $("app").hidden = show; }

  function login(token) {
    return request("/api/session", {method: "POST", headers: {"Content-Type": "application/json"},
                                    body: JSON.stringify({token})});
  }

  function enterApp() {
    showLogin(false);
    activateView(state.view);
    if (state.entered) return;
    state.entered = true;
    if (state.startNew) {                              // the New chat shortcut
      state.startNew = false;
      newMartyChat().then(started => { if (!started) loadThread(); });   // a reply still running: show it instead
    } else loadThread();
    refreshJobs(); refreshFiles(); fullStatus();
    setInterval(() => { if (!document.hidden) refreshJobs(); }, 15000);
    setInterval(() => { if (!document.hidden && state.view === "more") refreshMore(); }, 15000);
  }

  function registerWorker() {
    if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js", {updateViaCache: "none"}).catch(() => {});
  }

  async function boot() {
    const params = new URLSearchParams(location.search);
    // The installed app's "Marty Jr." shortcut opens /?view=more&lane=jr; it and ?view=jr both land on Jr.
    const wanted = params.get("lane") === "jr" ? "jr" : params.get("view");
    state.view = VIEWS.includes(wanted) ? wanted : "talk";
    // The installed app's "New chat" shortcut opens /?view=chat&new=1 (#new works too): start a
    // fresh Marty conversation once the app is open. The marker leaves the address at once, so a
    // reload or the back button never starts another one.
    if (params.get("new") === "1" || /^#new(=1)?$/.test(location.hash || "")) {
      state.view = "chat";
      state.startNew = true;
      try { history.replaceState(null, "", "/?view=chat"); } catch (_) {}
    }
    let qrError = "";
    if (qrToken) {
      try { await login(qrToken); } catch (error) { qrError = error.message || "That sign-in link was not accepted."; }
    }
    try { await request("/api/jobs"); enterApp(); }
    catch (error) {
      if (error.status === 401) { showLogin(true); showPasskeyLogin(); if (qrError) $("loginError").textContent = qrError; }
      else { enterApp(); setCaption("Marty", error.message); }
    }
    registerWorker();
  }

  window.addEventListener("hashchange", async () => {
    const token = takeTokenFromHash();
    if (!token) return;
    try { await login(token); $("loginError").textContent = ""; enterApp(); }
    catch (error) { showLogin(true); $("loginError").textContent = error.message; }
  });

  $("loginForm").addEventListener("submit", async event => {
    event.preventDefault();
    $("loginError").textContent = "Checking...";
    try { await login($("token").value.trim()); $("token").value = ""; $("loginError").textContent = ""; enterApp(); }
    catch (error) { $("loginError").textContent = error.message; }
  });

  // ---------- views and lanes ----------

  function activateView(name) {
    if (!VIEWS.includes(name)) name = "talk";
    if (name !== "jr") jrMicLeave();                   // never record for Jr from another view
    if (name !== "chat") chatMicLeave();               // dictation stops, and what was said still lands
    state.view = name;
    $("viewTitle").textContent = TITLES[name];
    document.querySelectorAll(".view").forEach(view => view.classList.toggle("active", view.id === name + "View"));
    document.querySelectorAll(".bottom-nav [data-view]").forEach(button => button.classList.toggle("active", button.dataset.view === name));
    $("app").classList.toggle("jr-mode", name === "jr");
    if (name === "jobs") refreshLive();                 // the Live line updates the moment Jobs opens
    $("personaMarty").classList.toggle("active", name !== "jr");
    $("personaJr").classList.toggle("active", name === "jr");
    try { history.replaceState(null, "", `/?view=${name}`); } catch (_) {}
    if (name === "jr") jrEnter();
    if (name === "jobs") refreshJobs();
    if (name === "files") refreshFiles();
    if (name === "more") { refreshMore(); refreshPasskeys(); }
  }

  document.addEventListener("click", event => {
    const view = event.target.closest("[data-view]");
    if (view) { activateView(view.dataset.view); if (view.dataset.open) showMore(view.dataset.open); return; }
    const prompt = event.target.closest("[data-prompt]");
    if (prompt) { sendChat(prompt.dataset.prompt, true); return; }
    const more = event.target.closest("[data-more]");
    if (more) showMore(more.dataset.more);
  });

  // One lane at a time, switched from the left pane on a wide screen or from the lane pill
  // (a native picker) at every width. Never while a reply is running.
  function setLane(name) {
    if (!LANES[name] || state.job || (name === "full" && !full.unlocked)) { $("laneSelect").value = state.lane; return false; }
    state.lane = name;
    document.querySelectorAll("#lanes [data-lane]").forEach(button => button.classList.toggle("active", button.dataset.lane === name));
    $("laneLabel").textContent = LANES[name];
    $("laneSelect").value = name;
    fullRenderBar();
    loadThread();
    return true;
  }
  $("lanes").addEventListener("click", event => {
    const button = event.target.closest("[data-lane]");
    if (button) setLane(button.dataset.lane);
  });
  $("laneSelect").addEventListener("change", () => setLane($("laneSelect").value));

  // ---------- chat ----------

  function setCaption(who, text) {
    $("captions").innerHTML = "";
    const p = el("p"), b = el("b", "", who);
    p.append(b, document.createTextNode(text));
    $("captions").append(p);
    $("captions").scrollTop = $("captions").scrollHeight;   // a long spoken reply shows its newest words
  }

  function addMessage(role, text, stateText = "") {
    const empty = $("messages").querySelector(".empty");
    if (empty) empty.remove();
    const div = el("div", `message ${role}`);
    if (stateText) div.append(el("span", "state", stateText));
    div.append(el("span", "body", text));
    $("messages").append(div);
    $("messages").scrollTop = $("messages").scrollHeight;
    return div;
  }

  // Steps in a reply (Lukas picked "Both", 2026-09-26): one small line per tool call the reply made,
  // live while it works ("Searching the vault"), and from the saved turn after a reload. The server
  // sends a plain label only; a tool's inputs and results never reach the page.
  const TOOL_LABELS = {read_file: "Reading a file", list_dir: "Looking in a folder", search_notes: "Searching the notes",
    search_vault: "Searching the vault", see_image: "Looking at an image", transcribe_media: "Transcribing audio or video",
    see_video_frame: "Looking at a video frame", avatar_roster: "Checking the avatar roster", avatar_cost: "Checking an avatar price",
    recon_lookup: "Looking up an address", recon_probe: "Checking a web server", web_fetch: "Reading a web page"};
  const stepText = name => { const n = String(name || ""); return TOOL_LABELS[n.split("__").pop()] || n || "Working"; };
  // A saved step that did not work. The Max lane saves "error"; the metered Claude lane saves "REFUSED"
  // or "ERROR" (marty_tools), which the old === "error" test missed, so those never turned red.
  const stepFailed = tool => /^(error|refused)$/i.test(String((tool && tool.verdict) || ""));
  // Steps from a saved turn: drawn in full when the bubble has none (a reload, or a reply whose live steps
  // never arrived), otherwise only reconciled, so a step the saved turn says failed is red.
  function drawSavedSteps(div, tools) {
    if (!div || !Array.isArray(tools) || !tools.length) return;
    const fresh = !(div._stepRows && div._stepRows.length);
    tools.forEach((tool, i) => {
      if (fresh) addStep(div, tool.tool, false, i + 1);
      if (stepFailed(tool) && div._stepRows && div._stepRows[i]) div._stepRows[i].classList.add("error");
    });
  }
  // n is the step's number in the reply (1-based); an error names the step that failed, so with several
  // calls in flight the right line turns red.
  function addStep(div, label, error, n) {
    if (!div) return;
    div._stepRows = div._stepRows || [];
    if (error && n && div._stepRows[n - 1]) { div._stepRows[n - 1].classList.add("error"); return; }
    let list = div.querySelector(".steps");
    if (!list) { list = el("div", "steps"); div.insertBefore(list, div.querySelector(".body")); }
    const text = stepText(label);
    const last = list.lastElementChild;
    if (last && last.dataset.label === text && !error) {
      const count = Number(last.dataset.count || 1) + 1;
      last.dataset.count = String(count);
      last.querySelector(".step-n").textContent = ` ×${count}`;
      if (n) div._stepRows[n - 1] = last;
      return;
    }
    const row = el("div", "step" + (error ? " error" : ""));
    row.dataset.label = text;
    row.append(el("span", "step-dot"), el("span", "step-text", text), el("span", "step-n", ""));
    list.append(row);
    if (n) div._stepRows[n - 1] = row;
  }

  // A reply that grows while it streams keeps the chat on its newest line, so it never runs on
  // out of sight behind the message box and the tabs; unless Lukas has scrolled up to read.
  function followChat(update) {
    const box = $("messages");
    const pinned = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    update();
    if (pinned) box.scrollTop = box.scrollHeight;
  }

  // ---------- Teach Jr ----------
  // A small button on Marty's answers (the two Claude lanes) that saves the answer into Marty
  // Jr.'s plaintext library via POST /api/jr/teach. Memory is retrieval, not retraining: the
  // saved note is searchable by Jr straight away. Nothing is ever saved without this click.
  const TEACH_LANES = new Set(["claude", "claude_sub", "claude_sub_tools"]);

  // Phase 1 auto-suggest heuristic: an answer worth offering to save is long enough AND has more
  // than one sentence. HOOK: a future model-judged "worth teaching" flag would plug in here,
  // e.g.  return modelFlag === true || (long && multiSentence);  -- for now it is length + shape.
  function teachWorthSuggesting(text) {
    const trimmed = (text || "").trim();
    const long = trimmed.length > 400;
    const multiSentence = (trimmed.match(/[.!?](\s|$)/g) || []).length >= 2;
    return long && multiSentence;
  }

  // The user's question for an assistant message: the nearest preceding user bubble's text. Sent
  // as `context` so the saved note carries provenance ("from: <question>").
  function questionFor(div) {
    let node = div && div.previousElementSibling;
    while (node) {
      if (node.classList && node.classList.contains("user")) {
        const body = node.querySelector(".body");
        return body ? body.textContent : node.textContent;
      }
      node = node.previousElementSibling;
    }
    return "";
  }

  function maybeTeachButton(div, text) {
    if (!div || !TEACH_LANES.has(state.lane)) return;
    text = (text || "").trim();
    if (text.length < 40) return;                 // too slight to be worth saving
    if (div.querySelector(".teach-jr")) return;   // already offered on this bubble
    const btn = el("button", "teach-jr", "Teach Jr");
    if (teachWorthSuggesting(text)) { btn.classList.add("suggested"); btn.textContent = "Teach Jr?"; }
    btn.addEventListener("click", () => teachJr(btn, text, questionFor(div)));
    div.append(btn);
  }

  async function teachJr(btn, text, question) {
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = "Saving to Jr...";
    try {
      const data = await request("/api/jr/teach", {method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({text, context: question || ""})});
      btn.classList.remove("suggested");
      btn.classList.add("taught");
      btn.textContent = data && data.title ? `Taught Jr: ${data.title}` : "Taught Jr";
    } catch (error) {
      btn.disabled = false;
      btn.textContent = original;
      const note = el("span", "teach-error", error.message || "Could not teach Jr");
      btn.after(note);
      setTimeout(() => note.remove(), 4000);
    }
  }

  // fromJr: the text came from Marty Jr. ("Ask Marty about this"). The request says so, and the
  // server checks the exact text against his never-send list again before anything is sent.
  async function sendChat(text, fromTalk = false, fromJr = false) {
    text = (text || "").trim();
    if (!text || state.job) return;
    if (state.lane === "full") {                       // Full Marty: its cards live in the chat view
      if (fromJr) { setCaption("Marty", "Text from Marty Jr. can't be sent to Full Marty."); return; }
      activateView("chat");
      addMessage("user", text);
      fullSend(text, fromTalk);
      return;
    }
    activateView(fromTalk ? "talk" : "chat");
    const mine = addMessage("user", text);
    if (fromTalk) setCaption("You", text);
    const reply = addMessage("assistant", "", "starting");
    state.job = {reply, id: null};
    $("cancel").hidden = false; updateSend(); $("orb").classList.add("thinking");
    try {
      const body = {lane: state.lane, text, thread_id: lsGet(sessionKey()),
                    client_id: (crypto.randomUUID ? crypto.randomUUID() : Date.now() + "-client")};
      if (fromJr) body.handoff = true;
      const payload = await request("/api/chat/job", {method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body)});
      state.job.id = payload.job_id;
      lsSet(sessionKey(), payload.thread_id);
      streamJob(payload.job_id, reply, fromTalk);
    } catch (error) {
      reply.querySelector(".state").textContent = "failed";
      reply.querySelector(".body").textContent = error.message;
      if (fromJr && error.status) handoffRefused(error, text, mine, reply);
      finishJob();
    }
  }

  // A reply a lane stopped short (it timed out, or its program had to be stopped): the text it got
  // to is kept, labelled incomplete, with the reason under it. Never shown as a finished reply.
  const incompleteLabel = reason => reason === "timeout" ? "timed out · incomplete" : "stopped · incomplete";
  function markIncomplete(div, error) {
    div.querySelectorAll(".incomplete-note").forEach(node => node.remove());
    div.append(el("span", "incomplete-note", error || "This reply is incomplete."));
  }

  function streamJob(id, reply, fromTalk) {
    const source = new EventSource(`/api/chat/stream/${id}`);
    state.source = source;
    // The last real state, so a stream that reconnects can put it back: "reconnecting" used to
    // stick after a successful Last-Event-ID resume until the next event, which during a long
    // tool run could be minutes.
    let label = reply.querySelector(".state").textContent || "starting";
    if (label === "reconnecting") label = "thinking";
    const setState = text => { if (text !== "reconnecting") label = text; reply.querySelector(".state").textContent = text; };
    source.addEventListener("state", event => { const data = JSON.parse(event.data); setState(data.state || "thinking"); });
    source.addEventListener("step", event => {
      let data = {};
      try { data = JSON.parse(event.data) || {}; } catch (_) {}
      setState("working");
      followChat(() => addStep(reply, data.label, !!data.error, Number(data.n) || 0));
    });
    source.addEventListener("delta", event => {
      const data = JSON.parse(event.data);
      setState("replying");
      followChat(() => { reply.querySelector(".body").textContent += data.text || ""; });
      if (fromTalk) setCaption("Marty", reply.querySelector(".body").textContent);
    });
    source.addEventListener("done", event => {
      const data = JSON.parse(event.data);
      // The saved reply is authoritative: after a resumed stream the server may resend it whole.
      followChat(() => {
        if (data.reply) reply.querySelector(".body").textContent = data.reply;
        drawSavedSteps(reply, data.tools);
        setState(data.status === "cancelled" ? "cancelled" : "done");
        if (data.status !== "cancelled") maybeTeachButton(reply, reply.querySelector(".body").textContent);
      });
      if (fromTalk && data.reply) setCaption("Marty", data.reply);
      source.close(); finishJob(); refreshJobs();
    });
    let drops = 0;
    source.addEventListener("open", () => {
      drops = 0;
      if (reply.querySelector(".state").textContent === "reconnecting") setState(label);   // back on the stream
    });
    source.addEventListener("error", event => {
      if (event.data) {
        // A real error the server sent for this turn. A lane that timed out or was stopped after
        // streaming part of a reply sends that text as reply: it stays, marked incomplete.
        let data = {};
        try { data = JSON.parse(event.data) || {}; } catch (_) {}
        const partial = typeof data.reply === "string" && data.reply.trim() ? data.reply : "";
        followChat(() => {
          if (partial) { reply.querySelector(".body").textContent = partial; markIncomplete(reply, data.error); }
          else reply.querySelector(".body").textContent = data.error || "Reply failed.";
        });
        setState(partial ? incompleteLabel(data.stop_reason) : "failed");
        source.close(); finishJob();
        return;
      }
      // The connection dropped (phone locked, network blip). The turn keeps running on the PC.
      // The browser reconnects by itself and resumes after the last event it saw (Last-Event-ID).
      setState("reconnecting");
      if (source.readyState === EventSource.CLOSED || ++drops > 8) {
        // It can't resume (server restarted, login expired): reload the saved conversation,
        // which re-attaches if the turn is still running or shows the saved reply.
        source.close();
        if (state.source === source) { finishJob(); setTimeout(loadThread, 1500); }
      }
    });
  }

  // Coming back to the app after the phone was locked: if the stream gave up, pick the thread back up.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && state.source && state.source.readyState === EventSource.CLOSED) {
      state.source.close(); finishJob(); loadThread();
    }
  });

  function finishJob() {
    state.job = null; state.source = null;
    $("cancel").hidden = true; updateSend(); $("orb").classList.remove("thinking");
  }

  // Send is off while a reply runs, and while text that came from Marty Jr. has not passed his
  // never-send check in its current form (see the handoff section below).
  function updateSend() { $("send").disabled = !!state.job || handoffBlocked(); }

  // The composer grows with its text (up to the CSS max-height), so an appended upload line is visible.
  // Every programmatic change calls this too, so it is also where a Jr handoff hears about edits.
  function fitComposer() {
    const box = $("message");
    box.style.height = "auto";
    box.style.height = Math.min(160, box.scrollHeight) + "px";
    if (handoff.active) handoffEdited();
    else if (handoffSeen.size && lineHashes(box.value).some(h => handoffSeen.has(h))) {
      Object.assign(handoff, {active: true, checking: false, error: "", hits: [], cleared: false, checkedText: null});
      handoffEdited();                                  // Jr's words are back: check them again
    }
  }
  $("message").addEventListener("input", fitComposer);
  $("composer").addEventListener("submit", event => {
    event.preventDefault();
    if (state.job) return;                             // keep the text while a reply runs (Enter still submits)
    if (handoffBlocked()) {
      // Never sent unchecked: re-check if the text changed since the last check, and wait.
      if (!handoff.checking && handoff.checkedText !== $("message").value) handoffCheck();
      return;
    }
    const text = $("message").value;
    if (!text.trim()) return;                          // nothing to send; a handoff stays open
    const fromJr = handoff.active;                     // marks the request so the server re-checks it
    $("message").value = "";
    handoffEnd();
    fitComposer();
    sendChat(text, false, fromJr);
  });
  $("message").addEventListener("keydown", event => {
    if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); $("composer").requestSubmit(); }
  });
  $("cancel").addEventListener("click", async () => {
    if (!state.job || !state.job.id) return;
    if (state.lane === "full") {
      try { await fullRequest("/api/full/stop", {method: "POST", headers: fullHeaders(), body: JSON.stringify({conv: full.conv})}); } catch (_) {}
      return;
    }
    try { await request(`/api/chat/cancel/${state.job.id}`, {method: "POST"}); } catch (_) {}
  });
  // A fresh Marty conversation for the current lane (the + button and the New chat shortcut).
  // True when one was started; false while a reply runs, or when the server said no.
  async function newMartyChat() {
    if (state.job) return false;
    try {
      const data = await request("/api/chat/new", {method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({brain: state.lane, session_id: lsGet(sessionKey())})});
      lsSet(sessionKey(), data.session);
      $("messages").innerHTML = EMPTY_CHAT;
      activateView("chat");
      return true;
    } catch (error) { setCaption("Marty", error.message); return false; }
  }
  $("newChat").addEventListener("click", () => {
    if (state.view === "jr") { jrNewThread(); return; }   // in Jr's view the top bar's + starts a new Jr conversation
    newMartyChat();
  });

  async function loadThread() {
    $("laneLabel").textContent = LANES[state.lane];
    if (state.lane === "full") { fullRenderBar(); try { await fullLoad(); } catch (_) {} return; }
    const sid = lsGet(sessionKey());
    // No conversation yet for this lane's kind: show an empty pane, never the other kind's turns.
    if (!sid) { $("messages").innerHTML = EMPTY_CHAT; return; }
    try {
      const data = await request(`/api/chat/thread?brain=${encodeURIComponent(state.lane)}&session=${encodeURIComponent(sid)}`);
      const turns = data.turns || [];
      $("messages").innerHTML = "";
      turns.forEach(turn => {
        if (turn.id === data.running) return;
        addMessage("user", turn.message);
        const partial = turn.status === "failed" && !!turn.reply;          // stopped short: text kept
        const div = addMessage("assistant", turn.reply || turn.error || "", partial ? incompleteLabel(turn.stop_reason) : turn.status);
        drawSavedSteps(div, turn.tools);
        if (partial) markIncomplete(div, turn.error);
        else if (turn.status === "done" && turn.reply) maybeTeachButton(div, turn.reply);
      });
      if (!turns.length) $("messages").innerHTML = EMPTY_CHAT;
      if (data.running) {
        const running = turns.find(turn => turn.id === data.running);
        if (running) addMessage("user", running.message);
        const reply = addMessage("assistant", "", "reconnecting");
        state.job = {id: data.running, reply};
        $("cancel").hidden = false; updateSend();
        streamJob(data.running, reply, false);
      }
    } catch (_) {}
  }

  // ---------- Marty Jr. (Phase 2: W2 lane, W3 lock, W4 handoff) ----------
  // His own lane: /api/jr/*, answered by a model on this PC. Kept apart from Marty's chat on
  // purpose: separate state, separate composer, and NOTHING Jr-related goes into localStorage
  // or sessionStorage: not a thread id, not the passphrase, not the never-send list. It lives in
  // this closure and is gone on reload; the server keeps his history encrypted (W3).
  // The lock: every /api/jr route answers 423 until THIS device types the passphrase. The page
  // shows the lock screen on a 423, after 15 idle minutes, and when it goes to the background;
  // then it wipes Jr's text from the page and (background, Lock button) tells the server to lock.
  const jr = {thread: null, job: null, source: null, entered: false, unlocked: false, lockMode: "unlock",
              idleTimer: null};
  // Jr's microphone (W3 voice; see "Jr's microphone" below). gen changes on every reset, so an
  // answer that arrives after a lock can tell it is stale and is dropped.
  const jrMic = {phase: "idle", recorder: null, stream: null, chunks: [], gen: 0, controller: null, timer: null};
  const JR_IDLE_MS = 15 * 60 * 1000;
  const JR_EMPTY = '<div class="empty jr-empty"><span class="mini-orb"></span><h2>Marty Jr.</h2>' +
    '<p class="muted">Jr works inside his separate VM. Review his plan, approve up to five actions, then he freezes and checks in. Emergency stop removes VM power. Lock ends the session. Each session expires after 15 minutes.</p></div>';
  const JR_NOTICES = {
    index_rebuilt: "Jr's conversation index was damaged, so it was rebuilt from the conversations themselves.",
    unreadable_threads: "Some of Jr's conversation files could not be read (damaged or altered). They were left as they are.",
    turns_waiting: "A reply that finished while Jr was locked could not be saved yet. It is kept until the next unlock.",
    turn_dropped: "A reply that finished while Jr was locked could not be saved.",
  };

  // Every Jr call goes through here: a 423 shows the lock screen, and a success counts as use.
  async function jrRequest(url, options) {
    try {
      const data = await request(url, options);
      jrTouch();
      return data;
    } catch (error) {
      if (error.status === 423) jrShowLock(error.data && error.data.needs_setup ? "setup" : "unlock");
      throw error;
    }
  }
  const jrPost = (url, body, method = "POST") =>
    jrRequest(url, {method, headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});

  let jrCloudPending = null, jrCloudAdvice = "";
  function jrCloudReset() {
    jrCloudPending = null; jrCloudAdvice = "";
    $("jrCloudText").value = "";
    $("jrCloudPreview").textContent = ""; $("jrCloudPreview").hidden = true;
    $("jrCloudAnswer").textContent = ""; $("jrCloudAnswer").hidden = true;
    $("jrCloudSend").hidden = true; $("jrCloudUse").hidden = true;
    $("jrCloudStatus").textContent = "Large-model tap off until provider connection is checked.";
  }
  async function jrCloudStatus() {
    if (!jr.unlocked) return;
    try {
      const s = await jrRequest("/api/jr/cloud/status");
      $("jrCloudStatus").textContent = s.configured
        ? "Connected: " + s.model + ". Review the exact text before each paid call."
        : "Off: no Abliteration.ai key is connected. Nothing can be sent.";
      $("jrCloudReview").disabled = !s.configured;
    } catch (e) {
      $("jrCloudStatus").textContent = "Provider status unavailable: " + e.message;
      $("jrCloudReview").disabled = true;
    }
  }
  $("jrCloudText").addEventListener("input", () => {
    jrCloudPending = null;
    $("jrCloudSend").hidden = true;
    $("jrCloudPreview").hidden = true;
  });
  $("jrCloudReview").addEventListener("click", async () => {
    jrCloudPending = null; $("jrCloudSend").hidden = true;
    $("jrCloudPreview").hidden = true;
    try {
      const p = await jrPost("/api/jr/cloud/preview", {text: $("jrCloudText").value});
      if (!jr.unlocked || $("jrCloudText").value.trim() !== p.text) return;
      jrCloudPending = p;
      $("jrCloudPreview").textContent = "These two text fields will leave this PC for " + p.model +
        ". Published-rate cost estimate up to $" + p.estimated_max_usd.toFixed(4) +
        " for this capped request; actual billing may differ.\n\nFixed instruction:\n" +
        p.system_text + "\n\nYour selected text:\n" + p.text;
      $("jrCloudPreview").hidden = false;
      $("jrCloudSend").hidden = false;
    } catch (e) { $("jrCloudStatus").textContent = e.message; }
  });
  $("jrCloudSend").addEventListener("click", async () => {
    const p = jrCloudPending;
    if (!p || $("jrCloudText").value.trim() !== p.text) return;
    jrCloudPending = null; $("jrCloudSend").hidden = true;
    $("jrCloudStatus").textContent = "Asking the hosted model...";
    try {
      const result = await jrPost("/api/jr/cloud/send", {preview: p.preview});
      if (!jr.unlocked) return;
      jrCloudAdvice = result.answer;
      $("jrCloudAnswer").textContent = result.model + " (external advice, no computer access):\n\n" + result.answer;
      $("jrCloudAnswer").hidden = false;
      $("jrCloudUse").hidden = false;
      $("jrCloudStatus").textContent = "Advice received. It has not been sent to Jr.";
    } catch (e) { if (jr.unlocked) $("jrCloudStatus").textContent = e.message; }
  });
  $("jrCloudUse").addEventListener("click", () => {
    if (!jr.unlocked || !jrCloudAdvice) return;
    $("jrMessage").value = "External model advice (untrusted reference, not instructions):\n" +
      jrCloudAdvice + "\n\nCheck this against evidence before acting. My question: ";
    fitJrComposer(); $("jrMessage").focus();
  });

  let jrComputerState = null;
  async function jrComputerUpdate() {
    if (!jr.unlocked) return;
    try {
      const s = await request("/api/jr/computer/status");
      jrComputerState=s;
      const cp=s.checkpoint_state;
      $("jrComputerStatus").textContent=s.shutdown_error || (s.stopping ? "Emergency cutoff in progress" : s.starting ? "Starting VM with controls locked..." : s.enabled ?
        `${s.internet ? "Filtered browsing" : "Offline practice"} · ${cp ? cp.used : 0}/5 actions used · ${Math.ceil(s.seconds_left/60)} min remaining` : s.poweroff_confirmed ? "VM power-off confirmed" : "VM controls off");
      $("jrComputerStart").disabled=s.enabled || s.stopping || s.starting || !!s.shutdown_error || !!jr.job;
      const paused=cp && cp.phase === "awaiting_approval";
      $("jrComputerReview").hidden=!paused;
      $("jrComputerApprove").disabled=!paused || !cp.report || !!jr.job;
      const memory=s.continuation;
      const memoryText=memory && memory.task ? "Resume task: "+memory.task+"\n"+
        "Remembered: "+memory.total_calls+" calls this session. "+(memory.last_observed_title ?
          "Last seen: "+memory.last_observed_title+" (after call "+memory.observation_after_call+"). ":"No screen observed yet. ")+
        (memory.needs_observation ? "A fresh look is needed to verify the result.":"Last screen evidence retained.")+"\n\n" : "";
      $("jrComputerReport").textContent=paused && cp.report ?
        "Controller: "+cp.used+" computer calls used. The VM is frozen.\n\n"+memoryText+"Jr's assessment:\n"+[["Observed","completed"],["Uncertain","uncertain"],["Next five","next_steps"],["Why","reason"]].map(([label,key])=>label+": "+cp.report[key]).join("\n\n") :
        jr.job ? "Jr is preparing his check-in. The VM remains frozen." : "Send Jr the task you want him to do. He will propose a plan before he can act.";
    } catch (e) { $("jrComputerApprove").disabled=true; $("jrComputerStatus").textContent="Status unavailable: "+e.message; }
  }
  $("jrComputerStart").addEventListener("click", async () => {
    $("jrComputerStart").disabled=true;
    $("jrComputerStatus").textContent="Starting VM with controls locked...";
    try { await jrPost("/api/jr/computer/start",{}); jrNewThread(); await jrComputerUpdate(); }
    catch(e) { $("jrComputerStatus").textContent=e.message; $("jrComputerStart").disabled=false; }
  });
  $("jrComputerStop").addEventListener("click", async () => {
    $("jrComputerApprove").disabled=true;
    $("jrComputerStatus").textContent="Cutting VM power...";
    try { const s=await request("/api/jr/computer/stop",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
      $("jrComputerStatus").textContent=s.shutdown_error || (s.poweroff_confirmed ? "VM power-off confirmed" : "Cutoff in progress");
      await jrComputerUpdate();
    } catch(e) { $("jrComputerStatus").textContent="Cutoff could not be confirmed: "+e.message+". Power off Jr-Computer-Lab in VirtualBox."; }
  });
  $("jrComputerApprove").addEventListener("click",async()=>{
    const s=jrComputerState,cp=s && s.checkpoint_state;
    if(!cp || !cp.report || jr.job) return;
    $("jrComputerApprove").disabled=true;
    const reply=jrAdd("assistant","","continuing approved plan");
    jr.job={id:null,reply};jrBusy(true);
    try {
      const result=await jrPost("/api/jr/computer/approve",{checkpoint:cp.checkpoint,thread_id:s.thread_id});
      jr.thread=result.thread_id;jr.job.id=result.job_id;jrStream(result.job_id,reply);
    } catch(e) { reply.querySelector(".body").textContent=e.message;jrFinish(); }
    await jrComputerUpdate();
  });
  setInterval(jrComputerUpdate,2000);

  function jrTouch() {
    clearTimeout(jr.idleTimer);
    jr.idleTimer = setTimeout(() => { if (jr.unlocked) jrShowLock("unlock", "Locked after 15 minutes without use."); }, JR_IDLE_MS);
  }

  // Take every piece of Jr's text out of the page: messages, his composer, the list editor. And
  // stop his microphone: the recorder, the mic itself, and any transcript still on its way.
  function jrWipe() {
    jrMicReset();
    jrCloudReset();
    jrComputerState=null;
    $("jrComputerReport").textContent="";
    $("jrComputerReview").hidden=true;
    $("jrComputerApprove").disabled=true;
    if (jr.source) { jr.source.close(); jr.source = null; }
    jr.job = null; jrBusy(false);
    $("jrMessages").innerHTML = "";
    $("jrMessage").value = ""; fitJrComposer();
    $("jrNeverSendTerms").value = ""; $("jrNeverSendMsg").textContent = ""; $("jrNeverSend").hidden = true;
    jrMissing(0);
    const select = $("jrThreads"), fresh = el("option", "", "New conversation");
    fresh.value = "";
    select.innerHTML = "";
    select.append(fresh);
    $("jrComputerStatus").textContent = "VM controls off · no internet";
    $("jrComputerStart").disabled = true;
    jr.entered = false;
  }

  function jrShowLock(mode, note) {
    jrWipe();
    if (handoff.active) { $("message").value = ""; handoffEnd(); fitComposer(); }   // Jr's text leaves Marty's box too
    jr.unlocked = false;
    clearTimeout(jr.idleTimer);
    jr.lockMode = mode === "setup" ? "setup" : "unlock";
    const setup = jr.lockMode === "setup";
    $("jrView").classList.add("locked");
    $("jrLock").hidden = false;
    $("jrLockTitle").textContent = setup ? "Choose Marty Jr.'s passphrase" : "Marty Jr. is locked";  // secret-scan: allow [export-reviewed]
    $("jrLockHint").textContent = setup
      ? "12 characters or more. It encrypts Jr's history on this PC and is never saved in this browser. " +
        "Keep a copy in your password manager: without it his history cannot be recovered."
      : (note ? note + " " : "") + "Type your passphrase. It is never saved in this browser.";
    $("jrPass2").hidden = !setup;
    $("jrUnlock").textContent = setup ? "Set passphrase" : "Unlock";
    $("jrPass").value = ""; $("jrPass2").value = "";
    $("jrLockError").textContent = "";
  }

  function jrHideLock() {
    $("jrPass").value = ""; $("jrPass2").value = "";
    $("jrLock").hidden = true;
    $("jrView").classList.remove("locked");
  }

  // Lock now (the Lock button, the page going to the background): wipe the page first, then
  // tell the server, with keepalive so the request still goes out while the page is hidden.
  function jrLockNow(note) {
    const wasOpen = jr.unlocked;
    jrShowLock("unlock", note);
    if (!wasOpen) return;
    try { fetch("/api/jr/lock", {method: "POST", keepalive: true, cache: "no-store", credentials: "same-origin"}).catch(() => {}); }
    catch (_) {}
  }

  $("jrLockForm").addEventListener("submit", async event => {
    event.preventDefault();
    const pass = $("jrPass").value, again = $("jrPass2").value;
    $("jrPass").value = ""; $("jrPass2").value = "";          // out of the page at once
    const note = $("jrLockError");
    if (!pass) { note.textContent = "Type the passphrase."; return; }
    if (jr.lockMode === "setup") {
      if (Array.from(pass).length < 12) { note.textContent = "Use 12 characters or more."; return; }
      if (pass !== again) { note.textContent = "The two did not match. Type both again."; return; }
    }
    note.textContent = jr.lockMode === "setup" ? "Setting up..." : "Unlocking...";
    $("jrUnlock").disabled = true;
    try {
      const data = await request("/api/jr/unlock", {method: "POST", headers: {"Content-Type": "application/json"},
                                                   body: JSON.stringify({passphrase: pass})});
      note.textContent = "";
      jrUnlocked(data);
    } catch (error) {
      if (error.status === 400 && error.data && error.data.needs_setup) { jrShowLock("setup"); $("jrLockError").textContent = error.message; }
      else if (error.status === 403) note.textContent = "That passphrase did not unlock Marty Jr.";
      else note.textContent = error.message;            // 429 says how long to wait
    } finally { $("jrUnlock").disabled = false; }
  });

  function jrUnlocked(data) {
    jr.unlocked = true;
    jrHideLock();
    jrTouch();
    jr.entered = false;
    jrCloudStatus();
    jrEnter().then(() => {
      ((data && data.notices) || []).map(code => JR_NOTICES[code]).filter(Boolean)
        .forEach(text => $("jrMessages").prepend(el("div", "jr-notice", text)));
    });
    if (handoff.active && handoffBlocked()) handoffCheck();     // a re-check that was waiting on the unlock
  }

  function jrAdd(role, text, stateText = "") {
    const box = $("jrMessages");
    const empty = box.querySelector(".empty, .card");
    if (empty) empty.remove();
    const div = el("div", `message ${role}`);
    if (role === "assistant") div.append(el("span", "state", stateText), el("div", "tool-chips"));
    div.append(el("span", "body", text));
    box.append(div);
    box.scrollTop = box.scrollHeight;
    return div;
  }
  function jrChip(reply, tool) {
    const chips = reply.querySelector(".tool-chips");
    if (!chips || !tool) return;
    const status = ["ok", "refused", "error"].includes(tool.status) ? tool.status : "error";
    chips.append(el("span", `tool-chip ${status}`, `${tool.tool || "tool"} · ${tool.note || status}`));
  }
  function jrNotice(text) { $("jrMessages").innerHTML = ""; $("jrMessages").append(el("div", "card muted", text)); }
  // Threads whose file is gone from the PC (the server counts them; it never drops one silently).
  // Dismiss tells the server the deletion was on purpose, and it forgets them.
  function jrMissing(count) {
    const n = Math.max(0, Math.floor(Number(count) || 0));
    $("jrMissing").hidden = n === 0;
    $("jrMissingText").textContent = n === 0 ? "" : (n === 1
      ? "1 of Jr's conversations could not be found on the PC: its file was deleted or moved, so it is not listed."
      : `${n} of Jr's conversations could not be found on the PC: their files were deleted or moved, so they are not listed.`)
      + " If that was on purpose, dismiss this.";
  }
  $("jrMissingDismiss").addEventListener("click", async () => {
    const button = $("jrMissingDismiss");
    button.disabled = true;
    try { jrMissing((await jrPost("/api/jr/missing/dismiss", {})).missing); }
    catch (error) { if (error.status !== 423) $("jrMissingText").textContent = `Could not dismiss this (${error.message}).`; }
    finally { button.disabled = false; }
  });
  function jrBusy(on) {
    $("jrCancel").hidden = !on; $("jrSend").disabled = on; $("jrNew").disabled = on; $("jrThreads").disabled = on;
  }
  function jrFinish() { jr.job = null; jr.source = null; jrBusy(false); }

  async function jrEnter() {
    if (jr.entered) return;
    jr.entered = true;
    $("jrMessages").innerHTML = JR_EMPTY;
    await jrRefreshThreads(true);
  }

  async function jrRefreshThreads(openLatest) {
    let data;
    try { data = await jrRequest("/api/jr/threads"); }
    catch (error) {
      jr.entered = false;
      if (error.status !== 423) jrNotice(`Marty Jr. is unavailable: ${error.message}`);
      return;
    }
    if (!jr.unlocked) { jr.unlocked = true; jrHideLock(); }    // this device's unlock is still current
    const threads = data.threads || [];
    jrMissing(data.missing);
    if (jr.thread && !threads.some(t => t.id === jr.thread)) jr.thread = null;   // gone from the history
    if (openLatest && !jr.thread && threads.length) jr.thread = threads[0].id;
    const select = $("jrThreads");
    select.innerHTML = "";
    const fresh = el("option", "", "New conversation");
    fresh.value = "";
    select.append(fresh);
    threads.forEach(t => {
      const option = el("option", "", `${t.title || "Conversation"} · ${relTime(t.updated)}`);
      option.value = t.id;
      select.append(option);
    });
    select.value = jr.thread || "";
    if (openLatest && jr.thread && !jr.job) await jrLoadThread(jr.thread);
  }

  async function jrLoadThread(id) {
    let data;
    try { data = await jrRequest(`/api/jr/thread/${encodeURIComponent(id)}`); }
    catch (error) {
      if (error.status === 423) return;
      if (error.status === 404) { jr.thread = null; $("jrThreads").value = ""; $("jrMessages").innerHTML = JR_EMPTY; }
      else jrNotice(error.message);
      return;
    }
    if (jr.thread !== id || jr.job) return;          // switched away, or a turn started meanwhile
    const box = $("jrMessages"), turns = data.turns || [];
    box.querySelectorAll(".message, .empty, .card").forEach(node => node.remove());
    if (!turns.length && !data.pending) box.insertAdjacentHTML("beforeend", JR_EMPTY);
    turns.forEach(turn => {
      jrAdd("user", turn.message || "");
      const text = turn.reply || turn.error || (turn.status === "cancelled" ? "Stopped." : "");
      const reply = jrAdd("assistant", text, turn.status === "completed" ? "" : turn.status);
      (turn.tools || []).forEach(tool => jrChip(reply, tool));
      if (turn.status === "completed" && turn.reply) jrOfferAsk(reply);
    });
    if (data.pending) {
      jrAdd("user", data.pending.message || "");
      const reply = jrAdd("assistant", "", "reconnecting");
      jr.job = {id: data.pending.id, reply};
      jrBusy(true);
      jrStream(data.pending.id, reply);
    }
  }

  async function jrSend(text) {
    text = (text || "").trim();
    if (!text || jr.job) return;
    jrAdd("user", text);
    const reply = jrAdd("assistant", "", "starting");
    jr.job = {id: null, reply};
    jrBusy(true);
    try {
      const payload = await jrPost("/api/jr/job", {text, thread_id: jr.thread});
      jr.job.id = payload.job_id;
      if (jr.thread !== payload.thread_id) { jr.thread = payload.thread_id; jrRefreshThreads(false); }
      jrStream(payload.job_id, reply);
    } catch (error) {
      if (error.status === 423) return;              // the lock screen took over and wiped the page
      reply.querySelector(".state").textContent = "failed";
      reply.querySelector(".body").textContent = error.message;
      jrFinish();
    }
  }

  function jrStream(id, reply) {
    const source = new EventSource(`/api/jr/stream/${id}`);
    jr.source = source;
    const body = reply.querySelector(".body");
    let label = reply.querySelector(".state").textContent || "starting";      // same reconnect fix as streamJob
    if (label === "reconnecting") label = "thinking";
    const setState = text => { if (text !== "reconnecting") label = text; reply.querySelector(".state").textContent = text; };
    source.addEventListener("state", event => { jrTouch(); const data = JSON.parse(event.data); setState(data.state || "thinking"); });
    source.addEventListener("tool", event => { jrTouch(); jrChip(reply, JSON.parse(event.data)); });
    source.addEventListener("delta", event => {
      jrTouch();
      const data = JSON.parse(event.data);
      setState("replying");
      body.textContent += data.text || "";
      $("jrMessages").scrollTop = $("jrMessages").scrollHeight;
    });
    source.addEventListener("done", event => {
      const data = JSON.parse(event.data);
      // The finished job is authoritative: after a resumed stream the server may resend it whole.
      if (data.reply) body.textContent = data.reply;
      if (Array.isArray(data.tools)) { reply.querySelector(".tool-chips").innerHTML = ""; data.tools.forEach(t => jrChip(reply, t)); }
      if (data.status === "cancelled" && !body.textContent) body.textContent = "Stopped.";
      setState(data.status === "cancelled" ? "cancelled" : "done");
      if (data.status === "completed" && body.textContent) jrOfferAsk(reply);
      source.close(); jrFinish(); jrRefreshThreads(false);
    });
    let drops = 0;
    source.addEventListener("open", () => {
      drops = 0;
      if (reply.querySelector(".state").textContent === "reconnecting") setState(label);
    });
    source.addEventListener("error", event => {
      if (event.data) {
        let data = {};
        try { data = JSON.parse(event.data); } catch (_) {}
        source.close(); jrFinish();
        if (data.locked) { jrShowLock("unlock", "Locked."); return; }   // locked from another device, idle or logout
        body.textContent = data.error || "Reply failed.";
        setState("failed");
        return;
      }
      // Dropped (phone locked, network blip): the turn keeps running on the PC and the browser
      // resumes after the last event it saw (Last-Event-ID). If it cannot (a 423 closes it too),
      // reload the thread, which shows the lock screen when that is the reason.
      setState("reconnecting");
      if (source.readyState === EventSource.CLOSED || ++drops > 8) {
        source.close();
        if (jr.source === source) { jrFinish(); if (jr.thread) setTimeout(() => jrLoadThread(jr.thread), 1500); }
      }
    });
  }

  // Background, switcher and screenshots: blur the moment the window loses focus, and lock
  // (wipe, then tell the server) the moment the page is hidden or unloaded.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      document.body.classList.add("jr-shield");
      if (jrMic.phase !== "idle" || jrMic.stream) jrMicReset();   // recorder stopped, microphone released
      if (jr.unlocked) jrLockNow("Locked when the app went to the background.");
      chatMicLeave("Stopped when the app went to the background.");
      return;
    }
    document.body.classList.remove("jr-shield");
    if (jr.source && jr.source.readyState === EventSource.CLOSED) {
      jr.source.close(); jrFinish(); if (jr.thread) jrLoadThread(jr.thread);
    }
  });
  window.addEventListener("pagehide", () => { jrMicReset(); if (jr.unlocked) jrLockNow("Locked."); chatMicReset(); });
  window.addEventListener("blur", () => { if (jr.unlocked) document.body.classList.add("jr-shield"); });
  window.addEventListener("focus", () => {
    if (document.visibilityState === "visible") document.body.classList.remove("jr-shield");
    jrProbe();
  });

  // Locked somewhere else (the phone went to the background, idle, logout): an open page finds
  // out within 20 s and drops Jr's text. /api/jr/status does not count as use, so this poll
  // never keeps the idle lock away.
  async function jrProbe() {
    if (!jr.unlocked) return;
    try {
      const status = await request("/api/jr/status");
      if (!status.open && jr.unlocked) jrShowLock("unlock", "Locked.");
    } catch (error) { if (error.status === 401 && jr.unlocked) jrShowLock("unlock", "Locked."); }
  }
  setInterval(() => { if (!document.hidden) jrProbe(); }, 20000);

  function jrNewThread() {
    if (jr.job || !jr.unlocked) return;
    jr.thread = null;
    $("jrThreads").value = "";
    $("jrMessages").innerHTML = JR_EMPTY;
    $("jrMessage").focus();
  }
  function fitJrComposer() {
    const box = $("jrMessage");
    box.style.height = "auto";
    box.style.height = Math.min(160, box.scrollHeight) + "px";
  }
  $("jrMessage").addEventListener("input", () => { fitJrComposer(); if (jr.unlocked) jrTouch(); });
  $("jrComposer").addEventListener("submit", event => {
    event.preventDefault();
    if (jr.job) return;                                // keep the text while a reply runs
    const text = $("jrMessage").value;
    $("jrMessage").value = "";
    fitJrComposer();
    jrSend(text);
  });
  $("jrMessage").addEventListener("keydown", event => {
    if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); $("jrComposer").requestSubmit(); }
  });
  $("jrCancel").addEventListener("click", async () => {
    if (!jr.job || !jr.job.id) return;
    try { await jrRequest(`/api/jr/cancel/${jr.job.id}`, {method: "POST"}); } catch (_) {}
  });
  $("jrNew").addEventListener("click", jrNewThread);
  $("jrThreads").addEventListener("change", () => {
    if (jr.job) { $("jrThreads").value = jr.thread || ""; return; }
    jr.thread = $("jrThreads").value || null;
    if (jr.thread) jrLoadThread(jr.thread); else $("jrMessages").innerHTML = JR_EMPTY;
  });
  $("jrLockNow").addEventListener("click", () => jrLockNow("Locked."));

  // ---------- Jr's microphone (Phase 2, W3 voice) ----------
  // Tap to record on this device, tap again to stop. The recording goes to /api/jr/talk, which
  // transcribes it on this PC with Talk's local Whisper and answers only while Jr is unlocked for
  // this device. The text lands in Jr's message box for Lukas to edit; nothing is sent until he
  // presses Send, and nothing is kept in the browser. A lock (Lock button, background, idle,
  // another device) stops the recorder, releases the microphone and drops any transcript still on
  // its way, so it never reaches the box. Leaving Jr's view discards a recording in progress.
  const JR_MIC_MAX_MS = 3 * 60 * 1000;
  const JR_MIC_LABELS = {idle: "Record a message for Marty Jr. (transcribed on this PC)",
                         asking: "Waiting for the microphone", recording: "Stop recording",
                         sending: "Transcribing on this PC"};
  function jrMicUi(phase) {
    jrMic.phase = phase;
    const button = $("jrMic");
    button.classList.toggle("recording", phase === "recording");
    button.classList.toggle("working", phase === "asking" || phase === "sending");
    button.disabled = phase === "asking" || phase === "sending";
    button.setAttribute("aria-pressed", phase === "recording" ? "true" : "false");
    button.setAttribute("aria-label", JR_MIC_LABELS[phase]);
    button.title = JR_MIC_LABELS[phase];
  }
  function jrMicStatus(text, isError) {
    const note = $("jrMicStatus");
    note.textContent = text || "";
    note.hidden = !text;
    note.classList.toggle("error", !!isError);
  }
  function jrMicRelease() {
    if (!jrMic.stream) return;
    jrMic.stream.getTracks().forEach(track => { try { track.stop(); } catch (_) {} });
    jrMic.stream = null;
  }
  // Stop everything and forget it: the recorder (without sending), the microphone, the recorded
  // chunks, and any transcription on its way (aborted; an answer that still arrives is stale).
  function jrMicReset() {
    jrMic.gen++;
    clearTimeout(jrMic.timer);
    if (jrMic.controller) { try { jrMic.controller.abort(); } catch (_) {} jrMic.controller = null; }
    const recorder = jrMic.recorder;
    jrMic.recorder = null;
    if (recorder) {
      recorder.ondataavailable = null; recorder.onstop = null;
      try { if (recorder.state !== "inactive") recorder.stop(); } catch (_) {}
    }
    jrMicRelease();
    jrMic.chunks = [];
    jrMicUi("idle");
    jrMicStatus("");
  }
  function jrMicLeave() {
    if (jrMic.phase !== "asking" && jrMic.phase !== "recording") return;   // a transcript on its way still lands in Jr's box
    jrMicReset();
    jrMicStatus("The recording was discarded when you left Jr's view. Nothing was sent.");
  }
  function jrMicType() {
    if (typeof MediaRecorder.isTypeSupported !== "function") return "";
    return ["audio/webm;codecs=opus", "audio/webm", "audio/mp4"].find(type => MediaRecorder.isTypeSupported(type)) || "";
  }
  function jrMicError(error) {
    const name = (error && error.name) || "";
    if (name === "NotAllowedError" || name === "SecurityError" || name === "PermissionDeniedError")
      return "Microphone blocked. Allow it for this site in your browser's site settings (Chrome: Settings > " +
             "Site settings > Microphone), then tap the microphone again. Typing still works.";
    if (name === "NotFoundError" || name === "DevicesNotFoundError" || name === "OverconstrainedError")
      return "No microphone was found on this device.";
    if (name === "NotReadableError" || name === "TrackStartError")
      return "The microphone is in use by another app. Close it, then try again.";
    return "The microphone could not start" + (error && error.message ? ` (${error.message}).` : ".");
  }

  async function jrMicStart() {
    if (!jr.unlocked || jrMic.phase !== "idle") return;
    if (state.recorder || chatMic.stream) {
      jrMicStatus(state.recorder
        ? "Marty's Talk microphone is still on. Stop it in the Talk tab first, so nothing meant for Jr is heard by Marty."
        : "Marty's chat microphone is still on. Wait a moment for it to finish, so nothing meant for Jr is heard by Marty.", true);
      return;
    }
    if (!navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== "function" || typeof MediaRecorder === "undefined") {
      jrMicStatus(window.isSecureContext ? "This browser cannot record audio." : "The microphone works only on the dashboard's https address.", true);
      return;
    }
    const gen = ++jrMic.gen;
    jrMicUi("asking");
    jrMicStatus("Waiting for the microphone...");
    let stream;
    try { stream = await navigator.mediaDevices.getUserMedia({audio: true}); }
    catch (error) {
      if (gen !== jrMic.gen) return;
      jrMicUi("idle");
      jrMicStatus(jrMicError(error), true);
      return;
    }
    // Locked, reset or hidden while the permission prompt was up: let go of the microphone at once.
    if (gen !== jrMic.gen || !jr.unlocked || state.view !== "jr" || document.visibilityState !== "visible") {
      stream.getTracks().forEach(track => { try { track.stop(); } catch (_) {} });
      if (gen === jrMic.gen) { jrMicUi("idle"); jrMicStatus(""); }
      return;
    }
    const type = jrMicType();
    let recorder;
    try { recorder = type ? new MediaRecorder(stream, {mimeType: type}) : new MediaRecorder(stream); }
    catch (_) {
      stream.getTracks().forEach(track => { try { track.stop(); } catch (__) {} });
      jrMicUi("idle");
      jrMicStatus("This browser cannot record audio.", true);
      return;
    }
    jrMic.stream = stream; jrMic.recorder = recorder; jrMic.chunks = [];
    recorder.ondataavailable = event => { if (gen === jrMic.gen && event.data && event.data.size) jrMic.chunks.push(event.data); };
    recorder.onstop = () => jrMicSubmit(gen, recorder.mimeType || type || "audio/webm");
    recorder.start();
    jrMic.timer = setTimeout(() => { if (gen === jrMic.gen) jrMicStop("Stopped at 3 minutes."); }, JR_MIC_MAX_MS);
    jrMicUi("recording");
    jrMicStatus("Listening on this device. Tap the microphone again to stop.");
    jrTouch();
  }

  function jrMicStop(note) {
    clearTimeout(jrMic.timer);
    const recorder = jrMic.recorder;
    if (!recorder || recorder.state === "inactive") return;
    jrMicUi("sending");
    jrMicStatus((note ? note + " " : "") + "Transcribing on this PC...");
    try { recorder.stop(); } catch (_) { jrMicReset(); }
  }

  async function jrMicSubmit(gen, mimeType) {
    clearTimeout(jrMic.timer);                         // a recorder that stopped by itself leaves no timer behind
    const chunks = jrMic.chunks;
    jrMic.chunks = []; jrMic.recorder = null;
    jrMicRelease();                                    // the microphone is off before the upload starts
    if (gen !== jrMic.gen) return;                     // locked or reset while recording: dropped
    const type = String(mimeType).split(";")[0].trim().toLowerCase() || "audio/webm";
    const blob = new Blob(chunks, {type});
    if (!blob.size) { jrMicUi("idle"); jrMicStatus("Nothing was recorded. Try again.", true); return; }
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    jrMic.controller = controller;
    let data = null, failure = "";
    try {
      data = await jrRequest("/api/jr/talk", {method: "POST", headers: {"Content-Type": type}, body: blob,
                                              signal: controller ? controller.signal : undefined});
    } catch (error) { failure = error.message || "the request failed"; }
    if (gen !== jrMic.gen || !jr.unlocked) return;     // locked while transcribing: the text never lands
    jrMic.controller = null;
    jrMicUi("idle");
    if (failure) { jrMicStatus(`Could not transcribe that: ${failure}`, true); return; }
    const text = ((data && data.text) || "").trim();
    if (!text) { jrMicStatus("Jr did not hear any speech in that recording."); return; }
    const box = $("jrMessage");
    box.value = box.value.trim() ? box.value.replace(/\s+$/, "") + " " + text : text;
    fitJrComposer();
    jrMicStatus("Transcribed on this PC. Edit it if you like, then press Send.");
    try { box.focus({preventScroll: true}); } catch (_) { box.focus(); }
    box.setSelectionRange(box.value.length, box.value.length);
  }

  $("jrMic").addEventListener("click", () => {
    if (jrMic.phase === "recording") jrMicStop();
    else jrMicStart();
  });

  // The never-send list: typed by Lukas here and nowhere else (no voice, no spellcheck service),
  // shown only while he edits it, and saved inside Jr's encrypted history.
  $("jrNeverSendOpen").addEventListener("click", async () => {
    const panel = $("jrNeverSend"), msg = $("jrNeverSendMsg");
    if (!panel.hidden) { panel.hidden = true; $("jrNeverSendTerms").value = ""; msg.textContent = ""; return; }
    panel.hidden = false;
    msg.textContent = "Loading...";
    try {
      const data = await jrRequest("/api/jr/never-send");
      $("jrNeverSendTerms").value = (data.terms || []).join("\n");
      msg.textContent = `${(data.terms || []).length} saved.`;
    } catch (error) { if (error.status !== 423) msg.textContent = error.message; }
  });
  $("jrNeverSendSave").addEventListener("click", async () => {
    const msg = $("jrNeverSendMsg");
    const terms = $("jrNeverSendTerms").value.split("\n").map(t => t.trim()).filter(Boolean);
    msg.textContent = "Saving...";
    try {
      const data = await jrPost("/api/jr/never-send", {terms}, "PUT");
      $("jrNeverSendTerms").value = (data.terms || []).join("\n");
      msg.textContent = `Saved ${(data.terms || []).length}.`;
      if (handoff.active) handoffCheck();            // a new list can change what is blocked
    } catch (error) { if (error.status !== 423) msg.textContent = error.message; }
  });
  $("jrNeverSendClose").addEventListener("click", () => {
    $("jrNeverSend").hidden = true; $("jrNeverSendTerms").value = ""; $("jrNeverSendMsg").textContent = "";
  });

  // ---------- Ask Marty about a Jr reply (W4) ----------
  // A human handoff, not a relay. The reply is checked against the never-send list on the PC,
  // then put into Marty's message box exactly as it is, with every match highlighted. Send stays
  // off until the matches are edited out; the check re-runs as Lukas edits; only his own Send
  // sends. If the check cannot run, nothing leaves Jr's view and Send stays off.
  function jrOfferAsk(reply) {
    if (!reply || reply.querySelector(".jr-ask")) return;
    const button = el("button", "jr-ask", "Ask Marty about this");
    button.type = "button";
    button.title = "Checks it against your never-send list, then puts it in Marty's message box. Nothing is sent until you press Send.";
    button.addEventListener("click", () => askMarty(reply, button));
    reply.append(button);
  }

  async function askMarty(reply, button) {
    const text = (reply.querySelector(".body").textContent || "").trim();
    if (!text) return;
    button.disabled = true;
    button.textContent = "Checking...";
    let result;
    try { result = await jrPost("/api/jr/handoff-check", {text}); }
    catch (error) {
      if (error.status !== 423) { button.disabled = false; button.textContent = "Ask Marty about this (the check failed; try again)"; }
      return;
    }
    button.disabled = false;
    button.textContent = "Ask Marty about this";
    lineHashes(text).forEach(h => { if (handoffSeen.size < 2000) handoffSeen.add(h); });
    const box = $("message");
    const before = box.value.trim() ? box.value.replace(/\s+$/, "") + "\n\n" : "";
    box.value = before + text;
    Object.assign(handoff, {active: true, checking: false, error: ""});
    if (before) { handoff.hits = []; handoff.cleared = false; handoff.checkedText = null; }   // Lukas's own text in front is not checked yet
    else { handoff.hits = result.hits || []; handoff.cleared = result.ok === true && !handoff.hits.length; handoff.checkedText = box.value; }
    activateView("chat");
    fitComposer();
    if (before) handoffCheck();
    box.focus();
    box.setSelectionRange(box.value.length, box.value.length);
  }

  // Send is enabled only by the server's ok:true for the exact text in the box (cleared), and the
  // Send itself is checked again on the server (/api/chat/job with handoff: true).
  function handoffBlocked() {
    return handoff.active && (handoff.checking || !!handoff.error || handoff.hits.length > 0 || !handoff.cleared ||
                              handoff.checkedText !== $("message").value);
  }
  // An emptied box does NOT end the handoff (skeptic, 2026-09-25): cut-and-paste or undo would
  // bring Jr's text back unchecked. Only Clear or a successful Send ends it.
  function handoffEdited() {
    clearTimeout(handoff.timer);
    if ($("message").value !== handoff.checkedText) handoff.timer = setTimeout(handoffCheck, 350);
    handoffRender();
  }
  async function handoffCheck() {
    clearTimeout(handoff.timer);
    if (!handoff.active) return;
    const text = $("message").value;
    if (!text.trim()) {                                // nothing to check, and nothing can be sent
      handoff.seq++;
      Object.assign(handoff, {checking: false, error: "", hits: [], cleared: true, checkedText: text});
      handoffRender();
      return;
    }
    const seq = ++handoff.seq;
    handoff.checking = true;
    handoff.error = "";
    handoffRender();
    try {
      const result = await jrPost("/api/jr/handoff-check", {text});
      if (seq !== handoff.seq) return;
      handoff.hits = result.hits || [];
      handoff.cleared = result.ok === true && !handoff.hits.length;
      handoff.checkedText = text;
    } catch (error) {
      if (seq !== handoff.seq) return;
      handoff.hits = [];
      handoff.cleared = false;
      handoff.checkedText = null;
      handoff.error = error.status === 423
        ? "Marty Jr. is locked, so this text cannot be re-checked. Unlock him in the Jr. tab, or clear it."
        : `Could not check this text (${error.message}). Send stays off.`;
    } finally {
      if (seq === handoff.seq) { handoff.checking = false; handoffRender(); }
    }
  }
  function handoffEnd() {
    clearTimeout(handoff.timer);
    handoff.seq++;
    Object.assign(handoff, {active: false, checking: false, error: "", hits: [], cleared: false, checkedText: null});
    handoffRender();
  }
  // A handoff Send the server refused: nothing was sent. Jr's text leaves the chat pane. After a
  // failed check (or any other refusal) it goes back into the box, re-armed, so the check runs
  // again and shows where; while Jr is locked it stays out, since his text leaves the page then.
  function handoffRefused(error, text, mine, reply) {
    mine.remove();
    reply.querySelector(".state").textContent = "not sent";
    if (error.status === 423) {
      reply.querySelector(".body").textContent =
        "Not sent: Marty Jr. is locked, so this could not be checked again. Unlock him and ask again.";
      jrShowLock(error.data && error.data.needs_setup ? "setup" : "unlock", "Locked.");
      return;
    }
    const box = $("message");
    const before = box.value.trim() ? box.value.replace(/\s+$/, "") + "\n\n" : "";
    box.value = before + text;
    Object.assign(handoff, {active: true, checking: false, error: "", hits: [], cleared: false, checkedText: null});
    fitComposer();                                     // re-checks it (handoffEdited)
  }
  const HIT_TITLES = {
    "never-send term": "On your never-send list. Tap to select it in the message box.",
    "mixed-script word": "A word mixing letters from two alphabets, which can hide a never-send name. Tap to select it in the message box.",
  };
  function hitSummary(hits) {
    const mixed = hits.filter(hit => hit.reason === "mixed-script word").length, terms = hits.length - mixed;
    const parts = [];
    if (terms) parts.push(`${terms} match${terms === 1 ? "" : "es"} from your never-send list`);
    if (mixed) parts.push(`${mixed} mixed-script word${mixed === 1 ? "" : "s"} (letters from two alphabets)`);
    return `${parts.join(" and ")}, highlighted below. Edit ${hits.length === 1 ? "it" : "them"} out to send.`;
  }
  function handoffRender() {
    const box = $("handoff"), preview = $("handoffPreview"), status = $("handoffStatus");
    preview.innerHTML = "";
    // While Jr's text sits in Marty's box: no spellcheck service sees it, and the background
    // shield blurs the box along with Jr's own view.
    $("message").spellcheck = !handoff.active;
    $("chatView").classList.toggle("handoff-live", handoff.active);
    if (!handoff.active) { box.hidden = true; preview.hidden = true; updateSend(); return; }
    box.hidden = false;
    const text = $("message").value, current = handoff.checkedText === text;
    if (current && handoff.hits.length) {
      let at = 0;
      handoff.hits.forEach(hit => {
        if (hit.start < at || hit.end > text.length) return;
        preview.append(document.createTextNode(text.slice(at, hit.start)));
        const mixedWord = hit.reason === "mixed-script word";
        const mark = el("mark", mixedWord ? "mixed" : "", text.slice(hit.start, hit.end));
        mark.title = HIT_TITLES[mixedWord ? "mixed-script word" : "never-send term"];
        mark.addEventListener("click", () => { const m = $("message"); m.focus(); m.setSelectionRange(hit.start, hit.end); });
        preview.append(mark);
        at = hit.end;
      });
      preview.append(document.createTextNode(text.slice(at)));
    }
    preview.hidden = !(current && handoff.hits.length);
    const n = current ? handoff.hits.length : 0;
    status.textContent = handoff.error ? handoff.error
      : (current && !text.trim()) ? "The message box is empty. Anything you put back is checked again."
      : (handoff.checking || !current) ? "Checking it against your never-send list..."
      : n ? hitSummary(handoff.hits)
      : !handoff.cleared ? "The check did not clear this text, so Send stays off. Edit it to check again, or clear it."
      : "Checked against your never-send list: clear. Nothing is sent until you press Send.";
    box.classList.toggle("blocked", handoffBlocked());
    updateSend();
  }
  $("handoffClear").addEventListener("click", () => { $("message").value = ""; handoffEnd(); fitComposer(); });

  // ---------- jobs: Lukas's board ----------

  // /api/jobs has two halves. The live rows ("running") come from the PC itself: chat replies,
  // services that need attention, an active backup, running scheduled tasks, and Marty working at
  // the PC (the newest activity-log line). "board" is Marty's curated half, status/board.json:
  // what waits on Lukas (with buttons), queued work with who and where, and what closed out
  // today. A tap records an answer through POST /api/board/answer for Marty to read back; it
  // never starts anything. Fail-soft: a failed refresh keeps the last board and says so.
  async function refreshJobs() {
    let data;
    try { data = await request("/api/jobs"); } catch (_) { waitingError(); return; }
    try { renderJobs(data || {}); } catch (_) { waitingError(); }
  }

  let waitingLoaded = false;
  let waitingSig = "";              // what the waiting cards were last drawn from; same = not redrawn
  let lastWaiting = {alerts: [], items: []};
  const boardAnswers = {};          // answers saved from this page, until the next redraw
  const answering = new Set();

  // **bold** spans in board text; everything else stays plain text, never HTML.
  function richText(text) {
    const frag = document.createDocumentFragment();
    String(text || "").split(/\*\*(.+?)\*\*/g).forEach((part, i) => {
      if (part) frag.append(i % 2 ? el("b", "", part) : document.createTextNode(part));
    });
    return frag;
  }
  function boardWhen(iso) {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    const time = d.toLocaleTimeString([], {hour: "numeric", minute: "2-digit"});
    return d.toDateString() === new Date().toDateString() ? time
      : `${d.toLocaleDateString([], {month: "short", day: "numeric"})} ${time}`;
  }
  const answerLine = ans => `Answered ${boardWhen(ans.at)}: ${ans.choice}. Marty picks it up at his next check.`;
  const answerOf = item => boardAnswers[item.id] || item.answer || null;

  function waitingCard(item) {
    const answer = answerOf(item);
    const card = el("article", "board-card" + (item.flag ? " flagged" : "") + (answer ? " answered" : ""));
    card.dataset.id = item.id;
    const chips = el("div", "board-chips");
    chips.append(el("span", "board-pill", item.tag || "Your call"), el("span", "board-where", item.where || ""));
    const body = el("p", "board-body");
    body.append(richText(item.body));
    const choices = el("div", "board-choices");
    const note = el("textarea", "board-note");
    Object.assign(note, {rows: 2, maxLength: 1000, hidden: true, placeholder: "Optional note, saved with your answer"});
    note.setAttribute("aria-label", "Note for Marty");
    const saved = el("p", "board-saved small", answer ? answerLine(answer) : "");
    saved.setAttribute("aria-live", "polite");
    (item.choices || []).forEach((label, i) => {
      const button = el("button", "board-choice" + (i === 0 ? " primary" : ""), label);
      button.type = "button";
      button.dataset.choice = label;
      if (answer) button.classList.add(answer.choice === label ? "picked" : "dim");
      button.addEventListener("click", () => answerBoard(item, label, note, card, saved));
      choices.append(button);
    });
    const noteButton = el("button", "board-addnote", "Add a note");
    noteButton.type = "button";
    noteButton.addEventListener("click", () => { note.hidden = !note.hidden; if (!note.hidden) note.focus(); });
    card.append(chips, el("h4", "board-title", item.title), body, choices, noteButton, note, saved);
    return card;
  }

  async function answerBoard(item, choice, note, card, saved) {
    if (answering.has(item.id)) return;
    answering.add(item.id);
    saved.classList.remove("err");
    saved.textContent = "Saving...";
    // The board can redraw while the tap is in flight; the result goes on the card that is on
    // screen by then, not the detached one the tap started from.
    const current = () => {
      const now = $("jobsWaiting").querySelector(`.board-card[data-id="${CSS.escape(item.id)}"]`) || card;
      return {card: now, saved: now.querySelector(".board-saved") || saved, note: now.querySelector(".board-note") || note};
    };
    try {
      const data = await request("/api/board/answer", {method: "POST", headers: {"Content-Type": "application/json"},
                                                       body: JSON.stringify({id: item.id, choice, note: note.value.trim()})});
      boardAnswers[item.id] = data.answer;
      const on = current();
      on.card.classList.add("answered");
      on.card.querySelectorAll(".board-choice").forEach(button => {
        button.classList.remove("picked", "dim");
        button.classList.add(button.dataset.choice === choice ? "picked" : "dim");
      });
      on.saved.classList.remove("err");
      on.saved.textContent = answerLine(data.answer);
      on.note.value = "";
      on.note.hidden = true;
      drawWaitingCounts();
      // Long enough to read "Answered", then the card goes.
      setTimeout(() => {
        const gone = current().card;
        gone.classList.add("leaving");
        setTimeout(() => { gone.remove(); drawWaitingFooter(); }, 400);
      }, 1500);
    } catch (error) {
      const on = current();
      on.saved.classList.add("err");
      on.saved.textContent = error.status === 404 ? "That item just left the board. Refresh to see the latest."
        : `Not saved: ${error.message}`;
    } finally {
      answering.delete(item.id);
    }
  }

  // Waiting count = system alerts (a failed or stalled backup) + board items not yet answered.
  function drawWaitingCounts() {
    const open = lastWaiting.alerts.length + lastWaiting.items.filter(item => !answerOf(item)).length;
    // Null-guarded: a page file from another build must never throw here and blank the Jobs view.
    ["jobsWaitingCount", "railWaitingCount", "talkWaitingCount"].forEach(id => { const n = $(id); if (n) n.textContent = open ? String(open) : ""; });
    const chip = document.querySelector("#boardTally .board-chip.you b");
    if (chip) chip.textContent = String(open);
    drawWaitingFooter();
    const rail = $("railWaiting");
    if (!rail) return;
    rail.innerHTML = "";
    const railRows = lastWaiting.alerts.map(a => a.title).concat(lastWaiting.items.filter(item => !answerOf(item)).map(item => item.title));
    if (!railRows.length) { rail.append(el("p", "muted", "Nothing is waiting on you.")); return; }
    railRows.forEach(title => {
      const row = el("div", "rail-item waiting-item board-link");
      row.dataset.view = "jobs";
      row.append(el("b", "", String(title || "Something needs you")));
      rail.append(row);
    });
  }

  function renderWaiting(alerts, items) {
    alerts = (Array.isArray(alerts) ? alerts : []).filter(a => a && typeof a === "object");
    items = (Array.isArray(items) ? items : []).filter(i => i && typeof i === "object" && i.id);
    waitingLoaded = true;
    lastWaiting = {alerts, items};
    // A good refresh clears any "could not refresh" line left by an earlier failed one.
    document.querySelectorAll("#jobsWaiting .waiting-error, #railWaiting .waiting-error").forEach(node => node.remove());
    const sig = JSON.stringify([alerts, items]);
    if (sig !== waitingSig) {
      // Redraw only when the board changed, keeping any half-typed note.
      const box = $("jobsWaiting");
      const drafts = {};
      box.querySelectorAll(".board-card").forEach(card => {
        const note = card.querySelector(".board-note");
        if (note && (note.value || !note.hidden)) {
          drafts[card.dataset.id] = {text: note.value, open: !note.hidden, focused: document.activeElement === note,
                                     caret: note.selectionStart};
        }
      });
      Object.keys(boardAnswers).forEach(id => delete boardAnswers[id]);   // the server's answers are current now
      waitingSig = sig;
      box.innerHTML = "";
      alerts.forEach(alert => {
        const row = el("div", "rail-item waiting-item");
        row.append(el("b", "", String(alert.title || "Something needs you")));
        const when = alert.since ? relTime(alert.since) : "";
        if (when) row.append(el("small", "", when));
        box.append(row);
      });
      let refocus = null;
      items.forEach(item => {
        if (answerOf(item)) return;                    // answered: off the list until he's needed again
        const card = waitingCard(item);
        const draft = drafts[item.id];
        if (draft) {
          const note = card.querySelector(".board-note");
          note.value = draft.text;
          note.hidden = !draft.open;
          if (draft.focused) refocus = [note, draft.caret];
        }
        box.append(card);
      });
      // A redraw while Lukas is typing must not close his phone keyboard mid-sentence.
      if (refocus) { refocus[0].focus({preventScroll: true}); try { refocus[0].setSelectionRange(refocus[1], refocus[1]); } catch (_) {} }
    }
    drawWaitingCounts();
  }
  // Answered cards leave the list (Lukas, 2026-09-26: "make them disappear until I am needed
  // again"). One quiet line counts the answers Marty hasn't acted on yet; a card that needs him
  // again comes back as a new card with a new id.
  function drawWaitingFooter() {
    const box = $("jobsWaiting");
    if (!box) return;
    box.querySelectorAll(".waiting-empty, .board-answered-line").forEach(node => node.remove());
    const answered = lastWaiting.items.filter(item => answerOf(item)).length;
    const cards = box.querySelectorAll(".board-card:not(.leaving)").length;
    if (!lastWaiting.alerts.length && !cards) box.append(el("p", "muted waiting-empty", "Nothing is waiting on you."));
    if (answered) box.append(el("p", "muted small board-answered-line",
      `${answered} answered · Marty picks ${answered === 1 ? "it" : "them"} up at his next check.`));
  }
  function waitingError() {
    ["railWaiting", "jobsWaiting"].forEach(boxId => {
      const box = $(boxId);
      box.querySelectorAll(".waiting-error").forEach(node => node.remove());
      if (!waitingLoaded) box.innerHTML = "";
      box.append(el("p", "muted small waiting-error",
                    waitingLoaded ? "Could not refresh just now; this is the last check." : "Could not check right now."));
    });
  }

  // ---------- Watch Marty work (2026-09-26) ----------
  // GET /api/live: Marty's narration and plain step labels from the Claude Code session at the PC
  // (live_feed.py strips everything else). Open, it refreshes every 3 s while Jobs is on screen;
  // closed, it only updates its one-line status. Open or closed is remembered on this device.
  const live = {open: lsGet("marty.live.open") === "1", busy: false, sig: "", tick: 0};
  function liveUi() {
    if (!$("liveFeed")) return;                        // an older index.html during a deploy: no panel, no error
    $("liveFeed").hidden = !live.open;
    $("liveHead").setAttribute("aria-expanded", live.open ? "true" : "false");
    $("liveToggle").textContent = live.open ? "Close" : "Open";
  }
  function liveClock(iso) {
    const d = new Date(iso);
    return isNaN(d.getTime()) ? "" : d.toLocaleTimeString([], {hour: "numeric", minute: "2-digit"});
  }
  function renderLive(data) {
    const dot = $("liveDot"), meta = $("liveMeta");
    if (!dot || !meta || !$("liveFeed")) return;
    dot.classList.toggle("on", !!data.active);
    if (!data.ok) meta.textContent = data.error || "Can't read the PC's session right now.";
    else if (data.active) meta.textContent = "Working now" + (data.title ? ` · ${data.title}` : "");
    else meta.textContent = data.updated ? `Quiet · last step ${relTime(data.updated)}` : "Quiet";
    if (!live.open) return;
    const events = data.events || [];
    const sig = JSON.stringify(events.length ? [events.length, events[events.length - 1]] : []);
    if (sig === live.sig) return;
    live.sig = sig;
    const feed = $("liveFeed");
    const pinned = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 60;
    feed.innerHTML = "";
    if (!events.length) feed.append(el("p", "muted small", "Nothing yet. When Marty works at the PC, it shows up here."));
    events.forEach(ev => {
      if (ev.kind === "say") {
        const say = el("div", "live-say");
        say.append(el("span", "live-time", liveClock(ev.ts)), el("div", "live-text", ev.text));
        feed.append(say);
      } else {
        const step = el("div", "live-step");
        step.append(el("span", "step-dot"), el("span", "step-text", ev.text),
                     el("span", "step-n", ev.count > 1 ? ` ×${ev.count}` : ""), el("span", "live-time", liveClock(ev.ts)));
        feed.append(step);
      }
    });
    if (pinned) feed.scrollTop = feed.scrollHeight;
  }
  async function refreshLive() {
    if (live.busy) return;
    live.busy = true;
    try { renderLive(await request("/api/live")); }
    catch (error) { if (error.status !== 401 && $("liveMeta")) $("liveMeta").textContent = "Can't reach the PC's session right now."; }
    finally { live.busy = false; }
  }
  if ($("liveHead")) $("liveHead").addEventListener("click", () => {
    live.open = !live.open;
    lsSet("marty.live.open", live.open ? "1" : null);
    live.sig = "";
    liveUi();
    refreshLive();
  });
  liveUi();
  setInterval(() => {
    if (document.hidden || state.view !== "jobs" || !state.entered) return;
    live.tick++;
    if (live.open || live.tick % 5 === 0) refreshLive();
  }, 3000);

  // One row: what, then who · where · state. Live rows and board rows share it.
  function workRow(what, who, where, state, extraClass, detail) {
    const row = el("div", "job-row board-row" + (extraClass ? " " + extraClass : ""));
    const top = el("div", "board-row-top");
    top.append(el("span", "board-dot"), el("b", "", what));
    const meta = el("small", "board-meta");
    meta.append(el("span", "board-who", who || "?"));
    [where, state].filter(Boolean).forEach(part => meta.append(document.createTextNode(" · " + part)));
    row.append(top, meta);
    if (detail) { const p = el("p", "board-detail small"); p.append(richText(detail)); row.append(p); }
    return row;
  }
  function liveRow(job) {
    const who = job.lane != null ? (LANES[job.lane] ? `Marty · ${LANES[job.lane]}` : "Marty") : (job.who || job.source);
    let state = job.state || "running";
    if (job.last_step && job.started) state = `${state} · ${relTime(job.started)}`;
    return workRow(job.name, who, job.where || job.source, state, job.last_step ? "live pc" : "live");
  }

  // The last board that read cleanly. A bad read (Marty mid-edit, a file that fails validation)
  // keeps showing it, marked stale, instead of wiping the cards and any half-typed note.
  let lastGoodBoard = null;

  function renderJobs(data) {
    const fresh = data.board && typeof data.board === "object" ? data.board : {ok: false, error: "no board in the reply"};
    if (fresh.ok) lastGoodBoard = fresh;
    const board = fresh.ok ? fresh : (lastGoodBoard || {waiting: [], work: [], done: []});
    renderWaiting(data.waiting_on_you, Array.isArray(board.waiting) ? board.waiting : []);
    const work = Array.isArray(board.work) ? board.work : [];
    const live = Array.isArray(data.running) ? data.running : [];
    const boardRunning = work.filter(w => w.state === "running");
    const queued = work.filter(w => w.state !== "running");
    const today = new Date().toDateString();
    const done = (Array.isArray(board.done) ? board.done : []).filter(x => new Date(x.at).toDateString() === today);
    const box = id => { const node = $(id); if (node) node.innerHTML = ""; return node; };   // null-safe

    const running = box("jobsList"), rail = box("railJobs");
    if (running) {
      live.forEach(job => running.append(liveRow(job)));
      boardRunning.forEach(w => running.append(workRow(w.what, w.who, w.where, w.eta || "running", "", w.detail)));
      if (!running.children.length) running.append(el("div", "card muted", "Nothing is running right now."));
    }
    if (rail) {
      live.concat(boardRunning).forEach(row => {
        const item = el("div", "rail-item");
        item.append(el("b", "", row.name || row.what), el("small", "", [row.lane != null ? "Marty" : row.who, row.where].filter(Boolean).join(" · ")));
        rail.append(item);
      });
      if (!rail.children.length) rail.append(el("p", "muted", "Nothing running."));
    }

    const q = box("jobsQueued");
    if (q) {
      queued.forEach(w => q.append(workRow(w.what, w.who, w.where,
        [w.state === "blocked" ? "blocked" : "", w.eta].filter(Boolean).join(", "), w.state === "blocked" ? "blocked" : "queued", w.detail)));
      if (!queued.length) q.append(el("p", "muted", lastGoodBoard ? "Nothing queued." : "The board can't be read, so queued work isn't shown."));
    }

    const d = box("jobsDone");
    if (d) {
      done.forEach(x => d.append(workRow(x.what, x.who, x.where, boardWhen(x.at), "done", x.detail)));
      if (!done.length) d.append(el("p", "muted", "Nothing closed out yet today."));
    }
    const doneCount = $("jobsDoneCount");
    if (doneCount) doneCount.textContent = done.length ? `(${done.length})` : "";

    const open = lastWaiting.alerts.length + lastWaiting.items.filter(item => !answerOf(item)).length;
    const tally = box("boardTally");
    if (tally) {
      [[open, "waiting on you", "you"], [live.length + boardRunning.length, "running", "run"],
       [queued.length, "queued", "queued"], [done.length, "done today", "done"]].forEach(([n, label, kind]) => {
        const chip = el("span", `board-chip ${kind}`);
        chip.append(el("b", "", String(n)), document.createTextNode(" " + label));
        tally.append(chip);
      });
    }
    const asOf = $("boardAsOf");
    if (asOf) {
      asOf.textContent = fresh.ok
        ? `Board updated ${boardWhen(board.as_of)}${board.note ? ". " + board.note : ""}. Live rows checked just now.`
        : lastGoodBoard
          ? `The board can't be read right now (${fresh.error}). Showing the last good copy (updated ${boardWhen(lastGoodBoard.as_of)}); live rows are current.`
          : `The board can't be read right now (${fresh.error}). Live rows below still work.`;
    }
  }

  async function refreshFiles() { try { renderFiles(await request("/api/files")); } catch (_) {} }
  function renderFiles(rows) {
    $("filesList").innerHTML = rows.length ? "" : "<div class='card muted'>No files waiting.</div>";
    $("railFiles").innerHTML = rows.length ? "" : "<p class='muted'>No files waiting.</p>";
    rows.forEach(file => {
      const row = el("div", "file-row"), info = el("div"), name = el("b", "", file.name);
      const meta = el("small", "", `${Math.max(1, Math.round(file.bytes / 1024))} KB`);
      const link = el("a", "", "Download");
      info.append(name, meta);
      link.href = `/api/files/${file.id}`;
      row.append(info, link);
      $("filesList").append(row);
      const rail = el("div", "rail-item");
      rail.append(name.cloneNode(true), meta.cloneNode(true));
      $("railFiles").append(rail);
    });
  }
  $("refreshJobs").addEventListener("click", refreshJobs);
  $("refreshFiles").addEventListener("click", refreshFiles);

  // ---------- More: status, spend, activity ----------

  function fmtTime(iso) {
    if (!iso) return "";
    const date = new Date(iso);
    return isNaN(date.getTime()) ? String(iso) : date.toLocaleString();
  }
  function relTime(iso) {
    const then = new Date(iso).getTime();
    if (isNaN(then)) return "";
    const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
    if (secs < 5) return "just now";
    if (secs < 60) return secs + "s ago";
    const mins = Math.round(secs / 60);
    if (mins < 60) return mins + "m ago";
    const hours = Math.round(mins / 60);
    return hours < 48 ? hours + "h ago" : Math.round(hours / 24) + "d ago";
  }
  function card(title) {
    const box = el("div", "card");
    if (title) box.append(el("h3", "", title));
    return box;
  }
  function badge(kind, text) { return el("span", `badge ${kind}`, text); }
  function entryList(items, emptyText) {
    if (!items || !items.length) return el("p", "muted", emptyText);
    const list = el("ul", "entry-list");
    items.forEach(item => {
      const li = el("li");
      if (item.time) li.append(el("time", "", fmtTime(item.time)));
      li.append(document.createTextNode(item.text || ""));
      list.append(li);
    });
    return list;
  }
  function meter(percent) {
    const track = el("div", "meter"), fill = el("i");
    fill.style.width = Math.max(0, Math.min(100, Number(percent) || 0)) + "%";
    track.append(fill);
    return track;
  }
  function panelError(panel, message) {
    panel.innerHTML = "";
    panel.append(el("div", "card muted", message));
  }

  function showMore(name) {
    if (!["status", "spend", "activity"].includes(name)) name = "status";
    state.more = name;
    document.querySelectorAll("[data-more]").forEach(tab => {
      const on = tab.dataset.more === name;
      tab.classList.toggle("active", on);
      tab.setAttribute("aria-selected", String(on));
    });
    document.querySelectorAll(".more-panel").forEach(panel => { panel.hidden = panel.id !== "more-" + name; });
    refreshMore();
  }

  function refreshMore() {
    if (state.more === "spend") return refreshSpend();
    if (state.more === "activity") return refreshActivity();
    return refreshStatus();
  }
  $("refreshMore").addEventListener("click", () => refreshMore());

  function backupBadge(backup) {
    if (!backup || !backup.available) return badge("bad", "backup log unavailable");
    const text = (backup.lines || []).join(" ").toLowerCase();
    if (text.includes("error") || text.includes("fail")) return badge("bad", "backup errors detected");
    if (text.includes("finish") || text.includes("complet") || text.includes("success")) return badge("good", "backup healthy");
    return badge("quiet", "backup status unclear");
  }
  // Three states, never two: a check that could not run is not drift.
  function voiceBadge(voice) {
    if (!voice || !voice.available) return badge("quiet", "voice: never checked");
    if (voice.stale) return badge("quiet", "voice: not checked recently");
    if (voice.state === "ok") return badge("good", "voice: Marty");
    if (voice.state === "drifted") return badge("bad", "voice: drifted");
    return badge("quiet", "voice: unverified");
  }
  function routineKind(status) {
    const s = (status || "").toLowerCase();
    if (s.includes("fail") || s.includes("error")) return "bad";
    if (!s || s.includes("unknown")) return "quiet";
    if (s.includes("warn") || s.includes("pending")) return "warn";
    if (s.includes("success") || s.includes("ok") || s.includes("complet") || s.includes("run")) return "good";
    return "quiet";
  }

  async function refreshStatus() {
    const panel = $("more-status");
    let data;
    try { data = await request("/api/status"); }
    catch (error) { panelError(panel, `Status unavailable: ${error.message}`); return; }
    const status = data.status || {};
    panel.innerHTML = "";

    const now = card("Right now");
    now.append(el("p", "", status.error ? `Status file error: ${status.error}` : (status.right_now || "Nothing set.")));
    now.append(el("small", "muted", `Server time ${fmtTime(data.server_time)}`));
    panel.append(now);

    const task = status.current_task;
    if (task && task.label) {
      const box = card("Current task");
      box.append(el("p", "", task.label), meter(task.percent), el("small", "muted", `${Math.max(0, Math.min(100, Number(task.percent) || 0))}%`));
      if (task.steps && task.steps.length) {
        const steps = el("ul", "steps");
        task.steps.forEach(step => {
          const kind = step.status || "pending";
          const li = el("li", kind);
          li.append(el("span", "mark", kind === "done" ? "✓" : kind === "active" ? "→" : "○"), el("span", "", step.label || ""));
          steps.append(li);
        });
        box.append(steps);
      }
      panel.append(box);
    }

    const health = el("div", "card-grid");
    const backup = card("Backups");
    backup.append(backupBadge(data.backup_log));
    const lines = (data.backup_log && data.backup_log.lines) || [];
    if (lines.length) backup.append(el("p", "muted small", lines[lines.length - 1]));
    else if (data.backup_log && data.backup_log.error) backup.append(el("p", "muted small", data.backup_log.error));
    const voice = card("Voice check");
    voice.append(voiceBadge(data.voice));
    const v = data.voice || {};
    const detail = v.available ? (v.state === "ok" && !v.stale ? "" : v.reason || "") : v.error || "";
    if (detail) voice.append(el("p", "muted small", detail));
    if (v.available && v.ts) voice.append(el("p", "muted small", `Last checked ${fmtTime(v.ts)}`));
    health.append(backup, voice);
    panel.append(health);

    // The status file names its owner in this key; it is matched by prefix so the public
    // shell carries no name.
    const waitingKey = Object.keys(status).find(key => key.indexOf("waiting_on_") === 0);
    const waiting = card("Waiting on you");
    waiting.append(entryList(waitingKey ? status[waitingKey] : [], "Nothing pending."));
    panel.append(waiting);

    const done = card("Done recently");
    done.append(entryList(status.done, "Nothing logged yet."));
    panel.append(done);

    const routines = card("Scheduled routines");
    const list = status.scheduled_routines || [];
    if (!list.length) routines.append(el("p", "muted", "No scheduled routines reported."));
    list.forEach(routine => {
      const row = el("div", "routine");
      row.append(el("b", "", routine.name || "Unnamed routine"), badge(routineKind(routine.status), routine.status || "unknown"));
      const bits = [];
      if (routine.last_run) bits.push(`last run ${fmtTime(routine.last_run)}`);
      if (routine.next_run) bits.push(`next run ${fmtTime(routine.next_run)}`);
      if (bits.length) row.append(el("small", "muted", bits.join(" · ")));
      if (routine.note) row.append(el("small", "muted", routine.note));
      routines.append(row);
    });
    panel.append(routines);
  }

  function spendRows(rows, total, named) {
    if (!rows || !rows.length) return el("p", "muted", "No priced calls logged yet.");
    const box = el("div");
    rows.forEach(row => {
      const line = el("div", "spend-row");
      const share = total > 0 ? Math.max(0, Math.min(100, (row.cost / total) * 100)) : 0;
      line.append(el("span", "", named ? (SPEND_NAMES[row.name] || row.name) : row.name), meter(share),
                  el("span", "amount", "$" + Number(row.cost || 0).toFixed(4)));
      box.append(line);
    });
    return box;
  }

  async function refreshSpend() {
    const panel = $("more-spend");
    const days = new Date().getDate();   // days so far this month, as a rolling window
    let data;
    try { data = await request(`/api/spend?days=${days}`); }
    catch (error) { panelError(panel, `Spend unavailable: ${error.message}`); return; }
    panel.innerHTML = "";
    const month = new Date().toLocaleString("en-US", {month: "long"});
    const head = card(`Spend · ${month}`);
    head.append(el("div", "spend-total", "$" + Number(data.total || 0).toFixed(4)));
    head.append(el("small", "muted", `Last ${data.days} day(s) · ${data.calls} call(s) · ${data.unpriced_calls || 0} unpriced. A plain meter reading, not a budget.`));
    panel.append(head);
    const byLane = card("By lane");
    byLane.append(spendRows(data.by_brain, data.total, true));
    panel.append(byLane);
    const byProject = card("By project");
    byProject.append(spendRows(data.by_project, data.total, false));
    panel.append(byProject);
  }

  async function refreshActivity() {
    const panel = $("more-activity");
    let data;
    try { data = await request("/api/activity?limit=30"); }
    catch (error) { panelError(panel, `Activity unavailable: ${error.message}`); return; }
    panel.innerHTML = "";
    const rows = data.rows || [];
    if (!rows.length) { panel.append(el("div", "card muted", "No activity logged yet.")); return; }
    panel.append(el("p", "muted small", "Real tool calls, logged the moment each one happens. Newest first."));
    rows.forEach(row => {
      const line = el("div", "activity-row");
      const tool = String(row.tool || "?");
      const name = el("span", "a-tool", tool.split("__").pop());
      name.title = tool;
      line.append(name, el("span", "a-summary", row.summary || ""), el("span", "a-time", relTime(row.ts)));
      panel.append(line);
    });
  }

  // ---------- attachments: chunked, resumable uploads ----------
  // Engine ported from the previous dashboard's upload.js, same wire format:
  // POST /api/upload one slice per request (X-Filename, X-Upload-Id, X-Upload-Offset,
  // X-Upload-Total, X-Chunk-SHA256), GET /api/upload/status?id=, POST /api/upload/abort,
  // /api/upload/note and /api/upload/transcribe. The id is a SHA-256 fingerprint of the
  // file (name, size, lastModified, first and last 1 MiB), so picking the same file again
  // resumes where the PC left off. Slices start at 8 MiB, halve to 1 MiB on a failure and
  // double back after three clean slices; retries back off 1, 2, 4, 8, 16, 30 s.
  const Intake = (() => {
    const CHUNK_MAX = 8 * 1024 * 1024, CHUNK_MIN = 1024 * 1024, CLEAN_SLICES_TO_DOUBLE = 3;
    const EDGE_BYTES = 1024 * 1024, BACKOFF_SECONDS = [1, 2, 4, 8, 16, 30], BACKOFF_CEILING = 30;
    const IN_FLIGHT_WAIT_MS = 2000, DISK_FULL_WAIT_SECONDS = 30, POLL_MS = 5000;
    const STALL_MS = 60000, RESPONSE_MS = 300000, RATE_WINDOW_MS = 5000, PROGRESS_EMIT_MS = 150;
    const TOGGLE_KEY = "marty.intake.transcribe", ID_RE = /^[a-f0-9]{64}$/;
    const SESSION_MSG = "Session expired. Log in again, then pick the same file to resume.";
    const NO_SUBTLE_MSG = "This browser cannot hash files here (crypto.subtle is unavailable). Open the dashboard over https.";
    let active = null;

    const now = () => Date.now();
    const noop = () => {};
    const logErr = e => { try { console.error("Intake:", e); } catch (_) {} };
    function parseJson(text) {
      if (typeof text !== "string" || !text) return null;
      try { const v = JSON.parse(text); return (v && typeof v === "object") ? v : null; } catch (_) { return null; }
    }
    function clampInt(v, lo, hi) { v = Number(v); if (!isFinite(v)) return lo; return Math.max(lo, Math.min(hi, Math.floor(v))); }
    function backoffSeconds(attempt) {
      attempt = Math.max(0, Math.floor(attempt || 0));
      return attempt < BACKOFF_SECONDS.length ? BACKOFF_SECONDS[attempt] : BACKOFF_CEILING;
    }
    function isCellular() { try { return !!(navigator.connection && navigator.connection.type === "cellular"); } catch (_) { return false; } }
    function getTranscribeDefault() { return lsGet(TOGGLE_KEY) === "1"; }

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
      const s = Math.round(seconds);
      if (s < 5) return "a few seconds";
      if (s < 60) return s + " s";
      if (s < 3600) return Math.round(s / 60) + " min";
      let h, m, d;
      if (s < 86400) { h = Math.floor(s / 3600); m = Math.round((s % 3600) / 60); if (m === 60) { h += 1; m = 0; } return h + " h" + (m ? " " + m + " min" : ""); }
      d = Math.floor(s / 86400); h = Math.round((s % 86400) / 3600); if (h === 24) { d += 1; h = 0; }
      return d + " d" + (h ? " " + h + " h" : "");
    }

    function subtle() {
      try { const c = typeof crypto !== "undefined" ? crypto : null; return (c && c.subtle && typeof c.subtle.digest === "function") ? c.subtle : null; }
      catch (_) { return null; }
    }
    function hex(buffer) { const b = new Uint8Array(buffer); let s = ""; for (let i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16); return s; }
    function readBuffer(blob) {
      if (typeof blob.arrayBuffer === "function") return blob.arrayBuffer();
      return new Promise((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(r.result);
        r.onerror = () => reject(r.error || new Error("read failed"));
        r.readAsArrayBuffer(blob);
      });
    }
    async function sha256Hex(bytes) { const s = subtle(); if (!s) throw new Error(NO_SUBTLE_MSG); return hex(await s.digest("SHA-256", bytes)); }
    async function fingerprint(file) {
      if (!subtle()) throw new Error(NO_SUBTLE_MSG);
      const size = file.size, enc = new TextEncoder(), sep = enc.encode("|");
      const head = new Uint8Array(await readBuffer(file.slice(0, Math.min(EDGE_BYTES, size))));
      const tail = new Uint8Array(await readBuffer(file.slice(Math.max(0, size - EDGE_BYTES), size)));
      const parts = [enc.encode(String(file.name == null ? "" : file.name)), sep, enc.encode(String(size)), sep,
                     enc.encode(String(file.lastModified)), sep, head, sep, tail];
      let len = 0;
      parts.forEach(p => { len += p.length; });
      const buf = new Uint8Array(len);
      let pos = 0;
      parts.forEach(p => { buf.set(p, pos); pos += p.length; });
      return sha256Hex(buf);
    }
    function readFailMessage(e) {
      const msg = (e && e.message) || "";
      if (msg === NO_SUBTLE_MSG) return msg;
      const name = (e && e.name) || "";
      if (name === "NotReadableError" || name === "NotFoundError") {
        return "Could not read the file: the browser lost access to it. Pick the same file again and the upload resumes where it stopped.";
      }
      return "Could not read the file" + (msg ? " (" + msg + ")" : "") + ". Pick it again to resume.";
    }

    function httpError(message, status, fatal) { const e = new Error(message); e.status = status || 0; e.fatal = !!fatal; return e; }
    function checkId(id) { if (typeof id !== "string" || !ID_RE.test(id)) throw httpError("bad upload id", 0, true); }

    async function getStatus(id) {
      let res;
      try { res = await fetch("/api/upload/status?id=" + encodeURIComponent(id), {method: "GET", cache: "no-store", credentials: "same-origin"}); }
      catch (_) { throw httpError("network error", 0, false); }
      let text = "";
      try { text = await res.text(); } catch (_) { throw httpError("network error", 0, false); }
      const json = parseJson(text);
      if (res.status === 401) throw httpError(SESSION_MSG, 401, true);
      if (res.status === 400 || res.status === 403) throw httpError((json && json.error) || ("HTTP " + res.status), res.status, true);
      if (!res.ok || !json) throw httpError("HTTP " + res.status, res.status, false);
      return json;
    }
    async function postJson(url, body) {
      const init = {method: "POST", cache: "no-store", credentials: "same-origin"};
      if (body !== undefined) { init.headers = {"Content-Type": "application/json"}; init.body = JSON.stringify(body); }
      let res;
      try { res = await fetch(url, init); } catch (_) { throw httpError("Dashboard unreachable", 0, false); }
      let text = "";
      try { text = await res.text(); } catch (_) { text = ""; }
      const json = parseJson(text);
      if (res.status === 401) throw httpError(SESSION_MSG, 401, true);
      if (!res.ok || (json && json.error)) throw httpError((json && json.error) || ("HTTP " + res.status), res.status, res.status >= 400 && res.status < 500);
      return json || {ok: true};
    }
    function postAbort(id) {
      try { fetch("/api/upload/abort?id=" + encodeURIComponent(id), {method: "POST", cache: "no-store", credentials: "same-origin", keepalive: true}).catch(noop); }
      catch (_) { /* the page is going away; the server's stale-part sweep cleans up */ }
    }
    async function saveNote(id, text) { checkId(id); return postJson("/api/upload/note?id=" + encodeURIComponent(id), {note: String(text == null ? "" : text)}); }
    async function transcribe(id) { checkId(id); return postJson("/api/upload/transcribe?id=" + encodeURIComponent(id)); }

    function pollStatus(id, cb) {
      let stopped = false, timer = null, nullTicks = 0;
      const handle = {stop() { stopped = true; if (timer) { clearTimeout(timer); timer = null; } }};
      const schedule = () => { if (!stopped) timer = setTimeout(tick, POLL_MS); };
      async function tick() {
        timer = null;
        if (stopped) return;
        let st = null;
        try { checkId(id); st = await getStatus(id); }
        catch (e) {
          if (e && e.fatal) { stopped = true; try { cb({error: e.message, transcript: null}); } catch (x) { logErr(x); } return; }
          schedule(); return;
        }
        if (stopped) return;
        try { cb(st); } catch (e) { logErr(e); }
        const t = st.transcript, s = t && t.state;
        if (s === "queued" || s === "running") { schedule(); return; }
        if (!t && nullTicks < 6) { nullTicks += 1; schedule(); return; }
        stopped = true;
      }
      tick();
      return handle;
    }

    function emit(job, stateName, extra) {
      const done = typeof job.progress === "number" ? job.progress : 0;
      const rate = stateName === "uploading" ? job.rate : 0;
      const eta = (stateName === "uploading" && rate > 0) ? Math.max(0, (job.total - done) / rate) : null;
      const o = {state: stateName, id: job.id, name: job.file.name, lane: job.lane, done, total: job.total, rate, eta,
                 chunk: job.chunk, attempt: job.attempt, message: "", cancel: job.handle.cancel};
      if (extra) Object.assign(o, extra);
      try { job.onState(o); } catch (e) { logErr(e); }
    }
    const emitUploading = (job, message) => emit(job, "uploading", {message});
    function resetRate(job) { job.samples = []; job.rate = 0; }
    function noteProgress(job, bytes) {
      const t = now();
      job.samples.push({t, b: bytes});
      while (job.samples.length > 2 && t - job.samples[0].t > RATE_WINDOW_MS) job.samples.shift();
      const first = job.samples[0], last = job.samples[job.samples.length - 1], span = last.t - first.t;
      if (span >= 500 && last.b >= first.b) job.rate = (last.b - first.b) * 1000 / span;
    }
    function shrink(job) { job.chunk = Math.max(CHUNK_MIN, Math.floor(job.chunk / 2)); job.clean = 0; resetRate(job); }
    function grow(job) {
      job.clean += 1;
      if (job.clean >= CLEAN_SLICES_TO_DOUBLE && job.chunk < CHUNK_MAX) { job.chunk = Math.min(CHUNK_MAX, job.chunk * 2); job.clean = 0; }
    }
    // A wait the job can be pulled out of: cancel() breaks every wait; "online" and the tab
    // becoming visible break only the retry backoff. Resolves true when broken early.
    function sleep(job, ms, interruptible) {
      return new Promise(resolve => {
        const timer = setTimeout(() => done(false), ms);
        function done(early) { clearTimeout(timer); job.breakSleep = null; job.wakeRetry = null; resolve(early); }
        job.breakSleep = () => done(true);
        job.wakeRetry = interruptible ? () => done(true) : null;
      });
    }
    async function countdownWait(job, stateName, reason, seconds, interruptible) {
      const until = now() + seconds * 1000;
      while (!job.finished) {
        const leftMs = until - now();
        if (leftMs <= 0) return;
        const left = Math.ceil(leftMs / 1000);
        emit(job, stateName, {message: reason + ", retrying in " + left + " s", retryIn: left});
        if (await sleep(job, Math.min(1000, leftMs), interruptible)) return;
      }
    }
    async function retryWait(job, reason) { const secs = backoffSeconds(job.attempt); job.attempt += 1; await countdownWait(job, "retrying", reason, secs, true); }
    async function acquireWakeLock(job) {
      if (job.finished) return;
      const wl = navigator.wakeLock;
      if (!wl || typeof wl.request !== "function") return;
      if (job.wakeLock && !job.wakeLock.released) return;
      try { job.wakeLock = await wl.request("screen"); } catch (_) { job.wakeLock = null; }
      if (job.finished) releaseWakeLock(job);
    }
    function releaseWakeLock(job) {
      const w = job.wakeLock;
      job.wakeLock = null;
      if (!w) return;
      try { const p = w.release(); if (p && typeof p.catch === "function") p.catch(noop); } catch (_) {}
    }
    function addListeners(job) {
      job.onOnline = () => { if (job.wakeRetry) job.wakeRetry(); };
      job.onVisible = () => { if (document.visibilityState === "visible") { acquireWakeLock(job); if (job.wakeRetry) job.wakeRetry(); } };
      window.addEventListener("online", job.onOnline);
      document.addEventListener("visibilitychange", job.onVisible);
    }
    function removeListeners(job) {
      if (job.onOnline) window.removeEventListener("online", job.onOnline);
      if (job.onVisible) document.removeEventListener("visibilitychange", job.onVisible);
      job.onOnline = null; job.onVisible = null;
    }
    function cleanup(job) { removeListeners(job); releaseWakeLock(job); job.xhr = null; if (active === job) active = null; }
    function succeed(job, payload) {
      if (job.finished) return;
      job.finished = true;
      cleanup(job);
      const out = Object.assign({id: job.id, name: job.file.name}, payload, {transcribeDefault: getTranscribeDefault()});
      if (out.duplicate !== true) out.duplicate = false;
      if (!out.id) out.id = job.id;
      job.progress = job.total;
      emit(job, "done", {message: out.duplicate ? "Already on the PC" : "Saved on the PC", done: job.total, result: out});
      try { job.onDone(out); } catch (e) { logErr(e); }
    }
    function fail(job, message) {
      if (job.finished) return;
      job.finished = true;
      cleanup(job);
      emit(job, "failed", {message});
      try { job.onError(message); } catch (e) { logErr(e); }
    }
    function cancelJob(job) {
      if (job.finished) return;
      job.cancelled = true; job.finished = true;
      if (job.xhr) { try { job.xhr.abort(); } catch (_) {} }
      if (job.breakSleep) job.breakSleep();
      if (job.confirmResolve) { const r = job.confirmResolve; job.confirmResolve = null; r(false); }
      cleanup(job);
      // No id yet means nothing was ever sent, so there is nothing on the PC to drop.
      if (job.id) postAbort(job.id);
      emit(job, "cancelled", {message: "Cancelled"});
    }
    function confirmCellular(job) {
      return new Promise(resolve => {
        job.confirmResolve = resolve;
        emit(job, "confirm-cellular", {message: "Upload " + fmtBytes(job.total) + " over mobile data?",
          proceed() { const r = job.confirmResolve; job.confirmResolve = null; if (r) r(true); }});
      });
    }
    function serverText(json, r, status) {
      if (json && json.error) return String(json.error);
      const plain = (r && r.text) ? r.text.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 200) : "";
      return "HTTP " + status + (plain ? ": " + plain : "");
    }
    // One slice, one XMLHttpRequest: upload.onprogress shows movement inside a slice on a
    // slow relay, which is the phone's normal path. Rejects on a network error, a stall, a
    // missing reply after all bytes were sent, or a cancel.
    function sendSlice(job, slice, offset, sha) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest(), end = offset + slice.size;
        let lastActivity = now(), sentAt = 0, reason = "", lastEmit = 0, watchdog = null;
        job.xhr = xhr;
        function settle(fn, value) { if (watchdog) { clearInterval(watchdog); watchdog = null; } if (job.xhr === xhr) job.xhr = null; fn(value); }
        xhr.open("POST", "/api/upload", true);
        xhr.setRequestHeader("X-Filename", encodeURIComponent(job.file.name));
        xhr.setRequestHeader("X-Upload-Id", job.id);
        xhr.setRequestHeader("X-Upload-Offset", String(offset));
        xhr.setRequestHeader("X-Upload-Total", String(job.total));
        if (sha) xhr.setRequestHeader("X-Chunk-SHA256", sha);
        xhr.setRequestHeader("Content-Type", "application/octet-stream");
        xhr.upload.onprogress = ev => {
          lastActivity = now();
          const loaded = (ev && ev.lengthComputable) ? ev.loaded : 0;
          const done = Math.min(end, offset + loaded);
          job.progress = done;
          noteProgress(job, done);
          if (now() - lastEmit >= PROGRESS_EMIT_MS) { lastEmit = now(); emitUploading(job, "Uploading"); }
        };
        xhr.upload.onload = () => {
          sentAt = now(); lastActivity = sentAt; job.progress = end; noteProgress(job, end);
          emitUploading(job, end >= job.total ? "All bytes sent, the PC is verifying the checksum" : "Waiting for the PC to confirm the slice");
        };
        xhr.onload = () => settle(resolve, {status: xhr.status, text: xhr.responseText || ""});
        xhr.onerror = () => settle(reject, new Error("network error"));
        xhr.ontimeout = () => settle(reject, new Error("timeout"));
        xhr.onabort = () => settle(reject, new Error(job.cancelled ? "cancelled" : (reason || "aborted")));
        watchdog = setInterval(() => {
          const t = now();
          if (!sentAt && t - lastActivity > STALL_MS) { reason = "stalled"; try { xhr.abort(); } catch (_) {} }
          else if (sentAt && t - sentAt > RESPONSE_MS) { reason = "no response"; try { xhr.abort(); } catch (_) {} }
        }, 5000);
        try { xhr.send(slice); } catch (e) { settle(reject, e); }
      });
    }

    async function run(job) {
      await Promise.resolve();   // let start() return before the first callback
      if (job.finished) return;
      try {
        if (job.total <= 0) return fail(job, "The file is empty (0 bytes), nothing to upload.");
        if (isCellular()) { const go = await confirmCellular(job); if (!go || job.finished) return; }
        emit(job, "hashing", {message: "Fingerprinting " + job.file.name});
        try { job.id = await fingerprint(job.file); } catch (e) { return fail(job, readFailMessage(e)); }
        if (job.finished) return;
        acquireWakeLock(job);
        let needSync = true, initial = true;
        while (!job.finished) {
          if (needSync) {
            let st;
            try { st = await getStatus(job.id); }
            catch (e) { if (job.finished) return; if (e.fatal) return fail(job, e.message); await retryWait(job, "Connection dropped"); continue; }
            if (job.finished) return;
            needSync = false;
            if (st.done) return succeed(job, Object.assign({}, st, {duplicate: initial}));
            const have = clampInt(st.bytes, 0, job.total);
            initial = false;
            job.offset = have; job.progress = have;
            resetRate(job);
            emitUploading(job, have > 0 ? "Resuming from " + fmtBytes(have) : "Uploading");
          }
          const end = Math.min(job.offset + job.chunk, job.total);
          const slice = job.file.slice(job.offset, end);
          let sha = null;
          try { sha = await sha256Hex(await readBuffer(slice)); }
          catch (e) { if (job.finished) return; return fail(job, readFailMessage(e)); }
          if (job.finished) return;
          let r;
          try { r = await sendSlice(job, slice, job.offset, sha); }
          catch (_) { if (job.finished) return; shrink(job); needSync = true; await retryWait(job, "Connection dropped"); continue; }
          if (job.finished) return;
          const json = parseJson(r.text), s = r.status;
          if (s === 200 && json && json.ok === true) {
            job.attempt = 0; job.bad422 = 0;
            if (json.done === true) return succeed(job, Object.assign({}, json, {duplicate: false}));
            job.offset = typeof json.bytes === "number" ? clampInt(json.bytes, 0, job.total) : end;
            job.progress = job.offset;
            grow(job);
            continue;
          }
          if (s === 409) {
            if (json && json.error === "chunk in flight") {
              emit(job, "retrying", {message: "The PC is still writing the previous slice, retrying in 2 s", retryIn: 2});
              await sleep(job, IN_FLIGHT_WAIT_MS, false);
              if (job.finished) return;
            }
            if (json && typeof json.bytes === "number") { job.offset = clampInt(json.bytes, 0, job.total); job.progress = job.offset; resetRate(job); }
            else needSync = true;
            continue;
          }
          if (s === 422) {
            job.bad422 += 1;
            if (job.bad422 <= 2) emit(job, "retrying", {message: "Slice failed its checksum on the PC, re-sending", retryIn: 0});
            else { needSync = true; await retryWait(job, "Slice keeps failing its checksum on the PC"); }
            continue;
          }
          if (s === 401) return fail(job, SESSION_MSG);
          if (s === 507) { await countdownWait(job, "waiting-disk", "PC disk nearly full", DISK_FULL_WAIT_SECONDS, false); continue; }
          if (s === 413 || s === 400 || s === 403) return fail(job, serverText(json, r, s));
          // 5xx, any other status, or a 200 whose body is not JSON: treat as a dropped connection.
          shrink(job);
          needSync = true;
          await retryWait(job, s >= 500 ? "The PC answered HTTP " + s : (s === 200 ? "Garbled reply from the PC" : "Connection dropped"));
        }
      } catch (e) {
        logErr(e);
        fail(job, "Upload failed: " + ((e && e.message) || String(e)));
      }
    }

    function start(file, opts) {
      opts = opts || {};
      const handle = {cancel: noop};
      const onError = typeof opts.onError === "function" ? opts.onError : noop;
      if (!file || typeof file.slice !== "function" || typeof file.size !== "number") { setTimeout(() => onError("No file to upload."), 0); return handle; }
      if (active && !active.finished) { const busy = active.file.name; setTimeout(() => onError("Still uploading " + busy), 0); return handle; }
      const job = {file, total: file.size, lane: opts.lane || "",
                   onState: typeof opts.onState === "function" ? opts.onState : noop,
                   onDone: typeof opts.onDone === "function" ? opts.onDone : noop, onError,
                   id: null, offset: 0, progress: 0, chunk: CHUNK_MAX, clean: 0, attempt: 0, bad422: 0, rate: 0, samples: [],
                   xhr: null, wakeLock: null, breakSleep: null, wakeRetry: null, confirmResolve: null,
                   finished: false, cancelled: false, handle, onOnline: null, onVisible: null};
      handle.cancel = () => cancelJob(job);
      active = job;
      addListeners(job);
      run(job);
      return handle;
    }

    return {start, saveNote, transcribe, pollStatus, fmtBytes, fmtEta};
  })();

  function intakeButton(label, onClick) {
    const button = el("button", "", label);
    button.type = "button";
    button.addEventListener("click", onClick);
    return button;
  }

  function renderCard(s) {
    const box = $("intake");
    box.hidden = false;
    box.className = "intake" + (s.state === "failed" ? " failed" : s.state === "done" ? " done" : "");
    box.innerHTML = "";
    box.append(el("div", "intake-name", s.name || ""));
    if (typeof s.total === "number" && s.total > 0) {
      const bar = el("div", "intake-bar"), fill = el("span");
      fill.style.width = Math.max(0, Math.min(100, ((s.done || 0) / s.total) * 100)) + "%";
      bar.append(fill);
      box.append(bar);
      let meta = Intake.fmtBytes(s.done || 0) + " of " + Intake.fmtBytes(s.total);
      if (s.rate) meta += " · " + Intake.fmtBytes(s.rate) + "/s";
      if (s.eta != null && isFinite(s.eta)) meta += " · about " + Intake.fmtEta(s.eta) + " left";
      box.append(el("div", "intake-meta", meta));
    }
    if (s.message) box.append(el("div", "intake-meta", s.message));
    const actions = el("div", "intake-actions");
    if (s.state === "confirm-cellular") {
      actions.append(intakeButton("Upload over mobile data", () => s.proceed()), intakeButton("Cancel", () => s.cancel()));
    } else if (!["done", "failed", "cancelled"].includes(s.state) && state.upload) {
      actions.append(intakeButton("Cancel", () => state.upload.cancel()));
    } else if (s.state === "failed" || s.state === "cancelled") {
      actions.append(intakeButton("Dismiss", () => { box.hidden = true; }));
    }
    if (actions.childNodes.length) box.append(actions);
  }

  function renderReceipt(payload, lane, id) {
    const box = $("intake"), input = $("message");
    box.hidden = false;
    box.className = "intake done";
    box.innerHTML = "";
    const dup = !!payload.duplicate;
    box.append(el("div", "intake-name", (dup ? "Already on the PC: " : "") + (payload.name || "")));
    box.append(el("div", "intake-meta", (dup ? "" : "Saved on the PC (not synced, not backed up). Logged for Marty. ")
      + Intake.fmtBytes(payload.bytes || 0) + (payload.sha256 ? " · sha256 " + String(payload.sha256).slice(0, 12) : "")));
    // The path as a selectable field: clipboard writes are unreliable on a phone.
    const pathField = el("input");
    pathField.type = "text"; pathField.readOnly = true; pathField.value = payload.path || "";
    pathField.setAttribute("aria-label", "Saved path");
    pathField.addEventListener("focus", () => pathField.select());
    const pathRow = el("div", "intake-actions");
    pathRow.append(pathField);
    box.append(pathRow);
    // A note for Marty: explicit and visible, never sniffed from the chat. Never pre-filled
    // on the Local lane: notes are logged where the cloud lanes can read them.
    const note = el("input");
    note.type = "text"; note.placeholder = "note for Marty (what this is, what to do with it)";
    note.setAttribute("aria-label", "Note for Marty");
    note.value = lane === "local" ? "" : ((input && input.value.trim()) || "");
    const saveBtn = intakeButton("Save note", async () => {
      saveBtn.disabled = true;
      try { await Intake.saveNote(id, note.value.trim()); saveBtn.textContent = "Saved"; }
      catch (_) { saveBtn.disabled = false; saveBtn.textContent = "Save failed, retry"; }
    });
    const noteRow = el("div", "intake-actions");
    noteRow.append(note, saveBtn);
    box.append(noteRow);
    const actions = el("div", "intake-actions");
    const ext = ((payload.name || "").match(/\.[^.]+$/) || [""])[0].toLowerCase();
    if (MEDIA_EXTS.includes(ext)) {
      // Explicit, never automatic: transcription takes minutes per file on the PC.
      const tBtn = intakeButton("Transcribe", () => startTranscribe(id, tBtn));
      actions.append(tBtn);
    }
    actions.append(intakeButton("Ask Marty about it", () => {
      if (state.job) return;
      setLane("claude");
      input.value = "Read " + (payload.path || "") + " and ";
      fitComposer();
      input.focus();
    }));
    actions.append(intakeButton("Dismiss", () => { box.hidden = true; }));
    box.append(actions);
    const line = "Uploaded: " + (payload.name || "") + " (" + Intake.fmtBytes(payload.bytes || 0)
      + (payload.sha256 ? ", sha256 " + String(payload.sha256).slice(0, 12) : "") + ") -> " + (payload.path || "");
    input.value = (input.value ? input.value.trimEnd() + "\n" : "") + line + "\n";
    fitComposer();
    box.append(el("div", "intake-meta", lane === "claude"
      ? "Marty can open it in this lane (what he reads is sent to Claude)."
      : "This lane is talk-only. Marty on the Claude tools lane can open it, and the next Marty session finds it in the uploads log."));
    input.focus();
  }

  async function startTranscribe(id, button) {
    button.disabled = true; button.textContent = "Transcribing...";
    try { await Intake.transcribe(id); }
    catch (_) { button.disabled = false; button.textContent = "Transcribe (failed, retry)"; return; }
    if (state.transcriptPoll) state.transcriptPoll.stop();
    state.transcriptPoll = Intake.pollStatus(id, st => {
      const t = st && st.transcript;
      if (!t) return;
      if (t.state === "done") {
        button.textContent = "Transcript ready: " + (t.parts || "?") + " part(s)";
        const dir = t.dir || "";
        button.parentNode.append(intakeButton("Read the transcript with Marty", () => {
          if (state.job) return;
          setLane("claude");
          $("message").value = "Read " + dir + "/00-index.md and then " + dir + "/part-001.md";
          fitComposer();
          $("message").focus();
        }));
      } else if (t.state === "failed") {
        button.textContent = "Transcribe failed";
        $("intake").append(el("div", "intake-meta", t.error || "transcription failed"));
      } else {
        button.textContent = "Transcribing... (" + t.state + ")";
      }
    });
  }

  function startUpload(file) {
    if (state.upload) {
      renderCard({state: "uploading", name: state.upload.name, message: "Still uploading " + state.upload.name + ". Cancel it first to attach another file."});
      return;
    }
    const lane = state.lane;
    const job = {name: file.name, id: null, cancel: () => {}};
    state.upload = job;
    renderCard({state: "hashing", name: file.name, message: "Preparing..."});
    const handle = Intake.start(file, {
      lane,
      onState: s => { if (s.id) job.id = s.id; renderCard(Object.assign({name: file.name}, s)); },
      onDone: payload => { state.upload = null; renderReceipt(payload, lane, job.id || (payload && payload.id)); },
      onError: message => { state.upload = null; renderCard({state: "failed", name: file.name, message}); },
    });
    job.cancel = () => {
      try { handle.cancel(); } catch (_) {}
      state.upload = null;
      renderCard({state: "cancelled", name: file.name, message: "Cancelled. Nothing was kept."});
    };
  }

  $("attach").addEventListener("click", () => $("file").click());
  $("file").addEventListener("change", () => {
    const picker = $("file");
    if (picker.files && picker.files[0]) startUpload(picker.files[0]);
    picker.value = "";
  });
  ["dragenter", "dragover", "dragleave", "drop"].forEach(name =>
    $("chatView").addEventListener(name, event => { event.preventDefault(); event.stopPropagation(); }));
  $("chatView").addEventListener("drop", event => {
    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) startUpload(file);
  });

  // ---------- talk ----------

  async function startRecording() {
    if (state.recorder) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({audio: true});
      const type = MediaRecorder.isTypeSupported("audio/webm;codecs=opus") ? "audio/webm;codecs=opus" : "audio/webm";
      state.recorder = new MediaRecorder(stream, {mimeType: type});
      state.chunks = [];
      state.recorder.ondataavailable = e => { if (e.data.size) state.chunks.push(e.data); };
      state.recorder.onstop = () => submitAudio(type, stream);
      state.recorder.start();
      $("mic").classList.add("recording"); $("orb").classList.add("listening");
      $("talkHint").textContent = "listening on this device";
    } catch (error) { setCaption("Marty", `Microphone unavailable: ${error.message}`); }
  }
  function stopRecording() { if (state.recorder && state.recorder.state !== "inactive") state.recorder.stop(); }
  async function submitAudio(type, stream) {
    const blob = new Blob(state.chunks, {type});
    stream.getTracks().forEach(track => track.stop());
    state.recorder = null;
    $("mic").classList.remove("recording"); $("orb").classList.remove("listening");
    $("talkHint").textContent = "transcribing on this PC";
    try {
      const data = await request("/api/talk", {method: "POST", headers: {"Content-Type": type}, body: blob});
      $("talkHint").textContent = "hold to talk · tap for hands-free";
      if (data.text) sendChat(data.text, true); else setCaption("Marty", "I did not hear speech in that recording.");
    } catch (error) { setCaption("Marty", error.message); $("talkHint").textContent = "hold to talk · tap for hands-free"; }
  }
  $("mic").addEventListener("pointerdown", event => { event.preventDefault(); state.pressAt = performance.now(); if (!state.handsFree) startRecording(); });
  $("mic").addEventListener("pointerup", event => {
    event.preventDefault();
    const quick = performance.now() - state.pressAt < 300;
    if (quick) {
      if (state.handsFree) { state.handsFree = false; stopRecording(); }
      else { state.handsFree = true; if (!state.recorder) startRecording(); $("talkHint").textContent = "hands-free · tap to stop"; }
    } else if (!state.handsFree) stopRecording();
  });

  // ---------- dictation in Marty's chat (2026-09-26) ----------
  // Lukas's own version of Jr's microphone (and styled by its .jr-mic rules): tap to record, tap
  // again to stop. The recording goes to /api/talk, the same local Whisper as Talk, and the words
  // land in Marty's message box for him to edit. Unlike Talk, nothing is sent until he presses
  // Send, and nothing is kept in the browser. Leaving the chat or the app going to the background
  // stops the recording and still transcribes it, so what he said is not lost; closing the page
  // throws it away. One microphone at a time: it will not start while Talk's is on, and Jr's will
  // not start while this one is.
  const CHAT_MIC_MAX_MS = 5 * 60 * 1000;
  const CHAT_MIC_LABELS = {idle: "Dictate a message (transcribed on this PC)", asking: "Waiting for the microphone",
                           recording: "Stop and transcribe", sending: "Transcribing on this PC"};
  const chatMic = {phase: "idle", recorder: null, stream: null, chunks: [], gen: 0, timer: null, note: "", pending: null};
  function chatMicUi(phase) {
    chatMic.phase = phase;
    const button = $("chatMic");
    if (!button) return;
    button.classList.toggle("recording", phase === "recording");
    button.classList.toggle("working", phase === "asking" || phase === "sending");
    button.disabled = phase === "asking" || phase === "sending";
    button.setAttribute("aria-pressed", phase === "recording" ? "true" : "false");
    button.setAttribute("aria-label", CHAT_MIC_LABELS[phase]);
    button.title = CHAT_MIC_LABELS[phase];
  }
  function chatMicStatus(text, isError, retry) {
    const note = $("chatMicStatus");
    if (!note) return;
    note.textContent = text || "";
    if (retry) {
      const button = el("button", "mic-retry", "Try again");
      button.type = "button";
      button.addEventListener("click", chatMicRetry);
      note.append(" ", button);
    }
    note.hidden = !text;
    note.classList.toggle("error", !!isError);
  }
  function chatMicRelease() {
    if (!chatMic.stream) return;
    chatMic.stream.getTracks().forEach(track => { try { track.stop(); } catch (_) {} });
    chatMic.stream = null;
  }
  // Throw it all away: the recorder (without sending), the microphone and the recorded chunks.
  function chatMicReset() {
    chatMic.gen++;
    clearTimeout(chatMic.timer);
    const recorder = chatMic.recorder;
    chatMic.recorder = null;
    if (recorder) {
      recorder.ondataavailable = null; recorder.onstop = null;
      try { if (recorder.state !== "inactive") recorder.stop(); } catch (_) {}
    }
    chatMicRelease();
    chatMic.chunks = []; chatMic.note = ""; chatMic.pending = null;
    chatMicUi("idle");
    chatMicStatus("");
  }
  // Leaving the chat: a recording stops and is transcribed; a permission prompt still up is dropped.
  function chatMicLeave(note) {
    if (chatMic.phase === "recording") chatMicStop(note || "Stopped when you left the chat.");
    else if (chatMic.phase === "asking") chatMicReset();
  }

  async function chatMicStart() {
    if (chatMic.phase !== "idle") return;
    if (state.recorder) { chatMicStatus("Talk's microphone is still on. Stop it in the Talk tab first.", true); return; }
    if (!navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== "function" || typeof MediaRecorder === "undefined") {
      chatMicStatus(window.isSecureContext ? "This browser cannot record audio." : "The microphone works only on the dashboard's https address.", true);
      return;
    }
    const gen = ++chatMic.gen;
    chatMic.pending = null;                            // a new recording replaces one that failed to upload
    chatMicUi("asking");
    chatMicStatus("Waiting for the microphone...");
    let stream;
    try { stream = await navigator.mediaDevices.getUserMedia({audio: true}); }
    catch (error) {
      if (gen !== chatMic.gen) return;
      chatMicUi("idle");
      chatMicStatus(jrMicError(error), true);
      return;
    }
    // Reset, left the chat or hidden while the permission prompt was up: let go of the microphone at once.
    if (gen !== chatMic.gen || state.view !== "chat" || document.visibilityState !== "visible") {
      stream.getTracks().forEach(track => { try { track.stop(); } catch (_) {} });
      if (gen === chatMic.gen) { chatMicUi("idle"); chatMicStatus(""); }
      return;
    }
    const type = jrMicType();
    let recorder;
    try { recorder = type ? new MediaRecorder(stream, {mimeType: type}) : new MediaRecorder(stream); }
    catch (_) {
      stream.getTracks().forEach(track => { try { track.stop(); } catch (__) {} });
      chatMicUi("idle");
      chatMicStatus("This browser cannot record audio.", true);
      return;
    }
    chatMic.stream = stream; chatMic.recorder = recorder; chatMic.chunks = [];
    recorder.ondataavailable = event => { if (gen === chatMic.gen && event.data && event.data.size) chatMic.chunks.push(event.data); };
    recorder.onstop = () => chatMicSubmit(gen, recorder.mimeType || type || "audio/webm");
    recorder.start();
    chatMic.timer = setTimeout(() => { if (gen === chatMic.gen) chatMicStop("Stopped at 5 minutes."); }, CHAT_MIC_MAX_MS);
    chatMicUi("recording");
    chatMicStatus("Listening on this device. Tap the microphone again to stop.");
  }

  function chatMicStop(note) {
    clearTimeout(chatMic.timer);
    const recorder = chatMic.recorder;
    if (!recorder || recorder.state === "inactive") return;
    chatMic.note = note ? note + " " : "";             // why it stopped, kept for the final note
    chatMicUi("sending");
    chatMicStatus(chatMic.note + "Transcribing on this PC...");
    try { recorder.stop(); } catch (_) { chatMicReset(); }
  }

  async function chatMicSubmit(gen, mimeType) {
    clearTimeout(chatMic.timer);                       // a recorder that stopped by itself leaves no timer behind
    const chunks = chatMic.chunks;
    chatMic.chunks = []; chatMic.recorder = null;
    chatMicRelease();                                  // the microphone is off before the upload starts
    if (gen !== chatMic.gen) return;
    const type = String(mimeType).split(";")[0].trim().toLowerCase() || "audio/webm";
    const blob = new Blob(chunks, {type});
    if (!blob.size) { chatMicUi("idle"); chatMicStatus("Nothing was recorded. Try again.", true); return; }
    chatMicUpload(gen, blob, type, 0);
  }

  // One upload of a finished recording. The PC busy with another transcription (Talk, Jr, another
  // device) is tried again by itself, up to three times. Any other failure keeps the recording in
  // this page's memory (never in storage) behind a "Try again" button, until he records again,
  // taps it, or the page closes, so a dropped connection never costs him what he said.
  async function chatMicUpload(gen, blob, type, tries) {
    chatMic.pending = null;
    chatMicUi("sending");
    chatMicStatus(chatMic.note + "Transcribing on this PC...");
    let data = null, failure = "";
    try { data = await request("/api/talk", {method: "POST", headers: {"Content-Type": type}, body: blob}); }
    catch (error) { failure = error.message || "the request failed"; }
    if (gen !== chatMic.gen) return;                   // the page is going away
    if (failure && /already running/.test(failure) && tries < 3) {
      chatMicStatus(chatMic.note + "The PC is transcribing something else. Trying again in a few seconds...");
      chatMic.timer = setTimeout(() => { if (gen === chatMic.gen) chatMicUpload(gen, blob, type, tries + 1); }, 5000);
      return;
    }
    chatMicUi("idle");
    const why = chatMic.note;
    chatMic.note = "";
    if (failure) {
      chatMic.pending = {blob, type};
      chatMicStatus(`${why}Could not transcribe that: ${failure}. The recording is kept on this page.`, true, true);
      return;
    }
    const text = ((data && data.text) || "").trim();
    if (!text) { chatMicStatus(why + "I did not hear any speech in that recording."); return; }
    const box = $("message");
    box.value = box.value.trim() ? box.value.replace(/\s+$/, "") + " " + text : text;
    fitComposer();                                     // also re-checks a Jr handoff that is open
    updateSend();
    chatMicStatus(why + "Transcribed on this PC. Edit it if you like, then press Send.");
    if (state.view !== "chat") return;                 // it waits in the box; no focus jump into another view
    try { box.focus({preventScroll: true}); } catch (_) { box.focus(); }
    box.setSelectionRange(box.value.length, box.value.length);
  }

  function chatMicRetry() {
    const pending = chatMic.pending;
    if (!pending || chatMic.phase !== "idle") return;
    chatMicUpload(chatMic.gen, pending.blob, pending.type, 0);
  }

  if ($("chatMic")) $("chatMic").addEventListener("click", () => {
    if (chatMic.phase === "recording") chatMicStop();
    else chatMicStart();
  });

  // ---------- passkeys (Phase 2, W5) ----------
  // The server does every check (passkeys.py). This only converts between the server's JSON
  // and the browser's WebAuthn API. A passkey login sets an ordinary device session cookie.

  const PASSKEY_HOST = "{{TAILNET_HOST}}";   // the rpId; passkeys work only on this name
  const passkeyCapable = () => !!(window.PublicKeyCredential && navigator.credentials &&
                                  window.isSecureContext && location.hostname === PASSKEY_HOST);
  function b64uToBuf(text) {
    const s = text.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(s + "===".slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64u(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  const withIds = list => (list || []).map(c => Object.assign({}, c, {id: b64uToBuf(c.id)}));
  const creationOptions = o => ({publicKey: Object.assign({}, o, {challenge: b64uToBuf(o.challenge),
    user: Object.assign({}, o.user, {id: b64uToBuf(o.user.id)}), excludeCredentials: withIds(o.excludeCredentials)})});
  const requestOptions = o => ({publicKey: Object.assign({}, o, {challenge: b64uToBuf(o.challenge),
    allowCredentials: withIds(o.allowCredentials)})});
  function credentialJSON(cred) {
    const r = cred.response;
    const out = {id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
                 authenticatorAttachment: cred.authenticatorAttachment || null,
                 clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
                 response: {clientDataJSON: bufToB64u(r.clientDataJSON)}};
    if (r.attestationObject) {
      out.response.attestationObject = bufToB64u(r.attestationObject);
      out.response.transports = typeof r.getTransports === "function" ? r.getTransports() : [];
    } else {
      out.response.authenticatorData = bufToB64u(r.authenticatorData);
      out.response.signature = bufToB64u(r.signature);
      out.response.userHandle = r.userHandle ? bufToB64u(r.userHandle) : null;
    }
    return out;
  }
  const postJSON = (url, body) => request(url, {method: "POST", headers: {"Content-Type": "application/json"},
                                                body: JSON.stringify(body || {})});
  function passkeyMessage(error, cancelled) {
    if (error && error.name === "NotAllowedError") return cancelled;
    if (error && error.name === "InvalidStateError") return "This device already has a Marty passkey.";
    return (error && error.message) || "The passkey step failed.";
  }

  // ---------- Full Marty (Stage B, deployed 2026-09-30) ----------
  // Real read/write on the PC. r15 (2026-10-06): no approval cards while unlocked; the key is the permission. Unlocked
  // per device with a device-bound passkey (a step-up; nothing new is signed in), 15 idle minutes and
  // 8 hours at most. The server and the worker are the authority; this page only shows their state.
  LANES.full = "Full Marty · bypass while unlocked";
  const full = {unlocked: false, csrf: "", conv: lsGet("mj.thread.full"), timer: null, idleLeft: 0, maxLeft: 0,
                cards: new Map()};
  const fullHeaders = () => ({"Content-Type": "application/json", "X-Full-CSRF": full.csrf});
  function fullShowLane(show) {
    $("laneFull").hidden = !show; $("laneFullOpt").hidden = !show; $("laneFullOpt").disabled = !show;
    if (!show && state.lane === "full") setLane("claude_sub_tools");
  }
  // Any Full answer of 423: locked. The lane hides, every card is withdrawn, the lock screen shows.
  function fullOnLocked() {
    full.unlocked = false; full.csrf = "";
    full.cards.forEach((_, nonce) => fullCardClosed({nonce, state: "withdrawn"}));
    fullShowLane(false); fullRenderBar();
  }
  async function fullRequest(url, options) {
    try {
      const data = await request(url, options);
      if (options && options.method === "POST") fullStatus();     // the server touched the idle timer: re-read it
      return data;
    } catch (error) {
      if (error.status === 423) fullOnLocked();
      throw error;
    }
  }

  async function fullStatus() {
    try {
      const s = await request("/api/full/status");
      full.unlocked = !!s.unlocked;
      if (s.unlocked) { full.csrf = s.csrf; full.idleLeft = s.idle_left; full.maxLeft = s.max_left; }
    } catch (_) { full.unlocked = false; }
    fullShowLane(full.unlocked); fullRenderBar();
  }
  async function fullUnlock() {
    $("fullUnlockError").textContent = "Waiting for your passkey…";
    try {
      const opts = await postJSON("/api/full/unlock/options");
      const cred = await navigator.credentials.get(requestOptions(opts));
      const res = await postJSON("/api/full/unlock/verify", {credential: credentialJSON(cred)});
      Object.assign(full, {unlocked: true, csrf: res.csrf, idleLeft: res.idle, maxLeft: res.max});
      $("fullUnlockError").textContent = "";
      fullWarn(res.warning);                              // pick 10: the disk-space warning, if any
      fullShowLane(true); setLane("full"); fullRenderBar();
    } catch (error) {
      if (error.data && error.data.warning) fullWarn(error.data.warning);
      $("fullUnlockError").textContent = passkeyMessage(error, "Unlock was cancelled.");
    }
  }
  function fullWarn(text) {                          // pick 10: shown as text, never HTML
    $("fullWarn").textContent = text || ""; $("fullWarn").hidden = !text;
  }
  function fullRenderBar() {
    const on = state.lane === "full";
    $("fullBar").hidden = !(on && full.unlocked);
    $("fullLocked").hidden = !(on && !full.unlocked);
    if (!full.unlocked) return;
    const left = Math.max(0, Math.min(full.idleLeft, full.maxLeft));
    $("fullTimer").textContent = `Full Marty · locks in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  }
  clearInterval(full.timer);
  full.timer = setInterval(() => {                       // a local countdown; the server is the authority
    if (!full.unlocked) return;
    full.idleLeft -= 1; full.maxLeft -= 1;
    if (full.idleLeft <= 0 || full.maxLeft <= 0) fullOnLocked();
    else fullRenderBar();
  }, 1000);
  // Re-sync, and see a lock from elsewhere. /api/full/status never touches the idle timer. (There is
  // deliberately no /api/full/pending poll: every gated GET counts as use, so a poll would keep Full
  // Marty unlocked forever while the app is open. Cards come back through history on a reload.)
  setInterval(() => { if (!document.hidden && state.entered) fullStatus(); }, 30000);
  $("fullUnlock").addEventListener("click", fullUnlock);
  $("fullMoreUnlock").addEventListener("click", () => {
    if (state.job) return;
    activateView("chat");
    if (full.unlocked) { fullShowLane(true); setLane("full"); return; }
    state.lane = "full";                                  // the locked lane: its lock screen, nothing else
    $("laneLabel").textContent = LANES.full;
    $("messages").innerHTML = EMPTY_CHAT;
    fullRenderBar();
  });
  $("fullLockNow").addEventListener("click", async () => {
    try { await request("/api/full/lock", {method: "POST", headers: fullHeaders(), body: "{}"}); } catch (_) {}
    fullOnLocked();
  });

  async function fullLoad() {
    if (!full.conv) { $("messages").innerHTML = EMPTY_CHAT; return; }
    let data;
    try { data = await fullRequest(`/api/full/history?conv=${encodeURIComponent(full.conv)}`); }
    catch (error) { if (error.status !== 423) $("messages").innerHTML = EMPTY_CHAT; return; }
    if (data.error === "no such conversation") { full.conv = null; lsSet("mj.thread.full", null); $("messages").innerHTML = EMPTY_CHAT; return; }
    $("messages").innerHTML = "";
    (data.turns || []).forEach(t => {
      addMessage("user", t.user);
      if (t.id === data.running) return;                 // followed live below
      const div = addMessage("assistant", t.reply || t.error || "", t.status === "completed" ? "" : t.status);
      (t.steps || []).forEach((s, i) => addStep(div, s, false, i + 1));
    });
    if (!(data.turns || []).length) $("messages").innerHTML = EMPTY_CHAT;
    (data.cards || []).forEach(fullCard);
    if (data.running) {
      const reply = addMessage("assistant", "", "working");
      state.job = {reply, id: data.running};
      $("cancel").hidden = false; updateSend();
      fullFollow(data.running, reply, false);
    }
  }
  async function fullSend(text, fromTalk) {
    const reply = addMessage("assistant", "", "starting");
    state.job = {reply, id: null};
    $("cancel").hidden = false; updateSend();
    try {
      if (!full.conv) {
        const made = await fullRequest("/api/full/new", {method: "POST", headers: fullHeaders(), body: "{}"});
        if (!made || !made.conversation) throw new Error((made && made.error) || "Full Marty could not start a conversation.");
        full.conv = made.conversation; lsSet("mj.thread.full", full.conv);
      }
      const r = await fullRequest("/api/full/turn", {method: "POST", headers: fullHeaders(),
        body: JSON.stringify({conv: full.conv, text})});
      state.job.id = r.turn; fullFollow(r.turn, reply, fromTalk);
    } catch (error) {
      reply.querySelector(".state").textContent = "failed";
      reply.querySelector(".body").textContent = error.message;
      finishJob();
    }
  }
  function fullFollow(turn, reply, fromTalk) {
    const source = new EventSource(`/api/full/stream/${full.conv}/${turn}`);
    state.source = source;
    const data = e => { try { return JSON.parse(e.data || "{}") || {}; } catch (_) { return {}; } };
    source.addEventListener("state", e => { reply.querySelector(".state").textContent = data(e).state || "working"; });
    source.addEventListener("step", e => { const d = data(e); followChat(() => addStep(reply, d.label, false, d.n)); });
    source.addEventListener("delta", e => { const d = data(e);
      followChat(() => { reply.querySelector(".body").textContent += d.text || ""; }); });
    source.addEventListener("approval", e => fullCard(data(e)));
    source.addEventListener("warning", e => fullWarn(data(e).text));   // pick 10
    source.addEventListener("approval_closed", e => fullCardClosed(data(e)));
    const end = e => {
      const d = data(e);
      if (d.locked) fullOnLocked();
      if (d.reply) reply.querySelector(".body").textContent = d.reply;
      reply.querySelector(".state").textContent = d.status === "completed" ? "done" : (d.locked ? "locked" : (d.status || "failed"));
      if (d.error && !d.reply) reply.querySelector(".body").textContent = d.error;
      source.close(); finishJob();
    };
    source.addEventListener("done", end);
    source.addEventListener("error", e => {
      if (e.data) { end(e); return; }                  // no data: a drop, EventSource reconnects
      if (source.readyState === EventSource.CLOSED) { source.close(); finishJob(); setTimeout(loadThread, 1500); }
    });
  }

  // The card. textContent only: the command and path are shown exactly, never as HTML.
  // Round 4: pick 3 (web cards: the site on its own line, never a link), pick 7 (a note when known key
  // formats were blanked), pick 8 (a card that is not one-tap has no Allow button; the worker refuses
  // those before a card is ever sent, so this is a second layer), and the cut notes (pick 9).
  const KIND_LABEL = {command: "Command", URL: "Web page", "search query": "Web search", input: "Details"};
  function fullSite(url) {                           // the host, as text; nothing is fetched or linked
    try { const u = new URL(url); return u.protocol === "https:" || u.protocol === "http:" ? u.host : ""; }
    catch (_) { return ""; }
  }
  function fullCard(c) {
    if (!c || !c.nonce || full.cards.has(c.nonce)) return;
    const box = el("div", "approval");
    box.append(el("h4", "", c.summary || ""));
    if (c.url !== undefined) {
      const host = fullSite(c.url);
      box.append(el("div", "site", host ? `Site: ${host}` : "Site: (not a normal web address)"));
    }
    if (c.detail_kind) box.append(el("div", "note", KIND_LABEL[c.detail_kind] || c.detail_kind));
    const pre = el("pre"); pre.textContent = c.detail || ""; box.append(pre);
    if (c.detail_blanked) box.append(el("div", "note",
      `${c.detail_blanked} known key(s) blanked on this card. The real value is used when it runs.`));
    if (c.detail_truncated) box.append(el("div", "note", `Cut: ${c.detail_chars} characters in full.`));
    if (c.preview) {
      if (c.tool === "WebFetch") box.append(el("div", "note", "What Marty will ask about the page:"));
      const p = el("pre"); p.textContent = c.preview; box.append(p);
      if (c.preview_truncated) box.append(el("div", "note",
        `Only the start is shown (${c.preview_chars} characters in full).`));
    }
    const row = el("div", "row");
    const allow = el("button", "allow", "Allow"), deny = el("button", "deny", "Deny");
    allow.type = deny.type = "button";
    const left = el("span", "muted", "");
    if (c.one_tap === false) { allow.hidden = true; left.textContent = "Too long to approve from the phone."; }
    row.append(allow, deny, left); box.append(row);
    const answer = async ok => {
      allow.disabled = deny.disabled = true;
      try {
        await fullRequest("/api/full/answer", {method: "POST", headers: fullHeaders(),
          body: JSON.stringify({nonce: c.nonce, tool_use_id: c.tool_use_id, allow: ok})});
        fullCardClosed({nonce: c.nonce, state: ok ? "allowed" : "denied"});
      } catch (error) { left.textContent = error.message; }
    };
    allow.addEventListener("click", () => answer(true));
    deny.addEventListener("click", () => answer(false));
    let secs = Number(c.expires_in) || 0;
    const tick = setInterval(() => { secs -= 1; left.textContent = secs > 0 ? `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")} left` : "timed out"; if (secs <= 0) clearInterval(tick); }, 1000);
    full.cards.set(c.nonce, {box, tick});
    followChat(() => $("messages").append(box));
    if (navigator.vibrate) navigator.vibrate(200);
  }
  function fullCardClosed(d) {
    const card = full.cards.get(d.nonce);
    if (!card) return;
    clearInterval(card.tick);
    card.box.classList.add("closed");
    card.box.querySelector(".muted").textContent =
      {allowed: "Allowed", denied: "Denied", withdrawn: "Withdrawn"}[d.state] || d.state;
    full.cards.delete(d.nonce);
  }

  function showPasskeyLogin() { $("passkeyLogin").hidden = !passkeyCapable(); }
  $("passkeyLogin").addEventListener("click", async () => {
    $("loginError").textContent = "Waiting for your passkey...";
    try {
      const options = await postJSON("/api/passkey/login/options");
      const cred = await navigator.credentials.get(requestOptions(options));
      await postJSON("/api/passkey/login/verify", {credential: credentialJSON(cred)});
      $("loginError").textContent = "";
      enterApp();
    } catch (error) { $("loginError").textContent = passkeyMessage(error, "Passkey sign-in was cancelled."); }
  });

  async function refreshPasskeys() {
    const card = $("passkeyCard"), info = $("passkeyInfo");
    card.hidden = !passkeyCapable();
    if (card.hidden) return;
    let s = null;
    try { s = (await request("/api/status")).passkeys; } catch (_) {}
    if (!s) { info.textContent = "Could not read passkey status."; return; }
    if (!s.available) { info.textContent = "Not available: the dashboard is running without its passkey support."; $("passkeySetup").hidden = true; return; }
    $("passkeySetup").hidden = false;
    info.textContent = s.registered
      ? `${s.registered} set up: ${(s.passkeys || []).map(p => p.label).join(", ")}`
      : "Not set up yet. Sign in with your fingerprint instead of the token.";
  }
  $("passkeySetup").addEventListener("click", async () => {
    const info = $("passkeyInfo");
    info.textContent = "Follow the prompt. On the S25, choose Google Password Manager.";
    try {
      const options = await postJSON("/api/passkey/register/options");
      const cred = await navigator.credentials.create(creationOptions(options));
      const saved = await postJSON("/api/passkey/register/verify", {credential: credentialJSON(cred)});
      await refreshPasskeys();
      info.textContent = `Saved: ${saved.passkey.label}. Next time, tap "Sign in with passkey".`;
    } catch (error) { info.textContent = passkeyMessage(error, "Setup was cancelled."); }
  });

  // ---------- theme and logout ----------

  $("theme").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    lsSet("mj.theme", next);
  });
  document.documentElement.dataset.theme = lsGet("mj.theme") || "dark";
  $("logout").addEventListener("click", async () => {
    try { await request("/api/logout", {method: "POST"}); location.reload(); }
    catch (error) { panelError($("more-" + state.more), `Log out failed: ${error.message}`); }
  });

  boot();
})();
