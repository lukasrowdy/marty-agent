// Flow tab: a live hub-and-spoke map of "who's the gatekeeper" -- Lukas and
// Marty as the two center nodes, everything else radiating out. Lights up
// for real, driven by the same /api/activity feed the Overview rail and
// center chat pane use (dashboard/log_activity.py's PostToolUse hook) --
// nothing here is scripted or fake. app.js calls window.updateFlowActivity()
// with the same rows it already fetched for refreshActivity(), so this pulls
// no extra network traffic of its own.

(function () {
  const NODES = [
    { id: "lukas", label: "Lukas", role: "talks or types", x: 0.32, y: 0.5, kind: "hub-lukas" },
    { id: "marty", label: "Marty", role: "decides what this needs", x: 0.5, y: 0.5, kind: "hub-marty" },

    { id: "claude", label: "Claude (me)", role: "the brain actually thinking and reading/editing files right now", x: 0.72, y: 0.14, kind: "live" },
    { id: "grok-gemini", label: "Grok / Gemini", role: "called via switchboard for a specific job, one at a time", x: 0.88, y: 0.32, kind: "live" },
    { id: "vault", label: "Vault (memory)", role: "notes read/written every turn", x: 0.94, y: 0.55, kind: "live" },
    { id: "tools", label: "Tools", role: "hands, deals, cred, walkthrough -- direct actions on this PC", x: 0.88, y: 0.78, kind: "live" },
    { id: "higgsfield", label: "Higgsfield", role: "image/video jobs, launched and watched, one at a time", x: 0.70, y: 0.90, kind: "live" },

    { id: "bg-agents", label: "Background Agents", role: "a big task spun off, running on its own while we keep talking", x: 0.5, y: 0.10, kind: "bg" },
    { id: "routines", label: "Scheduled Routines", role: "Morning Queue, NAS backup -- run on a clock", x: 0.30, y: 0.90, kind: "bg" },

    { id: "marty-local", label: "marty-local (Ollama)", role: "only in private mode -- cloud never touched", x: 0.30, y: 0.14, kind: "trig" },
    { id: "mic", label: "Mic mode", role: "push-to-talk vs hands-free", x: 0.10, y: 0.32, kind: "trig" },
    { id: "elevenlabs", label: "ElevenLabs voice", role: "speaks the reply out loud", x: 0.06, y: 0.55, kind: "trig" },
    { id: "whisper", label: "Whisper (ears)", role: "turns your speech into text", x: 0.12, y: 0.78, kind: "trig" },
  ];

  const KIND_COLOR = { "hub-lukas": "#fab219", "hub-marty": "#3987e5", live: "#0ca30c", bg: "#8a5cf6", trig: "#ec835a" };
  const PULSE_MS = 4500;

  let built = false;
  let nodesById = {};
  let linesByTo = {};
  let lastSeenTs = null;

  function el(tag, opts = {}) {
    const node = document.createElement(tag);
    if (opts.className) node.className = opts.className;
    if (opts.text !== undefined) node.textContent = opts.text;
    return node;
  }

  function build() {
    const stage = document.getElementById("flow-stage");
    if (!stage || built) return;
    built = true;
    NODES.forEach((n) => {
      const div = el("div", { className: `flow-node flow-${n.kind}` });
      div.dataset.id = n.id;
      const name = el("p", { className: "flow-name", text: n.label });
      const role = el("p", { className: "flow-role", text: n.role });
      div.appendChild(name);
      div.appendChild(role);
      stage.appendChild(div);
      nodesById[n.id] = { def: n, el: div, pulseUntil: 0 };
    });
  }

  function layout() {
    const stage = document.getElementById("flow-stage");
    const svg = document.getElementById("flow-lines");
    if (!stage || !svg) return;
    build();
    const rect = stage.getBoundingClientRect();
    if (!rect.width || !rect.height) return; // hidden tab, nothing to measure yet
    svg.setAttribute("viewBox", `0 0 ${rect.width} ${rect.height}`);
    svg.innerHTML = "";
    linesByTo = {};

    const points = {};
    NODES.forEach((n) => {
      const x = n.x * rect.width, y = n.y * rect.height;
      points[n.id] = { x, y };
      nodesById[n.id].el.style.left = x + "px";
      nodesById[n.id].el.style.top = y + "px";
    });

    function drawLine(a, b, color, width) {
      const l = document.createElementNS("http://www.w3.org/2000/svg", "line");
      l.setAttribute("x1", points[a].x); l.setAttribute("y1", points[a].y);
      l.setAttribute("x2", points[b].x); l.setAttribute("y2", points[b].y);
      l.setAttribute("stroke", color); l.setAttribute("stroke-width", width || 1.6);
      l.setAttribute("opacity", "0.22");
      svg.appendChild(l);
      return l;
    }
    drawLine("lukas", "marty", "#ffffff", 2.4);
    NODES.forEach((n) => {
      if (n.id === "lukas" || n.id === "marty") return;
      linesByTo[n.id] = drawLine("marty", n.id, KIND_COLOR[n.kind]);
    });
  }

  // ---- tool-call -> node mapping. Honest, not clever: every real action
  // routes through Marty deciding (marty) and Claude actually doing it
  // (claude); the specific worker node lights up alongside those two. ----
  function nodesForRow(row) {
    const tool = row.tool || "";
    const summary = (row.summary || "").toLowerCase();
    const hit = ["marty", "claude"];
    if (tool === "Bash" || tool === "PowerShell") { hit.push("tools"); return hit; }
    if (["Read", "Grep", "Glob", "Edit", "Write", "NotebookEdit"].includes(tool)) {
      hit.push(summary.includes("marty-vault") ? "vault" : "tools");
      return hit;
    }
    if (tool === "Agent") { hit.push("bg-agents"); return hit; }
    if (tool === "WebFetch" || tool === "WebSearch") return hit; // claude/marty only, honestly -- no dedicated node
    hit.push("tools");
    return hit;
  }

  function pulse(nodeIds) {
    const now = Date.now();
    nodeIds.forEach((id) => {
      const n = nodesById[id];
      if (!n) return;
      n.pulseUntil = now + PULSE_MS;
      n.el.classList.add("active");
      const line = linesByTo[id];
      if (line) { line.setAttribute("opacity", "1"); line.setAttribute("stroke-width", "3.2"); }
    });
  }

  function tick() {
    const now = Date.now();
    Object.values(nodesById).forEach((n) => {
      if (n.pulseUntil && now > n.pulseUntil) {
        n.pulseUntil = 0;
        n.el.classList.remove("active");
        const line = linesByTo[n.def.id];
        if (line) { line.setAttribute("opacity", "0.22"); line.setAttribute("stroke-width", "1.6"); }
      }
    });
  }
  setInterval(tick, 500);

  function pushTicker(row) {
    const box = document.getElementById("flow-ticker");
    if (!box) return;
    const line = el("p", { className: "flow-ticker-line" });
    const tool = el("span", { className: "flow-ticker-tool", text: row.tool || "?" });
    const summary = el("span", { className: "flow-ticker-summary", text: " " + (row.summary || "") });
    line.appendChild(tool);
    line.appendChild(summary);
    box.insertBefore(line, box.firstChild);
    while (box.children.length > 8) box.removeChild(box.lastChild);
  }

  // Called by app.js's refreshActivity() with the same rows (newest first)
  // it already fetched from /api/activity -- no extra network call here.
  window.updateFlowActivity = function (rows) {
    if (!rows || !rows.length) return;
    build();
    // First call: just record the watermark, don't replay history as "live now".
    if (lastSeenTs === null) {
      lastSeenTs = rows[0].ts;
      rows.slice(0, 5).reverse().forEach(pushTicker);
      return;
    }
    const fresh = rows.filter((r) => r.ts > lastSeenTs);
    if (!fresh.length) return;
    lastSeenTs = rows[0].ts;
    fresh.reverse().forEach((row) => {
      pushTicker(row);
      pulse(nodesForRow(row));
    });
  };

  window.__flowResize = layout;
  document.addEventListener("DOMContentLoaded", () => { build(); layout(); });
})();
