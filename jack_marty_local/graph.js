"use strict";
(() => {
  const REPULSION = 400;
  const ATTRACTION = 0.04;
  const DAMPING = 0.85;
  const canvas = document.getElementById("graphCanvas");
  const context = canvas.getContext("2d");
  const status = document.getElementById("connectionStatus");
  const counts = document.getElementById("graphCounts");
  const emptyState = document.getElementById("emptyState");
  const clearButton = document.getElementById("clearCanvasBtn");
  const nodes = new Map();
  const links = new Map();
  let width = 1, height = 1, dpr = 1, source = null, drag = null, retryTimer = null;
  let syncing = false, pendingEvents = [];

  const colors = { document: "#63c7b2", ipv4: "#78a9ff", topic_tag: "#e5b95c", technical_indicator: "#cf91ed" };
  const edgeKey = (a, b) => JSON.stringify([a, b]);
  function addNode(input) {
    if (!input || typeof input.id !== "string" || typeof input.type !== "string") return false;
    if (!nodes.has(input.id)) {
      if (nodes.size >= 600) return false;
      nodes.set(input.id, { id: input.id, type: input.type, label: typeof input.label === "string" ? input.label : input.id,
        x: width * (0.2 + Math.random() * 0.6), y: height * (0.2 + Math.random() * 0.6), vx: 0, vy: 0, fixed: false });
    } else { const node = nodes.get(input.id); if (input.type !== "unknown") node.type = input.type; if (typeof input.label === "string") node.label = input.label; }
    return true;
  }
  function addLink(input) {
    if (!input || typeof input.source !== "string" || typeof input.target !== "string") return false;
    addNode({ id: input.source, type: "unknown" }); addNode({ id: input.target, type: "unknown" });
    if (!nodes.has(input.source) || !nodes.has(input.target)) return false;
    const key = edgeKey(input.source, input.target, typeof input.type === "string" ? input.type : "");
    if (!links.has(key)) links.set(key, { source: input.source, target: input.target, type: input.type || "" });
    return true;
  }
  function mergeGraph(graph) {
    if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.links)) return false;
    for (const node of graph.nodes) addNode(node);
    for (const link of graph.links) addLink(link);
    updateCounts(); return true;
  }
  function mergeEvent(event) {
    if (event && event.type === "graph_snapshot") return replaceGraph(event);
    if (!event || event.type !== "graph_update" || !Array.isArray(event.nodes) || !Array.isArray(event.links)) return false;
    for (const node of event.nodes) addNode(node);
    for (const link of event.links) addLink(link);
    updateCounts(); return true;
  }
  function replaceGraph(graph) {
    if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.links)) return false;
    const previous = new Map(nodes); nodes.clear(); links.clear();
    const accepted = graph.nodes.filter(n => n && typeof n.id === "string" && typeof n.type === "string").slice(0, 600); const ids = new Set(accepted.map(n => n.id));
    mergeGraph({nodes: accepted, links: graph.links.filter(e => e && ids.has(e.source) && ids.has(e.target))});
    for (const [id, node] of nodes) if (previous.has(id)) Object.assign(node, { x: previous.get(id).x, y: previous.get(id).y });
    if (graph.nodes.length > 600) counts.textContent += " · view limited to 600 nodes";
    return true;
  }
  function updateCounts() {
    counts.textContent = `${nodes.size} nodes · ${links.size} links`;
    emptyState.hidden = nodes.size !== 0;
  }
  function resize() {
    const rect = canvas.getBoundingClientRect(); dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    width = Math.max(1, rect.width); height = Math.max(1, rect.height);
    canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr);
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    for (const node of nodes.values()) { node.x = Math.min(width - 20, Math.max(20, node.x)); node.y = Math.min(height - 20, Math.max(20, node.y)); }
  }
  function simulate() {
    const values = [...nodes.values()];
    for (let i = 0; i < values.length; i++) for (let j = i + 1; j < values.length; j++) {
      const a = values[i], b = values[j], dx = b.x - a.x, dy = b.y - a.y, d2 = Math.max(36, dx * dx + dy * dy);
      const force = REPULSION / d2, d = Math.sqrt(d2), fx = dx / d * force, fy = dy / d * force;
      if (!a.fixed) { a.vx -= fx; a.vy -= fy; } if (!b.fixed) { b.vx += fx; b.vy += fy; }
    }
    for (const link of links.values()) {
      const a = nodes.get(link.source), b = nodes.get(link.target); if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y, d = Math.max(1, Math.hypot(dx, dy)), force = (d - 115) * ATTRACTION;
      if (!a.fixed) { a.vx += dx / d * force; a.vy += dy / d * force; }
      if (!b.fixed) { b.vx -= dx / d * force; b.vy -= dy / d * force; }
    }
    for (const node of values) if (!node.fixed) {
      node.vx *= DAMPING; node.vy *= DAMPING; node.x += node.vx; node.y += node.vy;
      node.x = Math.max(16, Math.min(width - 16, node.x)); node.y = Math.max(16, Math.min(height - 16, node.y));
    }
  }
  function draw() {
    context.clearRect(0, 0, width, height); simulate();
    context.lineWidth = 1; context.strokeStyle = "rgba(131,157,188,.38)";
    for (const link of links.values()) { const a = nodes.get(link.source), b = nodes.get(link.target); if (!a || !b) continue;
      context.beginPath(); context.moveTo(a.x, a.y); context.lineTo(b.x, b.y); context.stroke(); }
    for (const node of nodes.values()) {
      context.beginPath(); context.arc(node.x, node.y, 7, 0, Math.PI * 2); context.fillStyle = colors[node.type] || "#9ba9bb"; context.fill();
      context.fillStyle = "#e9eef6"; context.font = "12px Segoe UI, sans-serif"; context.fillText(node.label, node.x + 11, node.y + 4);
    }
    requestAnimationFrame(draw);
  }
  function canvasPoint(event) { const rect = canvas.getBoundingClientRect(); return { x: event.clientX - rect.left, y: event.clientY - rect.top }; }
  canvas.addEventListener("pointerdown", event => { const p = canvasPoint(event); let nearest = null, best = 16 * 16;
    for (const node of nodes.values()) { const d = (node.x - p.x) ** 2 + (node.y - p.y) ** 2; if (d < best) { best = d; nearest = node; } }
    if (nearest) { drag = nearest; drag.fixed = true; canvas.setPointerCapture(event.pointerId); } });
  canvas.addEventListener("pointermove", event => { if (!drag) return; const p = canvasPoint(event); drag.x = p.x; drag.y = p.y; drag.vx = 0; drag.vy = 0; });
  function endDrag() { if (drag) drag.fixed = false; drag = null; }
  canvas.addEventListener("pointerup", endDrag); canvas.addEventListener("pointercancel", endDrag);
  clearButton.addEventListener("click", () => { nodes.clear(); links.clear(); updateCounts(); });
  window.addEventListener("resize", resize); resize();

  async function loadSnapshot() {
    if (syncing) return;
    syncing = true;
    try {
      const response = await fetch("/graph", { cache: "no-store" });
      if (!response.ok) throw new Error(`snapshot HTTP ${response.status}`);
      const graph = await response.json(); if (!replaceGraph(graph)) throw new Error("malformed graph snapshot");
    } finally {
      syncing = false;
      const queued = pendingEvents; pendingEvents = [];
      for (const event of queued) mergeEvent(event);
    }
  }

  function connect() {
    if (source) source.close(); if (retryTimer) clearTimeout(retryTimer);
    source = new EventSource("/stream");
    source.onopen = () => { loadSnapshot().then(() => { status.textContent = "Live updates connected"; }).catch(() => { status.textContent = "Snapshot unavailable"; }); };
    source.addEventListener("graph", event => { try { const parsed = JSON.parse(event.data); if (syncing) pendingEvents.push(parsed); else if (!mergeEvent(parsed)) throw new Error("invalid graph event"); }
      catch (_) { status.textContent = "Ignored malformed update"; } });
    source.onerror = async () => { status.textContent = "Reconnecting…"; source.close();
      try { await loadSnapshot(); } catch (_) { status.textContent = "Waiting for local server…"; }
      retryTimer = setTimeout(connect, 2000); };
  }
  loadSnapshot().catch(() => { status.textContent = "Local graph snapshot unavailable"; }).finally(connect);
  requestAnimationFrame(draw);
  window.JackMartyGraph = { mergeGraph, mergeEvent, nodeCount: () => nodes.size, edgeCount: () => links.size, clear: () => clearButton.click() };
})();
