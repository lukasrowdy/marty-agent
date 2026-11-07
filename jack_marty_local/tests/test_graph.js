"use strict";
const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const path = require("node:path");
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    textContent: "", hidden: false, handlers: {},
    addEventListener(name, callback) { this.handlers[name] = callback; },
    click() { this.handlers.click?.(); },
    getBoundingClientRect() { return {width: 900, height: 500, left: 0, top: 0}; },
    getContext() { return new Proxy({}, {get: () => () => {}}); },
    setPointerCapture() {},
  });
  return elements.get(id);
}
const window = {devicePixelRatio: 1, addEventListener() {}};
const scope = {
  window, document: {getElementById: element}, requestAnimationFrame() {},
  fetch: async () => ({ok: true, json: async () => ({nodes: [], links: []})}),
  EventSource: class { close() {} addEventListener() {} }, setTimeout, clearTimeout,
};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, "..", "graph.js"), "utf8"), scope);
setImmediate(() => {
  const graph = window.JackMartyGraph;
  const event = {type: "graph_update", nodes: [{id: "a", type: "ipv4"}, {id: "b", type: "ipv4"}], links: [{source: "a", target: "b"}]};
  assert.equal(graph.mergeEvent(event), true);
  graph.mergeEvent(event);
  assert.equal(graph.nodeCount(), 2);
  assert.equal(graph.edgeCount(), 1);
  for (const bad of [null, {}, {type: "other"}, {type: "graph_update", nodes: {}, links: []}]) assert.equal(graph.mergeEvent(bad), false);
  graph.mergeEvent({type: "graph_snapshot", nodes: [null, {id: "c", type: "document"}], links: [null]});
  assert.equal(graph.nodeCount(), 1);
  assert.equal(graph.edgeCount(), 0);
  graph.clear(); assert.equal(graph.nodeCount(), 0);
  assert.equal(element("emptyState").hidden, false);
  console.log("PASS: duplicate events, malformed events, snapshot replacement, and visual clear");
});
