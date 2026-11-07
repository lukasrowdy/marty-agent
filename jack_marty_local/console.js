"use strict";
(() => {
  const form = document.getElementById("taskForm"), input = document.getElementById("taskText");
  const target = document.getElementById("targetBrain"), send = document.getElementById("sendTaskBtn");
  const status = document.getElementById("taskStatus"), reply = document.getElementById("taskReply");
  const index = document.getElementById("indexDocsBtn"), notice = document.getElementById("handoffNotice");
  const preview = document.getElementById("handoffPreview"), cleanText = document.getElementById("cleanTaskText");
  const confirm = document.getElementById("confirmHandoffBtn");
  let token = null, pendingHandoff = null;
  const ready = fetch("/api/session", {cache: "no-store"}).then(async response => {
    if (!response.ok) throw new Error("Local task service is unavailable.");
    const value = await response.json(); token = value.token;
    document.getElementById("modelName").textContent = value.jack_model;
  }).catch(error => { status.textContent = error.message; });
  target.addEventListener("change", () => {
    const cloud = target.value === "marty"; notice.hidden = !cloud;
    input.value = ""; reply.textContent = ""; preview.hidden = true; pendingHandoff = null;
    send.textContent = cloud ? "Prepare sanitized handoff" : "Send to Marty Jr.";
  });
  function setBusy(busy) { send.disabled = busy; index.disabled = busy; target.disabled = busy; confirm.disabled = busy; }
  async function post(path, value) {
    await ready;
    const sessionResponse = await fetch("/api/session", {cache: "no-store"});
    if (!sessionResponse.ok) throw new Error("Local task service is unavailable.");
    const currentSession = await sessionResponse.json(); token = currentSession.token;
    document.getElementById("modelName").textContent = currentSession.jack_model;
    if (!token) throw new Error("Reload this page to establish a local session.");
    const response = await fetch(path, {method: "POST", headers: {"Content-Type": "application/json", "X-Local-Token": token}, body: JSON.stringify(value)});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "The operation could not complete.");
    return result;
  }
  form.addEventListener("submit", async event => {
    event.preventDefault(); if (!input.value.trim()) return;
    setBusy(true); reply.textContent = "";
    status.textContent = target.value === "jack" ? "Marty Jr. is working locally…" : "Preparing a sanitized task locally…";
    try {
      const result = await post("/api/chat", {text: input.value, target: target.value, handoff_authorized: target.value === "marty"});
      if (result.status === "prepared") {
        pendingHandoff = result.handoff_id; cleanText.textContent = result.preview; preview.hidden = false;
        status.textContent = "Review the exact task below before sending it to Marty."; return;
      }
      reply.textContent = typeof result.text === "string" ? result.text : JSON.stringify(result.text, null, 2);
      status.textContent = result.target === "jack" ? "Marty Jr. replied locally." : "Marty replied to the sanitized task.";
    } catch (error) { status.textContent = error.message; }
    finally { setBusy(false); }
  });
  input.addEventListener("input", () => { preview.hidden = true; pendingHandoff = null; });
  confirm.addEventListener("click", async () => {
    if (!pendingHandoff) return;
    setBusy(true); status.textContent = "Marty is working from the approved text…";
    const id = pendingHandoff; pendingHandoff = null;
    try { const result = await post("/api/handoff", {handoff_id: id});
      reply.textContent = result.text; status.textContent = "Marty replied to the sanitized task."; preview.hidden = true;
    } catch (error) { status.textContent = error.message; preview.hidden = true; }
    finally { setBusy(false); }
  });
  index.addEventListener("click", async () => {
    setBusy(true); status.textContent = "Indexing authorized local reference documents…";
    try { const result = await post("/api/index", {action: "index-local-documents"});
      status.textContent = `${result.documents} documents indexed; ${result.changed} changed.`;
    } catch (error) { status.textContent = error.message; }
    finally { setBusy(false); }
  });
})();
