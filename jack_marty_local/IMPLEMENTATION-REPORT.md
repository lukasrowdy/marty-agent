# Jack / Marty implementation report

Verified on September 25, 2026. Source: `C:/Users/{{WIN_USER}}/my-agent/jack_marty_local`.

The local text and technical-graph pipeline is operational at **http://127.0.0.1:8766/**. Private-media inference, Windows autostart for this new service, and integration into the parked MJ Dashboard are not configured.

## Verified components

| Component | Result |
|---|---|
| Jack local model | Real dashboard request returned `JACK_LOCAL_OK` using tonight's installed Qwen model. |
| Gatekeeper | Profile created successfully, existing large model layers reused. A real API request replaced synthetic host/IP identifiers while preserving the task. |
| Marty integration | Actual Claude subscription response through the new adapter; existing switchboard used to discover its installed CLI. No existing agent files were edited. |
| Defensive matrix | Created at the verified existing NAS Resources directory and byte-for-byte matched against its maintained vault source. |
| Backup/restore | Gzip snapshots, collision-safe names, atomic writes, maximum ten snapshots, restore preservation, corrupt-state recovery copy, and failure blocking verified. |
| Indexer | Email indicators, technical metadata, deduplication, stale relationship removal, path confinement, and preservation of unrelated entries verified. |
| PCAP watcher | Synthetic Ethernet/IPv4 fixture parsed; completed capture detected; incomplete and unsupported input rejected; graph/SSE update verified. |
| Dashboard | Real browser tests verified model replies, sanitized preview, graph nodes/edges, dragging, indexing, clear-view behavior, and refresh recovery. |
| HTTP boundary | Loopback bind, session token, Host/Origin checks, fixed operations, denial of extra attachment fields, server handoff policy, and one-time preview binding tested. |

The installed base is **`huihui_ai/qwen3.5-abliterated:35b-a3b`**, 23,869,179,786 bytes, downloaded at 11:54 PM on September 24. Lukas identified tonight's download as the intended model. The unavailable `qwen3.6` name from the original specification was corrected in the active Modelfile. No model pull was performed. Ollama responds on `127.0.0.1:11434`; the Gatekeeper profile is `gatekeeper-proxy`.

## Test evidence

- **14 Python tests passed** using Python 3.12.14: metadata, dedup/stale edges, snapshots, restore, retention, path limits, concurrent graph writes, backup failure, malformed/incomplete capture handling, watcher, HTTP/SSE, routing failures, authorization, preview tamper/replay rejection, and private-source sentinel isolation.
- **JavaScript checks passed:** syntax for both scripts; duplicate and malformed events, snapshot replacement, and clear-view assertions in `tests/test_graph.js`.
- **Live end-to-end test passed in 11.42 seconds:** actual Jack model, actual Gatekeeper, actual Marty subscription, permitted result indexing, capture watcher, and SSE. Result: eight nodes and nine links. Evidence is `runtime/live-smoke.json`.
- **Browser model results:** `JACK_LOCAL_OK`, `MARTY_BROWSER_OK`, and `MARTY_PREVIEW_OK`. The final preview visibly replaced `test.example.com` and `192.0.2.42` with placeholders before the send action.
- **Persistent graph protection:** Clear Canvas displayed zero nodes while `/graph` still contained the saved nodes and links; refresh restored them.
- **Final restart check passed:** clean shutdown and restart succeeded; the existing browser tab reconnected and indexed both synthetic documents without a page reload or stale-token error. Eight nodes and nine links remained available.
- **Isolation test:** synthetic private source bytes reached the local callback; the Marty sender received only the separately supplied sanitized task. Raw attachments and prior model results are not accepted by HTTP.
- **Existing service:** the original dashboard retains a separate loopback listener and expected unauthenticated HTTP 401 response. Existing switchboard import succeeds. Its authenticated chat/voice functions were not exercised or changed.
- **Independent review:** the existing Claude subscription reviewed the new authorization/privacy/backup code. Confirmed permission and restore defects were fixed and regression-tested. The console also gained exact-text preview and single-use handoff binding.

## Start and stop

```powershell
Set-Location 'C:\Users\{{WIN_USER}}\my-agent\jack_marty_local'
.\start.ps1
.\stop.ps1
```

Run the two scripts separately for the desired action. The new service was launched with the existing Python 3.12 installation at `C:/Users/{{WIN_USER}}/AppData/Local/Programs/Python/Python312/python.exe`. Ollama already has a Windows startup entry. This console has no autostart registration; run `start.ps1` after a reboot. The existing dashboard owns 8765, so this package uses 8766.

The created Gatekeeper can be reproduced without pulling another base:

```powershell
ollama create gatekeeper-proxy -f .\Modelfile
```

## Files created

- Runtime Python: `backup_vault.py`, `index_vault.py`, `watch_pcap.py`, `switchboard_router.py`, `agent_adapter.py`, `local_console.py`.
- Models/UI: `Modelfile`, `index.html`, `style.css`, `graph.js`, `console.js`.
- Launchers: `start.ps1`, `stop.ps1`.
- Tests: `tests/test_integration.py`, `tests/test_hardening.py`, `tests/test_graph.js`, `tests/live_smoke.py`.
- Documentation: `README.md`, `OPERATIONS.md`, this report, `abstract_threat_templates.md`.
- Application data: `Vault/graph_state.json`, `Vault/Targets_Index.md`, bounded `Vault/Backups`, clearly labeled synthetic documents in `Vault/OSINT_Targets`, and synthetic PCAP fixtures in `cache`.
- Runtime evidence: process record, endpoint-only server logs, review findings, and live smoke JSON in `runtime`.
- Vault: new `07 - Resources/Jack Marty Local Architecture.md` and `abstract_threat_templates.md`; resource index and today's daily note updated.
- NAS: `//{{NAS_MODEL}}/home/Marty Backup/vault/07 - Resources/abstract_threat_templates.md`. No unrelated NAS files were changed.

No existing agent source/configuration, Phase 1 project files, supervisor, tailnet route, or boot file was modified. No additional Python, npm, or browser runtime dependencies were installed. Node was used only for development checks.

## Remaining configuration and limits

The private-media interface requires a concrete local processor and local privacy screening before video/image inference is operational. No real family media was opened, uploaded, or tested. Media upload is intentionally unavailable in the new HTTP service.

Marty receives only separately prepared task text after local abstraction and explicit preview approval. A model cannot guarantee perfect anonymization of every possible identifying detail; programmatic callers must supply authorized minimal metadata and can designate exact identifiers for verification. Authorization remains independent of text transformation.

The package is not connected to the parked MJ Dashboard, phone/tailnet interface, voice, or existing supervisor. New-service autostart is not configured. Supported classic PCAP formats are documented in `OPERATIONS.md`; PCAPNG and IPv6 extraction are not implemented. The browser limits rendering to 600 nodes, while preserving the underlying graph.

For detailed commands and boundaries, see `OPERATIONS.md`.
