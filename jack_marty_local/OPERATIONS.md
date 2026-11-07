# Jack / Marty operations

Source package: `C:/Users/{{WIN_USER}}/my-agent/jack_marty_local`.

## Open and run

Open [the local console](http://127.0.0.1:8766/). Jack is the default destination. A Marty task first produces a locally sanitized preview; **Send this text to Marty** submits exactly that stored preview. Switching destinations clears the input. Prior Jack results and source attachments are never automatically included in a handoff.

From PowerShell in the package:

```powershell
.\start.ps1
.\stop.ps1
```

The start script chooses an existing Python 3.12 interpreter, starts only this console, and verifies its health endpoint. The stop script checks the saved process identity, then requests a clean shutdown. To run visibly in a terminal instead:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" .\local_console.py --port 8766
```

Ctrl+C stops a terminal instance. This package has no automatic Windows startup registration. After reboot, Ollama must be running before local model requests; then run `start.ps1`. No existing dashboard startup, supervisor, tailnet route, agent boot file, or configuration was modified.

## Models and handoffs

Jack uses `huihui_ai/qwen3.5-abliterated:35b-a3b`, the model Lukas identified as tonight's download. Its verified local size is 23,869,179,786 bytes. This corrects the unavailable qwen3.6 identifier in the original pasted specification. The active `Modelfile` records the installed base. Creating `gatekeeper-proxy` reused its large layers; no model download was performed.

```powershell
ollama create gatekeeper-proxy -f .\Modelfile
```

The profile already exists and passed local API tests. Do not run `ollama pull` merely to start this package. `JACK_MODEL` can explicitly select another installed Jack model. `JACK_MARTY_ALLOW_HANDOFF=0` disables external handoffs in server policy.

The adapter discovers the existing Claude subscription CLI through `tools/switchboard.py`. The new child invocation disables tools, customizations, MCP and browser access, and session persistence. It uses a separate working directory and removes API-key/provider overrides from the child environment. Existing Marty files are preserved. No unrestricted shell endpoint exists.

Authorization is independent of abstraction. Every external route requires `external-handoff`; explicitly local-only content is blocked. The local console requires a per-process session token for its fixed POST operations, validates Host and Origin, and binds only to loopback. Other processes already running as the local user are inside this trust boundary. The preview is held server-side for ten minutes and can be sent once; client-supplied replacement text is rejected.

The Gatekeeper is an aid to redaction, not proof that all possible personal information has been removed. The preview shows the exact outgoing task for review. For programmatic routes, callers can supply known `sensitive_identifiers` for a deterministic residual check. Raw media is never accepted by HTTP.

## Documents, captures, and backups

Place authorized `.md` or `.txt` references under `Vault/OSINT_Targets`, then select **Index local reference documents**. The indexer keeps email indicators as local document metadata and creates no person nodes. Two source files cannot silently claim the same document identifier. Source paths are confined to the designated directory.

Place authorized offline classic `.pcap` files under `cache`. Prefer writing to `.part`, then renaming to `.pcap` when complete. The watcher checks stable size/time, validates complete packet records, and retries incomplete captures. Ethernet/VLAN, raw IPv4, and Linux cooked v1/v2 are supported. PCAPNG and IPv6 extraction are not implemented. No interception, collection, or credential extraction is implemented.

Limits: 128 MiB per capture, 100,000 packets, 2 MiB per packet, 4,096 captures per watcher session, 16 SSE clients, bounded client queues. The browser renders at most 600 nodes to bound physics work; persistent data remains intact. Clear Canvas affects only the view. Refresh and SSE reconnection recover the current snapshot.

Graph mutations use shared file locks, validated gzip snapshots, atomic replacement, and retention of ten application snapshots in `Vault/Backups`. Restore also saves the state it replaces. If current JSON is corrupt, its bytes are retained in a separate `rejected-*.json` recovery file. Low-level initialization helpers are not a replacement for the higher-level transaction/mutation functions.

```python
from pathlib import Path
from backup_vault import restore_backup
restore_backup(Path("Vault/Backups/<chosen-snapshot>.json.gz"))
```

The defensive matrix is mirrored to the verified existing NAS directory at `//{{NAS_MODEL}}/home/Marty Backup/vault/07 - Resources/abstract_threat_templates.md`. Its maintained source is `C:/Users/{{WIN_USER}}/marty-vault/07 - Resources/abstract_threat_templates.md`, so the regular vault mirror retains it. The package holds a matching reference copy.

## Tests and limitations

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m unittest discover -s tests -v
node tests/test_graph.js
```

Node is used only for development checks; it is not required to run the dashboard. There are no external Python or browser dependencies.

`tests/live_smoke.py` explicitly invokes the installed local models and existing Claude subscription with synthetic data, then indexes permitted result markers and verifies the capture/SSE pipeline. It writes clearly labeled synthetic fixtures in the package. Run only when a real model integration check is wanted.

The private-media adapter is a local callback boundary, tested with synthetic sentinel bytes. A concrete media handler and local privacy screening still need to be connected before video/image processing is operational. No real family media was opened or tested. This new console is not integrated into the parked MJ Dashboard, phone/tailnet interface, or voice system.
