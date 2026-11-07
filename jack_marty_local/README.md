# Jack / Marty local build

The isolated console is at **http://127.0.0.1:8766/**.

Start with `./start.ps1`, stop with `./stop.ps1`. The existing dashboard and parked MJ Phase 1 remain separate.

Read [OPERATIONS.md](OPERATIONS.md) for commands, model provenance, privacy boundaries, supported formats, limits, and remaining configuration. Read [IMPLEMENTATION-REPORT.md](IMPLEMENTATION-REPORT.md) for verified results and file inventory.

Python Standard Library backend; native HTML, CSS, and JavaScript frontend. The existing Ollama model and Claude subscription CLI provide the model services. No additional runtime libraries were installed.
