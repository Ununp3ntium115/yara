# Re-engineering Blueprint (Node-RED + Svelte)

## Vision
Transform the classic YARA toolchain into a service-oriented system that:
1. Keeps libyara + rule corpus authoritative (no forked rule logic).
2. Orchestrates scans, rule curation, and exports through Node-RED flows.
3. Presents analysts with a modern Svelte interface powered by the MCP server.

## Target Architecture

```
[Svelte UI] ──HTTP/WebSocket──> [MCP Gateway (FastAPI wrapper)]
                               │
                               ├─ (MCP transport) ─> [MCP Server]
                               │                     ├─ Git resource provider
                               │                     ├─ Rule provider
                               │                     └─ Cryptex provider
                               │
                               └─REST/Webhooks──────> [Node-RED Runtime]
                                                        ├─ Scan Orchestrator Node
                                                        ├─ Rule Curator Node
                                                        └─ Notification Node
```

### Node-RED Layer
- **Custom Nodes**
  - `yara-scan` node: wraps `python tools/run_scan.py` (thin layer over `yara_scanner.py`) with inputs for directory, ruleset, recursion, output sink.
  - `yara-rule-curator` node: invokes the safe-index generator and optional filters (e.g., include/exclude modules).
  - `cry ptex-lookup` node: queries MCP `CryptexProvider` to display metadata or drive branching logic.
- **Flows**
  1. **On-demand Scan**
     - Trigger (HTTP-in / schedule) → `yara-scan` → store JSON results → send to MCP resource store.
  2. **Rule Refresh**
     - Daily cron → git pull `yara-rules` → `yara-rule-curator` → commit artifact + notify UI.
  3. **Training Export**
     - Analyst selects dataset in UI → Node-RED fetches from MCP → packages zipped bundle → exposes download link.
- **State**
  - Use filesystem or SQLite for small-scale deployments; upgrade to Redis/Postgres for multi-user.

### Svelte Interface
- **Panels**
  - *Dashboard*: statuses from Node-RED flows (last scan, rule updates), exposed via FastAPI aggregator.
  - *Rule Explorer*: tree view wired to MCP `list-rules` resource; supports filtering, download, Cryptex overlay.
  - *Scan Console*: start/stop scans, view progress logs streamed from Node-RED websockets.
  - *Cryptex Dictionary*: searchable table of Pyro/Fire Marshal names linking back to source files.
- **Tech Stack**
  - SvelteKit + TypeScript, Vite tooling.
  - Component library: Skeleton UI or Carbon (depending on design preference).
  - Auth: integrate with organization SSO or simple token for initial rollout.
- **Data Access**
  - Use typed client for MCP FastAPI gateway to fetch resources.
  - Subscribe to Server-Sent Events (SSE) / WebSockets for scan progress.

### Preservation of YARA Rules
- Node-RED nodes never modify `.yar` files directly; all writes go through curated generator scripts.
- Svelte UI offers downloads/exports by calling MCP resources (read-only).
- Compiled rule bundles (if needed) are generated on demand from the same sources and cached with SHA tags.

## Migration Steps
1. **Tool Packaging**
   - Move Python scripts into `tools/` package; expose CLI commands (`run-scan`, `create-safe-index`).
2. **MCP Gateway**
   - Implement FastAPI service that proxies MCP `list_resources`/`read_resource` plus triggers.
3. **Node-RED Nodes**
   - Develop custom nodes (JS) packaged under `packages/node-red-yara`.
   - Provide Dockerfile for Node-RED runtime with dependencies preinstalled (Python, yara-python).
4. **Svelte Frontend**
   - Scaffold SvelteKit project under `ui/`.
   - Create service layer for MCP gateway + Node-RED webhooks.
   - Build initial pages (Dashboard, Rule Explorer, Scan Console).
5. **Glue & Deployment**
   - Compose services via Docker Compose (Node-RED, FastAPI/MCP, Svelte static bundle, Redis/SQLite).
   - Add Makefile targets or npm scripts for local dev + prod builds.

## Acceptance Criteria
- Triggering a scan from the Svelte UI results in Node-RED running `yara_scanner.py` against selected directories and streaming the summary back.
- Rule updates initiated via UI produce a refreshed `safe_malware_index.yar` and log entry.
- Cryptex dictionary panel can fetch entries, show pyro names, and deep-link into source code (via MCP resource URIs).
- Under-the-hood YARA C sources and rule corpus remain untouched except for documented generator outputs.

