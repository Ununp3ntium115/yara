# MCP Server Plan

## Objectives
1. Serve the entire YARA repository (source, docs, rules, helper scripts) through the Model Context Protocol so downstream LLM tooling can request high-fidelity training/input data.
2. Preserve traceability of every exported artifact (rule provenance, commit hash, code license) to satisfy internal audit demands.
3. Provide higher-level views (Cryptex dictionary entries, curated rule bundles, scan telemetry) that other consumers—Node-RED flows, Svelte dashboards, or analysts—can query without touching git directly.

## Functional Scope
- **Data Domains**
  - *Source*: Everything under `libyara/`, `cli/`, `docs/`, `tests/`, helpers such as `create_safe_rules.py`, `yara_scanner.py`.
  - *Rules*: Entire `yara-rules/` tree plus generated derivatives (`safe_malware_index.yar`).
  - *Metadata*: Build configs, documentation snippets, rule manifests, Cryptex dictionary entries (see dedicated spec).
- **Consumers**
  - LLM tooling via MCP (structured `resources`, `tools`, `prompts` interfaces).
  - Internal automation (Node-RED nodes calling MCP server HTTP endpoint or local transport).
  - Svelte UI (reads aggregated/denormalized endpoints for dashboards).

## Architecture Outline
1. **Transport Layer**
   - Implement the MCP server in Python (shared ecosystem with helper scripts) using the official `mcp` SDK, exposing stdio/websocket transports.
   - Provide a lightweight HTTP façade (FastAPI) if Node-RED needs REST hooks without MCP awareness.
2. **Resource Providers**
   - `GitResourceProvider`: exposes file/directory listings, individual blobs, diffs, commit metadata; caches git rev and file digests.
   - `RuleResourceProvider`: wraps `yara-rules/` with filters (by category, hash, safe-only) and can return compiled rule bundles.
   - `TelemetryProvider`: streams scan summaries produced by `yara_scanner.py` runs (persisted as JSON artifacts).
   - `CryptexProvider`: serves generated dictionary entries (mapping YARA functions to pyro/fire-marshal nomenclature).
3. **Tool Endpoints**
   - `tool:scan-directory` – orchestrates `yara_scanner.py` with parameters such as ruleset, directory, recursion.
   - `tool:create-safe-index` – executes the logic currently in `create_safe_rules.py` with configurable filters.
   - `tool:list-rules` – queries indexes for tags, modules, dependencies.
   - `tool:get-function-profile` – fetches Cryptex dictionary entries and underlying source snippet.
4. **Data Flow**
   - File watcher (watchdog) monitors repo for changes → triggers re-indexers (source AST index, rule manifest builder, Cryptex generator).
   - Ingestion jobs emit artifacts into a versioned object store (local `data/` tree or sqlite) referenced by MCP resources.
   - Optional embedding step stores summaries/embeddings for semantic search (OpenSearch, SQLite-FTS, or LiteLLM vector store) to support fast retrieval by the MCP server.
5. **Security**
   - Enforce allowlist of directories served.
   - Tag each resource/tool response with commit SHA + license label.
   - Vault integration (or Windows DPAPI) for storing API tokens required by downstream Node-RED flows.

## Phased Delivery
1. **Phase 0 – Foundations**
   - Promote helper scripts into `tools/` package with `pyproject.toml`.
   - Add tests and GitHub Actions workflow ensuring scripts + MCP skeleton import.
2. **Phase 1 – Read-Only MCP Server**
   - Implement resource providers and list/get operations.
   - Expose Cryptex entries from a static JSON seed (generated offline).
3. **Phase 2 – Active Tools**
   - Wire `scan-directory` and `create-safe-index` tools.
   - Persist outputs under `artifacts/<timestamp>/...` so MCP consumers can fetch them.
4. **Phase 3 – Integrations**
   - Add HTTP façade for Node-RED (FastAPI + auth).
   - Generate webhook-style events when new scans finish; Node-RED subscribes.
5. **Phase 4 – Observability & UI**
   - Provide metrics endpoint (Prometheus scrapable).
   - Feed summarized data to the Svelte interface (see re-engineering blueprint).

## Open Questions
- Preferred datastore for Cryptex dictionary (SQLite vs. flat JSON)? Start with JSON for portability.
- Expected authentication story for MCP server? If exposed beyond localhost, mutually authenticated TLS or SSH tunneling is recommended.
- Deployment target? Windows host can run Python service + Node-RED, but containerizing (Docker/Podman) simplifies parity between dev/prod.

