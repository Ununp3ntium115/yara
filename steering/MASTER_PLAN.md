# Project Steering Plan — Pyro Anarchist Stack

## 0. Purpose
Create an MCP-backed knowledge and execution layer that ingests the entire YARA codebase, emits an anarchist Cryptex dictionary, and powers new Rust-first services (Redb-backed engine, Node-RED orchestration, Svelte/Electron UI, custom API) deployable across all major OS distributions.

---

## 1. Objectives (Iterative Loop)
1. **MCP Server** – Serve every file/rule/doc as structured resources, expose tools (`scan-directory`, `create-safe-index`, `cryptex-lookup`, future QKD hooks).
2. **Cryptex Dictionary** – Map every function/module/doc to anarchist aliases + pseudocode and sync it via MCP.
3. **Rust Rebuild** – Identify C/Python portions to be reauthored in Rust (libyara bindings, rule orchestration, persistence in `redb`).
4. **Node-RED + API** – Provide automation nodes and an HTTP/WebSocket API for external applications (Pyro Fire Marshal).
5. **UI Layer** – Ship both SvelteKit SPA and Electron bundle that talk to the same API gateway.
6. **Cross-Platform Delivery** – Produce binaries/containers/installers for Linux, macOS, Windows, *BSD.

---

## 2. Gap Analysis (Rust vs Legacy)
| Area | Current State | Rust Target | Notes |
| --- | --- | --- | --- |
| Rule Compilation & Scan | C `libyara` + CLI | Bindings via `yara-sys` or rewrite critical paths in Rust | Short-term FFI, long-term incremental rewrite |
| Helper Scripts | Python (`create_safe_rules.py`, `yara_scanner.py`) | Rust CLI services (`cargo workspace`) | Use `redb` for metadata, `reqwest` for API |
| Persistence | Flat files / JSON | `redb` embedded DB for Cryptex entries, scan logs | ACID, zero-copy |
| Automation | Ad-hoc CLI | Node-RED custom nodes hitting MCP API | Provide CLI fallback |
| UI | None | SvelteKit web + Electron (packaged Svelte bundle) | Both hit same gateway |

Action: Document each migration in dedicated subplans (see sections below) and keep Cryptex dictionary updated as functionality moves.

---

## 3. MCP Server Blueprint (Rust-Compatible)
1. **Implementation**: start in Python (fast iteration) with plan to mirror API in Rust (`axum` + `tokio`) once bindings settle.
2. **Resources**:
   - `source/*` (entire git tree with metadata)
   - `rules/*` (raw and safe indexes)
   - `cryptex/*` (JSON/SQLite via `redb`)
   - `artifacts/*` (scan outputs, telemetry)
3. **Tools**:
   - `scan-directory`: triggers scanner backend (Python now, Rust later)
   - `create-safe-index`: calls generator
   - `cryptex-annotate`: inserts/updates entries
   - `gap-audit`: reports modules not yet ported to Rust
4. **Transports**: stdio + WebSocket (MCP native) plus FastAPI gateway for HTTP clients.
5. **Security**: token-based auth at gateway, per-directory allowlist, signed artifacts (SHA-2/3 via RustCrypto when Rust services land).

Deliverable: `mcp/` directory with server code + tests, plus OpenAPI description for gateway.

---

## 4. Cryptex Dictionary Program
1. **Schema** already defined (`docs/CRYPTEX_DICTIONARY_SPEC.md`); storage moves to `redb` for fast lookup.
2. **Generation Loop**:
   - Harvest symbols (ctags/clangd, ripgrep for Python/PowerShell).
   - Assign anarchist alias (`prefix + intent`), capture signature + pseudocode.
   - Store entry → expose through MCP resource + `cryptex-lookup` tool.
3. **Automation**:
   - Rust CLI `cryptex-cli` to add/check entries (`cargo xtask cryptex`).
   - Node-RED node to fetch alias metadata for UI overlays.
4. **Frontends**:
   - Svelte dictionary panel with search/filter.
   - Electron offline mode bundling entire Cryptex dataset.

Action: Extend `docs/CRYPTEX_DICTIONARY_SEED.md` until 100% coverage, then auto-generate Redb DB snapshot.

---

## 5. Rust Conversion Strategy
### 5.1 Workspaces
```
/rust
  /crates
    mcp-gateway      # axum-based MCP HTTP bridge
    cryptex-store    # redb schema + CLI
    yara-runner      # wrappers over libyara or re-impl
    node-red-nodes   # JS packages w/ wasm helpers
```

### 5.2 Priorities
1. **Cryptex Store** – easiest starting point (pure Rust).
2. **Scanner Runner** – wrap libyara via FFI, gradually reimplement scanning logic (Aho-Corasick etc.) if feasible.
3. **Safe Index Generator** – port Python script to Rust (walk `yara-rules`, filter `cuckoo.`).
4. **Telemetry Service** – ingest scan results into `redb`, expose via API.

### 5.3 Gap Agent
Create a small “gap analyzer” CLI that:
- scans repo for `.c/.py` components without Rust counterparts,
- emits TODO entries into Cryptex,
- feeds Node-RED dashboard with progress.

---

## 6. Automation & API Surfaces
### 6.1 Node-RED
- Custom nodes: `mcp-call`, `yara-scan`, `cryptex-report`, `rust-gap-status`.
- Flows for scan scheduling, rule refresh, Cryptex enrichment, QKD/PQC integration.

### 6.2 Custom API
- Core endpoints (FastAPI → later axum):
  - `POST /scans` — trigger `scan-directory`
  - `GET /scans/{id}` — retrieve artifact
  - `GET /cryptex/{codename}` — fetch entry
  - `POST /cryptex` — add/update alias
  - `GET /gap` — report Rust migration status
- Authentication: JWT or mTLS.

### 6.3 Frontends
- **SvelteKit SPA** hitting HTTP API.
- **Electron shell** that bundles Svelte UI + offline Cryptex DB.

---

## 7. Deployment Targets
| OS | Packaging | Notes |
| --- | --- | --- |
| Linux (Deb/RPM) | systemd service for MCP + CLI packages | Provide Docker Compose stack too |
| macOS | Universal binaries + launchd plist | Sign/notarize Electron app |
| Windows | MSI installer + PowerShell helper scripts | Maintain compatibility with existing `scan.ps1` |
| *BSD | tarball + rc scripts | For forensic appliances |

All builds pull from same Rust workspace + Node-RED bundle + Svelte assets.

---

## 8. Immediate Actions
1. Flesh out MCP server scaffold (Python) + document API contract.
2. Expand Cryptex seed table until scanner + modules are covered.
3. Start Rust workspace skeleton (`cargo new --workspace rust`).
4. Draft Node-RED node spec + Svelte/Electron UX mocks.
5. Define CI jobs for docs linting, Python tools, initial Rust crates.

Keep iterating this plan as we discover new gaps; update Cryptex entries and this steering document in lockstep.

