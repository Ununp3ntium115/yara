# MCP Server Implementation Guide

## Mission
Stand up an MCP server that ingests the full YARA repository, exposes every artifact (source, rules, docs, Cryptex entries) for training, and provides tool endpoints used by Node-RED flows, Rust services, and Svelte/Electron front-ends. The MCP instance is the canonical interface to “Pyro Fire Marshal” and any other consumers.

## Core Responsibilities
1. **Resource Hosting**
   - `source/*`: raw files with metadata (path, commit, hash).
   - `rules/*`: rule corpus, safe indexes, compiled bundles.
   - `cryptex/*`: anarchist dictionary entries stored in `redb`.
   - `artifacts/*`: scan outputs, gap-analysis reports, telemetry.
2. **Tooling**
   - `scan-directory` → wraps scanner backend (Python now, Rust later).
   - `create-safe-index` → regenerates `safe_malware_index.yar`.
   - `cryptex-annotate` → adds/updates entries (codename, symbol, summary, pseudocode).
   - `gap-audit` → reports which subsystems still lack Rust equivalents.
   - Future: QKD/pqc hookups, packaging commands, Node-RED triggers.
3. **Training Feeds**
   - Provide streaming access so LLM workflows can “read” the codebase.
   - Tag every response with commit SHA, license, and provenance.

## Architecture
```
           +----------------------+
           |  Svelte / Electron   |
           +-----------+----------+
                       |
                   HTTPS/WebSocket
                       |
                +------+-------+
                | FastAPI/axum |  <-- gateway: auth, rate limits, REST
                +------+-------+
                       |
                   MCP Transport
                       |
           +-----------+-----------+
           |    MCP Core Server    |
           +-----------+-----------+
               |       |        |
             Git    Cryptex    Tools
```

### Implementation Stages
1. **Prototype (Python)**
   - Use official MCP SDK (stdio/WebSocket).
   - Resource providers backed by filesystem and JSON.
   - Gateway = FastAPI.
2. **Rust Port**
   - Mirror providers/tools using `tokio` + `axum`.
   - Persistence in `redb` (embedded key-value) with zero-copy reads.
   - Shared library crate consumed by Node-RED nodes and CLI clients.

## Interaction Patterns
| Client | Call | Result |
| --- | --- | --- |
| Node-RED | invoke `scan-directory` | Launches scanner, stores JSON artifact, emits event |
| Svelte UI | list `cryptex/*` | Fetches dictionary table for display |
| Pyro Fire Marshal | POST `/api/cryptex` | Gateway pipes to `cryptex-annotate`, returns new entry |
| Rust gap agent | invoke `gap-audit` | Receives structured report to update progress |

## Security & Compliance
- Token-based auth at gateway, optional mTLS.
- Access policies per directory (no accidental leakage).
- SHA-2/SHA-3 hashing (RustCrypto) for artifact signing.
- Audit logs stored in `redb` + forwarded to external SIEM if needed.

## Deliverables
1. `mcp/` source tree + unit tests.
2. Gateway OpenAPI spec (`steering/API_CONTRACT.md` upcoming).
3. Deployment manifests (systemd, Docker, Windows services).
4. CI job that boots the MCP server, runs sample calls, and validates Cryptex read/write paths.

