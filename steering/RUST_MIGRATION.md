# Rust Migration & Gap Analysis

## Goal
Rebuild the operational surface (scanning, rule management, data services) in Rust while maintaining interoperability with legacy C components until parity is achieved. Track gaps continuously so we know what remains non-Rust and where additional features are required.

## Current Stack Snapshot
| Component | Language | Status |
| --- | --- | --- |
| `libyara` core | C | Stays upstream-only; we consume via FFI initially. |
| CLI tools (`yara`, `yarac`) | C | Keep for comparison; wrap with Rust commands. |
| Helper scripts (`create_safe_rules.py`, `yara_scanner.py`) | Python | Need Rust equivalents. |
| Cryptex dictionary storage | Markdown/JSON | Move to `redb` via Rust crate. |
| Automation | PowerShell / manual | Replace with Node-RED flows + Rust APIs. |

## Rust Workspace Plan
```
rust/
  Cargo.toml (workspace)
  crates/
    cryptex-store      # redb-backed dictionary + CLI
    scan-runner        # wrap libyara -> later pure Rust engine
    safe-index         # replacement for create_safe_rules.py
    mcp-gateway        # axum-based REST/WebSocket interface
    telemetry-agent    # collects scan results, pushes to redb
    node-red-client    # utility lib for custom Node-RED nodes
```

## Migration Steps
1. **Bootstrap Workspace**
   - Initialize cargo workspace, add CI (fmt, clippy, tests).
2. **Port Helper Scripts**
   - `safe-index`: read `malware_index.yar`, exclude `cuckoo.` includes, emit safe index.
   - `scan-runner`: compile rules once, walk directories with async IO, serialize matches to JSON.
3. **Cryptex Store**
   - Define Redb tables (`codename`, `symbol`, `summary`, `pseudocode`, `status`, `deps`).
   - Provide CLI + MCP adapters.
4. **Gateway (axum)**
   - Mirror FastAPI endpoints for cross-platform deployment.
   - Implement WebSocket streaming for Node-RED and Svelte/Electron.
5. **Gap Analyzer Agent**
   - Rust CLI scanning for `.c`, `.py`, `.ps1` files without Rust analogs.
   - Writes report + updates Cryptex entries (`status = legacy/ported`).

## Gap Tracking
- Maintain `gap_report.json` (or `redb` table) with:
  - `component`
  - `language`
  - `rust_status` (`pending`, `in_progress`, `done`)
  - `responsible`
  - `linked_cryptex`
- Expose via MCP tool `gap-audit` so dashboards stay in sync.

## Feature Enhancements During Port
- Add `redb` caching for rule metadata, enabling instant lookups.
- Integrate SHA-2/SHA-3 hashing via RustCrypto for artifact signing.
- Provide optional PQC (Kyber) for API transport (using `rustls-post-quantum`).
- Embed Node-RED runtime triggers (via HTTP) for automation.

## Deployment Considerations
- Rust binaries produced for Linux/macOS/Windows/*BSD; align with packaging plan in `MASTER_PLAN.md`.
- Ensure `scan-runner` can operate purely in Rust when linked with `libyara` via `yara-sys`.
- Document fallback path (Python scripts) until Rust versions reach parity.

## Next Actions
1. Scaffold workspace + crates.
2. Port safe-index generator.
3. Implement Cryptex store + CLI.
4. Hook Rust components into MCP server (initially via subprocess calls, later direct integration).
5. Update Cryptex entries as each component migrates, noting new functionality unlocked by Rust implementation.

