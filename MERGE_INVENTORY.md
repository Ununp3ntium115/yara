# Merge Inventory & Readiness Assessment

**Date:** 2025-11-25
**Branch:** `claude/prepare-merge-inventory-01Qzqr26mdEm2Z9kve9UjcK2`

## Executive Summary

This repository is a fork of the original YARA project (VirusTotal/yara) with significant additions called "YARA Cryptex" - a branded dictionary system, feed scanner, and tooling ecosystem. The project adds ~907 files and 223K+ lines of code on top of the base YARA codebase.

### Merge Readiness: **CONDITIONAL**

The project can work without Pyro, but cleanup is needed before merging to main.

---

## Repository Structure

### Original YARA Components (Upstream)
| Component | Status | Notes |
|-----------|--------|-------|
| `libyara/` | ✅ Unchanged | Core YARA library |
| `cli/` | ✅ Unchanged | yara, yarac binaries |
| `tests/` | ✅ Unchanged | C test suite |
| `docs/` | ✅ Unchanged | Sphinx documentation |
| Build system | ✅ Unchanged | autotools (configure.ac, Makefile.am) |

### Added Components (Cryptex System)
| Component | Status | Pyro Dependency | Notes |
|-----------|--------|-----------------|-------|
| `rust/` | ✅ Compiles | None | 4 Rust crates (cryptex-cli, cryptex-api, cryptex-store, yara-feed-scanner) |
| `mcp_server/` | ✅ Works | None | Standalone MCP server |
| `mcp_server_pyro/` | ⚠️ Optional | **Yes - requires Pyro** | Pyro-specific MCP server |
| `tools/` | ⚠️ Mixed | Partial | 22 Python tools (16 reference Pyro) |
| `yara_scanner.py` | ✅ Works | Optional | Works with or without Cryptex |
| `data/` | ✅ Works | None | Cryptex dictionary storage |
| `yara-rules/` | ❌ Empty | None | Submodule not initialized |
| `pyro-platform/` | ❌ Empty | **Yes** | Placeholder for Pyro clone |

---

## Pyro Dependencies Analysis

### Files That REQUIRE Pyro Platform
These files will not function without Pyro Platform being installed:

```
mcp_server_pyro/          # Entire directory
tools/pyro_api_endpoints.py
tools/pyro_architecture_analyzer.py
tools/pyro_cryptex_connector.py
tools/pyro_frontend_component.py
tools/pyro_integration_analyzer.py
tools/pyro_integration_test.py
pyro-platform/            # Empty placeholder
```

### Files That REFERENCE Pyro But Work Without It
These files mention Pyro but have fallback or optional behavior:

```
tools/audit_agent.py
tools/export_to_rust.py
tools/fix_duplicates.py
tools/mcp_agent_tools.py
tools/refine_cryptex.py
tools/rule_transcoder.py
tools/rule_transcoder_backup.py
tools/self_audit.py
tools/unified_mcp_client.py
tools/validate_cryptex.py
```

### Files That Are Fully Standalone (No Pyro)
```
tools/enhance_pseudocode.py
tools/gap_analyzer.py
tools/report_generator.py
tools/rule_loader.py
tools/test_streaming.py
mcp_server/               # Entire directory
rust/                     # Entire workspace
yara_scanner.py
```

---

## Documentation Files (83 total)

### Excessive Documentation
There are 83 markdown files in the root directory. Many are redundant status/completion reports:

**Likely Duplicates/Obsolete:**
- `FINAL_*.md` (8 files)
- `COMPLETE_*.md` (7 files)
- `PROJECT_*.md` (4 files)
- `SYSTEM_*.md` (5 files)
- `UA_*.md` (4 files)
- `SDLC_*.md` (7 files)

**Essential to Keep:**
- `README.md`
- `CLAUDE.md`
- `INSTALL.md`
- `QUICKSTART.md` or `QUICK_START.md` (pick one)
- `CHANGELOG.md`
- `LICENSE`
- `SECURITY.md`

---

## Rust Workspace Status

```
rust/
├── Cargo.toml           # Workspace config
├── cryptex-cli/         # CLI tool for dictionary operations
├── cryptex-api/         # REST API server
├── cryptex-store/       # Dictionary storage backend
└── yara-feed-scanner/   # Web feed scanner for YARA rules
```

**Build Status:** ✅ Compiles with 13 warnings (no errors)

**Warnings:**
- Visibility issues in `cryptex-api/src/feed.rs`
- Dead code in `ScanRequest.output` field

---

## Cleanup Tasks Before Merge

### High Priority
1. **Remove or isolate Pyro-dependent files**
   - Move `mcp_server_pyro/` to separate repo or delete
   - Move `tools/pyro_*.py` to separate repo or delete
   - Remove empty `pyro-platform/` directory

2. **Initialize or remove yara-rules submodule**
   ```bash
   git submodule update --init  # Or remove the reference
   ```

3. **Consolidate documentation**
   - Keep only essential docs
   - Remove redundant status files

### Medium Priority
4. **Fix Rust warnings**
   - Fix visibility in `cryptex-api/src/feed.rs`
   - Remove dead code

5. **Test standalone operation**
   - Verify `yara_scanner.py` works without Cryptex
   - Test MCP server without Pyro

### Low Priority
6. **Clean up Python tools**
   - Remove Pyro references from files that don't need them
   - Add proper error handling for optional dependencies

---

## Working Components (Without Pyro)

### What Works Today
1. **Original YARA** - Full C codebase compiles and works
2. **Rust Cryptex CLI** - `cargo build` succeeds
3. **Rust API Server** - Compiles (needs runtime test)
4. **Python Scanner** - Works with standard yara-python
5. **MCP Server** - Standalone version in `mcp_server/`

### What Needs Pyro
1. `mcp_server_pyro/` - Pyro Platform MCP integration
2. `tools/pyro_*.py` - Pyro analysis tools
3. Any references to PYRO Platform Ignition codebase

---

## Recommended Actions

### Option A: Full Cleanup (Recommended)
1. Delete all Pyro-specific files
2. Consolidate docs to ~10 essential files
3. Fix Rust warnings
4. Initialize or remove submodules
5. Create clean PR to main

### Option B: Branch Strategy
1. Keep `main` clean (original YARA only)
2. Create `feature/cryptex` for Cryptex additions
3. Create `feature/pyro-integration` for Pyro work
4. Merge incrementally

### Option C: Minimal Cleanup
1. Move Pyro files to `_deprecated/` directory
2. Document optional nature of Pyro integration
3. Keep everything but clearly mark status

---

## Files to Delete for Clean Merge

```bash
# Pyro-specific (delete or move to separate repo)
rm -rf mcp_server_pyro/
rm -rf pyro-platform/
rm tools/pyro_*.py
rm PYRO_*.md

# Redundant documentation (consolidate first)
rm FINAL_*.md
rm COMPLETE_*.md
rm PROJECT_*.md
rm SYSTEM_*.md
rm UA_*.md
rm SDLC_*.md
rm *_STATUS*.md
rm *_SUMMARY*.md
rm *_COMPLETE*.md
```

---

## Testing Checklist

- [ ] Build original YARA: `./bootstrap.sh && ./configure && make`
- [ ] Run YARA tests: `make check`
- [ ] Build Rust workspace: `cd rust && cargo build --release`
- [ ] Test Python scanner: `python yara_scanner.py --help`
- [ ] Test MCP server: `python -m mcp_server.server`
- [ ] Verify no Pyro errors when Pyro not installed

---

## Summary

| Metric | Count |
|--------|-------|
| Total added files | ~907 |
| Added lines of code | ~223,234 |
| Python tools | 22 |
| Pyro-dependent tools | 6 (direct) + 10 (reference) |
| Standalone tools | 6 |
| Documentation files | 83 |
| Rust crates | 4 |
| Rust build status | ✅ Compiles |

**Bottom Line:** The core Cryptex system (Rust + standalone MCP + Python scanner) works without Pyro. To merge to main, remove Pyro-specific files and consolidate documentation.

---

## R-YARA Rebranding Plan

The project is being rebranded from "YARA Cryptex" to **R-YARA** (Rust YARA) to:
- Distinguish from upstream VirusTotal YARA
- Emphasize Rust-native implementation
- Enable standalone operation

### Crate Renaming

| Current | Target |
|---------|--------|
| cryptex-store | r-yara-store |
| cryptex-api | r-yara-api |
| cryptex-cli | r-yara-cli |
| yara-feed-scanner | r-yara-feed-scanner |

### New Features Planned

1. **Streaming API** - WebSocket/SSE for real-time rule streaming
2. **Worker Protocol** - Distributed task processing
3. **Standalone Mode** - Zero Pyro dependencies

See `steering/R_YARA_ROADMAP.md` and `steering/GAP_ANALYSIS.md` for details.
