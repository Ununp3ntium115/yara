# R-YARA Gap Analysis

**Date:** 2025-11-25
**Purpose:** Track what's missing to make R-YARA production-ready without Pyro dependencies

---

## Component Inventory

### Rust Crates (4 total)

| Crate | Lines | Status | Gaps |
|-------|-------|--------|------|
| cryptex-store | ~200 | ✅ Compiles | Rename to r-yara-store |
| cryptex-api | ~400 | ⚠️ 13 warnings | Fix visibility, add streaming |
| cryptex-cli | ~150 | ✅ Compiles | Rename, add stream commands |
| yara-feed-scanner | ~300 | ✅ Compiles | Add streaming output |

### Python Tools (22 total)

| Tool | Pyro Dependent | Standalone Alternative |
|------|----------------|----------------------|
| `yara_scanner.py` | No | Keep as-is |
| `rule_loader.py` | No | Keep as-is |
| `report_generator.py` | No | Keep as-is |
| `gap_analyzer.py` | No | Keep as-is |
| `enhance_pseudocode.py` | No | Keep as-is |
| `test_streaming.py` | No | Keep as-is |
| `pyro_*.py` (6 files) | **Yes** | Delete or move to separate repo |
| Others (10 files) | Reference only | Remove Pyro mentions |

### MCP Servers (2)

| Server | Pyro Dependent | Action |
|--------|----------------|--------|
| `mcp_server/` | No | Keep, rename endpoints to r-yara |
| `mcp_server_pyro/` | **Yes** | Delete or move to integration repo |

---

## Functional Gaps

### HIGH Priority

| Gap | Current State | Target | Effort |
|-----|--------------|--------|--------|
| Streaming API | None | WebSocket + SSE | 2-3 days |
| Worker Protocol | None | Task queue + heartbeat | 3-4 days |
| Rule Streaming | Batch only | Real-time stream | 2 days |
| API Rename | cryptex endpoints | r-yara endpoints | 1 day |

### MEDIUM Priority

| Gap | Current State | Target | Effort |
|-----|--------------|--------|--------|
| Health endpoint | None | /health, /metrics | 0.5 day |
| Batch processing | Manual | Queue-based | 2 days |
| Error recovery | Basic | Graceful degradation | 1 day |
| Config management | Hardcoded | TOML/env config | 1 day |

### LOW Priority

| Gap | Current State | Target | Effort |
|-----|--------------|--------|--------|
| PQC transport | None | Kyber integration | 1 week |
| Audit logging | Minimal | Full audit trail | 2 days |
| Rate limiting | None | Token bucket | 1 day |

---

## API Gaps

### Missing Endpoints

```
# Streaming (HIGH)
GET  /api/v2/r-yara/feed/stream     # SSE rule stream
WS   /api/v2/r-yara/worker/connect  # Worker WebSocket

# Worker Management (HIGH)
POST /api/v2/r-yara/worker/register
GET  /api/v2/r-yara/worker/tasks
POST /api/v2/r-yara/worker/heartbeat
POST /api/v2/r-yara/worker/result

# Operational (MEDIUM)
GET  /health
GET  /metrics
GET  /api/v2/r-yara/status
```

### Existing Endpoints (Need Rename)

```
# Current → Target
/api/v2/yara/cryptex/* → /api/v2/r-yara/dictionary/*
/api/v2/yara/scan/*    → /api/v2/r-yara/scan/*
/api/v2/yara/feed/*    → /api/v2/r-yara/feed/*
```

---

## Dependency Gaps

### Required Dependencies (Already Present)

- [x] tokio (async runtime)
- [x] axum (web framework)
- [x] redb (embedded DB)
- [x] serde/serde_json (serialization)
- [x] chrono (timestamps)
- [x] anyhow/thiserror (error handling)

### Missing Dependencies

- [ ] `tokio-tungstenite` - WebSocket support
- [ ] `axum-extra` - SSE support
- [ ] `tower` - Middleware (rate limiting, timeouts)
- [ ] `tracing` - Structured logging
- [ ] `metrics` - Prometheus metrics

---

## Code Quality Gaps

### Rust Warnings to Fix

```
cryptex-api/src/feed.rs:
  - Line 21: ScanResponse visibility mismatch
  - Line 17: Dead code in ScanRequest.output
  - 11 additional visibility warnings
```

### Documentation Gaps

- [ ] API documentation (OpenAPI spec)
- [ ] Worker protocol spec
- [ ] Streaming format spec
- [ ] Deployment guide for standalone mode

---

## Testing Gaps

### Missing Test Coverage

| Area | Current | Target |
|------|---------|--------|
| Unit tests | ~20% | 80% |
| Integration tests | ~5% | 60% |
| Load tests | 0% | Basic coverage |
| E2E tests | 0% | Happy path coverage |

### Missing Test Files

- [ ] `r-yara-store/tests/store_tests.rs`
- [ ] `r-yara-api/tests/api_tests.rs`
- [ ] `r-yara-api/tests/streaming_tests.rs`
- [ ] `r-yara-api/tests/worker_tests.rs`

---

## Files to Delete (Pyro-Specific)

```bash
# Directories
rm -rf mcp_server_pyro/
rm -rf pyro-platform/

# Python tools
rm tools/pyro_api_endpoints.py
rm tools/pyro_architecture_analyzer.py
rm tools/pyro_cryptex_connector.py
rm tools/pyro_frontend_component.py
rm tools/pyro_integration_analyzer.py
rm tools/pyro_integration_test.py

# Documentation
rm PYRO_*.md
```

---

## Files to Rename

```bash
# Rust crates
rust/cryptex-store/    → rust/r-yara-store/
rust/cryptex-api/      → rust/r-yara-api/
rust/cryptex-cli/      → rust/r-yara-cli/
rust/yara-feed-scanner/ → rust/r-yara-feed-scanner/

# Binaries
cryptex-cli → r-yara
cryptex-api → r-yara-server
```

---

## Streaming Implementation Gap

### Current: Batch Processing
```rust
// Current: Load all rules, process, return
let rules = load_rules(path)?;
let results = scan_all(rules, target)?;
return results;
```

### Target: Streaming Processing
```rust
// Target: Stream rules as they're processed
let (tx, rx) = channel();
spawn(async move {
    for rule in stream_rules(source) {
        tx.send(StreamMessage::Rule(rule)).await?;
        if let Some(match_) = scan(&rule, target) {
            tx.send(StreamMessage::Match(match_)).await?;
        }
    }
});
return rx;  // Client receives stream
```

---

## Worker Integration Gap

### Current: No Worker Support
- Single-process execution
- No task distribution
- No progress tracking

### Target: Distributed Workers
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   r-yara    │     │   Worker    │     │   Worker    │
│   Server    │────▶│     #1      │     │     #2      │
│             │     └─────────────┘     └─────────────┘
│  Task Queue │            │                   │
│             │◀───────────┴───────────────────┘
└─────────────┘         Results
```

---

## Priority Matrix

```
           HIGH IMPACT
               │
    Streaming  │  Worker System
    API        │
               │
LOW ───────────┼─────────────── HIGH EFFORT
               │
    Renaming   │  PQC Transport
    Cleanup    │
               │
           LOW IMPACT
```

**Focus Order:**
1. Renaming + Cleanup (quick win)
2. Streaming API (core feature)
3. Worker System (scalability)
4. Everything else

---

## Next Steps

1. [ ] Delete Pyro-specific files
2. [ ] Rename Rust crates to r-yara-*
3. [ ] Fix 13 Rust warnings
4. [ ] Add tokio-tungstenite dependency
5. [ ] Implement basic streaming endpoint
6. [ ] Create worker registration endpoint
7. [ ] Document API with OpenAPI
