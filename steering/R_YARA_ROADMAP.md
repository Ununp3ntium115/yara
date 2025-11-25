# R-YARA: Rust YARA Roadmap

**Date:** 2025-11-25
**Status:** Active Development
**Codename:** R-YARA (Rust YARA)

---

## Executive Summary

R-YARA is a Rust-native reimplementation of YARA pattern matching functionality, designed as a standalone component that can optionally integrate with the Pyro Platform. The system provides:

1. **Standalone Operation** - Works without Pyro dependencies
2. **API Compatibility** - REST/WebSocket endpoints for workers
3. **Streaming Support** - Rule streaming like the zip transcoder pattern
4. **Cryptex Dictionary** - Branded function mapping system

---

## Rebranding: YARA → R-YARA

| Old Name | New Name | Rationale |
|----------|----------|-----------|
| YARA Cryptex | R-YARA Cryptex | Distinguishes from upstream YARA |
| yara-feed-scanner | r-yara-feed-scanner | Rust-native implementation |
| cryptex-cli | r-yara-cli | Unified CLI tool |
| cryptex-api | r-yara-api | API server |
| cryptex-store | r-yara-store | Persistence layer |

### Why R-YARA?
- "R" = Rust (primary language)
- "R" = Reengineered (clean-room approach where needed)
- "R" = Ready (production-focused)
- Avoids confusion with VirusTotal's official YARA tool

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      R-YARA System                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  r-yara-cli │  │ r-yara-api  │  │ r-yara-feed-scanner │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                     │            │
│         └────────────────┼─────────────────────┘            │
│                          │                                  │
│                  ┌───────▼───────┐                         │
│                  │  r-yara-store │                         │
│                  │    (redb)     │                         │
│                  └───────────────┘                         │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                   Optional Integrations                     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐│
│  │ MCP Server  │  │  Node-RED   │  │  Pyro Platform (opt) ││
│  │ (standalone)│  │   Flows     │  │    Integration       ││
│  └─────────────┘  └─────────────┘  └──────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

---

## Gap Analysis: Current vs Target

### Rust Crates Status

| Crate | Current Status | Target | Gap |
|-------|---------------|--------|-----|
| `cryptex-store` | ✅ Compiles | `r-yara-store` | Rename, add streaming |
| `cryptex-api` | ✅ Compiles (13 warnings) | `r-yara-api` | Fix warnings, add worker endpoints |
| `cryptex-cli` | ✅ Compiles | `r-yara-cli` | Rename, add stream commands |
| `yara-feed-scanner` | ✅ Compiles | `r-yara-feed-scanner` | Add streaming output |

### Missing Components

| Component | Priority | Description |
|-----------|----------|-------------|
| Streaming API | HIGH | WebSocket/SSE for rule streaming |
| Worker Protocol | HIGH | API for distributed workers |
| Rule Transcoder Stream | HIGH | Like zip transcoder pattern |
| Health/Metrics Endpoint | MEDIUM | For orchestration |
| Batch Processing | MEDIUM | Queue-based rule processing |
| PQC Transport | LOW | Post-quantum crypto (future) |

---

## API/Endpoint Specification

### Core Endpoints (r-yara-api)

```
# Dictionary Operations
GET  /api/v2/r-yara/dictionary/stats
GET  /api/v2/r-yara/dictionary/lookup?symbol={name}
GET  /api/v2/r-yara/dictionary/search?q={query}
POST /api/v2/r-yara/dictionary/entry

# Scanning Operations
POST /api/v2/r-yara/scan/file
POST /api/v2/r-yara/scan/directory
GET  /api/v2/r-yara/scan/{job_id}/status
GET  /api/v2/r-yara/scan/{job_id}/results

# Feed Operations
GET  /api/v2/r-yara/feed/list
POST /api/v2/r-yara/feed/scan
GET  /api/v2/r-yara/feed/stream  # SSE/WebSocket

# Worker Operations (NEW)
POST /api/v2/r-yara/worker/register
GET  /api/v2/r-yara/worker/tasks
POST /api/v2/r-yara/worker/heartbeat
POST /api/v2/r-yara/worker/result

# Health/Metrics
GET  /health
GET  /metrics
```

### Streaming Protocol (Like Zip Transcoder)

```rust
// Stream message format
enum StreamMessage {
    RuleStart { rule_id: String, name: String },
    RuleChunk { rule_id: String, data: Vec<u8> },
    RuleEnd { rule_id: String, checksum: String },
    Match { rule_id: String, file: String, offset: u64 },
    Error { code: i32, message: String },
    Heartbeat { timestamp: u64 },
}
```

### Worker Integration

Workers connect via WebSocket and receive tasks:

```rust
// Worker task assignment
struct WorkerTask {
    task_id: String,
    task_type: TaskType,  // Scan, Transcode, Validate
    payload: TaskPayload,
    priority: u8,
    timeout_ms: u64,
}

enum TaskType {
    ScanFile { path: String, rules: Vec<String> },
    TranscodeRule { source: String, format: String },
    ValidateRule { content: String },
    StreamRules { feed_url: String },
}
```

---

## Implementation Plan

### Phase 1: Rename & Consolidate (Current)

1. ✅ Create merge inventory
2. 🔄 Update steering documentation
3. [ ] Rename crates to r-yara-*
4. [ ] Fix Rust warnings
5. [ ] Remove Pyro-specific dependencies

### Phase 2: Streaming Infrastructure

1. [ ] Add WebSocket support to r-yara-api
2. [ ] Implement StreamMessage protocol
3. [ ] Create streaming rule loader
4. [ ] Add SSE fallback for HTTP-only clients

### Phase 3: Worker System

1. [ ] Design worker registration protocol
2. [ ] Implement task queue (in-memory + redb persistence)
3. [ ] Add worker heartbeat monitoring
4. [ ] Create worker SDK (Rust library)

### Phase 4: Pyro Integration (Optional)

1. [ ] Create Pyro adapter crate
2. [ ] Map R-YARA endpoints to Pyro API
3. [ ] Bridge MCP server to Pyro Platform
4. [ ] Document integration patterns

---

## Files to Modify

### Crate Renaming

```bash
# Rename directories
mv rust/cryptex-store rust/r-yara-store
mv rust/cryptex-api rust/r-yara-api
mv rust/cryptex-cli rust/r-yara-cli
mv rust/yara-feed-scanner rust/r-yara-feed-scanner

# Update Cargo.toml workspace
[workspace]
members = [
    "r-yara-store",
    "r-yara-api",
    "r-yara-cli",
    "r-yara-feed-scanner",
]
```

### API Updates

```rust
// r-yara-api/src/main.rs - Add streaming routes
Router::new()
    .route("/api/v2/r-yara/feed/stream", get(stream_handler))
    .route("/api/v2/r-yara/worker/connect", get(worker_ws_handler))
```

---

## Dependencies (No Pyro Required)

### Required
- `tokio` - Async runtime
- `axum` - Web framework
- `redb` - Embedded database
- `serde` - Serialization
- `tokio-tungstenite` - WebSocket

### Optional (for Pyro integration)
- Pyro Platform SDK (when available)
- MCP SDK (for Claude integration)

---

## Testing Strategy

### Unit Tests
- Store operations (CRUD)
- Rule parsing
- Stream encoding/decoding

### Integration Tests
- API endpoint responses
- Worker task flow
- Streaming durability

### Load Tests
- Concurrent workers
- Large rule sets
- Sustained streaming

---

## Success Criteria

1. **Standalone Operation**: R-YARA runs without any Pyro dependencies
2. **API Compatibility**: All endpoints return expected formats
3. **Streaming**: Rules can be streamed to workers in real-time
4. **Performance**: Process 1000+ rules/second on modest hardware
5. **Reliability**: Graceful handling of worker disconnections

---

## Next Actions

1. [ ] Complete Phase 1 renaming
2. [ ] Add streaming endpoint scaffolding
3. [ ] Document worker protocol
4. [ ] Create example worker implementation
5. [ ] Remove remaining Pyro references from core
