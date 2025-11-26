# R-YARA TODO Feature List

**Version:** v0.1.0-beta
**Date:** 2025-11-26
**Status:** Beta Release

This document tracks features to be implemented in future R-YARA releases, comparing against upstream YARA capabilities and identifying gaps.

---

## Current State Summary

### What R-YARA Has (v0.1.0-beta)

| Category | Features |
|----------|----------|
| **Core API** | REST API server (axum), dictionary operations, health endpoints |
| **Scanning** | File/data scanning via YARA CLI wrapper, rule validation, compilation |
| **Dictionary** | redb storage backend, lookup, search with pagination |
| **Feed Scanner** | Web feed scanner with use case detection (malware/apt/ransomware/webshell) |
| **Task Queue** | Async task queue, priority support, status tracking |
| **Worker System** | Distributed worker protocol, task assignment, heartbeats |
| **PYRO Integration** | Connection management, retry logic, standalone mode |
| **Hashing** | 20 algorithms (MD5, SHA256, SHA3, BLAKE2/3, CRC32, fuzzy hashing) |

### What Upstream YARA Has (v4.5.5)

| Category | Features |
|----------|----------|
| **Core** | Native C library, pattern matching engine, regex support |
| **PE Module** | Section parsing, imports/exports, authenticode signatures |
| **ELF Module** | Symbol parsing, section analysis, telfhash similarity |
| **Dotnet Module** | .NET assembly parsing, type definitions, method signatures |
| **Hash Module** | MD5, SHA1, SHA256 on file regions |
| **Math Module** | Entropy, statistics, to_int/to_string functions |
| **Time Module** | Temporal conditions in rules |
| **Cuckoo Module** | Behavioral sandbox integration |
| **Magic Module** | File type identification (libmagic) |
| **Console Module** | Debug output during rule execution |
| **Process Scanning** | Memory scanning on Windows/Linux/macOS/BSD |

---

## Priority 1: Critical for Production

### 1.1 Native YARA Integration
**Status:** Not Started
**Effort:** 2-3 weeks
**Description:** Replace CLI wrapper with native YARA library bindings

```
Current: Spawns yara/yarac CLI processes
Target: Use yara-sys or yara crate for native integration
```

Tasks:
- [ ] Add yara-sys dependency or build bindings
- [ ] Implement native rule compilation
- [ ] Implement native file/data scanning
- [ ] Implement native rule validation
- [ ] Port all scanner worker functions to native API
- [ ] Benchmark native vs CLI performance

### 1.2 YARA-X Integration
**Status:** Not Started
**Effort:** 1-2 weeks
**Description:** Integrate VirusTotal's Rust YARA rewrite (released June 2025)

```
YARA-X is the official Rust rewrite by VirusTotal
Should be primary scanning engine for pure-Rust deployment
```

Tasks:
- [ ] Add yara-x dependency
- [ ] Implement scanning via YARA-X
- [ ] Compare YARA-X vs libyara performance
- [ ] Add configuration to select engine (yara/yara-x)
- [ ] Test rule compatibility between engines

### 1.3 WebSocket Streaming
**Status:** Partial (protocol defined, not connected)
**Effort:** 1 week
**Description:** Real-time streaming for workers and results

Tasks:
- [ ] Add WebSocket endpoint for worker connections
- [ ] Implement SSE fallback for HTTP-only clients
- [ ] Stream scan results in real-time
- [ ] Stream rule updates to workers
- [ ] Add reconnection logic with backoff

### 1.4 Prometheus Metrics
**Status:** Not Started
**Effort:** 2-3 days
**Description:** Production monitoring and observability

Tasks:
- [ ] Add `metrics` crate dependency
- [ ] Implement `/metrics` endpoint (Prometheus format)
- [ ] Track scan latency, throughput, queue depth
- [ ] Track worker health and task completion rates
- [ ] Add Grafana dashboard template

---

## Priority 2: Module Parity with YARA

### 2.1 PE Module (Rust Native)
**Status:** Not Started
**Effort:** 2-3 weeks
**Description:** Pure Rust PE parsing for malware analysis

Tasks:
- [ ] Add `goblin` or `object` crate for PE parsing
- [ ] Extract imports/exports tables
- [ ] Parse section headers and data
- [ ] Extract resources (icons, version info)
- [ ] Implement authenticode signature parsing
- [ ] Calculate imphash and other PE hashes

### 2.2 ELF Module (Rust Native)
**Status:** Not Started
**Effort:** 1-2 weeks
**Description:** Pure Rust ELF parsing

Tasks:
- [ ] Add ELF parsing via `goblin` crate
- [ ] Extract symbol tables
- [ ] Parse section and segment headers
- [ ] Implement telfhash (Trend Micro ELF hash)
- [ ] Calculate ELF-specific hashes

### 2.3 Dotnet Module (Rust Native)
**Status:** Not Started
**Effort:** 2-3 weeks
**Description:** .NET assembly parsing in Rust

Tasks:
- [ ] Add PE/CLI metadata parsing
- [ ] Extract type definitions and namespaces
- [ ] Parse method signatures
- [ ] Extract .NET resources
- [ ] Implement .NET-specific hash calculations

### 2.4 Math Module
**Status:** Partial (entropy in hashing.rs)
**Effort:** 3-4 days
**Description:** Statistical functions for rule conditions

Tasks:
- [ ] Implement mean, mode, deviation functions
- [ ] Add percentage calculations
- [ ] Add to_int and to_string conversions
- [ ] Expose as API endpoint for rule development

### 2.5 Time Module
**Status:** Not Started
**Effort:** 1-2 days
**Description:** Temporal conditions support

Tasks:
- [ ] Implement current time functions
- [ ] Add date comparison operators
- [ ] Support timezone handling

---

## Priority 3: Performance & Scalability

### 3.1 Rule Caching
**Status:** Not Started
**Effort:** 1 week
**Description:** Cache compiled rules for faster repeated scans

Tasks:
- [ ] Implement LRU cache for compiled rules
- [ ] Add cache invalidation on rule updates
- [ ] Persist compiled rules to disk
- [ ] Add cache statistics endpoint

### 3.2 Parallel Scanning
**Status:** Not Started
**Effort:** 1 week
**Description:** Multi-threaded file scanning

Tasks:
- [ ] Implement rayon-based parallel scanning
- [ ] Add configurable worker thread pool
- [ ] Batch file processing
- [ ] Progress reporting for batch jobs

### 3.3 Memory-Mapped Scanning
**Status:** Not Started
**Effort:** 3-4 days
**Description:** Efficient large file scanning

Tasks:
- [ ] Add memmap2 for memory-mapped files
- [ ] Handle files larger than RAM
- [ ] Stream scanning for very large files

### 3.4 Process Memory Scanning
**Status:** Not Started
**Effort:** 2 weeks
**Description:** Scan running process memory

Tasks:
- [ ] Linux /proc/pid/mem scanning
- [ ] macOS mach_vm_read scanning
- [ ] Windows ReadProcessMemory scanning
- [ ] Module and heap enumeration

---

## Priority 4: API & Integration

### 4.1 OpenAPI Documentation
**Status:** Not Started
**Effort:** 2-3 days
**Description:** Auto-generated API documentation

Tasks:
- [ ] Add `utoipa` for OpenAPI generation
- [ ] Document all endpoints
- [ ] Add Swagger UI endpoint
- [ ] Generate client SDKs

### 4.2 Rate Limiting
**Status:** Not Started
**Effort:** 2 days
**Description:** Protect API from abuse

Tasks:
- [ ] Add `tower-governor` for rate limiting
- [ ] Per-IP and per-API-key limits
- [ ] Rate limit headers in responses
- [ ] Configurable limits

### 4.3 Authentication
**Status:** Not Started
**Effort:** 1 week
**Description:** API authentication and authorization

Tasks:
- [ ] API key authentication
- [ ] JWT token support
- [ ] Role-based access control
- [ ] Audit logging

### 4.4 MCP Server Enhancement
**Status:** Basic implementation exists
**Effort:** 1 week
**Description:** Enhanced Model Context Protocol support

Tasks:
- [ ] Add more YARA-specific tools
- [ ] Improve rule generation prompts
- [ ] Add threat intelligence integration
- [ ] Streaming support in MCP

---

## Priority 5: Testing & Quality

### 5.1 Test Coverage
**Status:** ~30% coverage (39 tests)
**Target:** 80% coverage
**Effort:** 2 weeks

Tasks:
- [ ] Add unit tests for all modules
- [ ] Add integration tests for API endpoints
- [ ] Add end-to-end workflow tests
- [ ] Add property-based tests (proptest)
- [ ] Add fuzzing tests (cargo-fuzz)

### 5.2 Benchmarking Suite
**Status:** Not Started
**Effort:** 3-4 days
**Description:** Performance regression testing

Tasks:
- [ ] Add `criterion` for benchmarks
- [ ] Benchmark scanning throughput
- [ ] Benchmark rule compilation
- [ ] Benchmark dictionary operations
- [ ] CI benchmark comparisons

### 5.3 Load Testing
**Status:** Not Started
**Effort:** 3-4 days
**Description:** Stress testing for production readiness

Tasks:
- [ ] Create k6 or locust load test scripts
- [ ] Test concurrent API requests
- [ ] Test worker connection limits
- [ ] Document performance characteristics

---

## Priority 6: Developer Experience

### 6.1 Client Libraries
**Status:** Not Started
**Effort:** 2 weeks (all languages)

Tasks:
- [ ] Python client (requests-based)
- [ ] JavaScript/TypeScript client
- [ ] Go client
- [ ] Rust client library

### 6.2 Docker Support
**Status:** Not Started
**Effort:** 2-3 days

Tasks:
- [ ] Create Dockerfile
- [ ] Multi-stage build for small images
- [ ] docker-compose for full stack
- [ ] Kubernetes manifests

### 6.3 Configuration Management
**Status:** Environment/CLI args only
**Effort:** 2-3 days

Tasks:
- [ ] TOML configuration file support
- [ ] Environment variable override
- [ ] Configuration validation
- [ ] Hot reload for config changes

---

## Comparison Matrix: R-YARA vs YARA vs YARA-X

| Feature | YARA (C) | YARA-X (Rust) | R-YARA | Notes |
|---------|----------|---------------|--------|-------|
| Core scanning | Native | Native | CLI wrapper | Need native integration |
| PE module | Yes | Yes | No | High priority |
| ELF module | Yes | Yes | No | High priority |
| Dotnet module | Yes | Yes | No | Medium priority |
| Hash module | Yes | Yes | Partial | Has hashing.rs |
| Math module | Yes | Yes | Partial | Has entropy |
| Time module | Yes | Yes | No | Low priority |
| Process scan | Yes | No | No | Medium priority |
| REST API | No | No | Yes | R-YARA unique |
| Distributed | No | No | Yes | R-YARA unique |
| Dictionary | No | No | Yes | R-YARA unique |
| Feed scanner | No | No | Yes | R-YARA unique |

---

## Release Roadmap

### v0.2.0 (Target)
- Native YARA or YARA-X integration
- WebSocket streaming
- Prometheus metrics
- 50%+ test coverage

### v0.3.0 (Target)
- PE module (Rust native)
- ELF module (Rust native)
- Parallel scanning
- OpenAPI documentation

### v0.4.0 (Target)
- Dotnet module
- Process memory scanning
- Authentication
- Docker support

### v1.0.0 (Target)
- Full YARA module parity
- Production-ready performance
- 80%+ test coverage
- Client libraries

---

## References

- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA-X GitHub](https://github.com/VirusTotal/yara-x)
- [YARA Modules](https://yara.readthedocs.io/en/stable/modules.html)
- [R-YARA Roadmap](steering/R_YARA_ROADMAP.md)
- [R-YARA Gap Analysis](steering/GAP_ANALYSIS.md)
