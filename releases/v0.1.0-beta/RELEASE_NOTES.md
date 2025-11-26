# R-YARA v0.1.0-beta Release Notes

**Release Date:** 2025-11-26

## Overview

R-YARA (Rust YARA) is a Rust-native YARA implementation with dictionary system, feed scanner, and optional PYRO Platform integration capabilities.

## Binaries Included

| Binary | Description | Size |
|--------|-------------|------|
| `r-yara` | CLI tool for dictionary operations | 5.4 MB |
| `r-yara-server` | REST API server (axum-based) | 6.1 MB |
| `r-yara-feed` | Feed scanner CLI | 4.6 MB |
| `r-yara-feed-scanner` | Web feed scanner for YARA rules | 4.6 MB |
| `r-yara-pyro` | PYRO Platform integration worker | 8.1 MB |

## Available Platforms

- **linux-x86_64**: Linux x86_64 (glibc)

### Building for Other Platforms

To build for other platforms, clone the repository and run:

```bash
cd rust
cargo build --release --workspace
```

Supported platforms (build from source):
- macOS x86_64: `rustup target add x86_64-apple-darwin`
- macOS ARM64: `rustup target add aarch64-apple-darwin`
- Windows x86_64: `rustup target add x86_64-pc-windows-msvc`
- Linux ARM64: `rustup target add aarch64-unknown-linux-gnu`

## Features

### Core Features
1. **REST API** - Full axum-based REST API server
2. **Dictionary Storage** - redb-based key-value store for YARA metadata
3. **Feed Scanner** - Web feed scanner with use case detection (malware/apt/ransomware/webshell)
4. **CLI Tools** - Command-line interfaces for all operations

### PYRO Platform Integration
5. **Worker Protocol** - Distributed task processing
6. **Gateway Routing** - Load balancing and service discovery
7. **PYRO Connection** - Full worker connection with retry logic
8. **Task Queue** - Async task queue with priority support (max 1000 tasks)
9. **Task Status Tracking** - Full lifecycle (queued/running/completed/failed)

### Cryptographic Hashing (PYRO Signatures)
10. **Classical**: MD5, SHA1, SHA256, SHA384, SHA512
11. **SHA-3 (Post-Quantum)**: SHA3-256, SHA3-384, SHA3-512, Keccak256, Keccak512
12. **BLAKE**: BLAKE2b-512, BLAKE2s-256, BLAKE3
13. **Legacy**: CRC32, Adler32
14. **Fuzzy**: ssdeep-like, TLSH-like
15. **Entropy**: Shannon entropy calculation

## API Endpoints

```
GET  /api/v1/health              - Health check
GET  /api/v1/dictionary/lookup   - Dictionary lookup
GET  /api/v1/dictionary/search   - Full paginated search
GET  /api/v1/dictionary/stats    - Dictionary statistics
POST /api/v1/scan/file           - Scan file
POST /api/v1/scan/data           - Scan raw data
POST /api/v1/rules/validate      - Validate YARA rule
POST /api/v1/rules/compile       - Compile YARA rules
POST /api/v1/transcode/encode    - Encode data
POST /api/v1/transcode/decode    - Decode data
POST /api/v1/feed/scan/:use_case - Scan feeds for use case
POST /api/v1/worker/task         - Submit async task
GET  /api/v1/worker/task/:id     - Get task status
GET  /api/v1/worker/tasks        - List recent tasks
GET  /api/v1/stats               - Server statistics
```

## Quick Start

```bash
# Extract the release
tar -xzf r-yara-v0.1.0-beta-linux-x86_64.tar.gz
cd linux-x86_64

# Verify checksums
sha256sum -c SHA256SUMS

# Run the API server
./r-yara-server --help

# Run the CLI tool
./r-yara --help

# Run the PYRO worker (standalone mode)
./r-yara-pyro --help
```

## Test Status

- **39 tests passing** (38 in r-yara-pyro, 1 in r-yara-store)
- **Zero compiler warnings**
- **All components operational**

## Dependencies

Runtime dependencies (Linux):
- glibc 2.17+
- OpenSSL 1.1+ (for TLS connections)

## License

See LICENSE file in the repository.

## Repository

https://github.com/Ununp3ntium115/yara

## Checksums

See `SHA256SUMS` file in the release archive.
