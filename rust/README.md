# R-YARA - Rust YARA Implementation

**Version:** 0.1.0-alpha.1
**Status:** Alpha Release for Pyro Platform Integration

Complete Rust implementation of the YARA pattern-matching engine with quantum-resistant cryptographic support.

## Workspace Crates

| Crate | Description | Binary |
|-------|-------------|--------|
| `r-yara-parser` | Lexer, parser, AST | - |
| `r-yara-compiler` | Bytecode compilation | - |
| `r-yara-vm` | Virtual machine execution | - |
| `r-yara-matcher` | Pattern matching (Aho-Corasick) | - |
| `r-yara-modules` | PE, ELF, Hash, Math modules | - |
| `r-yara-scanner` | High-level scanning API | - |
| `r-yara-store` | Cryptex dictionary storage | - |
| `r-yara-api` | REST API server | `r-yara-server` |
| `r-yara-pyro` | Pyro Platform integration | `r-yara-pyro` |
| `r-yara-feed-scanner` | Web feed scanner | `r-yara-feed`, `r-yara-feed-scanner` |
| `r-yara-cli` | Command-line interface | `r-yara` |

## Quick Start

```bash
# Build all crates
cargo build --release

# Run CLI
./target/release/r-yara --help

# Scan files
./target/release/r-yara scan rules.yar target.exe

# Start Pyro server
./target/release/r-yara-pyro server

# Check version
./target/release/r-yara-pyro info
```

## Binaries

| Binary | Size | Description |
|--------|------|-------------|
| `r-yara` | 11.2 MB | Main CLI tool |
| `r-yara-pyro` | 12.3 MB | Pyro Fire Hydrant API |
| `r-yara-server` | 8.3 MB | Dictionary API server |
| `r-yara-feed-scanner` | 6.2 MB | Feed scanner |
| `r-yara-feed` | 6.3 MB | Feed tool |

## Features

### Core Engine
- Complete YARA rule parsing and compilation
- Bytecode generation with optimization
- Aho-Corasick multi-pattern matching
- XOR/Base64 modifier support
- Fullword boundary detection
- Regular expression support

### Modules
- **PE:** Headers, sections, imports, imphash, version_info, rich_signature
- **ELF:** Headers, sections, segments, symbols
- **Mach-O:** Universal binaries, segments, sections
- **DEX:** Android DEX file parsing
- **Hash:** MD5, SHA-1/256/384/512, SHA3, Keccak, BLAKE2/3, SHAKE256, SPHINCS+
- **Math:** Entropy, mean, deviation, serial correlation
- **Time:** Timestamp operations
- **Console:** Debug logging

### Quantum-Resistant Cryptography
- SHA3-256/384/512
- Keccak-256/512 (Ethereum compatible)
- BLAKE2b-512, BLAKE2s-256, BLAKE3
- SHAKE256 (XOF)
- SPHINCS+ post-quantum signatures

## API Endpoints

### Pyro Fire Hydrant (port 8080)
```
GET  /api/v2/r-yara/health           - Health check
GET  /api/v2/r-yara/stats            - Statistics
GET  /api/v2/r-yara/modules          - List modules
POST /api/v2/r-yara/scan/file        - Scan file
POST /api/v2/r-yara/scan/data        - Scan data
POST /api/v2/r-yara/scan/batch       - Batch scan
POST /api/v2/r-yara/scan/directory   - Directory scan
GET  /api/v2/r-yara/rules            - List rules
POST /api/v2/r-yara/rules/load       - Load rules
POST /api/v2/r-yara/rules/validate   - Validate rule
POST /api/v2/r-yara/rules/compile    - Compile rules
POST /api/v2/r-yara/transcode/encode - Encode rule
POST /api/v2/r-yara/transcode/decode - Decode rule
```

### Dictionary Server (port 3006)
```
GET /api/v2/r-yara/dictionary/lookup  - Lookup entry
GET /api/v2/r-yara/dictionary/entries - Get all entries
GET /api/v2/r-yara/dictionary/search  - Search entries
GET /api/v2/r-yara/dictionary/stats   - Statistics
```

## CLI Commands

```bash
# Scanning
r-yara scan <rules.yar> <target>      # Scan files/directories
r-yara scan -r <dir> <target>         # Recursive rule loading

# Compilation
r-yara compile <rules.yar> -o out.yarc # Compile rules
r-yara check <rules.yar>               # Validate rules

# Information
r-yara info <file>                    # File hashes, entropy, type

# Dictionary
r-yara dict lookup <symbol>           # Lookup
r-yara dict search <query>            # Search

# Server
r-yara server start                   # Start API server
```

## Pyro Commands

```bash
r-yara-pyro server                    # Start Fire Hydrant API
r-yara-pyro worker -t scanner         # Run scanner worker
r-yara-pyro worker -t transcoder      # Run transcoder worker
r-yara-pyro gateway                   # Start API gateway
r-yara-pyro config --generate         # Generate config
r-yara-pyro info                      # Show version/features
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         r-yara-cli                               │
│                      (Command Line Interface)                    │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                         r-yara-scanner                           │
│                     (High-Level Scanning API)                    │
└───────┬─────────────────┬────────────────────┬──────────────────┘
        │                 │                    │
┌───────▼───────┐ ┌───────▼───────┐ ┌─────────▼────────┐
│  r-yara-parser │ │r-yara-compiler│ │  r-yara-matcher  │
│ (Lexer/Parser) │ │  (Bytecode)   │ │ (Aho-Corasick)   │
└───────┬───────┘ └───────┬───────┘ └─────────┬────────┘
        │                 │                    │
┌───────▼─────────────────▼────────────────────▼──────────────────┐
│                          r-yara-vm                               │
│                    (Virtual Machine Execution)                   │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                        r-yara-modules                            │
│              (PE, ELF, Mach-O, DEX, Hash, Math, Time)           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────┐  ┌─────────────────────┐
│    r-yara-pyro      │  │    r-yara-api       │
│ (Fire Hydrant API)  │  │ (Dictionary Server) │
└─────────────────────┘  └─────────────────────┘
         │                         │
┌────────▼─────────────────────────▼──────────────────────────────┐
│                        r-yara-store                              │
│                   (Cryptex Dictionary Storage)                   │
└─────────────────────────────────────────────────────────────────┘
```

## Testing

```bash
# Run all tests
cargo test

# Run module tests
cargo test -p r-yara-modules

# Run with output
cargo test -- --nocapture
```

**Test Status:** 337+ tests passing

## Development

```bash
# Check code
cargo check

# Format code
cargo fmt

# Lint
cargo clippy

# Build release
cargo build --release
```

## Dependencies

### Core
- Rust 1.70+
- tokio (async runtime)
- serde (serialization)

### Cryptography
- sha1, sha2, sha3 (SHA family)
- blake2, blake3 (BLAKE family)
- pqcrypto-sphincsplus (post-quantum)
- md5, crc32fast (legacy)

### Binary Parsing
- goblin (PE, ELF, Mach-O)

### Networking
- axum (HTTP server)
- reqwest (HTTP client)

## License

Apache-2.0

---

*R-YARA v0.1.0-alpha.1 - The Fire Hydrant*
