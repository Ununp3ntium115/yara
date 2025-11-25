# R-YARA - Rust YARA Implementation

Rust workspace for the R-YARA pattern matching system.

## Crates

| Crate | Description | Binary |
|-------|-------------|--------|
| `r-yara-store` | Dictionary and rule storage (redb) | `r-yara-import`, `r-yara-export` |
| `r-yara-api` | REST API server | `r-yara-server` |
| `r-yara-cli` | Command-line interface | `r-yara` |
| `r-yara-feed-scanner` | Web feed scanner | `r-yara-feed` |

## Quick Start

```bash
# Build all crates
cargo build --release

# Run CLI
./target/release/r-yara --help

# Start API server
./target/release/r-yara-server

# Scan feeds
./target/release/r-yara-feed scan --output rules.json
```

## API Endpoints

```
# Dictionary
GET  /api/v2/r-yara/dictionary/lookup
GET  /api/v2/r-yara/dictionary/entries
GET  /api/v2/r-yara/dictionary/search
GET  /api/v2/r-yara/dictionary/stats

# Feed Scanning
POST /api/v2/r-yara/feed/scan/all
POST /api/v2/r-yara/feed/scan/malware
POST /api/v2/r-yara/feed/scan/apt
POST /api/v2/r-yara/feed/scan/ransomware
```

## Features

- **Standalone Operation**: No external dependencies required
- **Dictionary Storage**: redb-backed for fast lookups
- **Feed Scanner**: Scans GitHub, RSS, Atom feeds for YARA rules
- **REST API**: Full HTTP API for integration
- **CLI**: Complete command-line interface

## Development

```bash
# Check code
cargo check

# Run tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy
```

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│  r-yara-cli │────▶│ r-yara-api  │────▶│ r-yara-feed-scanner │
└─────────────┘     └─────────────┘     └─────────────────────┘
                           │
                    ┌──────▼──────┐
                    │ r-yara-store │
                    │    (redb)    │
                    └─────────────┘
```

## License

Apache-2.0
