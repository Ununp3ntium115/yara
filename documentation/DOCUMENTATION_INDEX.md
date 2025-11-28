# R-YARA Documentation Index

**Version:** 0.1.0-alpha.1
**Last Updated:** November 28, 2025

---

## Quick Links

| Document | Description |
|----------|-------------|
| [Getting Started](GETTING_STARTED.md) | Installation and basic usage |
| [CLI Guide](CLI_GUIDE.md) | Command-line interface reference |
| [API Reference](API_REFERENCE.md) | REST API documentation |
| [Architecture](ARCHITECTURE.md) | System architecture overview |
| [Modules](MODULES.md) | YARA module documentation |
| [Pyro Integration](PYRO_INTEGRATION.md) | Pyro Platform integration guide |

---

## Documentation Structure

```
documentation/
├── DOCUMENTATION_INDEX.md    # This file
├── GETTING_STARTED.md        # Quick start guide
├── CLI_GUIDE.md              # CLI reference
├── API_REFERENCE.md          # REST API docs
├── ARCHITECTURE.md           # System design
├── MODULES.md                # Module reference
└── PYRO_INTEGRATION.md       # Pyro Platform guide

docs/
├── CRYPTEXT_DICTIONARY.md    # Cryptex term catalog
├── IMPLEMENTATION_PRIORITIES.md # Feature priorities
├── R_YARA_PSEUDOCODE_COMPLETE.md # Implementation pseudocode
└── (other technical docs)

steering/
├── COMPREHENSIVE_GAP_ANALYSIS.md # Gap analysis
├── R_YARA_ROADMAP.md            # Development roadmap
└── (other planning docs)

releases/
└── v0.1.0-alpha.1/
    └── RELEASE_NOTES.md      # Current release notes
```

---

## Core Documentation

### 1. Getting Started
- Installation requirements
- Building from source
- Basic scanning examples
- Configuration

### 2. CLI Guide
Commands:
- `r-yara scan` - Scan files/directories
- `r-yara compile` - Compile rules
- `r-yara check` - Validate rules
- `r-yara info` - File information
- `r-yara dict` - Dictionary operations
- `r-yara server` - API server
- `r-yara feed` - Feed operations

### 3. API Reference
Endpoints:
- `/api/v2/r-yara/health` - Health check
- `/api/v2/r-yara/scan/*` - Scanning endpoints
- `/api/v2/r-yara/rules/*` - Rule management
- `/api/v2/r-yara/dictionary/*` - Dictionary ops
- `/api/v2/r-yara/transcode/*` - Transcoding

### 4. Architecture
Components:
- Parser (lexer, grammar, AST)
- Compiler (bytecode generation)
- VM (execution engine)
- Matcher (Aho-Corasick)
- Modules (PE, ELF, Hash, etc.)
- Scanner (high-level API)
- Store (dictionary storage)

### 5. Modules
Available modules:
- `pe` - PE file parsing
- `elf` - ELF file parsing
- `macho` - Mach-O parsing
- `dex` - Android DEX parsing
- `hash` - Hash functions
- `math` - Mathematical functions
- `time` - Time functions
- `console` - Debug output

### 6. Pyro Integration
- Fire Hydrant API
- Worker architecture
- Gateway configuration
- Task queue system

---

## Technical Documentation

### Cryptex Dictionary
Location: `docs/CRYPTEXT_DICTIONARY.md`

Complete catalog of:
- 81 lexical tokens
- 60+ AST node types
- 37+ VM opcodes
- Module functions
- String modifiers

### Implementation Priorities
Location: `docs/IMPLEMENTATION_PRIORITIES.md`

Priority rankings for:
- Core engine features
- Module implementations
- API endpoints
- Integration points

### Gap Analysis
Location: `steering/COMPREHENSIVE_GAP_ANALYSIS.md`

Analysis of:
- Feature coverage
- Test coverage
- Documentation coverage
- Integration status

---

## Hash Functions Reference

### Classical
| Function | Output | Usage |
|----------|--------|-------|
| `md5()` | 32 hex | Legacy fingerprinting |
| `sha1()` | 40 hex | Legacy fingerprinting |
| `sha256()` | 64 hex | Standard fingerprinting |
| `sha384()` | 96 hex | Extended fingerprinting |
| `sha512()` | 128 hex | Maximum security |
| `crc32()` | u32 | Fast checksums |

### Quantum-Resistant
| Function | Output | Usage |
|----------|--------|-------|
| `sha3_256()` | 64 hex | Post-quantum ready |
| `sha3_384()` | 96 hex | Post-quantum ready |
| `sha3_512()` | 128 hex | Post-quantum ready |
| `keccak256()` | 64 hex | Ethereum compatible |
| `keccak512()` | 128 hex | Extended Keccak |
| `blake2b512()` | 128 hex | Fast, secure |
| `blake2s256()` | 64 hex | 32-bit optimized |
| `blake3()` | 64 hex | Fastest hash |
| `shake256()` | Variable | XOF output |

### Post-Quantum Signatures
| Function | Description |
|----------|-------------|
| `sphincs_generate_keypair()` | Generate SPHINCS+ keys |
| `sphincs_sign()` | Sign with SPHINCS+ |
| `sphincs_verify()` | Verify SPHINCS+ signature |

---

## Examples

### Basic Scanning
```bash
# Scan with rules
r-yara scan rules.yar target.exe

# Scan directory recursively
r-yara scan -r rules_dir/ target_dir/

# Output JSON results
r-yara scan rules.yar target.exe -o json
```

### API Usage
```bash
# Health check
curl http://localhost:8080/api/v2/r-yara/health

# Scan file
curl -X POST http://localhost:8080/api/v2/r-yara/scan/file \
  -F "file=@sample.exe" \
  -F "rules=@rules.yar"

# Get statistics
curl http://localhost:8080/api/v2/r-yara/stats
```

### Pyro Integration
```bash
# Start server
r-yara-pyro server

# Start worker
r-yara-pyro worker -t scanner

# Start gateway
r-yara-pyro gateway
```

---

## Version History

| Version | Date | Status |
|---------|------|--------|
| 0.1.0-alpha.1 | 2025-11-28 | Current |

---

## Contributing

See the main repository for contribution guidelines.

---

*R-YARA Documentation - v0.1.0-alpha.1*
