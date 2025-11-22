# YARA Cryptex - Rust Implementation

Rust workspace for YARA Cryptex dictionary and migration.

## Structure

```
rust/
├── cryptex/              # Cryptex dictionary (auto-generated)
│   ├── Cargo.toml
│   ├── symbol_map.rs    # Symbol to codename lookup
│   ├── cryptex_types.rs # Type definitions
│   ├── modules.rs       # Module structure
│   └── function_stubs.rs # Function stubs with pseudocode
├── yara-runner/         # YARA execution wrapper (planned)
├── mcp-gateway/         # MCP server gateway (planned)
└── cryptex-store/       # redb-backed storage (planned)
```

## Usage

### View Generated Code

```bash
cd rust/cryptex
cat symbol_map.rs
cat cryptex_types.rs
```

### Build (when dependencies are added)

```bash
cd rust/cryptex
cargo build
```

## Migration Strategy

1. **Phase 1**: Core types and lookup tables (current)
2. **Phase 2**: Function stubs with pseudocode
3. **Phase 3**: Implement core scanning functions
4. **Phase 4**: Module system migration
5. **Phase 5**: Full feature parity

## Next Steps

1. Add proper Rust dependencies
2. Implement core functions based on pseudocode
3. Create redb schema for dictionary storage
4. Build MCP gateway in Rust
5. Create Node-RED integration

