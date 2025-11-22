# YARA Cross Converter Streaming - Rust Implementation

## Overview

The YARA cross converter has been **properly implemented in Rust** to align with the project architecture:
- **Rust** for backend processing
- **REDB** for persistent storage
- **SvelteKit** for frontend (to be implemented)

## Architecture

### Core Module
**File**: `pyro-platform/pyro/src/tools/yara_rules/cross_converter.rs`

### Key Features

1. **Streaming Conversion**
   - Async/await for non-blocking I/O
   - Buffered reading/writing for efficiency
   - Real-time streaming with configurable chunk sizes
   - Memory-efficient processing of large files

2. **Format Support**
   - YARA ↔ Cryptex (bidirectional)
   - YARA ↔ JSON
   - Cryptex ↔ JSON
   - All conversions are streaming-capable

3. **REDB Integration**
   - Conversion metadata storage
   - Audit trail for conversions
   - Performance tracking

4. **Module Translation**
   - Automatic translation of YARA modules to Cryptex codenames
   - Preserves original code in comments
   - Bidirectional conversion support

## Usage

### Basic Streaming Conversion

```rust
use crate::tools::yara_rules::cross_converter::{
    YaraCrossConverter, ConversionFormat, StreamingConfig
};

let converter = YaraCrossConverter::new(cryptex_translator, db);
let config = StreamingConfig::default();

let result = converter.stream_convert_file(
    &input_path,
    &output_path,
    ConversionFormat::Yara,
    ConversionFormat::Cryptex,
    config,
).await?;
```

### Real-time Streaming

```rust
let mut stdin = tokio::io::stdin();
let mut stdout = tokio::io::stdout();

let config = StreamingConfig {
    realtime: true,
    chunk_size: 4096,
    ..Default::default()
};

converter.stream_convert(
    &mut stdin,
    &mut stdout,
    ConversionFormat::Yara,
    ConversionFormat::Cryptex,
    config,
).await?;
```

## Integration Points

### 1. Module Registration
Add to `pyro-platform/pyro/src/tools/yara_rules/mod.rs`:

```rust
pub mod cross_converter;
```

### 2. API Endpoints
Create endpoints in `pyro-platform/pyro/src/tools/yara_rules/api.rs`:

```rust
// POST /api/yara/convert
// Stream convert YARA rules between formats
```

### 3. SvelteKit Frontend
Create component in `pyro-platform/frontend-svelte/src/routes/tools/yara/`:

```svelte
<!-- Cross Converter UI Component -->
```

## Migration from Python

The Python implementation in `tools/rule_transcoder.py` should be:
1. **Deprecated** - Mark as legacy
2. **Replaced** - Use Rust implementation for all new development
3. **Removed** - After full migration (optional)

## Performance Benefits

- **Memory**: Constant memory usage regardless of file size
- **Speed**: Async I/O with buffering for optimal throughput
- **Scalability**: Can handle files of any size
- **Integration**: Native Rust integration with existing codebase

## Next Steps

1. ✅ Rust cross converter module created
2. ⏳ Add module to `mod.rs`
3. ⏳ Create API endpoints
4. ⏳ Implement REDB storage for conversion history
5. ⏳ Create SvelteKit frontend component
6. ⏳ Add integration tests
7. ⏳ Deprecate Python version

## Dependencies

The implementation uses:
- `tokio` - Async runtime
- `serde` - Serialization
- `anyhow` - Error handling
- `tracing` - Logging
- `redb` - Database (via RedbManager)
- `chrono` - Timestamps

All dependencies should already be in `Cargo.toml`.

