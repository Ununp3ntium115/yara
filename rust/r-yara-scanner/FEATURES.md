# r-yara-scanner Features

## Overview

The r-yara-scanner crate is the **unified scanning engine** that integrates all R-YARA components into a cohesive, production-ready YARA scanner.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     r-yara-scanner                          │
│                    (Unified Scanner)                        │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ r-yara-parser│    │r-yara-compiler│   │ r-yara-vm   │
│   (Parse)    │───▶│  (Compile)   │───▶│  (Execute)  │
└──────────────┘    └──────────────┘    └──────────────┘
                            │                   │
                            ▼                   ▼
                    ┌──────────────┐    ┌──────────────┐
                    │r-yara-matcher│    │r-yara-modules│
                    │ (AC Search)  │    │(PE/ELF/etc.) │
                    └──────────────┘    └──────────────┘
```

## Scanning Pipeline

1. **Parse**: YARA rules → AST (Abstract Syntax Tree)
2. **Compile**: AST → Bytecode + Pattern extraction
3. **Match**: Aho-Corasick finds literal strings in target data
4. **Execute**: VM evaluates rule conditions using match results
5. **Report**: Matching rules with metadata and offsets

## Core Components Integration

### 1. r-yara-parser
- Tokenizes YARA rules with Logos lexer
- Parses into structured AST
- Handles strings, metadata, tags, imports

### 2. r-yara-compiler
- Compiles AST to stack-based bytecode
- Extracts patterns for Aho-Corasick
- Generates symbol tables and string indices

### 3. r-yara-matcher
- Builds Aho-Corasick automaton (daachorse)
- Multi-pattern matching for literals
- Regex engine for complex patterns
- XOR and Base64 variant generation

### 4. r-yara-vm
- Stack-based bytecode executor
- Boolean, arithmetic, and bitwise operations
- String matching predicates (at, in, count)
- Quantifier evaluation (all, any, N of)

### 5. r-yara-modules
- **hash**: MD5, SHA1, SHA256, SHA3, CRC32
- **math**: Entropy, mean, deviation, correlation
- **pe**: Windows PE file parsing (goblin)
- **elf**: Linux ELF file parsing (goblin)
- **macho**: macOS Mach-O parsing (goblin)
- **dex**: Android DEX file detection

## Key Features

### 🚀 Performance
- **Aho-Corasick**: Multi-pattern matching with double-array trie
- **Zero-copy**: SmolStr and efficient string handling
- **Optimized VM**: Stack-based execution with minimal overhead
- **Parallel-ready**: Scanner instances are Send + Sync

### 🎯 Accuracy
- **YARA-compatible**: Matches YARA 4.x behavior
- **Comprehensive tests**: 20+ unit tests covering all features
- **Type-safe**: Rust's type system prevents common bugs

### 🔧 Usability
- **Simple API**: One-line scans with `scan_bytes(rules, data)`
- **Reusable scanners**: Compile once, scan many
- **Rich results**: Match offsets, metadata, tags, file types
- **Directory scanning**: Recursive or flat directory traversal

### 📦 Auto-detection
- **File types**: PE, ELF, Mach-O, DEX, text, binary
- **Entry points**: Extracted from executable formats
- **Hashes**: Automatic MD5, SHA1, SHA256 calculation
- **Statistics**: Entropy and byte distribution

## API Design

### Convenience Functions
```rust
// One-off scans
scan_bytes(rules, data)?
scan_file(rules, path)?
scan_directory(rules, path, recursive)?
```

### Scanner Class
```rust
// Reusable scanner
let scanner = Scanner::new(rules)?;
let scanner = Scanner::from_file(path)?;
let scanner = Scanner::from_files(paths)?;

// Scan operations
scanner.scan_bytes(data)?
scanner.scan_file(path)?
scanner.scan_directory(path, recursive)?

// Introspection
scanner.rule_count()
scanner.pattern_count()
```

### Results Structure
```rust
struct RuleMatch {
    rule_name: SmolStr,
    tags: Vec<SmolStr>,
    strings: Vec<StringMatch>,
    meta: Vec<(SmolStr, MetaValue)>,
    file_type: FileType,
}

struct StringMatch {
    identifier: SmolStr,
    offsets: Vec<u64>,
}
```

## Context Management

### ScanContext
- Holds target data and analysis results
- Detects file type automatically
- Extracts module data (PE/ELF/Mach-O/DEX info)
- Calculates hashes and statistics

### Module Data
- PE: sections, imports, exports, entry point
- ELF: sections, machine type, entry point
- Mach-O: CPU type, file type, entry point
- DEX: version, class count
- Hashes: MD5, SHA1, SHA256
- Math: entropy, mean

## Error Handling

Comprehensive error types:
- `ParseError`: Syntax errors in rules
- `CompileError`: Semantic errors, undefined strings
- `MatcherError`: Pattern building failures
- `VMError`: Execution errors
- `IOError`: File access failures

All wrapped in `ScanError` enum with proper context.

## Testing

### Unit Tests (20 tests)
- Context creation and file detection
- Rule compilation (simple, complex, invalid)
- Pattern matching (literals, nocase, wide)
- Quantifiers (all, any, N of)
- Metadata and tags
- File size checks
- String match offsets
- Multi-rule scanning

### Integration Tests
- Full scanning pipeline
- Example program (scan_demo.rs)

## Use Cases

### 1. Malware Detection
```rust
let scanner = Scanner::from_file("malware.yar")?;
let matches = scanner.scan_file("suspicious.exe")?;
```

### 2. Bulk Scanning
```rust
let scanner = Scanner::from_files(&["rules/*.yar"])?;
for result in scanner.scan_directory("/samples", true)? {
    // Process matches
}
```

### 3. Custom Analysis
```rust
let ctx = ScanContext::new(data);
println!("Entropy: {}", ctx.entropy());
println!("Is PE: {}", ctx.is_pe());
```

### 4. Real-time Scanning
```rust
let scanner = Scanner::new(rules)?;
for data in stream {
    let matches = scanner.scan_bytes(&data)?;
    if !matches.is_empty() {
        alert(matches);
    }
}
```

## Performance Characteristics

- **Compilation**: O(n) where n = rules size
- **Pattern matching**: O(m + z) where m = data size, z = matches
  - Aho-Corasick is optimal for multi-pattern matching
- **VM execution**: O(k) where k = bytecode instructions
- **Memory**: Patterns + compiled bytecode (typically < 1MB per rule set)

## Future Enhancements

Potential improvements:
- JIT compilation for hot paths
- SIMD-accelerated pattern matching
- Incremental scanning for large files
- Async scanning support
- More module implementations (time, console, string)

## Dependencies

- `r-yara-parser`: Parsing with Logos
- `r-yara-compiler`: Bytecode generation
- `r-yara-matcher`: Aho-Corasick via daachorse
- `r-yara-vm`: Stack-based executor
- `r-yara-modules`: Binary format parsing via goblin
- `walkdir`: Directory traversal
- `thiserror`, `anyhow`: Error handling
- `smol_str`: String optimization

## Standards Compliance

Implements YARA 4.x features:
- Rule syntax and semantics
- String modifiers (nocase, wide, ascii, fullword, xor, base64)
- Hex patterns with wildcards
- Regular expressions
- Condition expressions
- Quantifiers and iterators
- Built-in variables (filesize, entrypoint)
- Built-in functions (uint8, uint16, uint32, etc.)
- Module imports

## License

Apache-2.0, compatible with YARA's original BSD license.
