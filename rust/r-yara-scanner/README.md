# r-yara-scanner

A unified YARA scanning engine that ties together all R-YARA components into a complete, easy-to-use scanning solution.

## Overview

`r-yara-scanner` is the main entry point for scanning files and data with YARA rules in the R-YARA ecosystem. It integrates:

- **r-yara-parser**: Parse YARA rules into AST
- **r-yara-compiler**: Compile rules to executable bytecode
- **r-yara-matcher**: High-performance Aho-Corasick pattern matching
- **r-yara-vm**: Execute bytecode conditions
- **r-yara-modules**: File format analysis (PE, ELF, Mach-O, DEX, hash, math)

## Features

- ✅ **Complete YARA implementation** - Supports all major YARA features
- ✅ **High performance** - Aho-Corasick multi-pattern matching
- ✅ **File type detection** - Auto-detects PE, ELF, Mach-O, DEX files
- ✅ **Module support** - Hash, math, and binary format modules
- ✅ **Easy API** - Simple functions for one-off scans or reusable scanners
- ✅ **Directory scanning** - Recursive or non-recursive directory scans
- ✅ **Rich metadata** - Match offsets, tags, and custom metadata

## Quick Start

### Simple Scanning

```rust
use r_yara_scanner::scan_bytes;

let rules = r#"
    rule detect_malware {
        strings:
            $mz = "MZ"
            $pe = "PE"
        condition:
            $mz at 0 and $pe
    }
"#;

let data = b"MZ\x90\x00...PE\x00\x00";
let matches = scan_bytes(rules, data)?;

for m in matches {
    println!("Matched: {}", m.rule_name);
    for s in m.strings {
        println!("  {} at offsets: {:?}", s.identifier, s.offsets);
    }
}
```

### Reusable Scanner

```rust
use r_yara_scanner::Scanner;

// Create scanner once
let scanner = Scanner::from_file("rules/malware.yar")?;

// Scan multiple targets
let matches1 = scanner.scan_file("suspicious.exe")?;
let matches2 = scanner.scan_bytes(data)?;
let results = scanner.scan_directory("/samples", true)?;
```

### Working with Results

```rust
use r_yara_scanner::Scanner;

let scanner = Scanner::new(rules)?;
let matches = scanner.scan_file("malware.bin")?;

for m in matches {
    println!("Rule: {} (tags: {:?})", m.rule_name, m.tags);

    // Access metadata
    for (key, value) in &m.meta {
        println!("  {}: {:?}", key, value);
    }

    // Access matched strings
    for s in &m.strings {
        println!("  {}: {} matches at {:?}",
                 s.identifier, s.offsets.len(), s.offsets);
    }

    // Check file type
    println!("  File type: {:?}", m.file_type);
}
```

## Advanced Features

### Loading Rules

```rust
use r_yara_scanner::{Scanner, load_rules_from_file, load_rules_from_files};

// From single file
let scanner = Scanner::from_file("rules.yar")?;

// From multiple files
let paths = vec!["rules/malware.yar", "rules/packer.yar"];
let scanner = Scanner::from_files(&paths)?;

// From string
let rules = r#"rule test { condition: true }"#;
let scanner = Scanner::new(rules)?;
```

### Directory Scanning

```rust
let scanner = Scanner::from_file("rules.yar")?;

// Recursive scan
let results = scanner.scan_directory("/suspicious", true)?;

for result in results {
    if let Some(err) = result.error {
        eprintln!("Error scanning {}: {}", result.path.display(), err);
    } else if !result.matches.is_empty() {
        println!("{}: {} matches",
                 result.path.display(),
                 result.matches.len());
    }
}
```

### Context and Module Data

The scanner automatically:
- Detects file types (PE, ELF, Mach-O, DEX)
- Extracts entry points from executables
- Calculates file hashes (MD5, SHA1, SHA256)
- Computes entropy and other statistics

```rust
use r_yara_scanner::ScanContext;

let ctx = ScanContext::new(data);

println!("File type: {:?}", ctx.file_type);
println!("MD5: {}", ctx.md5());
println!("Entropy: {:.2}", ctx.entropy());
println!("Is PE: {}", ctx.is_pe());
```

## Examples

See the [examples/](examples/) directory:

- `scan_demo.rs` - Comprehensive feature demonstration

Run with:
```bash
cargo run --example scan_demo
```

## YARA Feature Support

### Strings
- ✅ Text strings with modifiers (nocase, wide, ascii, fullword)
- ✅ Hex strings with wildcards
- ✅ Regular expressions
- ✅ XOR and Base64 modifiers

### Conditions
- ✅ Boolean logic (and, or, not)
- ✅ Comparison operators (==, !=, <, >, <=, >=)
- ✅ Arithmetic operations (+, -, *, /, %)
- ✅ Bitwise operations (&, |, ^, ~, <<, >>)
- ✅ String matching ($a, #a, @a, !a)
- ✅ Quantifiers (all, any, none, N of)
- ✅ Ranges and iterators
- ✅ Built-in variables (filesize, entrypoint)
- ✅ Built-in functions (uint8, uint16, uint32, etc.)

### Metadata
- ✅ String, integer, and boolean metadata
- ✅ Tags
- ✅ Private and global rules

### Modules
- ✅ hash (MD5, SHA1, SHA256, SHA3, CRC32)
- ✅ math (entropy, mean, deviation, etc.)
- ✅ pe (Windows PE file analysis)
- ✅ elf (Linux ELF file analysis)
- ✅ macho (macOS Mach-O file analysis)
- ✅ dex (Android DEX file analysis)

## Performance

The scanner is designed for high performance:

- **Aho-Corasick** - Multi-pattern matching for literal strings
- **Double-array trie** - Fast state transitions via daachorse
- **Zero-copy parsing** - Minimal allocations with SmolStr
- **Stack-based VM** - Efficient bytecode execution

## Testing

```bash
# Run all tests
cargo test -p r-yara-scanner

# Run with output
cargo test -p r-yara-scanner -- --nocapture

# Run specific test
cargo test -p r-yara-scanner test_scan_bytes_simple
```

## Documentation

Generate and view documentation:

```bash
cargo doc -p r-yara-scanner --open
```

## Integration

Add to your `Cargo.toml`:

```toml
[dependencies]
r-yara-scanner = { path = "../r-yara-scanner" }
```

## License

Apache-2.0

## Related Crates

- `r-yara-parser` - YARA rule parsing
- `r-yara-compiler` - Bytecode compilation
- `r-yara-matcher` - Pattern matching engine
- `r-yara-vm` - Virtual machine executor
- `r-yara-modules` - Module implementations
