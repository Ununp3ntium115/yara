# R-YARA Improvements: Learnings from YARA and YARA-X

This document captures key improvements, design decisions, and lessons learned from studying YARA (C implementation) and YARA-X (Rust reimplementation). These insights guide R-YARA's development to surpass both implementations.

---

## Table of Contents

1. [Pattern Matching Engine](#pattern-matching-engine)
2. [Parser and Compiler](#parser-and-compiler)
3. [Module System](#module-system)
4. [Memory Management](#memory-management)
5. [Performance Optimizations](#performance-optimizations)
6. [Error Handling](#error-handling)
7. [API Design](#api-design)
8. [Security Considerations](#security-considerations)
9. [Features Removed/Changed in YARA-X](#features-removed-changed-in-yara-x)
10. [R-YARA Innovations](#r-yara-innovations)

---

## 1. Pattern Matching Engine

### YARA (C) Approach
- **Aho-Corasick NFA**: Uses a non-deterministic finite automaton for multi-pattern matching
- **Atoms**: Extracts fixed-length substrings (atoms) from patterns for initial filtering
- **Atom Selection**: Chooses atoms based on frequency heuristics to minimize false positives
- **Regex Engine**: Custom regex implementation with bytecode compilation

**Strengths:**
- Proven, battle-tested over 15+ years
- Handles complex patterns well

**Weaknesses:**
- Single-threaded pattern matching
- NFA can have performance cliffs with many states
- Limited SIMD optimization

### YARA-X Approach
- **Daachorse Double-Array Aho-Corasick**: Uses a more memory-efficient DFA representation
- **Better Atom Selection**: Statistical analysis of byte frequency
- **Parallel Scanning**: Multi-threaded file scanning with Rayon
- **Improved Regex**: Uses Rust's `regex` crate with JIT compilation

**Improvements Over YARA:**
- 2-10x faster on large rule sets
- Better memory efficiency
- Native parallelism

### R-YARA Target Implementation
```
┌─────────────────────────────────────────────────────────────────┐
│                    R-YARA Pattern Engine                        │
├─────────────────────────────────────────────────────────────────┤
│ 1. Daachorse Double-Array AC (from YARA-X)                      │
│ 2. SIMD-accelerated byte scanning (AVX2/NEON)                   │
│ 3. Statistical atom selection with ML-optimized frequencies     │
│ 4. Parallel scanning with work-stealing (Rayon)                 │
│ 5. GPU acceleration for large-scale batch scanning              │
│ 6. Streaming matching for files larger than memory              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Parser and Compiler

### YARA (C) Approach
- **Flex/Bison**: Classic lexer/parser generators
- **Single-Pass Compiler**: Parses directly to bytecode
- **Arena Allocator**: Uses 12 memory arenas for compiled data
- **No AST**: Skips AST construction for speed

**Strengths:**
- Fast compilation
- Low memory overhead

**Weaknesses:**
- Hard to implement advanced optimizations
- Error messages are limited
- Difficult to extend grammar

### YARA-X Approach
- **Rust Parser**: Hand-written recursive descent parser
- **Full AST**: Builds complete AST before compilation
- **Multi-Pass Compilation**: Type checking, optimization passes
- **Rich Diagnostics**: Detailed error messages with source locations

**Improvements Over YARA:**
- Better error messages
- Cleaner code organization
- Easier to add new features

### R-YARA Target Implementation
```
┌─────────────────────────────────────────────────────────────────┐
│                    R-YARA Compiler Pipeline                     │
├─────────────────────────────────────────────────────────────────┤
│ 1. Logos Lexer (faster than hand-written)                       │
│ 2. LALRPOP Parser (formal grammar, better error recovery)       │
│ 3. Full AST with source locations                               │
│ 4. Type inference pass                                          │
│ 5. Optimization passes (constant folding, dead code elim)       │
│ 6. Register-based bytecode generation (vs stack-based)          │
│ 7. Optional JIT compilation for hot paths                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Module System

### YARA (C) Modules
Built-in modules with C-based extensions:

| Module | Purpose | Key Features |
|--------|---------|--------------|
| `pe` | Windows PE analysis | Imports, exports, sections, authenticode |
| `elf` | Linux ELF analysis | Symbols, sections, dynamic linking |
| `macho` | macOS Mach-O analysis | Load commands, code signing |
| `dotnet` | .NET assembly analysis | Streams, metadata, GUIDs |
| `hash` | Cryptographic hashes | MD5, SHA1, SHA256, CRC32 |
| `math` | Statistical functions | Entropy, mean, deviation |
| `time` | Time functions | Timestamps, comparisons |
| `cuckoo` | Sandbox integration | Behavioral analysis |
| `magic` | File type detection | libmagic integration |

### YARA-X Modules
Same modules with improvements:
- Lazy evaluation (only compute what's needed)
- Zero-copy parsing where possible
- Better error handling

### R-YARA Target Modules
```
┌─────────────────────────────────────────────────────────────────┐
│                    R-YARA Module System                         │
├─────────────────────────────────────────────────────────────────┤
│ CORE MODULES (built-in):                                        │
│ ├─ pe      - Enhanced with imphash, rich header parsing         │
│ ├─ elf     - telfhash, DWARF debug info                         │
│ ├─ macho   - Universal binary support, code signing             │
│ ├─ dotnet  - Full metadata parsing, GUID extraction             │
│ ├─ hash    - SIMD-accelerated, TLSH/ssdeep                      │
│ └─ math    - GPU-accelerated entropy                            │
│                                                                  │
│ EXTENDED MODULES (new):                                          │
│ ├─ pdf     - PDF structure and JavaScript extraction            │
│ ├─ office  - MS Office document parsing                         │
│ ├─ crypto  - Certificate chain validation                       │
│ ├─ network - PCAP analysis, protocol detection                  │
│ ├─ memory  - Process memory forensics                           │
│ └─ ml      - Machine learning model integration                 │
│                                                                  │
│ PLUGIN SYSTEM:                                                   │
│ └─ WebAssembly-based sandboxed plugins                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Memory Management

### YARA (C) Approach
- **Arena Allocator**: Pre-allocated memory regions
- **12 Arena Buffers**: Separate arenas for different data types
- **Manual Memory Management**: Explicit alloc/free

**Issues:**
- Memory leaks possible on error paths
- Fixed arena sizes can cause issues
- No automatic cleanup

### YARA-X Approach
- **Rust Ownership**: Automatic memory management
- **Zero-Copy Parsing**: References into original data where possible
- **Smart Pointers**: Arc/Rc for shared data

**Improvements:**
- No memory leaks
- Better cache utilization
- Safer code

### R-YARA Target
```rust
// R-YARA Memory Design
┌─────────────────────────────────────────────────────────────────┐
│ 1. Bumpalo Arena for AST nodes (fast allocation, batch free)   │
│ 2. SmolStr for small string optimization                       │
│ 3. Memory-mapped file scanning (mmap)                          │
│ 4. Streaming mode for files > available RAM                    │
│ 5. Custom allocator support (jemalloc, mimalloc)               │
│ 6. Resource limits to prevent DoS                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Performance Optimizations

### From YARA
1. **Atom-based filtering**: Only run full regex if atoms match
2. **State caching**: Avoid redundant state transitions
3. **Rule dependencies**: Skip rules if dependent rules fail

### From YARA-X
1. **Parallel scanning**: Process multiple files simultaneously
2. **SIMD byte matching**: AVX2/NEON for byte comparisons
3. **Lazy module evaluation**: Only compute accessed fields
4. **Better data structures**: Double-array AC, hash maps

### R-YARA Additional Optimizations
```
┌─────────────────────────────────────────────────────────────────┐
│                  R-YARA Performance Features                    │
├─────────────────────────────────────────────────────────────────┤
│ 1. GPU Acceleration                                              │
│    └─ Pattern matching on CUDA/OpenCL for batch processing      │
│                                                                  │
│ 2. Adaptive Algorithm Selection                                  │
│    └─ Choose best algorithm based on input characteristics      │
│                                                                  │
│ 3. JIT Compilation                                               │
│    └─ Compile hot rule conditions to native code                │
│                                                                  │
│ 4. Bloom Filter Pre-filtering                                    │
│    └─ Quick rejection of non-matching files                     │
│                                                                  │
│ 5. Incremental Scanning                                          │
│    └─ Resume partial scans, delta scanning                      │
│                                                                  │
│ 6. Caching Layer                                                 │
│    └─ Cache scan results for unchanged files                    │
│                                                                  │
│ 7. Profile-Guided Optimization                                   │
│    └─ Reorder rules based on match frequency                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Error Handling

### YARA (C) Issues
- Error messages often lack context
- Line numbers sometimes incorrect
- Hard to pinpoint exact error location
- No suggestions for fixes

### YARA-X Improvements
- Full source locations with line/column
- Colored terminal output
- Multiple errors reported at once
- Helpful error messages

### R-YARA Error Design
```
┌─────────────────────────────────────────────────────────────────┐
│                    R-YARA Error System                          │
├─────────────────────────────────────────────────────────────────┤
│ Using miette crate for rich diagnostics:                        │
│                                                                  │
│ error[E0001]: undefined string identifier                       │
│   ┌─ rules/malware.yar:15:12                                    │
│   │                                                              │
│ 15│     condition: $undefined_string                             │
│   │                ^^^^^^^^^^^^^^^^^ not defined in strings     │
│   │                                                              │
│   = help: did you mean `$defined_string`?                        │
│   = note: defined strings are: $a, $b, $defined_string           │
│                                                                  │
│ Features:                                                        │
│ ├─ Source code snippets with highlighting                       │
│ ├─ Suggested fixes                                               │
│ ├─ Related locations (where string was expected to be defined)  │
│ ├─ Error codes for documentation lookup                         │
│ └─ Machine-readable output for IDE integration                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. API Design

### YARA (C) API
- Callback-based scanning
- Global state issues
- Manual resource cleanup
- Complex threading model

### YARA-X API
- Builder pattern for configuration
- Async/await support
- Strongly typed
- Iterator-based results

### R-YARA API Design
```rust
// R-YARA API Examples

// Simple scanning
let rules = ryara::compile_file("rules.yar")?;
let matches = rules.scan_file("sample.exe")?;

// Builder pattern for configuration
let scanner = ryara::Scanner::builder()
    .with_rules_file("rules.yar")?
    .with_timeout(Duration::from_secs(30))
    .with_max_string_matches(100)
    .enable_module("pe")
    .enable_module("hash")
    .build()?;

// Async scanning
let matches = scanner.scan_file_async("sample.exe").await?;

// Streaming for large files
let stream = scanner.scan_stream(file_reader)?;
while let Some(match_result) = stream.next().await {
    println!("{:?}", match_result?);
}

// Parallel batch scanning
let results = scanner.scan_directory_parallel("samples/", 8)?;

// Memory scanning with regions
let matches = scanner.scan_process_memory(pid, &[
    MemoryRegion::new(0x1000, 0x2000, Protection::ReadWrite),
])?;
```

---

## 8. Security Considerations

### YARA Vulnerabilities (Historical)
- Buffer overflows in hex parsing
- Integer overflows in size calculations
- DoS via malformed rules
- Memory exhaustion attacks

### YARA-X Security Improvements
- Memory-safe Rust code
- Bounds checking by default
- Resource limits
- Fuzzing coverage

### R-YARA Security Features
```
┌─────────────────────────────────────────────────────────────────┐
│                  R-YARA Security Design                         │
├─────────────────────────────────────────────────────────────────┤
│ 1. Memory Safety                                                 │
│    └─ Rust's ownership model prevents memory corruption         │
│                                                                  │
│ 2. Resource Limits                                               │
│    ├─ Max rule size                                              │
│    ├─ Max string count per rule                                  │
│    ├─ Max regex complexity                                       │
│    ├─ Scan timeout                                               │
│    └─ Memory usage caps                                          │
│                                                                  │
│ 3. Sandboxed Plugins                                             │
│    └─ WebAssembly isolation for third-party modules             │
│                                                                  │
│ 4. Input Validation                                              │
│    └─ Strict validation of all external inputs                  │
│                                                                  │
│ 5. Fuzzing                                                       │
│    └─ Continuous fuzzing with AFL++, libFuzzer                  │
│                                                                  │
│ 6. Security Audit                                                │
│    └─ Regular third-party security audits                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. Features Removed/Changed in YARA-X

YARA-X made deliberate decisions to remove or change certain features. We should learn from these choices:

### Removed Features
| Feature | Reason | R-YARA Decision |
|---------|--------|-----------------|
| `entrypoint` in ELF | Unreliable, rarely used | Keep for compatibility, add warnings |
| Some hex jumps | Caused ambiguity | Implement with clear semantics |
| Implicit `ascii` | Confusing behavior | Require explicit modifiers |

### Changed Behaviors
| Behavior | YARA | YARA-X | R-YARA |
|----------|------|--------|--------|
| Default encoding | `ascii` | None (explicit) | Explicit, with migration tool |
| String matching | Greedy | Non-greedy | Configurable |
| Module loading | Always | Lazy | Lazy with preload hints |

### Compatibility Notes
```
R-YARA Compatibility Modes:
├─ --compat=yara     # Full YARA compatibility
├─ --compat=yara-x   # YARA-X compatible
└─ --compat=strict   # R-YARA strict mode (recommended)
```

---

## 10. R-YARA Innovations

Beyond learning from YARA and YARA-X, R-YARA introduces new capabilities:

### PYRO Platform Integration
```
┌─────────────────────────────────────────────────────────────────┐
│              PYRO Platform Integration                          │
├─────────────────────────────────────────────────────────────────┤
│ Real-time threat intelligence and collaborative analysis:       │
│                                                                  │
│ 1. Rule Sharing Network                                          │
│    └─ Share rules across teams with version control             │
│                                                                  │
│ 2. Threat Feed Integration                                       │
│    ├─ VirusTotal                                                 │
│    ├─ MISP                                                       │
│    ├─ AlienVault OTX                                             │
│    └─ Custom feeds                                               │
│                                                                  │
│ 3. Collaborative Analysis                                        │
│    └─ Real-time match notifications and discussion              │
│                                                                  │
│ 4. ML-Assisted Rule Generation                                   │
│    └─ Suggest rules based on sample analysis                    │
└─────────────────────────────────────────────────────────────────┘
```

### Endpoint Agent (Loki/THOR Replacement)
```
┌─────────────────────────────────────────────────────────────────┐
│                R-YARA Endpoint Agent                            │
├─────────────────────────────────────────────────────────────────┤
│ Full-featured endpoint scanning agent:                          │
│                                                                  │
│ 1. Process Scanning                                              │
│    └─ Scan running process memory and modules                   │
│                                                                  │
│ 2. Registry Scanning (Windows)                                   │
│    └─ Detect malicious registry entries                         │
│                                                                  │
│ 3. Schedule Scanning                                             │
│    └─ Cron-like scheduled scans                                 │
│                                                                  │
│ 4. Real-time Monitoring                                          │
│    └─ Watch directories for new files                           │
│                                                                  │
│ 5. Remote Management                                             │
│    └─ Central console for fleet management                      │
└─────────────────────────────────────────────────────────────────┘
```

### Container & Cloud Native
```
┌─────────────────────────────────────────────────────────────────┐
│             Cloud Native Capabilities                           │
├─────────────────────────────────────────────────────────────────┤
│ 1. Container Image Scanning                                      │
│    ├─ Docker image layer analysis                               │
│    ├─ OCI registry integration                                  │
│    └─ Kubernetes admission controller                           │
│                                                                  │
│ 2. CI/CD Integration                                             │
│    ├─ GitHub Actions                                             │
│    ├─ GitLab CI                                                  │
│    ├─ Jenkins                                                    │
│    └─ SARIF output for code scanning                            │
│                                                                  │
│ 3. Cloud Storage Scanning                                        │
│    ├─ AWS S3                                                     │
│    ├─ Google Cloud Storage                                       │
│    └─ Azure Blob Storage                                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Priority

Based on the analysis, here's the prioritized implementation order:

### Phase 1: Core Engine (Current)
1. ✅ Lexer with Logos
2. 🔄 Parser with LALRPOP
3. [ ] AST validation and type checking
4. [ ] Basic pattern matching engine

### Phase 2: Pattern Matching (Next)
1. [ ] Daachorse Aho-Corasick integration
2. [ ] Regex engine with SIMD
3. [ ] Parallel scanning
4. [ ] Streaming support

### Phase 3: Modules
1. [ ] PE module with imphash
2. [ ] ELF module with telfhash
3. [ ] Hash module with SIMD
4. [ ] Other core modules

### Phase 4: Advanced Features
1. [ ] JIT compilation
2. [ ] GPU acceleration
3. [ ] ML integration
4. [ ] Plugin system

### Phase 5: Ecosystem
1. [ ] Endpoint agent
2. [ ] Container scanning
3. [ ] CI/CD integration
4. [ ] PYRO platform expansion

---

## References

- [YARA Source Code](https://github.com/VirusTotal/yara)
- [YARA-X Source Code](https://github.com/VirusTotal/yara-x)
- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA-X Documentation](https://virustotal.github.io/yara-x/)
- [Aho-Corasick Algorithm](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
- [Daachorse Library](https://github.com/daac-tools/daachorse)
- [Logos Lexer](https://github.com/maciejhirsz/logos)
- [LALRPOP Parser](https://github.com/lalrpop/lalrpop)

---

## Appendix A: Indexed Pseudocode Reference

This appendix provides detailed pseudocode for all major R-YARA components.

### A.1 Pattern Matching Engine Pseudocode

```pseudocode
// INDEX: AC-001 - Aho-Corasick Automaton Construction
ALGORITHM BuildAhoCorasickAutomaton(patterns: List<Pattern>)
    INPUT: List of patterns to match
    OUTPUT: Double-array Aho-Corasick automaton

    // Phase 1: Build trie from patterns
    trie = EmptyTrie()
    FOR EACH pattern IN patterns:
        current = trie.root
        FOR EACH byte IN pattern.bytes:
            IF current.child[byte] == NULL:
                current.child[byte] = NewTrieNode()
            current = current.child[byte]
        current.pattern_id = pattern.id
        current.is_terminal = TRUE

    // Phase 2: Build failure links (BFS)
    queue = Queue()
    FOR EACH child IN trie.root.children:
        child.failure = trie.root
        queue.enqueue(child)

    WHILE NOT queue.isEmpty():
        current = queue.dequeue()
        FOR EACH (byte, child) IN current.children:
            queue.enqueue(child)
            failure = current.failure
            WHILE failure != root AND failure.child[byte] == NULL:
                failure = failure.failure
            child.failure = failure.child[byte] OR root
            child.output = child.output UNION child.failure.output

    // Phase 3: Convert to double-array
    RETURN ConvertToDoubleArray(trie)
END ALGORITHM

// INDEX: AC-002 - Double-Array Construction
ALGORITHM ConvertToDoubleArray(trie: Trie)
    INPUT: Trie structure
    OUTPUT: Double-array representation (base[], check[])

    base = Array[MAX_STATES]
    check = Array[MAX_STATES]
    output = Array[MAX_STATES]

    queue = Queue()
    queue.enqueue((trie.root, 0))  // (node, state_index)

    WHILE NOT queue.isEmpty():
        (node, state) = queue.dequeue()

        // Find valid base value
        children = node.children.keys()
        base_value = FindValidBase(children, check)
        base[state] = base_value

        FOR EACH (byte, child) IN node.children:
            next_state = base_value + byte
            check[next_state] = state
            output[next_state] = child.pattern_ids
            queue.enqueue((child, next_state))

    RETURN DoubleArrayAC(base, check, output)
END ALGORITHM

// INDEX: AC-003 - Pattern Matching with Double-Array AC
ALGORITHM MatchPatterns(automaton: DoubleArrayAC, data: Bytes)
    INPUT: Compiled automaton, data to scan
    OUTPUT: List of matches with positions

    matches = List()
    state = 0  // Start at root

    FOR position FROM 0 TO data.length - 1:
        byte = data[position]

        // Follow failure links until we find a transition
        WHILE state != 0 AND NOT HasTransition(automaton, state, byte):
            state = automaton.failure[state]

        // Take transition if exists
        IF HasTransition(automaton, state, byte):
            state = automaton.base[state] + byte

        // Check for pattern matches
        IF automaton.output[state] NOT EMPTY:
            FOR EACH pattern_id IN automaton.output[state]:
                matches.append(Match(
                    pattern_id: pattern_id,
                    start: position - patterns[pattern_id].length + 1,
                    end: position
                ))

    RETURN matches
END ALGORITHM

// INDEX: AC-004 - SIMD-Accelerated Scanning
ALGORITHM SIMDScan(data: Bytes, first_bytes: Set<Byte>)
    INPUT: Data buffer, set of pattern first bytes
    OUTPUT: Candidate positions for pattern starts

    candidates = List()
    mask = CreateByteMask(first_bytes)  // 256-bit mask

    FOR offset FROM 0 TO data.length - 32 STEP 32:
        // Load 32 bytes into SIMD register
        chunk = SIMD.load256(data[offset:offset+32])

        // Compare against all first bytes simultaneously
        matches = SIMD.compare_mask(chunk, mask)

        // Extract match positions
        WHILE matches != 0:
            bit_pos = CountTrailingZeros(matches)
            candidates.append(offset + bit_pos)
            matches = matches AND (matches - 1)  // Clear lowest bit

    RETURN candidates
END ALGORITHM
```

### A.2 Lexer Pseudocode

```pseudocode
// INDEX: LEX-001 - Token Recognition
ALGORITHM Tokenize(source: String)
    INPUT: YARA source code
    OUTPUT: Stream of tokens with spans

    position = 0
    tokens = List()

    WHILE position < source.length:
        // Skip whitespace
        WHILE IsWhitespace(source[position]):
            position += 1

        IF position >= source.length:
            BREAK

        // Try to match each token type
        token = NULL
        start = position

        // Keywords (highest priority)
        FOR keyword IN ["rule", "meta", "strings", "condition", ...]:
            IF source.startsWith(keyword, position) AND
               NOT IsIdentifierChar(source[position + keyword.length]):
                token = Token(type: keyword, span: (start, start + keyword.length))
                position += keyword.length
                BREAK

        IF token == NULL:
            // Identifiers
            IF IsIdentifierStart(source[position]):
                end = position
                WHILE IsIdentifierChar(source[end]):
                    end += 1
                token = Token(type: IDENTIFIER, value: source[position:end])
                position = end

            // Numbers
            ELSE IF IsDigit(source[position]) OR
                    (source[position] == '0' AND source[position+1] IN 'xXoO'):
                token = ParseNumber(source, position)
                position = token.span.end

            // String literals
            ELSE IF source[position] == '"':
                token = ParseStringLiteral(source, position)
                position = token.span.end

            // Hex strings
            ELSE IF source[position] == '{':
                token = ParseHexString(source, position)
                position = token.span.end

            // Regex
            ELSE IF source[position] == '/':
                token = ParseRegex(source, position)
                position = token.span.end

            // Operators and delimiters
            ELSE:
                token = ParseOperator(source, position)
                position = token.span.end

        IF token != NULL:
            tokens.append(token)

    RETURN tokens
END ALGORITHM

// INDEX: LEX-002 - Hex String Parsing
ALGORITHM ParseHexString(source: String, start: Int)
    INPUT: Source code, starting position
    OUTPUT: HexString token

    ASSERT source[start] == '{'
    position = start + 1
    tokens = List()

    WHILE source[position] != '}':
        SkipWhitespace()

        IF source[position:position+2] == '??':
            tokens.append(HexToken.Wildcard)
            position += 2

        ELSE IF IsHexDigit(source[position]) AND IsHexDigit(source[position+1]):
            byte = ParseHexByte(source[position:position+2])
            tokens.append(HexToken.Byte(byte))
            position += 2

        ELSE IF IsHexDigit(source[position]) AND source[position+1] == '?':
            nibble = ParseHexNibble(source[position])
            tokens.append(HexToken.NibbleWildcard(high: nibble, low: None))
            position += 2

        ELSE IF source[position] == '[':
            // Parse jump
            (min, max) = ParseJump(source, position)
            tokens.append(HexToken.Jump(min, max))

        ELSE IF source[position] == '(':
            // Parse alternation
            alternatives = ParseAlternation(source, position)
            tokens.append(HexToken.Alternation(alternatives))

        ELSE:
            ERROR "Invalid hex string token"

    RETURN Token(type: HEX_STRING, tokens: tokens, span: (start, position+1))
END ALGORITHM
```

### A.3 Parser Pseudocode

```pseudocode
// INDEX: PARSE-001 - Rule Parsing
ALGORITHM ParseRule(tokens: TokenStream)
    INPUT: Stream of tokens
    OUTPUT: Rule AST node

    // Parse modifiers
    modifiers = RuleModifiers()
    WHILE tokens.peek().type IN [PRIVATE, GLOBAL]:
        IF tokens.consume(PRIVATE):
            modifiers.is_private = TRUE
        IF tokens.consume(GLOBAL):
            modifiers.is_global = TRUE

    // Parse rule keyword and name
    EXPECT tokens.consume(RULE)
    name = EXPECT tokens.consume(IDENTIFIER)

    // Parse optional tags
    tags = List()
    IF tokens.peek().type == COLON:
        tokens.consume(COLON)
        WHILE tokens.peek().type == IDENTIFIER:
            tags.append(tokens.consume(IDENTIFIER).value)

    // Parse rule body
    EXPECT tokens.consume(LBRACE)

    meta = List()
    strings = List()

    IF tokens.peek().type == META:
        meta = ParseMetaSection(tokens)

    IF tokens.peek().type == STRINGS:
        strings = ParseStringsSection(tokens)

    EXPECT tokens.consume(CONDITION)
    EXPECT tokens.consume(COLON)
    condition = ParseExpression(tokens)

    EXPECT tokens.consume(RBRACE)

    RETURN Rule(
        name: name,
        modifiers: modifiers,
        tags: tags,
        meta: meta,
        strings: strings,
        condition: condition
    )
END ALGORITHM

// INDEX: PARSE-002 - Expression Parsing (Pratt Parser)
ALGORITHM ParseExpression(tokens: TokenStream, min_precedence: Int = 0)
    INPUT: Token stream, minimum precedence
    OUTPUT: Expression AST node

    // Parse prefix expression
    left = ParsePrefixExpression(tokens)

    // Parse infix expressions with precedence climbing
    WHILE TRUE:
        operator = tokens.peek()
        IF NOT IsInfixOperator(operator):
            BREAK

        precedence = GetPrecedence(operator)
        IF precedence < min_precedence:
            BREAK

        tokens.consume()

        // Handle right-associative operators
        next_min = precedence
        IF IsRightAssociative(operator):
            next_min = precedence
        ELSE:
            next_min = precedence + 1

        right = ParseExpression(tokens, next_min)
        left = BinaryExpr(left: left, op: operator, right: right)

    RETURN left
END ALGORITHM

// INDEX: PARSE-003 - Prefix Expression Parsing
ALGORITHM ParsePrefixExpression(tokens: TokenStream)
    INPUT: Token stream
    OUTPUT: Expression AST node

    token = tokens.peek()

    SWITCH token.type:
        CASE NOT:
            tokens.consume()
            expr = ParsePrefixExpression(tokens)
            RETURN UnaryExpr(op: NOT, operand: expr)

        CASE MINUS:
            tokens.consume()
            expr = ParsePrefixExpression(tokens)
            RETURN UnaryExpr(op: NEG, operand: expr)

        CASE DEFINED:
            tokens.consume()
            expr = ParsePrefixExpression(tokens)
            RETURN DefinedExpr(expr)

        CASE LPAREN:
            tokens.consume()
            expr = ParseExpression(tokens)
            EXPECT tokens.consume(RPAREN)
            RETURN ParenExpr(expr)

        CASE TRUE:
            tokens.consume()
            RETURN BoolLiteral(TRUE)

        CASE FALSE:
            tokens.consume()
            RETURN BoolLiteral(FALSE)

        CASE NUMBER:
            value = tokens.consume().value
            RETURN NumberLiteral(value)

        CASE STRING_ID:
            name = tokens.consume().value
            RETURN StringRef(name)

        CASE STRING_COUNT:
            RETURN ParseStringCount(tokens)

        CASE ALL, ANY, NONE:
            RETURN ParseQuantifier(tokens)

        CASE FOR:
            RETURN ParseForExpression(tokens)

        CASE IDENTIFIER:
            RETURN ParseIdentifierOrCall(tokens)

        DEFAULT:
            ERROR "Unexpected token: " + token
END ALGORITHM
```

### A.4 Bytecode Compiler Pseudocode

```pseudocode
// INDEX: BC-001 - Bytecode Generation
ALGORITHM CompileToByteCode(ast: SourceFile)
    INPUT: Parsed AST
    OUTPUT: Compiled bytecode

    compiler = BytecodeCompiler()

    FOR EACH rule IN ast.rules:
        // Compile rule strings
        FOR EACH string IN rule.strings:
            string_id = compiler.addString(string)

        // Compile condition to bytecode
        bytecode = compiler.compileExpression(rule.condition)

        // Register rule with bytecode
        compiler.addRule(Rule(
            name: rule.name,
            strings: rule.strings.map(s => s.id),
            bytecode: bytecode
        ))

    RETURN compiler.finalize()
END ALGORITHM

// INDEX: BC-002 - Expression Compilation
ALGORITHM CompileExpression(expr: Expression, compiler: BytecodeCompiler)
    INPUT: Expression AST node
    OUTPUT: Bytecode instructions

    SWITCH expr.type:
        CASE BoolLiteral:
            compiler.emit(PUSH_BOOL, expr.value)

        CASE NumberLiteral:
            compiler.emit(PUSH_INT, expr.value)

        CASE StringRef:
            string_idx = compiler.getStringIndex(expr.name)
            compiler.emit(PUSH_STRING_MATCH, string_idx)

        CASE BinaryExpr:
            // Compile left operand
            CompileExpression(expr.left, compiler)

            // Short-circuit for AND/OR
            IF expr.op == AND:
                jump_label = compiler.newLabel()
                compiler.emit(JUMP_IF_FALSE, jump_label)
                CompileExpression(expr.right, compiler)
                compiler.emit(AND)
                compiler.placeLabel(jump_label)

            ELSE IF expr.op == OR:
                jump_label = compiler.newLabel()
                compiler.emit(JUMP_IF_TRUE, jump_label)
                CompileExpression(expr.right, compiler)
                compiler.emit(OR)
                compiler.placeLabel(jump_label)

            ELSE:
                CompileExpression(expr.right, compiler)
                compiler.emit(BinaryOpcode(expr.op))

        CASE UnaryExpr:
            CompileExpression(expr.operand, compiler)
            compiler.emit(UnaryOpcode(expr.op))

        CASE StringCount:
            string_idx = compiler.getStringIndex(expr.name)
            compiler.emit(PUSH_STRING_COUNT, string_idx)

        CASE FunctionCall:
            FOR arg IN expr.arguments:
                CompileExpression(arg, compiler)
            compiler.emit(CALL, expr.function.name, expr.arguments.length)

        CASE ForExpr:
            CompileForExpression(expr, compiler)

        CASE OfExpr:
            CompileOfExpression(expr, compiler)
END ALGORITHM

// INDEX: BC-003 - Register-Based VM Execution
ALGORITHM ExecuteByteCode(bytecode: Bytes, context: ScanContext)
    INPUT: Compiled bytecode, scanning context
    OUTPUT: Boolean result

    registers = Array[256]  // R0-R255
    ip = 0  // Instruction pointer

    WHILE ip < bytecode.length:
        opcode = bytecode[ip]
        ip += 1

        SWITCH opcode:
            CASE LOAD_BOOL:
                dest = bytecode[ip++]
                value = bytecode[ip++]
                registers[dest] = value

            CASE LOAD_INT:
                dest = bytecode[ip++]
                value = ReadInt64(bytecode, ip)
                ip += 8
                registers[dest] = value

            CASE MATCH_STRING:
                dest = bytecode[ip++]
                string_idx = bytecode[ip++]
                registers[dest] = context.hasMatch(string_idx)

            CASE COUNT_STRING:
                dest = bytecode[ip++]
                string_idx = bytecode[ip++]
                registers[dest] = context.matchCount(string_idx)

            CASE AND:
                dest = bytecode[ip++]
                src1 = bytecode[ip++]
                src2 = bytecode[ip++]
                registers[dest] = registers[src1] AND registers[src2]

            CASE OR:
                dest = bytecode[ip++]
                src1 = bytecode[ip++]
                src2 = bytecode[ip++]
                registers[dest] = registers[src1] OR registers[src2]

            CASE JUMP_IF_FALSE:
                src = bytecode[ip++]
                offset = ReadInt16(bytecode, ip)
                ip += 2
                IF NOT registers[src]:
                    ip += offset

            CASE CALL_MODULE:
                dest = bytecode[ip++]
                module_id = bytecode[ip++]
                func_id = bytecode[ip++]
                arg_count = bytecode[ip++]
                args = PopArgs(registers, arg_count)
                registers[dest] = CallModuleFunction(module_id, func_id, args)

            CASE RETURN:
                src = bytecode[ip++]
                RETURN registers[src]

    RETURN registers[0]
END ALGORITHM
```

### A.5 Module System Pseudocode

```pseudocode
// INDEX: MOD-001 - PE Module Implementation
ALGORITHM PEModuleLoad(data: Bytes)
    INPUT: File data
    OUTPUT: PE module context

    // Lazy parsing - only parse headers initially
    IF data.length < 64:
        RETURN Error("File too small for PE")

    // Check MZ signature
    IF data[0:2] != "MZ":
        RETURN Error("Invalid MZ signature")

    // Get PE header offset
    pe_offset = ReadUInt32LE(data, 0x3C)
    IF pe_offset + 24 > data.length:
        RETURN Error("Invalid PE offset")

    // Check PE signature
    IF data[pe_offset:pe_offset+4] != "PE\0\0":
        RETURN Error("Invalid PE signature")

    // Parse COFF header
    machine = ReadUInt16LE(data, pe_offset + 4)
    num_sections = ReadUInt16LE(data, pe_offset + 6)
    timestamp = ReadUInt32LE(data, pe_offset + 8)
    optional_header_size = ReadUInt16LE(data, pe_offset + 20)

    // Determine PE type
    magic = ReadUInt16LE(data, pe_offset + 24)
    is_pe32plus = (magic == 0x20b)

    RETURN PEContext(
        data: data,
        pe_offset: pe_offset,
        machine: machine,
        num_sections: num_sections,
        is_pe32plus: is_pe32plus,
        // Lazy fields
        _imports: LAZY,
        _exports: LAZY,
        _sections: LAZY,
        _imphash: LAZY
    )
END ALGORITHM

// INDEX: MOD-002 - Lazy Import Parsing
ALGORITHM PEGetImports(ctx: PEContext)
    INPUT: PE context
    OUTPUT: List of imported functions

    IF ctx._imports != LAZY:
        RETURN ctx._imports

    // Find import directory
    import_rva = ctx.getDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)
    IF import_rva == 0:
        ctx._imports = []
        RETURN ctx._imports

    imports = List()
    offset = ctx.rvaToOffset(import_rva)

    WHILE TRUE:
        // Read IMAGE_IMPORT_DESCRIPTOR
        original_first_thunk = ReadUInt32LE(ctx.data, offset)
        name_rva = ReadUInt32LE(ctx.data, offset + 12)
        first_thunk = ReadUInt32LE(ctx.data, offset + 16)

        IF original_first_thunk == 0 AND name_rva == 0:
            BREAK

        // Read DLL name
        dll_name = ReadNullTerminated(ctx.data, ctx.rvaToOffset(name_rva))

        // Read imported functions
        thunk_offset = ctx.rvaToOffset(original_first_thunk OR first_thunk)
        functions = List()

        WHILE TRUE:
            IF ctx.is_pe32plus:
                thunk = ReadUInt64LE(ctx.data, thunk_offset)
                thunk_offset += 8
            ELSE:
                thunk = ReadUInt32LE(ctx.data, thunk_offset)
                thunk_offset += 4

            IF thunk == 0:
                BREAK

            IF thunk & IMAGE_ORDINAL_FLAG:
                functions.append(ImportByOrdinal(thunk & 0xFFFF))
            ELSE:
                name_offset = ctx.rvaToOffset(thunk & 0x7FFFFFFF) + 2
                func_name = ReadNullTerminated(ctx.data, name_offset)
                functions.append(ImportByName(func_name))

        imports.append(ImportedDLL(name: dll_name, functions: functions))
        offset += 20

    ctx._imports = imports
    RETURN imports
END ALGORITHM

// INDEX: MOD-003 - Imphash Calculation
ALGORITHM CalculateImphash(ctx: PEContext)
    INPUT: PE context
    OUTPUT: MD5 hash of imports

    IF ctx._imphash != LAZY:
        RETURN ctx._imphash

    imports = PEGetImports(ctx)

    parts = List()
    FOR dll IN imports:
        dll_name = dll.name.lower().removeSuffix(".dll")
        FOR func IN dll.functions:
            IF func.type == BY_NAME:
                parts.append(dll_name + "." + func.name.lower())
            ELSE:
                parts.append(dll_name + ".ord" + func.ordinal)

    import_string = parts.join(",")
    ctx._imphash = MD5(import_string)
    RETURN ctx._imphash
END ALGORITHM

// INDEX: MOD-004 - Hash Module with SIMD
ALGORITHM SIMDHash(data: Bytes, algorithm: HashAlgorithm)
    INPUT: Data to hash, algorithm type
    OUTPUT: Hash value

    SWITCH algorithm:
        CASE MD5:
            RETURN SIMD_MD5(data)
        CASE SHA256:
            RETURN SIMD_SHA256(data)
        CASE CRC32:
            RETURN SIMD_CRC32(data)

ALGORITHM SIMD_CRC32(data: Bytes)
    crc = 0xFFFFFFFF

    // Process 16 bytes at a time with PCLMULQDQ
    FOR offset FROM 0 TO data.length - 16 STEP 16:
        chunk = SIMD.load128(data[offset:offset+16])

        // Fold using carry-less multiplication
        fold_const = SIMD.set128(CRC32_FOLD_CONSTANT)
        crc_vec = SIMD.set128(crc, 0, 0, 0)

        folded = SIMD.clmul(crc_vec, fold_const, 0x00)
        folded = SIMD.xor(folded, chunk)

        crc = SIMD.extract32(folded, 0)

    // Process remaining bytes
    FOR i FROM (data.length - data.length % 16) TO data.length - 1:
        crc = CRC32_TABLE[(crc ^ data[i]) & 0xFF] ^ (crc >> 8)

    RETURN crc ^ 0xFFFFFFFF
END ALGORITHM
```

### A.6 Parallel Scanning Pseudocode

```pseudocode
// INDEX: SCAN-001 - Parallel File Scanning
ALGORITHM ParallelScan(files: List<Path>, rules: CompiledRules, threads: Int)
    INPUT: List of files, compiled rules, thread count
    OUTPUT: List of scan results

    // Create thread pool with work-stealing
    pool = ThreadPool(threads)
    results = ConcurrentList()

    // Create work queue
    work_queue = AtomicQueue()
    FOR file IN files:
        work_queue.push(ScanTask(file))

    // Spawn worker threads
    FOR i FROM 0 TO threads - 1:
        pool.spawn(() => {
            WHILE TRUE:
                task = work_queue.steal()
                IF task == NULL:
                    BREAK

                result = ScanFile(task.file, rules)
                results.push(result)
        })

    // Wait for completion
    pool.join()

    RETURN results.toList()
END ALGORITHM

// INDEX: SCAN-002 - Single File Scanning
ALGORITHM ScanFile(path: Path, rules: CompiledRules)
    INPUT: File path, compiled rules
    OUTPUT: Scan result with matches

    // Memory-map file for efficient access
    mapping = MemoryMap(path)
    data = mapping.asBytes()

    // Phase 1: Pattern matching
    matches = RunPatternMatching(data, rules.patterns)

    // Phase 2: Evaluate rule conditions
    results = List()

    FOR rule IN rules.rules:
        // Create scan context
        context = ScanContext(
            data: data,
            matches: matches.forRule(rule.id),
            modules: LoadModules(data, rule.modules)
        )

        // Evaluate condition
        matched = EvaluateCondition(rule.bytecode, context)

        IF matched:
            results.append(Match(
                rule: rule.name,
                strings: context.matchedStrings(),
                meta: rule.meta
            ))

    mapping.close()
    RETURN ScanResult(file: path, matches: results)
END ALGORITHM

// INDEX: SCAN-003 - Streaming Scan for Large Files
ALGORITHM StreamingScan(path: Path, rules: CompiledRules, chunk_size: Int)
    INPUT: File path, rules, chunk size
    OUTPUT: Scan result

    file = OpenFile(path)
    total_size = file.size()

    // Precompute pattern start bytes for SIMD scanning
    start_bytes = ExtractPatternStartBytes(rules.patterns)

    // Process file in chunks with overlap
    overlap = MaxPatternLength(rules.patterns)
    matches = ConcurrentList()

    offset = 0
    WHILE offset < total_size:
        // Read chunk with overlap
        chunk_start = MAX(0, offset - overlap)
        chunk_end = MIN(total_size, offset + chunk_size)
        chunk = file.read(chunk_start, chunk_end - chunk_start)

        // SIMD scan for candidate positions
        candidates = SIMDScan(chunk, start_bytes)

        // Full pattern matching at candidates
        FOR pos IN candidates:
            absolute_pos = chunk_start + pos
            FOR pattern IN rules.patterns:
                IF MatchAt(chunk, pos, pattern):
                    matches.push(Match(
                        pattern_id: pattern.id,
                        position: absolute_pos
                    ))

        offset += chunk_size

    file.close()
    RETURN EvaluateRules(matches, rules)
END ALGORITHM
```

### A.7 GPU Acceleration Pseudocode

```pseudocode
// INDEX: GPU-001 - GPU Pattern Matching
ALGORITHM GPUPatternMatch(data: Bytes, patterns: List<Pattern>)
    INPUT: Data buffer, patterns to match
    OUTPUT: Match positions

    // Transfer data to GPU
    d_data = GPU.allocate(data.length)
    GPU.copyToDevice(d_data, data)

    // Build pattern lookup table on GPU
    d_patterns = GPU.allocate(patterns.totalBytes())
    GPU.copyToDevice(d_patterns, patterns.serialize())

    // Allocate result buffer
    max_matches = data.length * 10
    d_results = GPU.allocate(max_matches * sizeof(Match))
    d_count = GPU.allocate(sizeof(Int))

    // Launch kernel
    threads_per_block = 256
    blocks = CEIL(data.length / threads_per_block)

    GPU.launch(PatternMatchKernel, blocks, threads_per_block,
        d_data, data.length,
        d_patterns, patterns.count,
        d_results, d_count
    )

    // Retrieve results
    count = GPU.copyFromDevice(d_count)
    results = GPU.copyFromDevice(d_results, count * sizeof(Match))

    // Cleanup
    GPU.free(d_data)
    GPU.free(d_patterns)
    GPU.free(d_results)
    GPU.free(d_count)

    RETURN results
END ALGORITHM

// INDEX: GPU-002 - CUDA Kernel for Pattern Matching
KERNEL PatternMatchKernel(
    data: Bytes, data_len: Int,
    patterns: PatternTable, pattern_count: Int,
    results: Match[], result_count: AtomicInt
)
    // Each thread processes one byte position
    tid = blockIdx.x * blockDim.x + threadIdx.x
    IF tid >= data_len:
        RETURN

    // Load patterns to shared memory
    __shared__ PatternCache cache
    IF threadIdx.x < pattern_count:
        cache.load(patterns[threadIdx.x])
    __syncthreads()

    // Check each pattern at this position
    FOR i FROM 0 TO pattern_count - 1:
        pattern = cache.get(i)

        IF tid + pattern.length <= data_len:
            IF MatchPattern(data + tid, pattern):
                // Atomic append to results
                idx = atomicAdd(result_count, 1)
                IF idx < MAX_RESULTS:
                    results[idx] = Match(
                        pattern_id: i,
                        position: tid
                    )

END KERNEL
```

---

## Appendix B: Algorithm Complexity Analysis

| Algorithm | Time Complexity | Space Complexity | Notes |
|-----------|-----------------|------------------|-------|
| AC Build | O(n) | O(n) | n = total pattern length |
| AC Match | O(m + z) | O(1) | m = data length, z = matches |
| Double-Array Conversion | O(n) | O(n) | Worst case with collision |
| SIMD Scan | O(m/32) | O(1) | 32 bytes per iteration |
| Parallel Scan | O(m/p) | O(m) | p = threads |
| GPU Match | O(m/1024) | O(m) | Per-thread parallel |
| Imphash | O(i) | O(i) | i = import count |
| Streaming | O(m) | O(c) | c = chunk size |

---

*This document is maintained as part of the R-YARA project and should be updated as new insights are gained.*
