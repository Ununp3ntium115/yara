# R-YARA Architecture

This document provides a comprehensive overview of R-YARA's system architecture, component organization, and design patterns.

## Table of Contents

1. [High-Level Overview](#high-level-overview)
2. [Component Diagram](#component-diagram)
3. [Crate Structure](#crate-structure)
4. [Data Flow](#data-flow)
5. [Module System](#module-system)
6. [Compilation Pipeline](#compilation-pipeline)
7. [Execution Model](#execution-model)

## High-Level Overview

R-YARA is a modular, Rust-based implementation of the YARA pattern matching system. The architecture is designed around several key principles:

- **Modularity**: Separate crates for distinct functionality
- **Performance**: Zero-cost abstractions and efficient algorithms
- **Safety**: Rust's memory safety guarantees
- **Extensibility**: Plugin-based module system
- **Integration**: Multiple interfaces (CLI, API, Library)

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                          R-YARA System                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐        ┌──────────────┐       ┌──────────────┐  │
│  │  r-yara-cli  │        │  r-yara-api  │       │ r-yara-pyro  │  │
│  │   (Binary)   │        │   (Server)   │       │  (Platform)  │  │
│  └──────┬───────┘        └──────┬───────┘       └──────┬───────┘  │
│         │                       │                       │          │
│         └───────────┬───────────┴───────────┬───────────┘          │
│                     │                       │                      │
│           ┌─────────▼────────┐    ┌────────▼──────────┐           │
│           │  r-yara-compiler │    │ r-yara-feed-      │           │
│           │                  │    │    scanner        │           │
│           └─────────┬────────┘    └────────┬──────────┘           │
│                     │                      │                      │
│           ┌─────────▼────────┐    ┌────────▼──────────┐           │
│           │  r-yara-parser   │    │  r-yara-store     │           │
│           │                  │    │    (redb)         │           │
│           └─────────┬────────┘    └───────────────────┘           │
│                     │                                              │
│           ┌─────────▼────────┐                                     │
│           │  r-yara-matcher  │                                     │
│           │  (Aho-Corasick)  │                                     │
│           └─────────┬────────┘                                     │
│                     │                                              │
│      ┌──────────────┼──────────────┐                              │
│      │              │               │                              │
│  ┌───▼────┐    ┌────▼─────┐   ┌────▼──────┐                      │
│  │ r-yara-│    │ r-yara-  │   │ r-yara-   │                      │
│  │   vm   │    │ modules  │   │ matcher   │                      │
│  └────────┘    └──────────┘   └───────────┘                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Crate Structure

R-YARA is organized as a Cargo workspace with the following crates:

### Core Crates

#### 1. **r-yara-parser**
- **Purpose**: Parse YARA rule syntax into Abstract Syntax Tree (AST)
- **Key Components**:
  - Lexer: Tokenizes YARA rule text
  - Parser: Builds AST from tokens
  - AST nodes: Rule, String, Condition, Expression
- **Dependencies**: None (foundation layer)

#### 2. **r-yara-compiler**
- **Purpose**: Compile AST into executable bytecode
- **Key Components**:
  - Bytecode generator
  - Symbol table management
  - Type checking
  - Optimization passes
- **Dependencies**: `r-yara-parser`
- **Output**: CompiledRules with bytecode instructions

#### 3. **r-yara-matcher**
- **Purpose**: Efficient pattern matching using Aho-Corasick algorithm
- **Key Components**:
  - Multi-pattern matcher
  - String search optimization
  - Match deduplication
- **Dependencies**: None
- **Algorithm**: Aho-Corasick automaton for multi-pattern matching

#### 4. **r-yara-vm**
- **Purpose**: Execute bytecode to evaluate rule conditions
- **Key Components**:
  - Stack-based virtual machine
  - Instruction dispatcher
  - Value types (Bool, Int, Float, String)
  - Function call handling
- **Dependencies**: `r-yara-compiler`, `r-yara-matcher`
- **Execution Model**: Stack-based evaluation

#### 5. **r-yara-modules**
- **Purpose**: Provide YARA module functions (pe, elf, hash, math, etc.)
- **Key Components**:
  - PE parser (Windows executables)
  - ELF parser (Linux executables)
  - Mach-O parser (macOS executables)
  - DEX parser (Android executables)
  - Hash functions (MD5, SHA1, SHA256, etc.)
  - Math functions (entropy, mean, min, max, etc.)
- **Dependencies**: External parsing libraries
- **Interface**: Function-based API for VM

### Storage & Data

#### 6. **r-yara-store**
- **Purpose**: Persistent storage for rules and metadata
- **Key Components**:
  - Database wrapper (redb)
  - Dictionary management
  - Rule caching
  - Import/Export functionality
- **Dependencies**: `redb`
- **Storage Format**: Embedded key-value database

### Application Crates

#### 7. **r-yara-cli**
- **Purpose**: Command-line interface
- **Key Components**:
  - Subcommands (dict, feed, server)
  - Argument parsing
  - Output formatting
- **Dependencies**: All core crates, `clap`
- **Binary**: `r-yara`

#### 8. **r-yara-api**
- **Purpose**: REST API server
- **Key Components**:
  - HTTP endpoints
  - Request/Response handlers
  - Authentication
- **Dependencies**: Core crates, `axum`, `tower`
- **Binary**: `r-yara-server`

#### 9. **r-yara-feed-scanner**
- **Purpose**: Scan external sources for YARA rules
- **Key Components**:
  - GitHub API integration
  - RSS/Atom feed parsing
  - Rule extraction
  - Use-case classification
- **Dependencies**: `reqwest`, `r-yara-store`
- **Binaries**: `r-yara-feed`, `r-yara-feed-scanner`

#### 10. **r-yara-pyro**
- **Purpose**: PYRO Platform integration
- **Key Components**:
  - Worker implementations
  - API gateway
  - WebSocket streaming
  - Task queue management
  - PYRO connection handling
- **Dependencies**: All core crates, WebSocket libraries
- **Binary**: `r-yara-pyro`

## Data Flow

### Rule Compilation Flow

```
YARA Rule Text
      │
      ▼
┌─────────────┐
│   Parser    │  Tokenize and parse rule syntax
└──────┬──────┘
       │ AST (Abstract Syntax Tree)
       ▼
┌─────────────┐
│  Compiler   │  Generate bytecode, build symbol tables
└──────┬──────┘
       │ CompiledRules (bytecode + metadata)
       ▼
┌─────────────┐
│   Matcher   │  Build Aho-Corasick automaton for strings
└──────┬──────┘
       │ PatternMatcher
       ▼
    Ready for Scanning
```

### Scan Execution Flow

```
Target Data (file/memory)
      │
      ▼
┌─────────────┐
│   Matcher   │  Find all string pattern matches
└──────┬──────┘
       │ Match positions
       ▼
┌─────────────┐
│     VM      │  Execute bytecode with match context
└──────┬──────┘
       │ Evaluate conditions
       ▼
┌─────────────┐
│   Modules   │  Call module functions (hash, pe, etc.)
└──────┬──────┘
       │ Module results
       ▼
┌─────────────┐
│     VM      │  Complete condition evaluation
└──────┬──────┘
       │ Boolean result per rule
       ▼
  Scan Results
  (matched rules)
```

### Complete System Flow

```
┌──────────────┐
│  YARA Rules  │
└──────┬───────┘
       │
       ▼
┌──────────────┐      ┌──────────────┐
│   Compiler   │─────▶│    Store     │  Optional: Cache compiled rules
└──────┬───────┘      └──────────────┘
       │
       │ CompiledRules
       │
       ▼
┌──────────────┐
│   Scanner    │◀──── Target Data
└──────┬───────┘
       │
       ├─────▶ Matcher ─────▶ Find patterns
       │
       ├─────▶ VM ──────────▶ Evaluate conditions
       │          │
       │          └────────▶ Modules (pe, elf, hash, math)
       │
       ▼
┌──────────────┐
│   Results    │
└──────────────┘
```

## Module System

The module system provides extensibility through a function-based API:

### Module Architecture

```
┌─────────────────────────────────────┐
│         r-yara-modules              │
├─────────────────────────────────────┤
│                                     │
│  ┌──────┐  ┌──────┐  ┌──────┐     │
│  │  PE  │  │ ELF  │  │Mach-O│     │
│  └───┬──┘  └───┬──┘  └───┬──┘     │
│      │         │          │         │
│  ┌───▼─────────▼──────────▼───┐    │
│  │    Module Interface API     │    │
│  └─────────────┬───────────────┘    │
│                │                     │
│  ┌─────────────▼───────────────┐    │
│  │   Hash    Math    Time      │    │
│  │   DEX     Console  ...       │    │
│  └─────────────────────────────┘    │
│                                     │
└─────────────┬───────────────────────┘
              │
              ▼
        Called by VM during
        condition evaluation
```

### Module Function Interface

Each module exposes functions that:
1. Accept data range (offset, size)
2. Perform specialized analysis
3. Return typed values (int, float, string, bool)

Example:
```rust
// hash module
pub fn md5(data: &[u8], offset: usize, size: usize) -> String

// math module
pub fn entropy(data: &[u8], offset: usize, size: usize) -> f64

// pe module
pub fn is_pe(data: &[u8]) -> bool
pub fn number_of_sections(data: &[u8]) -> i64
```

## Compilation Pipeline

### Phase 1: Parsing
1. Lexical analysis (tokenization)
2. Syntax analysis (AST construction)
3. Validation (syntax errors)

### Phase 2: Compilation
1. Symbol resolution
2. Type checking
3. Bytecode generation
4. String pattern extraction

### Phase 3: Optimization
1. Constant folding
2. Dead code elimination
3. Pattern deduplication
4. Automaton construction

### Bytecode Format

Instructions are stack-based:
```
PUSH_INT <value>      ; Push integer onto stack
PUSH_STRING <id>      ; Push string reference
ADD                   ; Pop 2, add, push result
CALL_FUNC <id>        ; Call module function
JUMP_IF_FALSE <addr>  ; Conditional jump
```

## Execution Model

### Virtual Machine

The VM uses a **stack-based execution model**:

```
Stack: [value1, value2, ...]
       ▲
       │
    push/pop
       │
Instructions: PUSH, ADD, CALL, etc.
```

### Execution Example

Rule:
```yara
rule Example {
    strings:
        $a = "hello"
    condition:
        #a > 2
}
```

Bytecode execution:
```
1. COUNT_STRING "a"     ; Count matches of $a
2. PUSH_INT 2           ; Push constant 2
3. GREATER_THAN         ; Pop 2 values, compare, push bool
4. RETURN               ; Return top of stack
```

Stack evolution:
```
[]                    ; Initial
[3]                   ; After COUNT_STRING (found 3 matches)
[3, 2]                ; After PUSH_INT
[true]                ; After GREATER_THAN (3 > 2)
```

### Scan Context

During scanning, the VM maintains:
- **Data buffer**: The scanned content
- **Matches**: String pattern match positions
- **Variables**: Rule-defined variables
- **Module state**: Cached module computations

## Integration Points

### CLI Integration
```
User Command
     │
     ▼
  CLI Parser (clap)
     │
     ▼
  Core Libraries
     │
     ▼
  Results Display
```

### API Integration
```
HTTP Request
     │
     ▼
  Axum Handler
     │
     ▼
  Core Libraries
     │
     ▼
  JSON Response
```

### PYRO Integration
```
PYRO Task
     │
     ▼
  Worker Queue
     │
     ▼
  Core Libraries
     │
     ▼
  WebSocket Stream
```

## Performance Considerations

### Pattern Matching
- **Aho-Corasick**: O(n + m + z) where n=text length, m=pattern total length, z=matches
- **Single-pass**: Scans data once for all patterns
- **Automaton caching**: Reuse compiled automaton across scans

### Memory Management
- **Zero-copy parsing**: Minimize allocations during parsing
- **Arena allocation**: Batch allocations for AST nodes
- **Lazy module evaluation**: Only compute when needed

### Parallelism
- **Thread-safe scanning**: Multiple files scanned in parallel
- **Async I/O**: Non-blocking API operations
- **Worker pools**: Distributed scanning in PYRO mode

## Error Handling

R-YARA uses Rust's type-based error handling:

```
Result<T, E>
     │
     ├─ Ok(value)     ; Success
     │
     └─ Err(error)    ; Failure
           │
           ├─ ParseError
           ├─ CompileError
           ├─ VMError
           └─ ModuleError
```

## Security Considerations

1. **Memory Safety**: Rust guarantees prevent buffer overflows
2. **Input Validation**: All inputs validated before processing
3. **Resource Limits**: Configurable limits on recursion, stack depth
4. **Sandboxing**: Module functions operate in controlled environment

## Future Architecture Enhancements

- **JIT Compilation**: Compile bytecode to native code for frequently-used rules
- **GPU Acceleration**: Offload pattern matching to GPU
- **Distributed Scanning**: Coordinate scans across multiple machines
- **Incremental Compilation**: Recompile only changed rules

## Summary

R-YARA's architecture emphasizes:
- **Modularity**: Clear separation of concerns
- **Performance**: Efficient algorithms and zero-cost abstractions
- **Safety**: Rust's memory safety and type system
- **Extensibility**: Plugin-based modules
- **Integration**: Multiple interfaces for different use cases

For more details on specific components, see:
- [API Reference](API_REFERENCE.md)
- [Module Reference](MODULES.md)
- [CLI Guide](CLI_GUIDE.md)
