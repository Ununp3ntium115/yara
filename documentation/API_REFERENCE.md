# R-YARA API Reference

Complete API documentation for R-YARA library and REST API.

## Table of Contents

1. [Rust Library API](#rust-library-api)
2. [REST API](#rest-api)
3. [Error Handling](#error-handling)
4. [Module Functions](#module-functions)
5. [Examples](#examples)

## Rust Library API

### Core Types

#### CompiledRules

Represents compiled YARA rules ready for scanning.

```rust
use r_yara_compiler::CompiledRules;

pub struct CompiledRules {
    pub rules: Vec<CompiledRule>,
    pub patterns: Vec<Pattern>,
    // ... internal fields
}
```

**Methods:**

```rust
// Get rule by name
pub fn get_rule(&self, name: &str) -> Option<&CompiledRule>

// Get all rule names
pub fn rule_names(&self) -> Vec<&str>

// Number of rules
pub fn len(&self) -> usize
```

#### Scanner

Main interface for scanning data with compiled rules.

```rust
use r_yara_vm::Scanner;

pub struct Scanner {
    // ... internal fields
}
```

**Methods:**

```rust
// Create new scanner
pub fn new(rules: &CompiledRules) -> Self

// Scan byte slice
pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<Match>, VMError>

// Scan file
pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Match>, VMError>

// Scan with timeout
pub fn scan_bytes_timeout(
    &self,
    data: &[u8],
    timeout: Duration
) -> Result<Vec<Match>, VMError>
```

#### Match

Represents a rule match result.

```rust
pub struct Match {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, MetaValue>,
    pub strings: Vec<StringMatch>,
}
```

#### StringMatch

Represents a matched string within a rule.

```rust
pub struct StringMatch {
    pub identifier: String,  // e.g., "$a"
    pub offset: usize,       // Position in file
    pub data: Vec<u8>,       // Matched bytes
}
```

### Compiler API

#### Parser

Parse YARA rule text into AST.

```rust
use r_yara_parser::{Parser, ParseError};

pub struct Parser {
    // ... internal fields
}

impl Parser {
    // Create new parser
    pub fn new() -> Self

    // Parse rule string
    pub fn parse(&mut self, input: &str) -> Result<Vec<Rule>, ParseError>

    // Parse file
    pub fn parse_file<P: AsRef<Path>>(
        &mut self,
        path: P
    ) -> Result<Vec<Rule>, ParseError>
}
```

**Example:**

```rust
use r_yara_parser::Parser;

let mut parser = Parser::new();
let rules = parser.parse(r#"
    rule Test {
        strings:
            $a = "test"
        condition:
            $a
    }
"#)?;
```

#### Compiler

Compile AST into executable bytecode.

```rust
use r_yara_compiler::{Compiler, CompileError};

pub struct Compiler {
    // ... internal fields
}

impl Compiler {
    // Create new compiler
    pub fn new() -> Self

    // Compile parsed rules
    pub fn compile(&mut self, rules: Vec<Rule>) -> Result<CompiledRules, CompileError>

    // Add namespace
    pub fn set_namespace(&mut self, ns: &str)
}
```

**Example:**

```rust
use r_yara_parser::Parser;
use r_yara_compiler::Compiler;

let mut parser = Parser::new();
let ast = parser.parse(rule_text)?;

let mut compiler = Compiler::new();
let compiled = compiler.compile(ast)?;
```

### Pattern Matcher API

#### PatternMatcher

Efficient multi-pattern matching using Aho-Corasick.

```rust
use r_yara_matcher::{PatternMatcher, Pattern};

pub struct PatternMatcher {
    // ... internal fields
}

impl PatternMatcher {
    // Create from patterns
    pub fn new(patterns: Vec<Pattern>) -> Result<Self, MatcherError>

    // Find all matches in data
    pub fn find_matches(&self, data: &[u8]) -> Vec<PatternMatch>

    // Find matches in range
    pub fn find_matches_range(
        &self,
        data: &[u8],
        start: usize,
        end: usize
    ) -> Vec<PatternMatch>
}
```

**Example:**

```rust
use r_yara_matcher::{PatternMatcher, Pattern};

let patterns = vec![
    Pattern::new(0, b"malware".to_vec()),
    Pattern::new(1, b"virus".to_vec()),
];

let matcher = PatternMatcher::new(patterns)?;
let matches = matcher.find_matches(b"this is malware code");
```

### Virtual Machine API

#### VM

Execute bytecode to evaluate rule conditions.

```rust
use r_yara_vm::{VM, ScanContext, Value};

pub struct VM<'a> {
    // ... internal fields
}

impl<'a> VM<'a> {
    // Create new VM
    pub fn new(
        rules: &'a CompiledRules,
        matcher: &'a PatternMatcher
    ) -> Self

    // Scan data
    pub fn scan(&self, ctx: &ScanContext) -> Vec<Match>

    // Execute single rule
    pub fn execute_rule(
        &self,
        rule: &CompiledRule,
        ctx: &ScanContext
    ) -> Result<bool, VMError>
}
```

#### ScanContext

Context for a scanning operation.

```rust
pub struct ScanContext<'a> {
    pub data: &'a [u8],
    pub matches: HashMap<usize, Vec<PatternMatch>>,
    pub variables: HashMap<String, Value>,
}

impl<'a> ScanContext<'a> {
    // Create new context
    pub fn new(data: &'a [u8]) -> Self

    // Add pattern matches
    pub fn add_matches(&mut self, matches: Vec<PatternMatch>)

    // Set variable
    pub fn set_variable(&mut self, name: String, value: Value)
}
```

### Store API

#### CryptexStore

Persistent storage for rules and metadata.

```rust
use r_yara_store::{CryptexStore, DictEntry};

pub struct CryptexStore {
    // ... internal fields
}

impl CryptexStore {
    // Create new database
    pub fn new(path: &str) -> Result<Self, StoreError>

    // Open existing database
    pub fn open(path: &str) -> Result<Self, StoreError>

    // Initialize schema
    pub fn initialize(&self) -> Result<(), StoreError>

    // Add entry
    pub fn add_entry(&self, entry: &DictEntry) -> Result<(), StoreError>

    // Lookup by symbol
    pub fn lookup_by_symbol(&self, symbol: &str)
        -> Result<Option<DictEntry>, StoreError>

    // Search entries
    pub fn search_entries(&self, query: &str)
        -> Result<Vec<DictEntry>, StoreError>

    // Import from JSON
    pub fn import_from_json(&self, json: &str)
        -> Result<usize, StoreError>

    // Get statistics
    pub fn get_statistics(&self) -> Result<Statistics, StoreError>
}
```

**Example:**

```rust
use r_yara_store::CryptexStore;

let store = CryptexStore::new("cryptex.db")?;
store.initialize()?;

// Import dictionary
let json = std::fs::read_to_string("dict.json")?;
let count = store.import_from_json(&json)?;
println!("Imported {} entries", count);

// Lookup
if let Some(entry) = store.lookup_by_symbol("yr_compiler_create")? {
    println!("Found: {} -> {}", entry.symbol, entry.pyro_name);
}
```

## REST API

### Base URL

```
http://localhost:3006/api/v2/r-yara
```

### Authentication

Currently, the API does not require authentication. Future versions will support:
- API keys
- JWT tokens
- OAuth 2.0

### Endpoints

#### Dictionary Endpoints

##### GET /dictionary/lookup

Lookup dictionary entry by symbol or codename.

**Query Parameters:**
- `q` (required): Symbol or codename to lookup

**Response:**
```json
{
  "symbol": "yr_compiler_create",
  "pyro_name": "CreateCompiler",
  "category": "function",
  "description": "Creates a new YARA compiler instance"
}
```

**Example:**
```bash
curl "http://localhost:3006/api/v2/r-yara/dictionary/lookup?q=yr_compiler_create"
```

##### GET /dictionary/entries

Get all dictionary entries.

**Query Parameters:**
- `limit` (optional): Maximum entries to return (default: 100)
- `offset` (optional): Offset for pagination (default: 0)

**Response:**
```json
{
  "entries": [
    {
      "symbol": "yr_compiler_create",
      "pyro_name": "CreateCompiler",
      "category": "function"
    },
    ...
  ],
  "total": 150,
  "limit": 100,
  "offset": 0
}
```

##### GET /dictionary/search

Search dictionary entries.

**Query Parameters:**
- `q` (required): Search query

**Response:**
```json
{
  "results": [
    {
      "symbol": "yr_compiler_create",
      "pyro_name": "CreateCompiler",
      "category": "function",
      "relevance": 0.95
    }
  ],
  "count": 5
}
```

##### GET /dictionary/stats

Get dictionary statistics.

**Response:**
```json
{
  "total_entries": 150,
  "functions": 85,
  "cli_tools": 10,
  "modules": 12,
  "categories": {
    "function": 85,
    "cli": 10,
    "module": 12,
    "constant": 43
  }
}
```

#### Feed Scanner Endpoints

##### POST /feed/scan/all

Scan all feed sources for YARA rules.

**Request Body:**
```json
{
  "output_format": "json",
  "filters": {
    "min_quality": 0.7
  }
}
```

**Response:**
```json
{
  "rules": [
    {
      "name": "MalwareRule",
      "source": "https://github.com/...",
      "content": "rule MalwareRule { ... }",
      "metadata": {
        "author": "Security Team",
        "date": "2025-01-15"
      }
    }
  ],
  "count": 42,
  "sources_scanned": 15
}
```

##### POST /feed/scan/malware

Scan for malware detection rules.

##### POST /feed/scan/apt

Scan for APT detection rules.

##### POST /feed/scan/ransomware

Scan for ransomware detection rules.

#### Scan Endpoints

##### POST /scan/bytes

Scan raw bytes with YARA rules.

**Request Body:**
```json
{
  "data": "base64_encoded_data",
  "rules": "rule Test { ... }",
  "timeout": 30
}
```

**Response:**
```json
{
  "matches": [
    {
      "rule": "Test",
      "namespace": "default",
      "tags": ["malware"],
      "strings": [
        {
          "identifier": "$a",
          "offset": 123,
          "data": "matched_bytes"
        }
      ]
    }
  ],
  "scan_time_ms": 15
}
```

##### POST /scan/file

Scan uploaded file.

**Request:**
- Content-Type: multipart/form-data
- Fields:
  - `file`: File to scan
  - `rules`: YARA rules (text)

**Response:**
```json
{
  "filename": "sample.bin",
  "matches": [...],
  "file_size": 1024,
  "scan_time_ms": 25
}
```

#### Compilation Endpoints

##### POST /compile

Compile YARA rules to bytecode.

**Request Body:**
```json
{
  "rules": "rule Test { strings: $a = \"test\" condition: $a }",
  "namespace": "default"
}
```

**Response:**
```json
{
  "success": true,
  "rules": ["Test"],
  "bytecode": "base64_encoded_bytecode",
  "warnings": []
}
```

##### POST /check

Validate YARA rules without compiling.

**Request Body:**
```json
{
  "rules": "rule Test { ... }"
}
```

**Response:**
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "Line 5: Unreachable condition"
  ]
}
```

### Error Responses

All endpoints return errors in this format:

```json
{
  "error": {
    "code": "PARSE_ERROR",
    "message": "Syntax error at line 5",
    "details": {
      "line": 5,
      "column": 12
    }
  }
}
```

**Error Codes:**
- `PARSE_ERROR`: Rule syntax error
- `COMPILE_ERROR`: Compilation failure
- `VM_ERROR`: Runtime execution error
- `NOT_FOUND`: Resource not found
- `INVALID_REQUEST`: Invalid request parameters
- `TIMEOUT`: Operation timeout
- `INTERNAL_ERROR`: Server error

### HTTP Status Codes

- `200 OK`: Success
- `400 Bad Request`: Invalid input
- `404 Not Found`: Resource not found
- `408 Request Timeout`: Operation timeout
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

## Error Handling

### Rust Error Types

#### ParseError

```rust
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Syntax error at line {line}, column {column}: {message}")]
    SyntaxError {
        line: usize,
        column: usize,
        message: String,
    },

    #[error("Unexpected end of input")]
    UnexpectedEOF,

    #[error("Invalid token: {0}")]
    InvalidToken(String),
}
```

#### CompileError

```rust
#[derive(Debug, Error)]
pub enum CompileError {
    #[error("Undefined identifier: {0}")]
    UndefinedIdentifier(String),

    #[error("Type mismatch: expected {expected}, got {got}")]
    TypeMismatch {
        expected: String,
        got: String,
    },

    #[error("Duplicate rule: {0}")]
    DuplicateRule(String),

    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
}
```

#### VMError

```rust
#[derive(Debug, Error)]
pub enum VMError {
    #[error("Stack underflow")]
    StackUnderflow,

    #[error("Division by zero")]
    DivisionByZero,

    #[error("Unknown function: {0}")]
    UnknownFunction(usize),

    #[error("Timeout")]
    Timeout,
}
```

### Error Handling Patterns

#### Basic Error Handling

```rust
use r_yara_parser::Parser;

match parser.parse(rule_text) {
    Ok(ast) => {
        // Process AST
    }
    Err(e) => {
        eprintln!("Parse error: {}", e);
        // Handle error
    }
}
```

#### Using ? Operator

```rust
use anyhow::Result;

fn compile_and_scan(rule_text: &str, data: &[u8]) -> Result<Vec<Match>> {
    let mut parser = Parser::new();
    let ast = parser.parse(rule_text)?;

    let mut compiler = Compiler::new();
    let compiled = compiler.compile(ast)?;

    let scanner = Scanner::new(&compiled);
    let matches = scanner.scan_bytes(data)?;

    Ok(matches)
}
```

## Module Functions

See [Module Reference](MODULES.md) for complete module function documentation.

### Quick Reference

#### hash module

```rust
hash.md5(offset, size) -> string
hash.sha1(offset, size) -> string
hash.sha256(offset, size) -> string
```

#### math module

```rust
math.entropy(offset, size) -> float
math.mean(offset, size) -> float
math.min(offset, size) -> int
math.max(offset, size) -> int
```

#### pe module

```rust
pe.is_pe() -> bool
pe.number_of_sections -> int
pe.machine -> int
pe.characteristics -> int
```

#### elf module

```rust
elf.is_elf() -> bool
elf.type -> int
elf.machine -> int
elf.number_of_sections -> int
```

## Examples

### Example 1: Basic Scanning

```rust
use r_yara_parser::Parser;
use r_yara_compiler::Compiler;
use r_yara_vm::Scanner;

fn scan_file(rule_path: &str, file_path: &str) -> anyhow::Result<()> {
    // Parse rules
    let mut parser = Parser::new();
    let ast = parser.parse_file(rule_path)?;

    // Compile
    let mut compiler = Compiler::new();
    let compiled = compiler.compile(ast)?;

    // Scan
    let scanner = Scanner::new(&compiled);
    let matches = scanner.scan_file(file_path)?;

    // Print results
    for m in matches {
        println!("Match: {} in {}", m.rule_name, file_path);
        for s in m.strings {
            println!("  {}:0x{:x}: {:?}",
                s.identifier, s.offset, s.data);
        }
    }

    Ok(())
}
```

### Example 2: In-Memory Scanning

```rust
use r_yara_parser::Parser;
use r_yara_compiler::Compiler;
use r_yara_vm::Scanner;

fn scan_memory(rule_text: &str, data: &[u8]) -> anyhow::Result<bool> {
    let mut parser = Parser::new();
    let ast = parser.parse(rule_text)?;

    let mut compiler = Compiler::new();
    let compiled = compiler.compile(ast)?;

    let scanner = Scanner::new(&compiled);
    let matches = scanner.scan_bytes(data)?;

    Ok(!matches.is_empty())
}
```

### Example 3: Using Store

```rust
use r_yara_store::CryptexStore;

fn lookup_pyro_name(symbol: &str) -> anyhow::Result<String> {
    let store = CryptexStore::open("cryptex.db")?;

    if let Some(entry) = store.lookup_by_symbol(symbol)? {
        Ok(entry.pyro_name)
    } else {
        Err(anyhow::anyhow!("Symbol not found: {}", symbol))
    }
}
```

### Example 4: REST API Client

```rust
use reqwest;
use serde_json::json;

async fn scan_via_api(data: &[u8], rules: &str) -> anyhow::Result<serde_json::Value> {
    let client = reqwest::Client::new();

    let payload = json!({
        "data": base64::encode(data),
        "rules": rules,
        "timeout": 30
    });

    let response = client
        .post("http://localhost:3006/api/v2/r-yara/scan/bytes")
        .json(&payload)
        .send()
        .await?
        .json()
        .await?;

    Ok(response)
}
```

### Example 5: Async Scanning

```rust
use tokio::task;
use std::sync::Arc;

async fn scan_multiple_files(
    rules: Arc<CompiledRules>,
    files: Vec<String>
) -> Vec<anyhow::Result<Vec<Match>>> {
    let mut tasks = vec![];

    for file in files {
        let rules = Arc::clone(&rules);
        let task = task::spawn(async move {
            let scanner = Scanner::new(&rules);
            scanner.scan_file(&file)
        });
        tasks.push(task);
    }

    let mut results = vec![];
    for task in tasks {
        results.push(task.await.unwrap());
    }

    results
}
```

## Performance Tips

### 1. Reuse Compiled Rules

```rust
// Good: Compile once
let compiled = compiler.compile(ast)?;
let scanner = Scanner::new(&compiled);

for file in files {
    scanner.scan_file(file)?;
}

// Bad: Compile for each file
for file in files {
    let compiled = compiler.compile(ast)?;
    let scanner = Scanner::new(&compiled);
    scanner.scan_file(file)?;
}
```

### 2. Use Parallel Scanning

```rust
use rayon::prelude::*;

files.par_iter().for_each(|file| {
    let scanner = Scanner::new(&compiled);
    match scanner.scan_file(file) {
        Ok(matches) => process_matches(matches),
        Err(e) => eprintln!("Error: {}", e),
    }
});
```

### 3. Set Timeouts

```rust
use std::time::Duration;

scanner.scan_bytes_timeout(data, Duration::from_secs(30))?;
```

## Versioning

R-YARA follows [Semantic Versioning](https://semver.org/):

- **Major version**: Incompatible API changes
- **Minor version**: Backward-compatible functionality
- **Patch version**: Backward-compatible bug fixes

Current version: **0.1.0**

## See Also

- [Getting Started](GETTING_STARTED.md)
- [CLI Guide](CLI_GUIDE.md)
- [Module Reference](MODULES.md)
- [Architecture](ARCHITECTURE.md)
