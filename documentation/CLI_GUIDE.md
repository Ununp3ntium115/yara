# R-YARA CLI Guide

Complete command-line interface reference for R-YARA.

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Subcommands](#subcommands)
5. [Global Options](#global-options)
6. [Use Cases](#use-cases)
7. [Advanced Usage](#advanced-usage)

## Overview

R-YARA provides a comprehensive command-line interface with the following capabilities:

- **Scanning**: Scan files and directories with YARA rules
- **Dictionary Management**: Import, export, and query the Cryptex dictionary
- **Feed Scanning**: Scan GitHub and RSS feeds for YARA rules
- **API Server**: Run REST API server

### Main Binary

```bash
r-yara [OPTIONS] <SUBCOMMAND>
```

## Installation

See [Getting Started](GETTING_STARTED.md#installation) for installation instructions.

Verify installation:
```bash
r-yara --version
# r-yara 0.1.0
```

## Basic Usage

### Quick Scan

```bash
# Scan single file
r-yara scan rules.yar target.bin

# Scan directory
r-yara scan rules.yar /path/to/files/

# Scan with output
r-yara scan -o results.json rules.yar /path/to/scan/
```

### Dictionary Lookup

```bash
# Lookup symbol
r-yara dict lookup yr_compiler_create

# Search dictionary
r-yara dict search compiler
```

### Feed Scanner

```bash
# Scan all feeds
r-yara feed scan

# Scan for malware rules
r-yara feed scan --use-case malware
```

## Subcommands

### 1. dict - Dictionary Operations

Manage the Cryptex dictionary for symbol translation.

#### Subcommands

##### dict import

Import dictionary from JSON file.

**Syntax:**
```bash
r-yara dict import <INPUT_FILE>
```

**Example:**
```bash
r-yara dict import cryptex_dict.json
# Importing dictionary from "cryptex_dict.json"...
# Imported 150 entries
```

**Input Format:**
```json
{
  "entries": [
    {
      "symbol": "yr_compiler_create",
      "pyro_name": "CreateCompiler",
      "category": "function",
      "description": "Creates a new YARA compiler instance"
    }
  ]
}
```

##### dict export

Export dictionary to JSON file.

**Syntax:**
```bash
r-yara dict export <OUTPUT_FILE>
```

**Example:**
```bash
r-yara dict export exported_dict.json
# Exporting dictionary to "exported_dict.json"...
# Exported 150 entries
```

##### dict lookup

Lookup entry by symbol or codename.

**Syntax:**
```bash
r-yara dict lookup <QUERY>
```

**Examples:**
```bash
# Lookup by symbol
r-yara dict lookup yr_compiler_create

# Lookup by PYRO name
r-yara dict lookup CreateCompiler

# Output:
# {
#   "symbol": "yr_compiler_create",
#   "pyro_name": "CreateCompiler",
#   "category": "function",
#   "description": "Creates a new YARA compiler instance"
# }
```

##### dict search

Search dictionary entries.

**Syntax:**
```bash
r-yara dict search <QUERY>
```

**Example:**
```bash
r-yara dict search compiler
# Found 8 entries:
#   yr_compiler_create -> CreateCompiler
#   yr_compiler_destroy -> DestroyCompiler
#   yr_compiler_add_file -> CompilerAddFile
#   ...
```

##### dict stats

Show dictionary statistics.

**Syntax:**
```bash
r-yara dict stats
```

**Output:**
```
R-YARA Dictionary Statistics:
  Total entries: 150
  Functions: 85
  CLI tools: 10
  Modules: 12
  Constants: 43
```

### 2. feed - Feed Scanner Operations

Scan external sources for YARA rules.

#### Subcommands

##### feed scan

Scan all configured feed sources.

**Syntax:**
```bash
r-yara feed scan [OPTIONS]
```

**Options:**
- `-u, --use-case <USE_CASE>`: Filter by use case (default: all)
  - `all`: All rules
  - `new_tasks`: New task detection
  - `old_tasks`: Legacy detection
  - `malware`: Malware detection
  - `apt`: APT detection
  - `ransomware`: Ransomware detection
- `-o, --output <FILE>`: Save results to file

**Examples:**
```bash
# Scan all feeds
r-yara feed scan

# Scan for malware rules only
r-yara feed scan --use-case malware

# Save to file
r-yara feed scan -o malware_rules.json -u malware
# Scanning feeds for use case: malware...
# Found 42 rules
# Saved to "malware_rules.json"
```

##### feed list

List all configured feed sources.

**Syntax:**
```bash
r-yara feed list
```

**Output:**
```
Available sources:
  - GitHub YARA Rules (https://github.com/Yara-Rules/rules)
  - Signature Base (https://github.com/Neo23x0/signature-base)
  - CAPE Sandbox (https://github.com/kevoreilly/CAPEv2)
  - ...
```

### 3. server - API Server

Start REST API server.

**Syntax:**
```bash
r-yara server [OPTIONS]
```

**Options:**
- `-p, --port <PORT>`: Port to listen on (default: 3006)
- `--host <HOST>`: Host to bind to (default: 0.0.0.0)

**Example:**
```bash
r-yara server --port 8080
# Starting R-YARA API server on 0.0.0.0:8080
# Press Ctrl+C to stop
```

**Endpoints:**

See [API Reference](API_REFERENCE.md#rest-api) for complete endpoint documentation.

```
GET  /api/v2/r-yara/dictionary/lookup
GET  /api/v2/r-yara/dictionary/entries
GET  /api/v2/r-yara/dictionary/search
GET  /api/v2/r-yara/dictionary/stats
POST /api/v2/r-yara/feed/scan/all
POST /api/v2/r-yara/feed/scan/malware
POST /api/v2/r-yara/feed/scan/apt
POST /api/v2/r-yara/feed/scan/ransomware
```

### 4. scan - Scan Files (Future)

Scan files with YARA rules.

**Syntax:**
```bash
r-yara scan [OPTIONS] <RULES> <TARGET>
```

**Options:**
- `-s, --strings`: Show matched strings
- `-j, --json`: JSON output
- `-r, --recursive`: Recursive directory scanning
- `-f, --fast`: Fast mode (stop after first match)
- `-p, --threads <N>`: Number of threads
- `-a, --timeout <SECONDS>`: Timeout per file

**Examples:**
```bash
# Basic scan
r-yara scan rules.yar sample.bin

# Show matched strings
r-yara scan -s rules.yar sample.bin

# JSON output
r-yara scan -j rules.yar sample.bin

# Recursive scan
r-yara scan -r rules.yar /malware_samples/

# Fast mode with 4 threads
r-yara scan -f -p 4 rules.yar /large_dataset/
```

### 5. compile - Compile Rules (Future)

Compile YARA rules to bytecode.

**Syntax:**
```bash
r-yara compile [OPTIONS] <RULES> <OUTPUT>
```

**Options:**
- `-n, --namespace <NS>`: Set namespace

**Example:**
```bash
r-yara compile rules.yar rules.yarc
# Compiled 10 rules
# Saved to rules.yarc
```

### 6. check - Validate Rules (Future)

Validate YARA rules without compiling.

**Syntax:**
```bash
r-yara check <RULES>
```

**Example:**
```bash
r-yara check rules.yar
# ✓ All rules valid
# Found 10 rules, 0 errors, 2 warnings
```

## Global Options

These options apply to all subcommands:

### -d, --database <PATH>

Path to database file (default: cryptex.db)

```bash
r-yara -d /path/to/custom.db dict stats
```

### -h, --help

Show help information.

```bash
r-yara --help
r-yara dict --help
r-yara feed scan --help
```

### -V, --version

Show version information.

```bash
r-yara --version
# r-yara 0.1.0
```

## Use Cases

### Use Case 1: Setup Dictionary

```bash
# Create new database and import dictionary
r-yara -d cryptex.db dict import seed_dictionary.json

# Verify import
r-yara -d cryptex.db dict stats
```

### Use Case 2: Search for Symbols

```bash
# Search for compiler-related symbols
r-yara dict search compiler

# Lookup specific symbol
r-yara dict lookup yr_compiler_create

# Export results
r-yara dict export my_dict.json
```

### Use Case 3: Collect Malware Rules

```bash
# Scan feeds for malware rules
r-yara feed scan -u malware -o malware_rules.json

# Scan for APT rules
r-yara feed scan -u apt -o apt_rules.json

# Scan for ransomware rules
r-yara feed scan -u ransomware -o ransomware_rules.json

# Scan all feeds
r-yara feed scan -o all_rules.json
```

### Use Case 4: Run API Server

```bash
# Start server on default port
r-yara server

# Start on custom port
r-yara server -p 8080

# Start on specific host
r-yara server --host 127.0.0.1 -p 3000
```

### Use Case 5: Automated Workflow

```bash
#!/bin/bash

# Setup
r-yara dict import initial_dict.json

# Collect rules
r-yara feed scan -u malware -o rules.json

# Start server for integration
r-yara server -p 3006 &
SERVER_PID=$!

# Wait for server
sleep 2

# Use API (via curl)
curl http://localhost:3006/api/v2/r-yara/dictionary/stats

# Cleanup
kill $SERVER_PID
```

## Advanced Usage

### Scripting with R-YARA

#### Batch Dictionary Operations

```bash
# Import multiple dictionaries
for dict in dicts/*.json; do
    echo "Importing $dict"
    r-yara dict import "$dict"
done

# Export merged dictionary
r-yara dict export merged_dict.json
```

#### Automated Feed Scanning

```bash
#!/bin/bash

# Scan different use cases
for case in malware apt ransomware; do
    echo "Scanning $case..."
    r-yara feed scan -u $case -o "rules_${case}.json"
done

# Combine results
jq -s 'add' rules_*.json > all_rules.json
```

### Integration with Other Tools

#### With curl (API)

```bash
# Start server
r-yara server &

# Query dictionary
curl "http://localhost:3006/api/v2/r-yara/dictionary/lookup?q=yr_compiler_create"

# Get statistics
curl "http://localhost:3006/api/v2/r-yara/dictionary/stats"
```

#### With jq (JSON Processing)

```bash
# Export and filter
r-yara dict export dict.json
jq '.entries[] | select(.category == "function")' dict.json

# Feed scan and extract names
r-yara feed scan -o rules.json
jq '.[] | .name' rules.json
```

#### With Python

```python
import subprocess
import json

# Run r-yara
result = subprocess.run(
    ['r-yara', 'dict', 'lookup', 'yr_compiler_create'],
    capture_output=True,
    text=True
)

# Parse output
entry = json.loads(result.stdout)
print(f"Symbol: {entry['symbol']}")
print(f"PYRO Name: {entry['pyro_name']}")
```

### Performance Optimization

#### Use Local Database

```bash
# Store database in fast storage
r-yara -d /dev/shm/cryptex.db dict import dict.json
```

#### Parallel Feed Scanning

```bash
# Scan multiple use cases in parallel
r-yara feed scan -u malware -o malware.json &
r-yara feed scan -u apt -o apt.json &
r-yara feed scan -u ransomware -o ransomware.json &
wait
```

### Debugging

#### Verbose Output

Most subcommands provide detailed output:

```bash
# Dictionary operations show progress
r-yara dict import large_dict.json
# Importing dictionary from "large_dict.json"...
# Processing entries...
# Imported 5000 entries

# Feed scanning shows sources
r-yara feed scan
# Scanning feeds for use case: all...
# Scanning GitHub YARA Rules...
# Scanning Signature Base...
# ...
# Found 142 rules
```

#### Check Database

```bash
# Verify database integrity
r-yara dict stats

# Export and inspect
r-yara dict export check.json
jq '.' check.json
```

## Configuration

### Database Location

Default: `cryptex.db` in current directory

Override with `-d` flag:
```bash
r-yara -d ~/.r-yara/cryptex.db dict stats
```

### Environment Variables

```bash
# Set default database path
export R_YARA_DB="/var/lib/r-yara/cryptex.db"

# Use in commands
r-yara dict stats
```

### Server Configuration

```bash
# Development
r-yara server --host 127.0.0.1 -p 3006

# Production
r-yara server --host 0.0.0.0 -p 80
```

## Output Formats

### Plain Text

Default output format:

```bash
r-yara dict search compiler
# Found 8 entries:
#   yr_compiler_create -> CreateCompiler
#   yr_compiler_destroy -> DestroyCompiler
```

### JSON

Use `-o` flag or redirect:

```bash
# Feed scan
r-yara feed scan -o rules.json

# Dictionary export
r-yara dict export dict.json

# Lookup (stdout)
r-yara dict lookup yr_compiler_create
# {
#   "symbol": "yr_compiler_create",
#   ...
# }
```

## Error Handling

### Common Errors

#### Database Not Found

```bash
r-yara dict stats
# Error: Database not found: cryptex.db
# Hint: Run 'r-yara dict import dict.json' first
```

**Solution:**
```bash
r-yara dict import initial_dict.json
```

#### Entry Not Found

```bash
r-yara dict lookup nonexistent
# Entry not found: nonexistent
```

#### Network Errors (Feed Scanner)

```bash
r-yara feed scan
# Error: Failed to connect to https://github.com/...
# Hint: Check internet connection
```

### Exit Codes

- `0`: Success
- `1`: General error
- `2`: Invalid arguments
- `3`: Database error
- `4`: Network error

## Shell Completion

Generate shell completions:

```bash
# Bash
r-yara completions bash > ~/.bash_completion.d/r-yara

# Zsh
r-yara completions zsh > ~/.zsh/completions/_r-yara

# Fish
r-yara completions fish > ~/.config/fish/completions/r-yara.fish
```

## Examples Summary

### Dictionary Management

```bash
# Import
r-yara dict import dict.json

# Lookup
r-yara dict lookup yr_compiler_create

# Search
r-yara dict search compiler

# Export
r-yara dict export output.json

# Stats
r-yara dict stats
```

### Feed Scanning

```bash
# Scan all
r-yara feed scan

# Scan malware
r-yara feed scan -u malware -o malware.json

# List sources
r-yara feed list
```

### API Server

```bash
# Start server
r-yara server

# Custom port
r-yara server -p 8080

# Specific host
r-yara server --host 127.0.0.1
```

## Quick Reference

```
r-yara dict import <file>           Import dictionary
r-yara dict export <file>           Export dictionary
r-yara dict lookup <query>          Lookup entry
r-yara dict search <query>          Search entries
r-yara dict stats                   Show statistics

r-yara feed scan                    Scan all feeds
r-yara feed scan -u <case>          Scan by use case
r-yara feed scan -o <file>          Save results
r-yara feed list                    List sources

r-yara server                       Start API server
r-yara server -p <port>             Custom port
r-yara server --host <host>         Custom host

r-yara -d <db>                      Use custom database
r-yara --help                       Show help
r-yara --version                    Show version
```

## See Also

- [Getting Started](GETTING_STARTED.md)
- [API Reference](API_REFERENCE.md)
- [Module Reference](MODULES.md)
- [PYRO Integration](PYRO_INTEGRATION.md)
