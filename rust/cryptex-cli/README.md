# YARA Cryptex CLI

Complete self-sustaining command-line application for YARA Cryptex Dictionary.

## Installation

### From Source

```bash
cd rust/cryptex-cli
cargo build --release
```

### From Package

- **Debian/Ubuntu**: `sudo dpkg -i yara-cryptex_0.1.0_amd64.deb`
- **Red Hat/CentOS**: `sudo rpm -i yara-cryptex-0.1.0-1.x86_64.rpm`
- **macOS**: Install `yara-cryptex-0.1.0.pkg`
- **Windows**: Run `yara-cryptex-0.1.0-setup.exe`

## Usage

### Dictionary Operations

```bash
# Import dictionary
cryptex dict import data/cryptex.json

# Export dictionary
cryptex dict export output.json

# Lookup entry
cryptex dict lookup yr_initialize

# Search entries
cryptex dict search "initialize"

# Show statistics
cryptex dict stats
```

### Feed Scanner

```bash
# Scan all sources
cryptex feed scan

# Scan for specific use case
cryptex feed scan --use-case malware
cryptex feed scan --use-case new_tasks
cryptex feed scan --use-case apt

# List sources
cryptex feed list
```

### Server

```bash
# Start API server
cryptex server --port 3006 --host 0.0.0.0
```

## Features

- ✅ Complete dictionary management
- ✅ Feed scanning with 5 use cases
- ✅ REST API server
- ✅ Self-contained (no external dependencies)
- ✅ Cross-platform (Linux, macOS, Windows)

## Self-Sustaining

The application is completely self-contained:
- All functionality built-in
- No external dependencies required
- Dictionary data can be bundled
- Ready for distribution

**Just like YARA itself!** 🎉

