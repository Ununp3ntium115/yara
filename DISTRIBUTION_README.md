# YARA Cryptex - Distribution Guide

## 🎯 Complete Self-Sustaining Application

The YARA Cryptex system is a complete, standalone application that can be distributed as executables or packages for any platform.

## 📦 Built Components

### Binaries (Release Build)

All binaries are built in `rust/*/target/release/`:

1. **cryptex.exe** (or `cryptex` on Unix)
   - Main CLI application
   - Location: `rust/cryptex-cli/target/release/`

2. **cryptex-api.exe** (or `cryptex-api` on Unix)
   - REST API server
   - Location: `rust/cryptex-api/target/release/`

3. **yara-feed-scanner.exe** (or `yara-feed-scanner` on Unix)
   - Feed scanner tool
   - Location: `rust/yara-feed-scanner/target/release/`

4. **import_cryptex.exe** (or `import_cryptex` on Unix)
   - Import tool
   - Location: `rust/cryptex-store/target/release/`

5. **export_cryptex.exe** (or `export_cryptex` on Unix)
   - Export tool
   - Location: `rust/cryptex-store/target/release/`

## 🚀 Quick Start

### Using the Build Scripts

```bash
# Windows
.\build.ps1

# Linux/macOS
./build.sh

# Universal
make build
```

This will:
1. Build all Rust components in release mode
2. Copy binaries to `build/bin/`
3. Copy data files to `build/data/`
4. Copy documentation to `build/docs/`

## 📦 Creating Packages

### Debian/Ubuntu Package

```bash
make deb
# Creates: yara-cryptex_0.1.0_amd64.deb

# Install
sudo dpkg -i yara-cryptex_0.1.0_amd64.deb
```

### Red Hat/CentOS Package

```bash
make rpm
# Creates RPM in ~/rpmbuild/RPMS/

# Install
sudo rpm -i yara-cryptex-0.1.0-1.x86_64.rpm
```

### macOS Package

```bash
make pkg
# Creates: yara-cryptex-0.1.0.pkg

# Install
sudo installer -pkg yara-cryptex-0.1.0.pkg -target /
```

### Windows Installer

```bash
make exe
# Requires NSIS installed
# Creates: yara-cryptex-0.1.0-setup.exe
```

## 🎯 Using the CLI

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

### API Server

```bash
# Start server
cryptex server --port 3006

# Access API
curl http://localhost:3006/api/v2/yara/cryptex/stats
```

## 📊 System Requirements

### Runtime Requirements
- **None!** All dependencies are statically linked
- Binaries are self-contained

### Build Requirements
- Rust 1.70+ and Cargo
- For packages:
  - Debian: `dpkg-deb`
  - RPM: `rpmbuild`
  - macOS: `pkgbuild`
  - Windows: NSIS

## 🔧 Configuration

### Database Location

Default: `cryptex.db` (current directory)

Override:
```bash
cryptex --database /path/to/cryptex.db dict stats
```

### API Server

Default: `0.0.0.0:3006`

Override:
```bash
cryptex server --host 127.0.0.1 --port 8080
```

## 📁 Distribution Structure

```
yara-cryptex/
├── bin/
│   ├── cryptex              # Main CLI
│   ├── cryptex-api          # API server
│   ├── yara-feed-scanner    # Feed scanner
│   ├── import_cryptex       # Import tool
│   └── export_cryptex       # Export tool
├── data/
│   └── cryptex.json         # Dictionary data (587 entries)
└── docs/                    # Documentation
```

## ✨ Features

- ✅ **587 Cryptex Dictionary Entries** - Complete YARA function mapping
- ✅ **Feed Scanner** - 5 use cases (new tasks, old tasks, malware, APT, ransomware)
- ✅ **REST API** - Full API server with all endpoints
- ✅ **CLI Tools** - Complete command-line interface
- ✅ **Cross-Platform** - Linux, macOS, Windows
- ✅ **Self-Contained** - No external dependencies

## 🎊 Ready for Distribution!

The system is complete and ready to be distributed as:
- Standalone executables
- Platform-specific packages (.deb, .rpm, .pkg, .exe)
- Docker containers (can be added)
- Source code distribution

**Just like YARA - a complete, self-sustaining application!** 🚀

