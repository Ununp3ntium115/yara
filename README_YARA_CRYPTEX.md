# YARA Cryptex - Complete Self-Sustaining System

## 🎯 Overview

YARA Cryptex is a complete, self-sustaining application that provides a branded dictionary system for YARA functions, feed scanning capabilities, and a full REST API. Built with Rust, Python, and Svelte, it's designed to be just like YARA itself - a complete, standalone tool.

## ✨ Features

### Dictionary System
- **587 Cryptex Entries** - Complete YARA function mapping
- **Symbol to Codename Mapping** - Branded terminology
- **Search & Lookup** - Fast dictionary queries
- **Import/Export** - JSON-based management

### Feed Scanner
- **Multiple Sources** - GitHub, RSS, Atom feeds
- **5 Use Cases** - new_tasks, old_tasks, malware, APT, ransomware
- **Automatic Discovery** - YARA rule detection
- **JSON Output** - Structured results

### API Server
- **RESTful Endpoints** - Complete API
- **Async Support** - High performance
- **Statistics** - Dictionary analytics
- **Search** - Full-text search

### CLI Tools
- **Dictionary Operations** - Import, export, lookup, search
- **Feed Scanning** - All use cases
- **Server Management** - Start/stop API

### UI Components
- **Cryptex Browser** - Dictionary interface
- **Feed Scanner** - Web feed interface
- **YARA Scanner** - File scanning interface

## 🚀 Quick Start

### Build

```bash
cd rust
cargo build --release --workspace
```

### Setup

```powershell
# Windows
.\setup_and_test.ps1

# Or manually
cd rust\cryptex-api
cargo run --release
```

### Use CLI

```bash
# Dictionary operations
cryptex dict stats
cryptex dict lookup yr_initialize
cryptex dict search "compile"

# Feed scanning
cryptex feed scan --use-case malware
cryptex feed list

# Server
cryptex server --port 3006
```

### Start Frontend

```bash
cd pyro-platform/frontend-svelte
npm run dev
```

Access UI at:
- Cryptex: http://localhost:5173/tools/yara/cryptex
- Feed: http://localhost:5173/tools/yara/feed
- Scanner: http://localhost:5173/tools/yara/scan

## 📦 Components

### Rust Backend
- `cryptex-store` - Database backend (redb)
- `cryptex-api` - REST API server (axum)
- `yara-feed-scanner` - Feed scanner
- `cryptex-cli` - CLI application

### Python Tools
- `yara_scanner.py` - YARA file scanner
- Rule transcoder and loader
- Cryptex integration

### Svelte UI
- Cryptex Dictionary Browser
- Feed Scanner Interface
- YARA Scanner Interface

## 📚 Documentation

- `README_YARA_CRYPTEX.md` - This file
- `COMPLETE_SYSTEM_READY.md` - System overview
- `PROJECT_COMPLETE.md` - Project summary
- `FINAL_UA_STATUS.md` - UA testing
- `README_BUILD.md` - Build instructions
- `INSTALL.md` - Installation guide
- `QUICK_START.md` - Quick start guide

## 🔧 API Endpoints

### Dictionary
- `GET /api/v2/yara/cryptex/stats` - Statistics
- `GET /api/v2/yara/cryptex/entries` - All entries
- `GET /api/v2/yara/cryptex/search?query=...` - Search
- `GET /api/v2/yara/cryptex/lookup?symbol=...` - Lookup

### Feed Scanner
- `POST /api/v2/yara/feed/scan/all` - Scan all
- `POST /api/v2/yara/feed/scan/malware` - Scan malware
- `POST /api/v2/yara/feed/scan/apt` - Scan APT
- `POST /api/v2/yara/feed/scan/ransomware` - Scan ransomware

## 📊 System Requirements

### Runtime
- **None!** All dependencies are statically linked
- Binaries are self-contained

### Build
- Rust 1.70+ and Cargo
- Python 3.8+ (for Python tools)
- Node.js and npm (for frontend)

## 🎯 Use Cases

### 1. Dictionary Lookup
```bash
cryptex dict lookup yr_initialize
```

### 2. Feed Scanning
```bash
cryptex feed scan --use-case malware --output rules.json
```

### 3. YARA Scanning
```bash
python yara_scanner.py -d /path/to/scan -r rules.yar
```

### 4. API Integration
```bash
curl http://localhost:3006/api/v2/yara/cryptex/stats
```

## 🔨 Build System

### Cross-Platform
- **Windows**: `build.ps1`
- **Linux/macOS**: `build.sh`
- **Universal**: `make build`

### Packages
- **Debian/Ubuntu**: `make deb`
- **Red Hat/CentOS**: `make rpm`
- **macOS**: `make pkg`
- **Windows**: `make exe`

## ✅ Status

**PRODUCTION READY** ✅

- All components built
- All tests passing
- Documentation complete
- Ready for distribution

## 📝 License

Apache License 2.0

## 🎊 Conclusion

YARA Cryptex is a complete, self-sustaining application ready for production use. Just like YARA itself - a complete, standalone tool that can be built into executables and packages for any platform.

---

**Quick Commands:**
- Build: `cd rust && cargo build --release --workspace`
- Setup: `.\setup_and_test.ps1`
- Test: `.\test_api_endpoints.ps1`
- Start: `.\start_services.ps1`

