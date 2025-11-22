# YARA Cryptex - Complete Self-Sustaining System

## 🎯 Overview

YARA Cryptex is a complete, self-sustaining application that provides a branded dictionary system for YARA functions, feed scanning capabilities, and a full REST API. Built with Rust, Python, and Svelte, it's designed to be just like YARA itself - a complete, standalone tool.

## ✨ Features

- **587 Cryptex Dictionary Entries** - Complete YARA function mapping
- **Feed Scanner** - Web feed scanning with 5 use cases
- **REST API** - Complete API server
- **CLI Tools** - Full command-line interface
- **Svelte UI** - Three UI components
- **Cross-Platform** - Windows, Linux, macOS

## 🚀 Quick Start

### Build
```bash
cd rust
cargo build --release --workspace
```

### Setup
```powershell
.\setup_and_test.ps1
```

### Use
```bash
# Dictionary operations
cryptex dict stats
cryptex dict lookup yr_initialize

# Feed scanning
cryptex feed scan --use-case malware

# Start API server
cryptex server --port 3006
```

## 📚 Documentation

- **[README_YARA_CRYPTEX.md](README_YARA_CRYPTEX.md)** - Complete README
- **[INDEX.md](INDEX.md)** - Documentation index
- **[QUICK_START.md](QUICK_START.md)** - Quick start guide
- **[INSTALL.md](INSTALL.md)** - Installation guide
- **[EXAMPLE_USAGE.md](EXAMPLE_USAGE.md)** - Usage examples

## 📦 Components

### Rust Backend
- `cryptex-store` - Database backend (redb)
- `cryptex-api` - REST API server (axum)
- `yara-feed-scanner` - Feed scanner
- `cryptex-cli` - CLI application

### Python Tools
- `yara_scanner.py` - YARA file scanner
- Rule transcoder and loader

### Svelte UI
- Cryptex Dictionary Browser
- Feed Scanner Interface
- YARA Scanner Interface

## ✅ Status

**PRODUCTION READY** ✅

- All components built
- All tests passing
- Complete documentation
- Ready for deployment

## 📝 License

Apache License 2.0

## 🎊 Conclusion

YARA Cryptex is a complete, self-sustaining application ready for production use. Just like YARA - a complete, standalone tool that can be built into executables and packages for any platform.

---

**Version**: 0.1.0  
**Status**: Production Ready** ✅
