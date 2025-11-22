# YARA Cryptex - Build and Packaging Guide

## 🚀 Building the Complete System

### Quick Build

```bash
# Build all components
make build
# or
./build.sh
# or (Windows)
.\build.ps1
```

### Build Individual Components

```bash
# Build cryptex-store
cd rust/cryptex-store && cargo build --release

# Build cryptex-api
cd rust/cryptex-api && cargo build --release

# Build yara-feed-scanner
cd rust/yara-feed-scanner && cargo build --release

# Build cryptex-cli
cd rust/cryptex-cli && cargo build --release
```

## 📦 Creating Packages

### Debian/Ubuntu (.deb)

```bash
make deb
# or
bash packaging/deb/make-deb.sh
```

Creates: `yara-cryptex_0.1.0_amd64.deb`

Install:
```bash
sudo dpkg -i yara-cryptex_0.1.0_amd64.deb
```

### Red Hat/CentOS (.rpm)

```bash
make rpm
```

Creates: RPM package in `~/rpmbuild/RPMS/`

Install:
```bash
sudo rpm -i yara-cryptex-0.1.0-1.x86_64.rpm
```

### macOS (.pkg)

```bash
make pkg
# or
bash packaging/macos/make-pkg.sh
```

Creates: `yara-cryptex-0.1.0.pkg`

Install: Double-click the .pkg file

### Windows (.exe Installer)

```bash
make exe
# Requires NSIS installed
makensis packaging/windows/installer.nsi
```

Creates: `yara-cryptex-0.1.0-setup.exe`

Install: Run the installer

## 🎯 Complete CLI Usage

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

# List sources
cryptex feed list
```

### Server

```bash
# Start API server
cryptex server --port 3006
```

## 📁 Build Output

After building, you'll have:

```
build/
├── bin/
│   ├── cryptex              # Main CLI
│   ├── cryptex-api          # API server
│   ├── yara-feed-scanner    # Feed scanner
│   ├── import_cryptex       # Import tool
│   └── export_cryptex       # Export tool
├── data/
│   └── cryptex.json         # Dictionary data
└── docs/                    # Documentation
```

## 🔧 Requirements

- Rust 1.70+ (for building)
- Cargo (Rust package manager)
- For packages:
  - Debian: `dpkg-deb`
  - RPM: `rpmbuild`
  - macOS: `pkgbuild`
  - Windows: NSIS

## ✨ Self-Sustaining Application

The built system is completely self-contained:
- ✅ No external dependencies at runtime
- ✅ All binaries included
- ✅ Dictionary data bundled
- ✅ Ready for distribution

**The system is ready to build into executables and packages!** 🎉

