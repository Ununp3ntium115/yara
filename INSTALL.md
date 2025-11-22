# YARA Cryptex - Installation Guide

## 🚀 Quick Installation

### From Pre-built Packages

#### Debian/Ubuntu
```bash
sudo dpkg -i yara-cryptex_0.1.0_amd64.deb
sudo apt-get install -f  # Install dependencies if needed
```

#### Red Hat/CentOS/Fedora
```bash
sudo rpm -i yara-cryptex-0.1.0-1.x86_64.rpm
```

#### macOS
```bash
# Double-click yara-cryptex-0.1.0.pkg
# Or via command line:
sudo installer -pkg yara-cryptex-0.1.0.pkg -target /
```

#### Windows
```bash
# Run yara-cryptex-0.1.0-setup.exe
# Follow the installer wizard
```

### From Source

#### Prerequisites
- Rust 1.70+ and Cargo
- Git

#### Build Steps

```bash
# Clone repository
git clone <repository-url>
cd yara-cryptex

# Build all components
make build
# or
./build.sh
# or (Windows)
.\build.ps1

# Install to system
sudo make install
```

## 📦 Package Contents

After installation, you'll have:

### Binaries
- `cryptex` - Main CLI application
- `cryptex-api` - REST API server
- `yara-feed-scanner` - Feed scanner tool
- `import_cryptex` - Import dictionary tool
- `export_cryptex` - Export dictionary tool

### Data
- `/etc/yara-cryptex/cryptex.json` - Dictionary data (587 entries)

### Documentation
- `/usr/share/doc/yara-cryptex/` - Documentation files

## ✅ Verify Installation

```bash
# Check version
cryptex --version

# Test dictionary
cryptex dict stats

# Test feed scanner
cryptex feed list
```

## 🎯 First Steps

1. **Import Dictionary**
   ```bash
   cryptex dict import /etc/yara-cryptex/cryptex.json
   ```

2. **Check Statistics**
   ```bash
   cryptex dict stats
   ```

3. **Start API Server**
   ```bash
   cryptex server --port 3006
   ```

4. **Scan Feeds**
   ```bash
   cryptex feed scan --use-case malware
   ```

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

## 🎉 Installation Complete!

The YARA Cryptex system is now installed and ready to use!

**Just like YARA - a complete, self-sustaining application!** 🚀

