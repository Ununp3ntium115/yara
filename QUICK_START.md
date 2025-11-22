# YARA Cryptex - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### 1. Build the System

```bash
# Windows
.\build.ps1

# Linux/macOS
./build.sh

# Or use Make
make build
```

### 2. Test the CLI

```bash
# Check if it works
cd build/bin
./cryptex --help

# Show dictionary statistics
./cryptex dict stats
```

### 3. Import Dictionary

```bash
# Import the Cryptex dictionary
./cryptex dict import ../data/cryptex.json
```

### 4. Use the CLI

```bash
# Lookup a function
./cryptex dict lookup yr_initialize

# Search for functions
./cryptex dict search "compile"

# Scan feeds
./cryptex feed scan --use-case malware
```

### 5. Start the API Server

```bash
# Start server
./cryptex server --port 3006

# In another terminal, test it
curl http://localhost:3006/api/v2/yara/cryptex/stats
```

## 📦 Create a Package

### Debian/Ubuntu

```bash
make deb
sudo dpkg -i yara-cryptex_0.1.0_amd64.deb
```

### macOS

```bash
make pkg
sudo installer -pkg yara-cryptex-0.1.0.pkg -target /
```

### Windows

```bash
make exe
# Run yara-cryptex-0.1.0-setup.exe
```

## 🎯 Common Tasks

### Dictionary Management

```bash
# Import
cryptex dict import data/cryptex.json

# Export
cryptex dict export backup.json

# Lookup
cryptex dict lookup yr_initialize

# Search
cryptex dict search "hash"

# Stats
cryptex dict stats
```

### Feed Scanning

```bash
# Scan all
cryptex feed scan

# Scan for malware
cryptex feed scan --use-case malware

# List sources
cryptex feed list
```

### API Usage

```bash
# Start server
cryptex server --port 3006

# API endpoints
GET  /api/v2/yara/cryptex/lookup?symbol=yr_initialize
GET  /api/v2/yara/cryptex/entries
GET  /api/v2/yara/cryptex/search?query=compile
GET  /api/v2/yara/cryptex/stats
POST /api/v2/yara/feed/scan/malware
```

## ✅ Verification

Check that everything works:

```bash
# 1. CLI works
cryptex --version

# 2. Dictionary loaded
cryptex dict stats

# 3. Feed scanner works
cryptex feed list

# 4. API server starts
cryptex server --port 3006 &
curl http://localhost:3006/api/v2/yara/cryptex/stats
```

## 🎊 You're Ready!

The YARA Cryptex system is now ready to use. It's a complete, self-sustaining application just like YARA itself!

