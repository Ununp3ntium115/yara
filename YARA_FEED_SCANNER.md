# YARA Rules Feed Scanner

## 🎯 Overview

The YARA Feed Scanner automatically searches the web for the latest YARA rules from multiple sources and makes them available for various use cases.

## 🚀 Features

### Use Cases

1. **New Tasks** - Scan for recent rules for new investigations
2. **Old Tasks** - Scan for historical/legacy rules
3. **Malware Detection** - Filter for malware-specific rules
4. **APT Detection** - Filter for Advanced Persistent Threat rules
5. **Ransomware Detection** - Filter for ransomware-specific rules

### Sources

- YARA Rules GitHub (official repository)
- Neo23x0 signature base
- ReversingLabs YARA rules
- InQuest YARA rules
- RSS/Atom feeds
- Direct rule URLs

## 📦 Components

### 1. Rust Feed Scanner (`rust/yara-feed-scanner/`)

**Features:**
- Multi-source scanning (GitHub, RSS, Atom, Direct)
- Use case filtering
- Async/await support
- Error handling

**Usage:**
```bash
cd rust/yara-feed-scanner
cargo run -- scan --output rules.json
cargo run -- new-tasks
cargo run -- malware
```

### 2. API Endpoints (`rust/cryptex-api/src/feed.rs`)

**Endpoints:**
- `POST /api/v2/yara/feed/scan/all` - Scan all sources
- `POST /api/v2/yara/feed/scan/new-tasks` - Scan for new tasks
- `POST /api/v2/yara/feed/scan/old-tasks` - Scan for old tasks
- `POST /api/v2/yara/feed/scan/malware` - Scan for malware
- `POST /api/v2/yara/feed/scan/apt` - Scan for APT
- `POST /api/v2/yara/feed/scan/ransomware` - Scan for ransomware

### 3. Node-RED Node (`node-red/nodes/yara-feed-scanner/`)

**Features:**
- Configurable use case selection
- Output handling
- Status indicators

**Usage:**
1. Add `yara-feed-scanner` node to flow
2. Select use case
3. Configure output
4. Deploy and test

### 4. Svelte Frontend (`pyro-platform/frontend-svelte/src/routes/tools/yara/feed/`)

**Features:**
- Use case selector
- Real-time scanning
- Results display
- Rule download
- Source links

**Access:**
- Route: `/tools/yara/feed`
- Integrated into PYRO Platform

## 🔧 Setup

### Build Rust Components

```bash
# Build feed scanner
cd rust/yara-feed-scanner
cargo build --release

# Build API (includes feed endpoints)
cd ../cryptex-api
cargo build --release
```

### Install Node-RED Node

```bash
cd node-red/nodes/yara-feed-scanner
npm install
# Copy to Node-RED nodes directory
```

### Frontend

The Svelte component is already integrated into PYRO Platform.

## 📊 Usage Examples

### CLI

```bash
# Scan all sources
./yara-feed-scanner scan --output all-rules.json

# Scan for new tasks
./yara-feed-scanner new-tasks --output new-rules.json

# Scan for malware detection
./yara-feed-scanner malware --output malware-rules.json

# Scan for APT detection
./yara-feed-scanner apt --output apt-rules.json

# Scan for ransomware detection
./yara-feed-scanner ransomware --output ransomware-rules.json
```

### API

```bash
# Scan all
curl -X POST http://localhost:3006/api/v2/yara/feed/scan/all \
  -H "Content-Type: application/json" \
  -d '{}'

# Scan for new tasks
curl -X POST http://localhost:3006/api/v2/yara/feed/scan/new-tasks \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Node-RED

1. Add `yara-feed-scanner` node
2. Configure use case
3. Connect to output nodes
4. Deploy flow

### Svelte Frontend

1. Navigate to `/tools/yara/feed`
2. Select use case
3. Click "Scan Feeds"
4. View results
5. Download rules if needed

## 🎯 Use Case Details

### New Tasks
- Focuses on recently updated rules
- Best for new investigations
- Includes latest threat signatures

### Old Tasks
- Historical rule sets
- Legacy threat patterns
- Retroactive analysis

### Malware Detection
- Filters for malware tags
- General malware signatures
- Broad threat coverage

### APT Detection
- Advanced Persistent Threats
- Nation-state actors
- Sophisticated attack patterns

### Ransomware Detection
- Ransomware-specific rules
- Encryption indicators
- Ransom note patterns

## 📁 File Structure

```
.
├── rust/
│   └── yara-feed-scanner/
│       ├── src/
│       │   ├── lib.rs          # Core scanner logic
│       │   └── main.rs         # CLI interface
│       └── Cargo.toml
├── node-red/
│   └── nodes/
│       └── yara-feed-scanner/
│           ├── yara-feed-scanner.js
│           └── package.json
└── pyro-platform/
    └── frontend-svelte/
        └── src/
            ├── routes/tools/yara/feed/+page.svelte
            └── lib/services/feedAPI.js
```

## ✨ Benefits

1. **Automated Discovery** - No manual rule hunting
2. **Multiple Sources** - Comprehensive coverage
3. **Use Case Filtering** - Targeted rule sets
4. **Integration Ready** - Works with existing systems
5. **Real-time Updates** - Latest rules available

## 🎉 Production Ready

All components are production-ready:
- ✅ Rust feed scanner
- ✅ API endpoints
- ✅ Node-RED integration
- ✅ Svelte frontend
- ✅ Multiple use cases

**Ready for deployment!**

