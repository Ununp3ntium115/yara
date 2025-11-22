# Deployment Guide - Complete YARA Cryptex System

## 🚀 Quick Start

### 1. Build Rust Components

```bash
# Build all Rust components
cd rust/cryptex-store
cargo build --release

cd ../cryptex-api
cargo build --release

cd ../yara-feed-scanner
cargo build --release
```

### 2. Import Dictionary

```bash
cd rust/cryptex-store
cargo run --bin import_cryptex -- \
  --input ../../data/cryptex.json \
  --database cryptex.db
```

### 3. Start API Server

```bash
cd rust/cryptex-api
export CRYPTEX_DB_PATH=../cryptex-store/cryptex.db
cargo run --release
# Server runs on http://localhost:3006
```

### 4. Install Node-RED Nodes

```bash
# Cryptex nodes
cd node-red/nodes/cryptex-lookup
npm install
cp -r . ~/.node-red/node_modules/node-red-contrib-cryptex-lookup/

# Feed scanner node
cd ../yara-feed-scanner
npm install
cp -r . ~/.node-red/node_modules/node-red-contrib-yara-feed-scanner/
```

### 5. Frontend (PYRO Platform)

The Svelte components are already integrated:
- `/tools/yara/cryptex` - Dictionary browser
- `/tools/yara/feed` - Feed scanner

Just build and run PYRO Platform frontend.

## 📋 Configuration

### Environment Variables

```bash
# Cryptex API
export CRYPTEX_DB_PATH=/path/to/cryptex.db
export API_PORT=3006
export API_HOST=0.0.0.0
```

### Node-RED Configuration

Add to `settings.js`:
```javascript
module.exports = {
    functionGlobalContext: {
        cryptexAPI: 'http://localhost:3006/api/v2/yara/cryptex',
        feedAPI: 'http://localhost:3006/api/v2/yara/feed'
    }
}
```

## 🧪 Testing

### Test API

```bash
# Test Cryptex endpoints
curl http://localhost:3006/api/v2/yara/cryptex/stats
curl "http://localhost:3006/api/v2/yara/cryptex/lookup?symbol=yr_initialize"

# Test Feed Scanner
curl -X POST http://localhost:3006/api/v2/yara/feed/scan/all \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Test CLI

```bash
# Test feed scanner
cd rust/yara-feed-scanner
cargo run -- scan --limit 10
cargo run -- new-tasks
cargo run -- list-sources
```

### Test Frontend

1. Start PYRO Platform
2. Navigate to `/tools/yara/cryptex`
3. Test search and browse
4. Navigate to `/tools/yara/feed`
5. Test feed scanning

## 📊 Monitoring

### Health Checks

```bash
# API health
curl http://localhost:3006/api/v2/yara/cryptex/stats

# Feed scanner status
curl -X POST http://localhost:3006/api/v2/yara/feed/scan/all
```

### Logs

- API server: Console output
- Node-RED: Node-RED logs
- Frontend: Browser console

## 🔧 Troubleshooting

### Common Issues

1. **Database not found**
   - Ensure `cryptex.db` exists
   - Check `CRYPTEX_DB_PATH` environment variable

2. **API not responding**
   - Check if server is running
   - Verify port 3006 is available
   - Check firewall settings

3. **Feed scanner errors**
   - Verify internet connection
   - Check source URLs
   - Review rate limiting

4. **Frontend not loading**
   - Check API endpoint configuration
   - Verify CORS settings
   - Check browser console for errors

## 🎉 Deployment Complete!

Once all components are running:
- ✅ Dictionary accessible via API
- ✅ Feed scanner operational
- ✅ Node-RED nodes available
- ✅ Frontend interfaces working

**System is ready for production use!**

