# YARA Cryptex - End-to-End Test Guide

## 🎯 Complete System Verification

This guide walks through testing the entire YARA Cryptex system from start to finish.

## ✅ Prerequisites

- Rust 1.70+ installed
- Python 3.8+ installed
- Node.js and npm (for frontend testing)
- All components built

## 🚀 Step-by-Step Testing

### Step 1: Build All Components

```bash
cd rust
cargo build --release --workspace
```

**Verify:**
- [ ] All crates compile without errors
- [ ] Binaries exist in `target/release/`
- [ ] No warnings (or acceptable warnings)

### Step 2: Import Dictionary

```bash
# If dictionary file exists
rust/cryptex-store/target/release/import_cryptex.exe --input data/cryptex.json --database cryptex.db
```

**Verify:**
- [ ] Database file created
- [ ] Entries imported successfully
- [ ] Statistics displayed

### Step 3: Test CLI Tools

```bash
# Test dictionary operations
rust/cryptex-cli/target/release/cryptex.exe dict stats
rust/cryptex-cli/target/release/cryptex.exe dict lookup yr_initialize
rust/cryptex-cli/target/release/cryptex.exe dict search "compile"

# Test feed scanner
rust/cryptex-cli/target/release/cryptex.exe feed list
rust/cryptex-cli/target/release/cryptex.exe feed scan --use-case malware
```

**Verify:**
- [ ] All commands execute
- [ ] Output is correct
- [ ] No errors

### Step 4: Start API Server

```bash
# Start server
rust/cryptex-api/target/release/cryptex-api.exe
# Or use script
.\start_services.ps1
```

**Verify:**
- [ ] Server starts without errors
- [ ] Listens on port 3006
- [ ] No crash on startup

### Step 5: Test API Endpoints

```bash
# Test statistics
curl http://localhost:3006/api/v2/yara/cryptex/stats

# Test entries
curl http://localhost:3006/api/v2/yara/cryptex/entries

# Test search
curl "http://localhost:3006/api/v2/yara/cryptex/search?query=initialize"

# Test lookup
curl "http://localhost:3006/api/v2/yara/cryptex/lookup?symbol=yr_initialize"
```

**Verify:**
- [ ] All endpoints respond
- [ ] JSON responses are valid
- [ ] Status codes are correct (200 OK)

### Step 6: Test Python Scanner

```bash
# Test with sample file
python yara_scanner.py -d . -r yara-rules/index.yar -e .txt .md --output test_results.json
```

**Verify:**
- [ ] Scanner runs without errors
- [ ] Results file created
- [ ] Output is valid JSON

### Step 7: Test Frontend (Optional)

```bash
cd pyro-platform/frontend-svelte
npm install
npm run dev
```

**Verify in Browser:**
- [ ] Cryptex page loads: http://localhost:5173/tools/yara/cryptex
- [ ] Feed page loads: http://localhost:5173/tools/yara/feed
- [ ] Scanner page loads: http://localhost:5173/tools/yara/scan
- [ ] API calls work
- [ ] Search functions
- [ ] Results display

## 📊 Test Results Template

### Build Test
- [ ] Rust components build: ✅/❌
- [ ] Binaries created: ✅/❌
- [ ] Build time: ___ seconds

### CLI Test
- [ ] Dictionary stats: ✅/❌
- [ ] Dictionary lookup: ✅/❌
- [ ] Dictionary search: ✅/❌
- [ ] Feed list: ✅/❌
- [ ] Feed scan: ✅/❌

### API Test
- [ ] Server starts: ✅/❌
- [ ] Stats endpoint: ✅/❌
- [ ] Entries endpoint: ✅/❌
- [ ] Search endpoint: ✅/❌
- [ ] Lookup endpoint: ✅/❌

### Integration Test
- [ ] CLI → API: ✅/❌
- [ ] Python → API: ✅/❌
- [ ] Frontend → API: ✅/❌

## 🐛 Troubleshooting

### Build Issues
- **Error**: "cannot find crate"
  - **Solution**: Run `cargo clean && cargo build --release`

### API Issues
- **Error**: "address already in use"
  - **Solution**: Change port or stop existing server

### Database Issues
- **Error**: "database not found"
  - **Solution**: Run import tool first

### Frontend Issues
- **Error**: "API connection failed"
  - **Solution**: Ensure API server is running

## ✅ Success Criteria

All tests pass when:
- [x] All components build successfully
- [x] CLI tools execute correctly
- [x] API server responds to all endpoints
- [x] Python scanner works
- [x] Frontend loads and connects (if tested)

## 🎊 Test Complete

When all tests pass, the system is verified and ready for production use!

---

**Quick Test Command:**
```powershell
.\setup_and_test.ps1
.\test_api_endpoints.ps1
```

