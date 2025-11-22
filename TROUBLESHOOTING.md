# YARA Cryptex - Troubleshooting Guide

## 🔧 Common Issues and Solutions

### Build Issues

#### Issue: "cannot find crate"
**Symptoms**: Build fails with crate not found errors

**Solutions**:
```bash
# Clean and rebuild
cd rust
cargo clean
cargo build --release --workspace

# Update dependencies
cargo update
```

#### Issue: "linking failed"
**Symptoms**: Linker errors during build

**Solutions**:
- Ensure Rust toolchain is up to date: `rustup update`
- Check system dependencies are installed
- Try: `cargo clean && cargo build --release`

#### Issue: "out of memory" during build
**Symptoms**: Build process runs out of memory

**Solutions**:
- Build one crate at a time
- Increase system swap space
- Use `cargo build --release` instead of workspace build

### Runtime Issues

#### Issue: "API server won't start"
**Symptoms**: Server fails to start or crashes immediately

**Solutions**:
```bash
# Check if port is in use
netstat -ano | findstr :3006  # Windows
lsof -i :3006                 # Linux/macOS

# Change port
cryptex server --port 3007

# Check database
ls -la cryptex.db
```

#### Issue: "database not found"
**Symptoms**: API server can't find database

**Solutions**:
```bash
# Import dictionary first
import_cryptex --input data/cryptex.json --database cryptex.db

# Or create empty database
cryptex dict stats  # Will create if needed
```

#### Issue: "CLI command not found"
**Symptoms**: `cryptex` command not recognized

**Solutions**:
```bash
# Use full path
rust/cryptex-cli/target/release/cryptex.exe dict stats

# Or add to PATH
export PATH=$PATH:/path/to/rust/cryptex-cli/target/release
```

### API Issues

#### Issue: "connection refused"
**Symptoms**: Can't connect to API server

**Solutions**:
1. Verify server is running: `ps aux | grep cryptex-api`
2. Check firewall settings
3. Verify port: `curl http://localhost:3006/api/v2/yara/cryptex/stats`
4. Check server logs for errors

#### Issue: "404 Not Found"
**Symptoms**: API returns 404 for endpoints

**Solutions**:
- Verify endpoint URL is correct
- Check API server version matches
- Review API documentation

#### Issue: "500 Internal Server Error"
**Symptoms**: API returns 500 errors

**Solutions**:
- Check database is initialized
- Review server logs
- Verify dictionary data is valid

### Python Tool Issues

#### Issue: "ModuleNotFoundError: No module named 'yara'"
**Symptoms**: Python can't find yara module

**Solutions**:
```bash
# Install yara-python
pip install yara-python

# Or use system package manager
sudo apt-get install python3-yara  # Debian/Ubuntu
```

#### Issue: "Error loading YARA rules"
**Symptoms**: Scanner can't load rule files

**Solutions**:
- Verify rule file path is correct
- Check rule file syntax
- Ensure YARA is properly installed
- Test with: `yara rules.yar file.exe`

### Frontend Issues

#### Issue: "API connection failed"
**Symptoms**: Frontend can't connect to API

**Solutions**:
1. Verify API server is running
2. Check API URL in frontend config
3. Check CORS settings
4. Verify network connectivity

#### Issue: "Page not loading"
**Symptoms**: UI pages don't load

**Solutions**:
- Check frontend server is running: `npm run dev`
- Verify routes are correct
- Check browser console for errors
- Clear browser cache

### Feed Scanner Issues

#### Issue: "0 rules found"
**Symptoms**: Feed scanner returns no rules

**Solutions**:
- Check internet connectivity
- Verify feed URLs are accessible
- Try different use case
- Check feed format is supported

#### Issue: "Feed parsing error"
**Symptoms**: Can't parse feed content

**Solutions**:
- Verify feed URL is valid
- Check feed format (RSS/Atom)
- Review feed content manually
- Try different feed source

### Database Issues

#### Issue: "Database locked"
**Symptoms**: Can't access database

**Solutions**:
- Close other processes using database
- Check file permissions
- Restart API server
- Use separate database file

#### Issue: "Import failed"
**Symptoms**: Can't import dictionary

**Solutions**:
- Verify JSON file is valid: `python -m json.tool data/cryptex.json`
- Check file permissions
- Ensure database path is writable
- Review import tool logs

## 🔍 Diagnostic Commands

### Check System Status
```bash
# Check Rust version
rustc --version
cargo --version

# Check Python version
python --version
python -c "import yara; print('YARA available')"

# Check Node.js version
node --version
npm --version
```

### Check Build Status
```bash
# Verify binaries exist
ls -la rust/*/target/release/*.exe  # Windows
ls -la rust/*/target/release/*       # Linux/macOS

# Check build output
cd rust && cargo build --release --workspace 2>&1 | tee build.log
```

### Check API Status
```bash
# Test API endpoint
curl http://localhost:3006/api/v2/yara/cryptex/stats

# Check server process
ps aux | grep cryptex-api
netstat -ano | findstr :3006  # Windows
```

### Check Database
```bash
# Verify database exists
ls -la cryptex.db

# Check database size
du -h cryptex.db

# Test database access
cryptex dict stats
```

## 📝 Log Locations

### API Server Logs
- Console output (when run directly)
- System logs (when run as service)
- Check for error messages in output

### Build Logs
- `cargo build` output
- Check for warnings or errors
- Review compilation messages

### Application Logs
- CLI output
- Python script output
- Frontend browser console

## 🆘 Getting Help

### Check Documentation
1. Review `INDEX.md` for documentation index
2. Check `README_YARA_CRYPTEX.md` for overview
3. Review `EXAMPLE_USAGE.md` for examples
4. Check `END_TO_END_TEST.md` for testing

### Common Solutions
- **Rebuild**: `cargo clean && cargo build --release`
- **Restart**: Stop and restart services
- **Reimport**: Reimport dictionary data
- **Check Logs**: Review error messages

### Still Having Issues?
1. Check error messages carefully
2. Review relevant documentation
3. Verify system requirements
4. Test with minimal configuration

---

**Quick Fixes:**
- Build issues: `cargo clean && cargo build --release`
- API issues: Restart server, check port
- Database issues: Reimport dictionary
- Frontend issues: Clear cache, restart dev server

