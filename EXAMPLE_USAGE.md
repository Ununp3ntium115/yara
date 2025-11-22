# YARA Cryptex - Example Usage

## 🎯 Common Use Cases and Examples

### 1. Dictionary Lookup

#### Lookup by Symbol
```bash
cryptex dict lookup yr_initialize
```

#### Lookup by Codename
```bash
cryptex dict lookup BlackFlag-Bootstrap
```

#### Search Entries
```bash
cryptex dict search "compile"
cryptex dict search "hash"
cryptex dict search "scan"
```

#### Get Statistics
```bash
cryptex dict stats
```

**Output:**
```
Cryptex Dictionary Statistics:
  Total entries: 587
  Functions: 450
  CLI tools: 2
  Modules: 135
```

### 2. Feed Scanning

#### Scan All Sources
```bash
cryptex feed scan
```

#### Scan for Malware Rules
```bash
cryptex feed scan --use-case malware --output malware_rules.json
```

#### Scan for APT Rules
```bash
cryptex feed scan --use-case apt --output apt_rules.json
```

#### List Available Sources
```bash
cryptex feed list
```

### 3. YARA File Scanning

#### Scan Single File
```bash
python yara_scanner.py --rules rules.yar --target file.exe
```

#### Scan Directory
```bash
python yara_scanner.py -d /path/to/scan -r rules.yar
```

#### Scan with Cryptex Transcoding
```bash
python yara_scanner.py -d /path/to/scan -r rules.yar --cryptex
```

#### Scan Specific Extensions
```bash
python yara_scanner.py -d /path/to/scan -r rules.yar -e .exe .dll .sys
```

### 4. API Usage

#### Get Statistics
```bash
curl http://localhost:3006/api/v2/yara/cryptex/stats
```

#### Get All Entries
```bash
curl http://localhost:3006/api/v2/yara/cryptex/entries
```

#### Search Entries
```bash
curl "http://localhost:3006/api/v2/yara/cryptex/search?query=initialize"
```

#### Lookup Entry
```bash
curl "http://localhost:3006/api/v2/yara/cryptex/lookup?symbol=yr_initialize"
```

#### Scan Feed (POST)
```bash
curl -X POST http://localhost:3006/api/v2/yara/feed/scan/malware \
  -H "Content-Type: application/json" \
  -d '{"output": "malware_rules.json"}'
```

### 5. Dictionary Management

#### Import Dictionary
```bash
import_cryptex --input data/cryptex.json --database cryptex.db
```

#### Export Dictionary
```bash
export_cryptex --database cryptex.db --output backup.json
```

### 6. Server Management

#### Start API Server
```bash
cryptex server --port 3006
```

#### Start with Custom Host
```bash
cryptex server --host 127.0.0.1 --port 8080
```

### 7. Complete Workflow Example

#### Scenario: Scan for Malware with Latest Rules

```bash
# Step 1: Get latest malware rules
cryptex feed scan --use-case malware --output latest_malware_rules.json

# Step 2: Scan files with rules
python yara_scanner.py -d /path/to/scan -r latest_malware_rules.json --output scan_results.json

# Step 3: Lookup matched functions in dictionary
cryptex dict lookup yr_rule_match_strings

# Step 4: Get statistics
cryptex dict stats
```

### 8. Integration Examples

#### Python Script Using API
```python
import requests

# Get statistics
response = requests.get('http://localhost:3006/api/v2/yara/cryptex/stats')
stats = response.json()
print(f"Total entries: {stats['data']['total_entries']}")

# Search entries
response = requests.get('http://localhost:3006/api/v2/yara/cryptex/search?query=compile')
results = response.json()
for entry in results['data']:
    print(f"{entry['symbol']} -> {entry['pyro_name']}")
```

#### Shell Script Automation
```bash
#!/bin/bash
# Automated scanning workflow

# Get latest rules
cryptex feed scan --use-case malware --output /tmp/rules.json

# Scan directory
python yara_scanner.py -d /var/samples -r /tmp/rules.json --output /tmp/results.json

# Check results
if [ -s /tmp/results.json ]; then
    echo "Matches found!"
    cryptex dict stats
fi
```

## 🎯 Best Practices

### Dictionary Usage
- Use search for discovery
- Use lookup for specific entries
- Check stats regularly

### Feed Scanning
- Use specific use cases for better results
- Save output for later use
- Update rules regularly

### File Scanning
- Use specific extensions when possible
- Save results for analysis
- Use Cryptex transcoding for branded rules

### API Usage
- Handle errors gracefully
- Cache results when appropriate
- Use async requests for performance

## 📝 Tips

1. **Dictionary**: Start with `dict stats` to see what's available
2. **Feeds**: Use `feed list` to see available sources
3. **Scanning**: Use `-e` flag to limit file types
4. **API**: Test endpoints with `curl` first
5. **Integration**: Use JSON output for automation

---

**More Examples**: See `USAGE_GUIDE.md` for detailed usage instructions.

