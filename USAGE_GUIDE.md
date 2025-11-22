# Cryptex Dictionary Usage Guide

## Quick Reference

### View Statistics
```bash
python show_stats.py
```

### Audit Core Library
```bash
python audit_sample.py
```

### Audit CLI Tools
```bash
python audit_cli.py
```

### View Dictionary
```bash
# On Windows (PowerShell)
Get-Content data\cryptex.json | ConvertFrom-Json | ConvertTo-Json -Depth 10

# Or use Python
python -c "import json; print(json.dumps(json.load(open('data/cryptex.json')), indent=2))"
```

## Python API Usage

### Load Dictionary
```python
from mcp_server.api import CryptexAPI

api = CryptexAPI()
data = api.load()
print(f"Total entries: {len(data['entries'])}")
```

### Lookup Entry
```python
from mcp_server.api import lookup_entry

# By symbol name
entry = lookup_entry(symbol="yr_initialize")
print(entry['pyro_name'])  # BlackFlag-Bootstrap-Initialize

# By codename
entry = lookup_entry(pyro_name="BlackFlag-Bootstrap-Initialize")
print(entry['symbol'])  # yr_initialize
```

### Add/Update Entry
```python
from mcp_server.api import annotate_entry

annotate_entry(
    symbol="my_function",
    pyro_name="My-Codename",
    kind="function",
    location="libyara/my_file.c",
    signature="int my_function(void);",
    summary="Does something important",
    pseudocode="function my_function():\n    return value",
    line_references=[{"file": "libyara/my_file.c", "start": 100, "end": 150}],
    owner="libyara/core",
    risk="standard"
)
```

### Get Statistics
```python
from mcp_server.api import get_stats

stats = get_stats()
print(f"Functions: {stats['functions']}")
print(f"CLI tools: {stats.get('total_cli', 0)}")
```

### List Entries
```python
from mcp_server.api import CryptexAPI

api = CryptexAPI()

# All entries
all_entries = api.list_entries()

# Only functions
functions = api.list_entries(kind="function")

# Only CLI tools
cli_tools = api.list_entries(kind="cli")
```

## Iterative Refinement Workflow

### 1. Audit New/Modified Files
```bash
# Single file
python -c "
from tools.audit_agent import audit_file
from pathlib import Path
import asyncio

asyncio.run(audit_file(
    Path('libyara/new_file.c'),
    Path('data/cryptex.json')
))
"

# Directory
python audit_sample.py  # Processes all files
```

### 2. Review Generated Entries
```python
from mcp_server.api import CryptexAPI
import json

api = CryptexAPI()
data = api.load()

# Find entries needing review
for entry in data['entries']:
    if not entry.get('pseudocode') or entry['pseudocode'].startswith('#'):
        print(f"Needs review: {entry['symbol']}")
```

### 3. Refine Entry
```python
from mcp_server.api import annotate_entry

# Update with better pseudocode
annotate_entry(
    symbol="yr_initialize",
    pyro_name="BlackFlag-Bootstrap-Initialize",
    kind="function",
    location="libyara/libyara.c",
    signature="YR_API int yr_initialize(void);",
    summary="Initializes libyara global state (allocators, modules, threads)",
    pseudocode="""function yr_initialize():
    if runtime_already_initialized:
        return ERROR_SUCCESS
    zero_global_state()
    initialize_memory_arenas()
    initialize_module_registry()
    register_builtin_modules()
    initialize_threading_primitives()
    set_runtime_flag(True)
    return ERROR_SUCCESS""",
    line_references=[{"file": "libyara/libyara.c", "start": 100, "end": 200}],
    dependencies=["yr_modules_initialize"],
    owner="libyara/core",
    risk="critical",
    notes=["Must be called before any other YARA API"]
)
```

### 4. Validate
```python
from mcp_server.api import CryptexAPI

api = CryptexAPI()
entries = api.list_entries()

# Check for missing fields
missing = []
for entry in entries:
    required = ['symbol', 'pyro_name', 'kind', 'location', 'summary', 'pseudocode']
    for field in required:
        if not entry.get(field):
            missing.append((entry['symbol'], field))

if missing:
    print("Missing fields:")
    for symbol, field in missing:
        print(f"  {symbol}: {field}")
else:
    print("All entries complete!")
```

## MCP Server Usage

### Start MCP Server
```bash
python -m mcp_server.server
```

### Available Resources
- `yara://source/libyara/*.c` - Source files
- `yara://source/libyara/*.h` - Header files
- `yara://cli/*.c` - CLI source files
- `yara://cryptex/dictionary` - Complete dictionary

### Available Tools
- `cryptex-annotate` - Add/update entries
- `function-discovery` - Find functions in files
- `gap-audit` - Find unmapped functions
- `cryptex-lookup` - Query dictionary

## Common Tasks

### Find All Functions in a File
```python
from tools.audit_agent import FunctionAnalyzer
from pathlib import Path

analyzer = FunctionAnalyzer()
functions = analyzer.extract_functions(Path('libyara/rules.c'))

for func in functions:
    print(f"{func['name']} at line {func['start_line']}")
```

### Generate Codename for Function
```python
from audit_sample import generate_pyro_name

codename = generate_pyro_name("yr_rules_scan_file", "libyara/rules.c")
print(codename)  # Molotov-Sweep-File
```

### Export to Different Format
```python
import json
from mcp_server.api import CryptexAPI

api = CryptexAPI()
data = api.load()

# Export as CSV
import csv
with open('cryptex.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Symbol', 'Codename', 'Location', 'Summary'])
    for entry in data['entries']:
        writer.writerow([
            entry['symbol'],
            entry['pyro_name'],
            entry['location'],
            entry['summary']
        ])
```

## Tips

1. **Regular Audits**: Run audits after code changes
2. **Review Pseudocode**: Ensure pseudocode accurately represents logic
3. **Update Dependencies**: Keep dependency lists current
4. **Validate Line References**: Verify line numbers are correct
5. **Consistent Naming**: Follow anarchist codename conventions

## Troubleshooting

**Dictionary not found?**
- Ensure `data/` directory exists
- Run an audit to create initial dictionary

**Import errors?**
- Check Python path includes project root
- Verify `mcp_server/` and `tools/` directories exist

**Missing functions?**
- Run gap-audit to find unmapped functions
- Check file extensions in audit scripts
- Verify function pattern matching

**Pseudocode issues?**
- Manually refine complex functions
- Use function body analysis for better pseudocode
- Review generated pseudocode for accuracy

