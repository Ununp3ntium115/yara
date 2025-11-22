# Quick Start: YARA Cryptex Dictionary Workflow

This guide will get you started with the agent-based audit system for building the Cryptex dictionary.

## Setup

1. **Install Python dependencies** (if needed):
```bash
pip install -r mcp_server/requirements.txt
```

2. **Ensure data directory exists**:
```bash
mkdir -p data
```

## Step 1: Run Initial Audit

Start by auditing the core YARA library:

```bash
# Audit all C source files in libyara
python tools/audit_agent.py --directory libyara --extensions .c

# This will create/update data/cryptex.json with function mappings
```

## Step 2: Review Generated Entries

Check what was generated:

```bash
# View the Cryptex dictionary
cat data/cryptex.json | python -m json.tool

# Or use Python to query
python -c "from mcp_server.api import get_stats; import json; print(json.dumps(get_stats(), indent=2))"
```

## Step 3: Refine Entries

You can refine entries using the API:

```python
from mcp_server.api import annotate_entry

# Update an entry with better pseudocode or summary
annotate_entry(
    symbol="yr_initialize",
    pyro_name="BlackFlag-Bootstrap",
    kind="function",
    location="libyara/include/yara/libyara.h",
    signature="YR_API int yr_initialize(void);",
    summary="Initializes libyara global state (allocators, modules).",
    pseudocode="""if runtime_already_init:
    return OK
zero_global_state()
init_arenas()
init_modules()
register_builtin_modules()
return status""",
    line_references=[{"file": "libyara/libyara.c", "start": 100, "end": 150}],
    dependencies=[],
    owner="libyara/core",
    risk="critical",
    notes=["Must be called before any other YARA API"]
)
```

## Step 4: Iterative Audit Cycle

Run the audit cycle repeatedly:

```bash
# 1. Audit new/modified files
python tools/audit_agent.py --file libyara/rules.c

# 2. Check for gaps (functions not yet mapped)
python -c "
from mcp_server.api import CryptexAPI, SourceFileAPI
import re

api = CryptexAPI()
source_api = SourceFileAPI()
mapped = {e['symbol'] for e in api.list_entries()}

# Find unmapped functions
for file_path in source_api.list_source_files():
    content = source_api.read_source_file(file_path)
    if content:
        for match in re.finditer(r'^\s*(\w+\s+)*(\w+)\s*\([^)]*\)\s*\{', content, re.MULTILINE):
            func_name = match.group(2) if match.lastindex >= 2 else None
            if func_name and func_name not in mapped:
                print(f'Unmapped: {func_name} in {file_path}')
"

# 3. Review and refine
# Edit data/cryptex.json or use API

# 4. Repeat
```

## Step 5: Use MCP Server (Optional)

If you have MCP SDK installed:

```bash
# Start MCP server
python -m mcp_server.server

# In another terminal or MCP client, you can:
# - List resources: yara://source/libyara/rules.c
# - Use tools: cryptex-annotate, function-discovery, gap-audit
```

## Example: Complete Audit Workflow

```bash
#!/bin/bash
# audit_workflow.sh

echo "=== YARA Cryptex Dictionary Audit ==="

# Step 1: Audit core library
echo "Auditing libyara..."
python tools/audit_agent.py --directory libyara --extensions .c

# Step 2: Audit headers
echo "Auditing headers..."
python tools/audit_agent.py --directory libyara/include --extensions .h

# Step 3: Audit CLI
echo "Auditing CLI..."
python tools/audit_agent.py --directory cli --extensions .c

# Step 4: Show statistics
echo "=== Statistics ==="
python -c "
from mcp_server.api import get_stats
import json
print(json.dumps(get_stats(), indent=2))
"

echo "=== Done ==="
echo "Review data/cryptex.json and refine entries as needed"
```

## Next Steps

1. **Complete Coverage**: Continue auditing until all functions are mapped
2. **Quality Review**: Ensure pseudocode and summaries are accurate
3. **Dependency Mapping**: Verify all dependencies are resolved
4. **Documentation**: Update documentation with new mappings
5. **Rust Migration**: Use completed dictionary for Rust implementation planning

## Tips

- Start with high-level functions (yr_initialize, yr_rules_scan_file, etc.)
- Work through modules systematically
- Review generated pseudocode for accuracy
- Add notes for complex functions
- Keep line references up to date

## Troubleshooting

**No functions found?**
- Check that file paths are correct
- Ensure source files exist
- Verify file extensions match

**Pseudocode looks wrong?**
- Manually refine using the API
- Add better analysis in audit_agent.py
- Review function body for better heuristics

**Missing dependencies?**
- Run gap-audit to find unmapped functions
- Add entries for missing dependencies
- Update dependency lists

