# YARA Cryptex Dictionary Project - Status

## ✅ Completed Setup

### 1. MCP Server Infrastructure
- **Location**: `mcp_server/`
- **Components**:
  - `server.py` - MCP server implementation (with fallback for standalone mode)
  - `api.py` - Direct API for Cryptex dictionary operations
  - `requirements.txt` - Dependencies

**Features**:
- Exposes YARA source files as resources (`yara://source/*`)
- Provides tools: `cryptex-annotate`, `function-discovery`, `gap-audit`, `cryptex-lookup`
- Works with or without MCP SDK installed

### 2. Agent-Based Audit Tools
- **Location**: `tools/audit_agent.py`
- **Capabilities**:
  - Analyzes C source files to extract functions
  - Generates Cryptex dictionary entries automatically
  - Creates branded anarchist codenames
  - Generates pseudocode representations
  - Extracts line references and dependencies

### 3. Cryptex Dictionary Schema
- **Location**: `data/cryptex.json`
- **Format**: JSON with entries containing:
  - `symbol` - Original YARA function name
  - `pyro_name` - Branded codename (e.g., "BlackFlag-Bootstrap")
  - `kind` - Type (function, struct, module, etc.)
  - `location` - File path
  - `signature` - Function signature
  - `summary` - Description (≤160 chars)
  - `pseudocode` - Pseudocode example
  - `line_references` - Line number ranges
  - `dependencies` - Related symbols
  - `owner` - Component/team
  - `risk` - Criticality level
  - `notes` - Additional information

### 4. Documentation
- `WORKFLOW.md` - Complete SDLC workflow guide
- `QUICKSTART.md` - Quick start instructions
- `mcp_server/README.md` - MCP server documentation
- `tools/README.md` - Audit tools documentation

## 🎯 Current Workflow

### Phase 1: Initial Audit (Ready to Start)
```bash
# Audit core library
python tools/audit_agent.py --directory libyara --extensions .c

# Review generated entries
cat data/cryptex.json | python -m json.tool
```

### Phase 2: Iterative Refinement
1. Run audit agent on codebase sections
2. Review generated Cryptex entries
3. Refine using API or direct editing
4. Validate completeness with gap-audit
5. Repeat until 100% coverage

### Phase 3: Quality Assurance
- Verify pseudocode accuracy
- Check dependency resolution
- Validate line references
- Review codename assignments

### Phase 4: Rust Migration (Future)
- Use completed Cryptex dictionary
- Map C functions to Rust equivalents
- Implement based on pseudocode
- Build Electron/Svelte UI
- Integrate Node-RED + redb

## 📊 Project Structure

```
.
├── mcp_server/          # MCP server implementation
│   ├── server.py        # Main MCP server
│   ├── api.py           # Direct API access
│   └── README.md
├── tools/               # Audit and analysis tools
│   ├── audit_agent.py  # Function analysis and Cryptex generation
│   └── README.md
├── data/                # Generated data
│   └── cryptex.json     # Cryptex dictionary (created by audit)
├── WORKFLOW.md          # SDLC workflow guide
├── QUICKSTART.md        # Quick start guide
└── PROJECT_STATUS.md    # This file
```

## 🚀 Next Steps

1. **Run Initial Audit**
   ```bash
   python tools/audit_agent.py --directory libyara --extensions .c
   ```

2. **Review Generated Entries**
   - Check `data/cryptex.json`
   - Verify function signatures
   - Review pseudocode quality

3. **Refine Entries**
   - Use `mcp_server/api.py` to update entries
   - Improve pseudocode where needed
   - Add missing dependencies

4. **Iterate**
   - Continue auditing remaining files
   - Run gap-audit to find unmapped functions
   - Achieve complete coverage

5. **Validate**
   - Ensure all functions mapped
   - Verify dependency resolution
   - Check line reference accuracy

## 🔧 Usage Examples

### Add/Update Cryptex Entry
```python
from mcp_server.api import annotate_entry

annotate_entry(
    symbol="yr_initialize",
    pyro_name="BlackFlag-Bootstrap",
    kind="function",
    location="libyara/include/yara/libyara.h",
    signature="YR_API int yr_initialize(void);",
    summary="Initializes libyara global state",
    pseudocode="if runtime_already_init: return OK\ninit_arenas()\ninit_modules()",
    line_references=[{"file": "libyara/libyara.c", "start": 100, "end": 150}],
    dependencies=[],
    owner="libyara/core",
    risk="critical"
)
```

### Lookup Entry
```python
from mcp_server.api import lookup_entry

entry = lookup_entry(symbol="yr_initialize")
# or
entry = lookup_entry(pyro_name="BlackFlag-Bootstrap")
```

### Get Statistics
```python
from mcp_server.api import get_stats

stats = get_stats()
print(f"Total entries: {stats['total_entries']}")
print(f"Functions: {stats['functions']}")
```

## 📝 Notes

- The MCP server can run with or without the MCP SDK
- The audit agent uses regex-based function extraction (can be enhanced with proper C parser)
- Cryptex dictionary is stored as JSON (can be migrated to redb later)
- All tools are designed for iterative SDLC cycles

## 🎓 Learning Resources

- Review `docs/CRYPTEX_DICTIONARY_SPEC.md` for naming conventions
- Check `docs/CRYPTEX_DICTIONARY_SEED.md` for example entries
- See `steering/MASTER_PLAN.md` for overall project vision

