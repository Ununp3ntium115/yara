# PYRO Platform MCP Server - Setup Guide

## Quick Start

### 1. Clone PYRO Platform Repository

```bash
# From YARA project root
git clone https://github.com/Ununp3ntium115/PYRO_Platform_Ignition.git pyro-platform

# If you encounter path issues:
cd pyro-platform
git config core.protectNTFS false
git restore --source=HEAD :/
```

### 2. Start MCP Server

```bash
# From YARA project root
python -m mcp_server_pyro.server
```

### 3. Use Integration Analyzer

```bash
# Generate integration report
python tools/pyro_integration_analyzer.py --report

# JSON output for programmatic use
python tools/pyro_integration_analyzer.py --json
```

## What the MCP Server Provides

### Resources

1. **PYRO Platform Source Code**
   - All Python, JavaScript, TypeScript, Rust files
   - Documentation files
   - Configuration files

2. **YARA Cryptex Dictionary**
   - Complete 587-entry dictionary
   - Function mappings
   - Pseudocode

3. **API Documentation**
   - API endpoint documentation
   - Integration guides
   - Component documentation

### Tools

1. **pyro-codebase-search** - Search codebase
2. **pyro-cryptex-lookup** - Look up Cryptex entries
3. **pyro-api-docs** - Get API docs
4. **pyro-integration-points** - Find integration points
5. **pyro-structure-analysis** - Analyze structure

## Integration Analysis

The integration analyzer helps you:

1. **Understand PYRO Platform**
   - Directory structure
   - File organization
   - Component layout

2. **Find YARA References**
   - Where YARA is used
   - How it's integrated
   - What components interact

3. **Map Cryptex to PYRO**
   - Match codenames to components
   - Identify integration points
   - Plan data flow

4. **API Endpoints**
   - Find existing endpoints
   - Plan new endpoints
   - Design integration

## Example Usage

### Python API

```python
from mcp_server_pyro.api import search_pyro_codebase, get_pyro_structure

# Search for YARA references
results = search_pyro_codebase("yara", file_type=".py")
print(f"Found {len(results)} files with YARA references")

# Get platform structure
structure = get_pyro_structure(max_depth=2)
print(f"Directories: {len(structure['directories'])}")
```

### MCP Tools

```python
from mcp_server_pyro.server import PyroPlatformMCPServer

server = PyroPlatformMCPServer()

# Search codebase
result = await server._codebase_search({
    "query": "yara",
    "file_type": "py"
})

# Find integration points
result = await server._integration_points({})
```

## Next Steps

1. **Complete Repository Clone**
   - Fix any git path issues
   - Verify all files are accessible

2. **Run Integration Analysis**
   - Generate full report
   - Identify all integration points
   - Map components

3. **Plan Integration**
   - Design API endpoints
   - Plan data flow
   - Map Cryptex to PYRO

4. **Implement Integration**
   - Add Cryptex endpoints
   - Integrate rule transcoder
   - Connect systems

## Files Created

- `mcp_server_pyro/server.py` - Main MCP server
- `mcp_server_pyro/api.py` - Direct API access
- `mcp_server_pyro/README.md` - Server documentation
- `tools/pyro_integration_analyzer.py` - Analysis tool
- `PYRO_INTEGRATION_PLAN.md` - Integration plan
- `PYRO_MCP_SETUP.md` - This file

The PYRO Platform MCP server is ready to help analyze and plan the integration!

