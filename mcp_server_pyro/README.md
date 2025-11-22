# PYRO Platform Ignition MCP Server

MCP server that exposes the PYRO Platform Ignition codebase, YARA Cryptex dictionary, and API documentation for integration analysis.

## Purpose

This MCP server provides access to:
1. **PYRO Platform Codebase** - All source files, documentation, and structure
2. **YARA Cryptex Dictionary** - Complete function mapping (587 entries)
3. **API Documentation** - Integration points and API references
4. **Integration Analysis** - Tools to find how YARA Cryptex integrates with PYRO Platform

## Setup

### 1. Clone PYRO Platform Repository

```bash
git clone https://github.com/Ununp3ntium115/PYRO_Platform_Ignition.git pyro-platform
```

Note: If you encounter path issues with special characters, you may need to:
```bash
cd pyro-platform
git config core.protectNTFS false
git restore --source=HEAD :/
```

### 2. Install Dependencies

```bash
pip install -r mcp_server_pyro/requirements.txt
```

### 3. Start MCP Server

```bash
python -m mcp_server_pyro.server
```

## Available Resources

### PYRO Platform Source
- `pyro://source/**/*.py` - Python source files
- `pyro://source/**/*.js` - JavaScript files
- `pyro://source/**/*.ts` - TypeScript files
- `pyro://source/**/*.rs` - Rust files
- `pyro://source/**/*.md` - Documentation

### YARA Cryptex Dictionary
- `pyro://cryptex/yara-dictionary` - Complete Cryptex dictionary (587 entries)

### API Documentation
- `pyro://docs/**/*.md` - API and documentation files

## Available Tools

### 1. pyro-codebase-search
Search PYRO Platform codebase for functions, classes, or patterns.

```python
{
  "query": "yara",
  "file_type": "py",
  "directory": "src"
}
```

### 2. pyro-cryptex-lookup
Look up YARA Cryptex entries.

```python
{
  "symbol": "yr_initialize",
  # or
  "pyro_name": "BlackFlag-Bootstrap-Initialize"
}
```

### 3. pyro-api-docs
Get API documentation.

```python
{
  "endpoint": "scan",
  "component": "yara"
}
```

### 4. pyro-integration-points
Find integration points between PYRO Platform and YARA Cryptex.

```python
{
  "component": "scanner"
}
```

### 5. pyro-structure-analysis
Analyze PYRO Platform structure.

```python
{
  "depth": 2
}
```

## Integration Analysis

### Finding Integration Points

Use the `pyro-integration-points` tool to discover:
- Where YARA is referenced in PYRO Platform
- How Cryptex codenames are used
- API endpoints that interact with YARA
- Component dependencies

### Codebase Search

Search for YARA-related code:
```python
# Search for YARA references
{
  "query": "yara",
  "file_type": "py"
}

# Search for Cryptex references
{
  "query": "cryptex",
  "file_type": "py"
}
```

## Usage Examples

### Python API

```python
from mcp_server_pyro.server import PyroPlatformMCPServer
import asyncio

async def example():
    server = PyroPlatformMCPServer()
    
    # Search codebase
    result = await server._codebase_search({
        "query": "yara",
        "file_type": "py"
    })
    print(result[0].text)
    
    # Look up Cryptex entry
    result = await server._cryptex_lookup({
        "symbol": "yr_initialize"
    })
    print(result[0].text)

asyncio.run(example())
```

### Command Line

```bash
# Start server
python -m mcp_server_pyro.server

# Use with MCP client
# (Connect via stdio or WebSocket)
```

## Integration with YARA Cryptex

The MCP server provides seamless access to:
- YARA Cryptex dictionary (587 entries)
- PYRO Platform codebase
- Integration analysis tools
- API documentation

This allows agents and tools to:
1. Understand PYRO Platform architecture
2. Find where YARA Cryptex integrates
3. Map Cryptex codenames to PYRO components
4. Plan integration strategies

## Next Steps

1. **Analyze PYRO Platform Structure**
   - Understand architecture
   - Identify components
   - Map dependencies

2. **Find Integration Points**
   - Where YARA is used
   - How to integrate Cryptex
   - API endpoints needed

3. **Plan Integration**
   - Map Cryptex to PYRO components
   - Design API integration
   - Plan data flow

4. **Implement Integration**
   - Add Cryptex endpoints
   - Integrate rule transcoder
   - Connect MCP servers

## Notes

- The server works with or without MCP SDK
- PYRO Platform directory must be cloned first
- Cryptex dictionary is automatically loaded
- All tools are async for performance

