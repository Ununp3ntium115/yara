# YARA MCP Server

Model Context Protocol server that exposes the YARA codebase, rules, and Cryptex dictionary for agent-based analysis.

## Features

- **Resource Providers**: Expose all YARA source files, headers, rules, and documentation
- **Cryptex Dictionary**: Access and update the anarchist codename mapping
- **Agent Tools**: Tools for function discovery, gap auditing, and dictionary annotation

## Installation

```bash
pip install -r mcp_server/requirements.txt
```

## Usage

### Start the MCP Server

```bash
python -m mcp_server.server
```

The server communicates via stdio using the MCP protocol.

### Available Resources

- `yara://source/*` - All YARA source files (.c, .h, .y, .l)
- `yara://cli/*` - CLI source files
- `yara://rules/*` - YARA rule files
- `yara://cryptex/dictionary` - Complete Cryptex dictionary

### Available Tools

1. **cryptex-annotate** - Add or update Cryptex dictionary entries
2. **function-discovery** - Discover functions in source files
3. **gap-audit** - Find unmapped functions in codebase
4. **cryptex-lookup** - Look up entries by symbol or codename

## Integration

The MCP server can be used with:
- Claude Desktop (via MCP configuration)
- Custom agents and automation
- Node-RED flows (via HTTP gateway, future)
- Rust services (via MCP client, future)

## Cryptex Dictionary Format

Each entry contains:
- `symbol` - Original YARA function/symbol name
- `pyro_name` - Branded anarchist codename
- `kind` - Type (function, struct, module, etc.)
- `location` - File path
- `signature` - Function signature
- `summary` - What it does (≤160 chars)
- `pseudocode` - Pseudocode example
- `line_references` - Line number ranges
- `dependencies` - Related symbols
- `owner` - Component/team
- `risk` - Criticality level
- `notes` - Additional notes

