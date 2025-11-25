# R-YARA MCP Server

Model Context Protocol server for R-YARA integration with PYRO Platform Ignition.

## Features

### Resources
- `r-yara://dictionary` - Complete R-YARA function mapping dictionary
- `r-yara://rules/*` - YARA rule files
- `r-yara://config` - Server configuration and status

### Tools

| Tool | Description |
|------|-------------|
| `r-yara-lookup` | Look up symbol or codename in dictionary |
| `r-yara-search` | Search dictionary entries |
| `r-yara-scan-feeds` | Scan web feeds for YARA rules |
| `r-yara-validate-rule` | Validate YARA rule syntax |
| `r-yara-transcode` | Transcode rules to/from codenames |
| `r-yara-stream-rules` | Stream rules for worker processing |
| `r-yara-stats` | Get system statistics |

### Prompts
- `analyze-malware` - Analyze file for malware using R-YARA rules
- `generate-rule` - Generate YARA rule for specific threat

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Start MCP Server (stdio)

```bash
python -m mcp_server_ryara.server
```

### Claude Desktop Configuration

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "r-yara": {
      "command": "python",
      "args": ["-m", "mcp_server_ryara.server"],
      "cwd": "/path/to/yara"
    }
  }
}
```

## API Endpoints (via R-YARA API Server)

When integrated with PYRO Platform, the following endpoints are available:

```
# Dictionary
GET  /api/v2/r-yara/dictionary/lookup?query=<symbol>
GET  /api/v2/r-yara/dictionary/search?q=<query>
GET  /api/v2/r-yara/dictionary/stats

# Feed Scanning
POST /api/v2/r-yara/feed/scan/all
POST /api/v2/r-yara/feed/scan/malware
POST /api/v2/r-yara/feed/scan/apt
POST /api/v2/r-yara/feed/scan/ransomware

# Streaming (WebSocket)
WS   /api/v2/r-yara/stream/rules
WS   /api/v2/r-yara/stream/worker
```

## PYRO Platform Integration

This MCP server is designed to integrate with PYRO Platform Ignition:

1. **Import R-YARA as submodule** in PYRO Platform
2. **Configure MCP server** in platform settings
3. **Use R-YARA tools** from platform agents
4. **Stream rules** to platform workers

### Integration Points

| PYRO Component | R-YARA Feature |
|----------------|----------------|
| Scanner Engine | Rule streaming, validation |
| Dictionary Service | Codename lookup, search |
| Worker Queue | Task distribution via WebSocket |
| Analytics | Statistics, metadata |

## Development

```bash
# Run tests
python -m pytest tests/

# Check types
mypy mcp_server_ryara/

# Format code
black mcp_server_ryara/
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PYRO Platform Ignition                   │
├─────────────────────────────────────────────────────────────┤
│                           MCP                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              R-YARA MCP Server                       │   │
│  │  ┌─────────┐ ┌─────────┐ ┌──────────────────────┐  │   │
│  │  │Resources│ │  Tools  │ │      Prompts         │  │   │
│  │  └────┬────┘ └────┬────┘ └──────────┬───────────┘  │   │
│  └───────┼───────────┼─────────────────┼──────────────┘   │
│          │           │                 │                   │
├──────────┼───────────┼─────────────────┼───────────────────┤
│          ▼           ▼                 ▼                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  R-YARA Rust Backend                 │   │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────────────┐  │   │
│  │  │r-yara-cli │ │r-yara-api │ │r-yara-feed-scanner│  │   │
│  │  └─────┬─────┘ └─────┬─────┘ └─────────┬─────────┘  │   │
│  │        └─────────────┼─────────────────┘            │   │
│  │                      ▼                              │   │
│  │              ┌───────────────┐                      │   │
│  │              │ r-yara-store  │                      │   │
│  │              │    (redb)     │                      │   │
│  │              └───────────────┘                      │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## License

Apache-2.0
