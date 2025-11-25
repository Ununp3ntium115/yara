#!/usr/bin/env python3
"""
R-YARA MCP Server
Model Context Protocol server exposing R-YARA capabilities for PYRO Platform integration.

This server provides:
- Dictionary lookup and management
- Feed scanning for YARA rules
- Rule transcoding and validation
- Streaming rule support for workers

Designed to integrate with PYRO Platform Ignition.
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

class RYaraMCPServer:
    """R-YARA Model Context Protocol Server"""

    def __init__(self, data_dir: str = "data", rust_bin_dir: str = "rust/target/release"):
        self.data_dir = Path(data_dir)
        self.rust_bin_dir = Path(rust_bin_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Server info
        self.name = "r-yara-mcp"
        self.version = "0.1.0"
        self.capabilities = {
            "resources": True,
            "tools": True,
            "prompts": True,
        }

        # Resource definitions
        self.resources = {
            "r-yara://dictionary": {
                "name": "R-YARA Dictionary",
                "description": "Complete R-YARA function mapping dictionary",
                "mimeType": "application/json",
            },
            "r-yara://rules/*": {
                "name": "YARA Rules",
                "description": "YARA rule files from feeds and local storage",
                "mimeType": "text/plain",
            },
            "r-yara://config": {
                "name": "R-YARA Configuration",
                "description": "Server configuration and status",
                "mimeType": "application/json",
            },
        }

        # Tool definitions for PYRO Platform integration
        self.tools = {
            "r-yara-lookup": {
                "name": "r-yara-lookup",
                "description": "Look up a symbol or codename in the R-YARA dictionary",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Symbol or codename to look up"
                        }
                    },
                    "required": ["query"]
                }
            },
            "r-yara-search": {
                "name": "r-yara-search",
                "description": "Search the R-YARA dictionary",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum results to return",
                            "default": 20
                        }
                    },
                    "required": ["query"]
                }
            },
            "r-yara-scan-feeds": {
                "name": "r-yara-scan-feeds",
                "description": "Scan web feeds for new YARA rules",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "use_case": {
                            "type": "string",
                            "enum": ["all", "malware", "apt", "ransomware", "new_tasks", "old_tasks"],
                            "description": "Type of rules to scan for",
                            "default": "all"
                        }
                    }
                }
            },
            "r-yara-validate-rule": {
                "name": "r-yara-validate-rule",
                "description": "Validate a YARA rule syntax",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rule_content": {
                            "type": "string",
                            "description": "YARA rule content to validate"
                        }
                    },
                    "required": ["rule_content"]
                }
            },
            "r-yara-transcode": {
                "name": "r-yara-transcode",
                "description": "Transcode a YARA rule to use R-YARA codenames",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rule_content": {
                            "type": "string",
                            "description": "YARA rule content to transcode"
                        },
                        "direction": {
                            "type": "string",
                            "enum": ["to_codename", "from_codename"],
                            "description": "Direction of transcoding",
                            "default": "to_codename"
                        }
                    },
                    "required": ["rule_content"]
                }
            },
            "r-yara-stream-rules": {
                "name": "r-yara-stream-rules",
                "description": "Stream YARA rules for worker processing",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source": {
                            "type": "string",
                            "description": "Source of rules (feed URL, file path, or 'all')",
                            "default": "all"
                        },
                        "format": {
                            "type": "string",
                            "enum": ["json", "yara", "binary"],
                            "description": "Output format for streaming",
                            "default": "json"
                        }
                    }
                }
            },
            "r-yara-stats": {
                "name": "r-yara-stats",
                "description": "Get R-YARA dictionary and system statistics",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
        }

        # Prompt templates for PYRO integration
        self.prompts = {
            "analyze-malware": {
                "name": "analyze-malware",
                "description": "Analyze a file for malware using R-YARA rules",
                "arguments": [
                    {"name": "file_path", "description": "Path to file to analyze", "required": True}
                ]
            },
            "generate-rule": {
                "name": "generate-rule",
                "description": "Generate a YARA rule for a specific threat",
                "arguments": [
                    {"name": "threat_name", "description": "Name of the threat", "required": True},
                    {"name": "indicators", "description": "Known indicators (strings, hashes, etc.)", "required": True}
                ]
            },
        }

    async def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP initialize request"""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": self.capabilities,
            "serverInfo": {
                "name": self.name,
                "version": self.version,
            }
        }

    async def handle_list_resources(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List available resources"""
        resources = []
        for uri, info in self.resources.items():
            resources.append({
                "uri": uri,
                "name": info["name"],
                "description": info["description"],
                "mimeType": info["mimeType"],
            })
        return {"resources": resources}

    async def handle_read_resource(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Read a specific resource"""
        uri = params.get("uri", "")

        if uri == "r-yara://dictionary":
            return await self._read_dictionary()
        elif uri == "r-yara://config":
            return await self._read_config()
        elif uri.startswith("r-yara://rules/"):
            rule_name = uri.replace("r-yara://rules/", "")
            return await self._read_rule(rule_name)
        else:
            return {"error": f"Unknown resource: {uri}"}

    async def handle_list_tools(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List available tools"""
        tools = []
        for name, info in self.tools.items():
            tools.append({
                "name": info["name"],
                "description": info["description"],
                "inputSchema": info["inputSchema"],
            })
        return {"tools": tools}

    async def handle_call_tool(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool"""
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        handlers = {
            "r-yara-lookup": self._tool_lookup,
            "r-yara-search": self._tool_search,
            "r-yara-scan-feeds": self._tool_scan_feeds,
            "r-yara-validate-rule": self._tool_validate_rule,
            "r-yara-transcode": self._tool_transcode,
            "r-yara-stream-rules": self._tool_stream_rules,
            "r-yara-stats": self._tool_stats,
        }

        handler = handlers.get(tool_name)
        if handler:
            return await handler(arguments)
        else:
            return {"error": f"Unknown tool: {tool_name}"}

    async def handle_list_prompts(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List available prompts"""
        prompts = []
        for name, info in self.prompts.items():
            prompts.append({
                "name": info["name"],
                "description": info["description"],
                "arguments": info["arguments"],
            })
        return {"prompts": prompts}

    # Resource handlers
    async def _read_dictionary(self) -> Dict[str, Any]:
        """Read the R-YARA dictionary"""
        dict_file = self.data_dir / "cryptex.json"
        if dict_file.exists():
            with open(dict_file) as f:
                data = json.load(f)
            return {
                "contents": [{
                    "uri": "r-yara://dictionary",
                    "mimeType": "application/json",
                    "text": json.dumps(data, indent=2)
                }]
            }
        return {
            "contents": [{
                "uri": "r-yara://dictionary",
                "mimeType": "application/json",
                "text": json.dumps({"entries": [], "metadata": {"status": "empty"}})
            }]
        }

    async def _read_config(self) -> Dict[str, Any]:
        """Read server configuration"""
        config = {
            "server": {
                "name": self.name,
                "version": self.version,
            },
            "paths": {
                "data_dir": str(self.data_dir),
                "rust_bin_dir": str(self.rust_bin_dir),
            },
            "capabilities": self.capabilities,
            "endpoints": {
                "dictionary": "/api/v2/r-yara/dictionary/*",
                "feed": "/api/v2/r-yara/feed/*",
                "scan": "/api/v2/r-yara/scan/*",
                "stream": "/api/v2/r-yara/stream/*",
            },
            "status": "ready",
            "timestamp": datetime.utcnow().isoformat(),
        }
        return {
            "contents": [{
                "uri": "r-yara://config",
                "mimeType": "application/json",
                "text": json.dumps(config, indent=2)
            }]
        }

    async def _read_rule(self, rule_name: str) -> Dict[str, Any]:
        """Read a specific YARA rule"""
        rules_dir = self.data_dir / "rules"
        rule_file = rules_dir / f"{rule_name}.yar"

        if rule_file.exists():
            with open(rule_file) as f:
                content = f.read()
            return {
                "contents": [{
                    "uri": f"r-yara://rules/{rule_name}",
                    "mimeType": "text/plain",
                    "text": content
                }]
            }
        return {"error": f"Rule not found: {rule_name}"}

    # Tool handlers
    async def _tool_lookup(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Look up a dictionary entry"""
        query = args.get("query", "")
        dict_file = self.data_dir / "cryptex.json"

        if dict_file.exists():
            with open(dict_file) as f:
                data = json.load(f)

            entries = data.get("entries", [])
            for entry in entries:
                if entry.get("symbol") == query or entry.get("pyro_name") == query:
                    return {
                        "content": [{
                            "type": "text",
                            "text": json.dumps(entry, indent=2)
                        }]
                    }

        return {
            "content": [{
                "type": "text",
                "text": f"No entry found for: {query}"
            }]
        }

    async def _tool_search(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Search dictionary entries"""
        query = args.get("query", "").lower()
        limit = args.get("limit", 20)
        dict_file = self.data_dir / "cryptex.json"

        results = []
        if dict_file.exists():
            with open(dict_file) as f:
                data = json.load(f)

            entries = data.get("entries", [])
            for entry in entries:
                if (query in entry.get("symbol", "").lower() or
                    query in entry.get("pyro_name", "").lower() or
                    query in entry.get("summary", "").lower()):
                    results.append(entry)
                    if len(results) >= limit:
                        break

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "query": query,
                    "count": len(results),
                    "results": results
                }, indent=2)
            }]
        }

    async def _tool_scan_feeds(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan feeds for YARA rules"""
        use_case = args.get("use_case", "all")

        # Try to use Rust binary if available
        rust_bin = self.rust_bin_dir / "r-yara-feed"
        if rust_bin.exists():
            import subprocess
            try:
                result = subprocess.run(
                    [str(rust_bin), use_case, "--output", "/tmp/scan_results.json"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if Path("/tmp/scan_results.json").exists():
                    with open("/tmp/scan_results.json") as f:
                        rules = json.load(f)
                    return {
                        "content": [{
                            "type": "text",
                            "text": json.dumps({
                                "use_case": use_case,
                                "rules_found": len(rules),
                                "rules": rules[:10]  # First 10 rules
                            }, indent=2)
                        }]
                    }
            except Exception as e:
                pass

        # Fallback response
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "use_case": use_case,
                    "status": "rust_binary_not_available",
                    "message": "Build with: cd rust && cargo build --release"
                }, indent=2)
            }]
        }

    async def _tool_validate_rule(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Validate YARA rule syntax"""
        rule_content = args.get("rule_content", "")

        # Basic validation
        errors = []
        if "rule " not in rule_content:
            errors.append("Missing 'rule' keyword")
        if "condition:" not in rule_content:
            errors.append("Missing 'condition:' section")
        if "{" not in rule_content or "}" not in rule_content:
            errors.append("Missing rule body braces")

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "valid": len(errors) == 0,
                    "errors": errors,
                    "rule_preview": rule_content[:200] + "..." if len(rule_content) > 200 else rule_content
                }, indent=2)
            }]
        }

    async def _tool_transcode(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Transcode YARA rule to/from codenames"""
        rule_content = args.get("rule_content", "")
        direction = args.get("direction", "to_codename")

        # Load dictionary for transcoding
        dict_file = self.data_dir / "cryptex.json"
        mappings = {}

        if dict_file.exists():
            with open(dict_file) as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                if direction == "to_codename":
                    mappings[entry.get("symbol", "")] = entry.get("pyro_name", "")
                else:
                    mappings[entry.get("pyro_name", "")] = entry.get("symbol", "")

        # Simple transcoding (replace known symbols)
        transcoded = rule_content
        for old, new in mappings.items():
            if old and new:
                transcoded = transcoded.replace(old, new)

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "direction": direction,
                    "original_length": len(rule_content),
                    "transcoded_length": len(transcoded),
                    "transcoded": transcoded
                }, indent=2)
            }]
        }

    async def _tool_stream_rules(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Stream rules for worker processing"""
        source = args.get("source", "all")
        format = args.get("format", "json")

        # This would connect to the streaming API
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "stream_endpoint": f"/api/v2/r-yara/stream/rules?source={source}&format={format}",
                    "protocol": "websocket",
                    "message_format": {
                        "type": "enum",
                        "values": ["rule_start", "rule_chunk", "rule_end", "match", "error", "heartbeat"]
                    },
                    "status": "ready"
                }, indent=2)
            }]
        }

    async def _tool_stats(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get system statistics"""
        dict_file = self.data_dir / "cryptex.json"

        stats = {
            "dictionary": {
                "total_entries": 0,
                "functions": 0,
                "modules": 0,
            },
            "system": {
                "rust_available": (self.rust_bin_dir / "r-yara").exists(),
                "api_available": (self.rust_bin_dir / "r-yara-server").exists(),
                "feed_scanner_available": (self.rust_bin_dir / "r-yara-feed").exists(),
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

        if dict_file.exists():
            with open(dict_file) as f:
                data = json.load(f)
            entries = data.get("entries", [])
            stats["dictionary"]["total_entries"] = len(entries)
            stats["dictionary"]["functions"] = sum(1 for e in entries if e.get("kind") == "function")
            stats["dictionary"]["modules"] = sum(1 for e in entries if e.get("kind") == "module")

        return {
            "content": [{
                "type": "text",
                "text": json.dumps(stats, indent=2)
            }]
        }

    async def run_stdio(self):
        """Run server using stdio transport"""
        import sys

        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                request = json.loads(line)
                method = request.get("method", "")
                params = request.get("params", {})
                request_id = request.get("id")

                handlers = {
                    "initialize": self.handle_initialize,
                    "resources/list": self.handle_list_resources,
                    "resources/read": self.handle_read_resource,
                    "tools/list": self.handle_list_tools,
                    "tools/call": self.handle_call_tool,
                    "prompts/list": self.handle_list_prompts,
                }

                handler = handlers.get(method)
                if handler:
                    result = await handler(params)
                    response = {"jsonrpc": "2.0", "id": request_id, "result": result}
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32601, "message": f"Unknown method: {method}"}
                    }

                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()

            except json.JSONDecodeError:
                continue
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.stderr.flush()


def run_server():
    """Entry point for running the MCP server"""
    server = RYaraMCPServer()
    asyncio.run(server.run_stdio())


if __name__ == "__main__":
    run_server()
