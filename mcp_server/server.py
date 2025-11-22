"""
MCP Server implementation for YARA codebase.
Exposes source files, rules, and Cryptex dictionary as MCP resources.

This is a simplified MCP-compatible server that can be extended with the official
MCP SDK when available, or used as a standalone service.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

# Try to import MCP SDK, fallback to basic implementation
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Resource, Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    # Create minimal type stubs
    class Resource:
        def __init__(self, uri, name, description, mimeType):
            self.uri = uri
            self.name = name
            self.description = description
            self.mimeType = mimeType
    
    class Tool:
        def __init__(self, name, description, inputSchema):
            self.name = name
            self.description = description
            self.inputSchema = inputSchema
    
    class TextContent:
        def __init__(self, type, text):
            self.type = type
            self.text = text

# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent
LIBYARA_DIR = PROJECT_ROOT / "libyara"
CLI_DIR = PROJECT_ROOT / "cli"
RULES_DIR = PROJECT_ROOT / "yara-rules"
CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class YaraMCPServer:
    """MCP Server for YARA codebase resources and tools."""
    
    def __init__(self):
        if MCP_AVAILABLE:
            self.server = Server("yara-mcp-server")
            self._setup_resources()
            self._setup_tools()
        else:
            self.server = None
        self._ensure_data_dir()
    
    def _ensure_data_dir(self):
        """Ensure data directory exists for Cryptex dictionary."""
        data_dir = PROJECT_ROOT / "data"
        data_dir.mkdir(exist_ok=True)
        if not CRYPTEX_FILE.exists():
            self._initialize_cryptex()
    
    def _initialize_cryptex(self):
        """Initialize empty Cryptex dictionary."""
        initial_data = {
            "version": "0.1.0",
            "entries": [],
            "metadata": {
                "total_functions": 0,
                "total_modules": 0,
                "last_updated": None
            }
        }
        with open(CRYPTEX_FILE, 'w') as f:
            json.dump(initial_data, f, indent=2)
    
    def _setup_resources(self):
        """Register MCP resource providers."""
        
        @self.server.list_resources()
        async def list_resources() -> List[Resource]:
            """List all available YARA resources."""
            resources = []
            
            # Source code resources
            for pattern in ["**/*.c", "**/*.h", "**/*.y", "**/*.l"]:
                for path in LIBYARA_DIR.rglob(pattern):
                    rel_path = path.relative_to(PROJECT_ROOT)
                    resources.append(Resource(
                        uri=f"yara://source/{rel_path.as_posix()}",
                        name=f"YARA Source: {rel_path}",
                        description=f"Source file: {rel_path}",
                        mimeType="text/x-c"
                    ))
            
            # CLI resources
            for path in CLI_DIR.rglob("*.c"):
                rel_path = path.relative_to(PROJECT_ROOT)
                resources.append(Resource(
                    uri=f"yara://cli/{rel_path.as_posix()}",
                    name=f"YARA CLI: {rel_path}",
                    description=f"CLI source: {rel_path}",
                    mimeType="text/x-c"
                ))
            
            # Rules resources
            if RULES_DIR.exists():
                for path in RULES_DIR.rglob("*.yar"):
                    rel_path = path.relative_to(PROJECT_ROOT)
                    resources.append(Resource(
                        uri=f"yara://rules/{rel_path.as_posix()}",
                        name=f"YARA Rule: {rel_path.name}",
                        description=f"YARA rule file: {rel_path}",
                        mimeType="text/x-yara"
                    ))
            
            # Cryptex dictionary
            if CRYPTEX_FILE.exists():
                resources.append(Resource(
                    uri="yara://cryptex/dictionary",
                    name="Cryptex Dictionary",
                    description="Complete Cryptex dictionary with all function mappings",
                    mimeType="application/json"
                ))
            
            return resources
        
        @self.server.read_resource()
        async def read_resource(uri: str) -> str:
            """Read a resource by URI."""
            if uri.startswith("yara://source/"):
                rel_path = uri.replace("yara://source/", "")
                file_path = PROJECT_ROOT / rel_path
                if file_path.exists():
                    return file_path.read_text(encoding='utf-8', errors='ignore')
            
            elif uri.startswith("yara://cli/"):
                rel_path = uri.replace("yara://cli/", "")
                file_path = PROJECT_ROOT / rel_path
                if file_path.exists():
                    return file_path.read_text(encoding='utf-8', errors='ignore')
            
            elif uri.startswith("yara://rules/"):
                rel_path = uri.replace("yara://rules/", "")
                file_path = PROJECT_ROOT / rel_path
                if file_path.exists():
                    return file_path.read_text(encoding='utf-8', errors='ignore')
            
            elif uri == "yara://cryptex/dictionary":
                if CRYPTEX_FILE.exists():
                    return CRYPTEX_FILE.read_text(encoding='utf-8')
            
            raise ValueError(f"Resource not found: {uri}")
    
    def _setup_tools(self):
        """Register MCP tools for agent interaction."""
        
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """List available tools."""
            return [
                Tool(
                    name="cryptex-annotate",
                    description="Add or update a Cryptex dictionary entry with function details, branded name, pseudocode, and line references",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "symbol": {"type": "string", "description": "YARA function/symbol name"},
                            "pyro_name": {"type": "string", "description": "Branded anarchist codename"},
                            "kind": {"type": "string", "enum": ["function", "struct", "module", "cli", "rule", "script"], "description": "Type of symbol"},
                            "location": {"type": "string", "description": "File path relative to project root"},
                            "signature": {"type": "string", "description": "Function signature or declaration"},
                            "summary": {"type": "string", "description": "What the function does (≤160 chars)"},
                            "pseudocode": {"type": "string", "description": "Pseudocode example showing how it works"},
                            "line_references": {"type": "array", "items": {"type": "object", "properties": {"file": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}}}, "description": "Line number references"},
                            "dependencies": {"type": "array", "items": {"type": "string"}, "description": "List of other Cryptex pyro_name values"},
                            "owner": {"type": "string", "description": "Component/team label"},
                            "risk": {"type": "string", "enum": ["critical", "high", "standard", "informational"]},
                            "notes": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["symbol", "pyro_name", "kind", "location", "summary", "pseudocode"]
                    }
                ),
                Tool(
                    name="function-discovery",
                    description="Discover and analyze functions in YARA source files, extracting signatures and context",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "Path to source file to analyze"},
                            "function_name": {"type": "string", "description": "Optional: specific function to find"}
                        },
                        "required": ["file_path"]
                    }
                ),
                Tool(
                    name="gap-audit",
                    description="Audit codebase to find functions/modules not yet in Cryptex dictionary",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "directory": {"type": "string", "description": "Directory to audit (default: libyara)"},
                            "extensions": {"type": "array", "items": {"type": "string"}, "description": "File extensions to analyze"}
                        }
                    }
                ),
                Tool(
                    name="cryptex-lookup",
                    description="Look up a Cryptex entry by symbol or pyro_name",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "symbol": {"type": "string", "description": "YARA symbol name"},
                            "pyro_name": {"type": "string", "description": "Branded codename"}
                        }
                    }
                )
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Execute a tool."""
            if name == "cryptex-annotate":
                return await self._cryptex_annotate(arguments)
            elif name == "function-discovery":
                return await self._function_discovery(arguments)
            elif name == "gap-audit":
                return await self._gap_audit(arguments)
            elif name == "cryptex-lookup":
                return await self._cryptex_lookup(arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
    
    async def _cryptex_annotate(self, args: Dict[str, Any]) -> List[TextContent]:
        """Add or update Cryptex dictionary entry."""
        # Load existing dictionary
        if CRYPTEX_FILE.exists():
            with open(CRYPTEX_FILE, 'r') as f:
                data = json.load(f)
        else:
            data = {"version": "0.1.0", "entries": [], "metadata": {"total_functions": 0, "total_modules": 0}}
        
        entry = {
            "symbol": args["symbol"],
            "pyro_name": args["pyro_name"],
            "kind": args["kind"],
            "location": args["location"],
            "signature": args.get("signature", ""),
            "summary": args["summary"],
            "pseudocode": args["pseudocode"],
            "line_references": args.get("line_references", []),
            "dependencies": args.get("dependencies", []),
            "owner": args.get("owner", "libyara/core"),
            "risk": args.get("risk", "standard"),
            "notes": args.get("notes", [])
        }
        
        # Update or add entry
        existing_idx = None
        for i, e in enumerate(data["entries"]):
            if e["symbol"] == entry["symbol"]:
                existing_idx = i
                break
        
        if existing_idx is not None:
            data["entries"][existing_idx] = entry
            action = "updated"
        else:
            data["entries"].append(entry)
            action = "added"
        
        # Update metadata
        data["metadata"]["total_functions"] = len([e for e in data["entries"] if e["kind"] == "function"])
        data["metadata"]["total_modules"] = len([e for e in data["entries"] if e["kind"] == "module"])
        from datetime import datetime
        data["metadata"]["last_updated"] = datetime.utcnow().isoformat()
        
        # Save
        with open(CRYPTEX_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        
        return [TextContent(
            type="text",
            text=f"✓ Cryptex entry {action}: {entry['pyro_name']} ({entry['symbol']})"
        )]
    
    async def _function_discovery(self, args: Dict[str, Any]) -> List[TextContent]:
        """Discover functions in a source file."""
        file_path = PROJECT_ROOT / args["file_path"]
        if not file_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        lines = content.split('\n')
        
        # Simple C function detection (can be enhanced)
        functions = []
        in_function = False
        function_start = None
        function_name = None
        brace_count = 0
        
        for i, line in enumerate(lines, 1):
            # Look for function definitions
            if not in_function:
                # Match: return_type function_name(...) {
                import re
                match = re.search(r'^\s*(\w+\s+)*(\w+)\s*\([^)]*\)\s*\{', line)
                if match:
                    function_name = match.group(2) if match.lastindex >= 2 else None
                    if function_name and (not args.get("function_name") or function_name == args["function_name"]):
                        in_function = True
                        function_start = i
                        brace_count = 1
            else:
                brace_count += line.count('{') - line.count('}')
                if brace_count == 0:
                    functions.append({
                        "name": function_name,
                        "start_line": function_start,
                        "end_line": i,
                        "signature": lines[function_start - 1].strip()
                    })
                    in_function = False
        
        result = f"Found {len(functions)} function(s) in {args['file_path']}:\n\n"
        for func in functions:
            result += f"Function: {func['name']}\n"
            result += f"  Lines: {func['start_line']}-{func['end_line']}\n"
            result += f"  Signature: {func['signature']}\n\n"
        
        return [TextContent(type="text", text=result)]
    
    async def _gap_audit(self, args: Dict[str, Any]) -> List[TextContent]:
        """Audit codebase for unmapped functions."""
        directory = args.get("directory", "libyara")
        extensions = args.get("extensions", [".c", ".h"])
        
        audit_dir = PROJECT_ROOT / directory
        if not audit_dir.exists():
            return [TextContent(type="text", text=f"Error: Directory not found: {directory}")]
        
        # Load existing Cryptex entries
        if CRYPTEX_FILE.exists():
            with open(CRYPTEX_FILE, 'r') as f:
                cryptex_data = json.load(f)
            mapped_symbols = {e["symbol"] for e in cryptex_data.get("entries", [])}
        else:
            mapped_symbols = set()
        
        # Find all source files
        unmapped = []
        for ext in extensions:
            for path in audit_dir.rglob(f"*{ext}"):
                rel_path = path.relative_to(PROJECT_ROOT)
                # Simple function extraction (would need proper C parser for production)
                content = path.read_text(encoding='utf-8', errors='ignore')
                import re
                # Match function definitions
                for match in re.finditer(r'^\s*(\w+\s+)*(\w+)\s*\([^)]*\)\s*\{', content, re.MULTILINE):
                    func_name = match.group(2) if match.lastindex >= 2 else None
                    if func_name and func_name not in mapped_symbols:
                        unmapped.append({
                            "symbol": func_name,
                            "file": str(rel_path),
                            "line": content[:match.start()].count('\n') + 1
                        })
        
        result = f"Gap Audit Results for {directory}:\n"
        result += f"Total unmapped functions: {len(unmapped)}\n\n"
        for item in unmapped[:50]:  # Limit output
            result += f"  {item['symbol']} in {item['file']}:{item['line']}\n"
        
        if len(unmapped) > 50:
            result += f"\n... and {len(unmapped) - 50} more\n"
        
        return [TextContent(type="text", text=result)]
    
    async def _cryptex_lookup(self, args: Dict[str, Any]) -> List[TextContent]:
        """Look up Cryptex entry."""
        if not CRYPTEX_FILE.exists():
            return [TextContent(type="text", text="Cryptex dictionary not found")]
        
        with open(CRYPTEX_FILE, 'r') as f:
            data = json.load(f)
        
        symbol = args.get("symbol")
        pyro_name = args.get("pyro_name")
        
        for entry in data.get("entries", []):
            if (symbol and entry["symbol"] == symbol) or (pyro_name and entry["pyro_name"] == pyro_name):
                result = json.dumps(entry, indent=2)
                return [TextContent(type="text", text=result)]
        
        return [TextContent(type="text", text="Entry not found")]
    
    async def run(self):
        """Run the MCP server."""
        if MCP_AVAILABLE and self.server:
            async with stdio_server() as (read_stream, write_stream):
                await self.server.run(
                    read_stream,
                    write_stream,
                    self.server.create_initialization_options()
                )
        else:
            # Fallback: run as simple service
            print("MCP SDK not available. Running in standalone mode.")
            print("Use the tools directly via Python API or install mcp package.")
            # Keep running for direct API access
            while True:
                await asyncio.sleep(1)


async def main():
    """Main entry point."""
    server = YaraMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())

