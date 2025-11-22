"""
MCP Server for PYRO Platform Ignition
Exposes codebase, Cryptex dictionary, and API documentation.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

# Try to import MCP SDK
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Resource, Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
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

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
PYRO_PLATFORM_DIR = PROJECT_ROOT / "pyro-platform"
YARA_CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')

# Use workspace path if available
if (WORKSPACE / "data" / "cryptex.json").exists():
    YARA_CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
    PROJECT_ROOT = WORKSPACE


class PyroPlatformMCPServer:
    """MCP Server for PYRO Platform Ignition."""
    
    def __init__(self):
        if MCP_AVAILABLE:
            self.server = Server("pyro-platform-mcp-server")
            self._setup_resources()
            self._setup_tools()
        else:
            self.server = None
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Ensure required directories exist."""
        if not PYRO_PLATFORM_DIR.exists():
            print(f"Warning: PYRO Platform directory not found: {PYRO_PLATFORM_DIR}")
            print("Clone it with: git clone https://github.com/Ununp3ntium115/PYRO_Platform_Ignition.git pyro-platform")
    
    def _setup_resources(self):
        """Register MCP resource providers."""
        
        @self.server.list_resources()
        async def list_resources() -> List[Resource]:
            """List all available PYRO Platform resources."""
            resources = []
            
            # PYRO Platform source code
            if PYRO_PLATFORM_DIR.exists():
                for pattern in ["**/*.py", "**/*.js", "**/*.ts", "**/*.rs", "**/*.md", "**/*.json"]:
                    try:
                        for path in PYRO_PLATFORM_DIR.rglob(pattern):
                            if path.is_file():
                                rel_path = path.relative_to(PYRO_PLATFORM_DIR)
                                mime_type = self._get_mime_type(path.suffix)
                                resources.append(Resource(
                                    uri=f"pyro://source/{rel_path.as_posix()}",
                                    name=f"PYRO: {rel_path.name}",
                                    description=f"PYRO Platform source: {rel_path}",
                                    mimeType=mime_type
                                ))
                    except Exception as e:
                        pass
            
            # YARA Cryptex Dictionary
            if YARA_CRYPTEX_FILE.exists():
                resources.append(Resource(
                    uri="pyro://cryptex/yara-dictionary",
                    name="YARA Cryptex Dictionary",
                    description="Complete YARA Cryptex dictionary with 587 entries",
                    mimeType="application/json"
                ))
            
            # API Documentation
            if PYRO_PLATFORM_DIR.exists():
                api_docs = list(PYRO_PLATFORM_DIR.rglob("*API*.md")) + \
                          list(PYRO_PLATFORM_DIR.rglob("*api*.md")) + \
                          list(PYRO_PLATFORM_DIR.rglob("README.md"))
                for doc in api_docs[:20]:  # Limit to first 20
                    rel_path = doc.relative_to(PYRO_PLATFORM_DIR)
                    resources.append(Resource(
                        uri=f"pyro://docs/{rel_path.as_posix()}",
                        name=f"PYRO Docs: {doc.name}",
                        description=f"PYRO Platform documentation: {rel_path}",
                        mimeType="text/markdown"
                    ))
            
            return resources
        
        @self.server.read_resource()
        async def read_resource(uri: str) -> str:
            """Read a resource by URI."""
            if uri.startswith("pyro://source/"):
                rel_path = uri.replace("pyro://source/", "")
                file_path = PYRO_PLATFORM_DIR / rel_path
                if file_path.exists() and file_path.is_file():
                    try:
                        return file_path.read_text(encoding='utf-8', errors='ignore')
                    except Exception:
                        return f"Error reading file: {rel_path}"
            
            elif uri.startswith("pyro://docs/"):
                rel_path = uri.replace("pyro://docs/", "")
                file_path = PYRO_PLATFORM_DIR / rel_path
                if file_path.exists() and file_path.is_file():
                    try:
                        return file_path.read_text(encoding='utf-8', errors='ignore')
                    except Exception:
                        return f"Error reading documentation: {rel_path}"
            
            elif uri == "pyro://cryptex/yara-dictionary":
                if YARA_CRYPTEX_FILE.exists():
                    try:
                        return YARA_CRYPTEX_FILE.read_text(encoding='utf-8')
                    except Exception:
                        return "Error reading Cryptex dictionary"
            
            raise ValueError(f"Resource not found: {uri}")
    
    def _get_mime_type(self, suffix: str) -> str:
        """Get MIME type from file suffix."""
        mime_types = {
            '.py': 'text/x-python',
            '.js': 'text/javascript',
            '.ts': 'text/typescript',
            '.rs': 'text/x-rust',
            '.md': 'text/markdown',
            '.json': 'application/json',
            '.yaml': 'text/yaml',
            '.yml': 'text/yaml',
            '.toml': 'text/x-toml',
        }
        return mime_types.get(suffix.lower(), 'text/plain')
    
    def _setup_tools(self):
        """Register MCP tools."""
        
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """List available tools."""
            return [
                Tool(
                    name="pyro-codebase-search",
                    description="Search PYRO Platform codebase for functions, classes, or patterns",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "Search query (function name, class, pattern)"},
                            "file_type": {"type": "string", "description": "File type filter (py, js, rs, etc.)"},
                            "directory": {"type": "string", "description": "Directory to search in"}
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="pyro-cryptex-lookup",
                    description="Look up YARA Cryptex entries by symbol or codename",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "symbol": {"type": "string", "description": "YARA function symbol"},
                            "pyro_name": {"type": "string", "description": "Cryptex codename"}
                        }
                    }
                ),
                Tool(
                    name="pyro-api-docs",
                    description="Get API documentation from PYRO Platform",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "endpoint": {"type": "string", "description": "API endpoint name"},
                            "component": {"type": "string", "description": "Component name"}
                        }
                    }
                ),
                Tool(
                    name="pyro-integration-points",
                    description="Find integration points between PYRO Platform and YARA Cryptex",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "component": {"type": "string", "description": "PYRO component to analyze"}
                        }
                    }
                ),
                Tool(
                    name="pyro-structure-analysis",
                    description="Analyze PYRO Platform structure and architecture",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "depth": {"type": "integer", "description": "Analysis depth (1-3)"}
                        }
                    }
                )
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Execute a tool."""
            if name == "pyro-codebase-search":
                return await self._codebase_search(arguments)
            elif name == "pyro-cryptex-lookup":
                return await self._cryptex_lookup(arguments)
            elif name == "pyro-api-docs":
                return await self._api_docs(arguments)
            elif name == "pyro-integration-points":
                return await self._integration_points(arguments)
            elif name == "pyro-structure-analysis":
                return await self._structure_analysis(arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
    
    async def _codebase_search(self, args: Dict[str, Any]) -> List[TextContent]:
        """Search PYRO Platform codebase."""
        if not PYRO_PLATFORM_DIR.exists():
            return [TextContent(type="text", text="PYRO Platform directory not found. Clone the repository first.")]
        
        query = args.get("query", "")
        file_type = args.get("file_type", "")
        directory = args.get("directory", "")
        
        results = []
        search_dir = PYRO_PLATFORM_DIR / directory if directory else PYRO_PLATFORM_DIR
        
        pattern = f"**/*{file_type}" if file_type else "**/*"
        
        try:
            for path in search_dir.rglob(pattern):
                if path.is_file():
                    try:
                        content = path.read_text(encoding='utf-8', errors='ignore')
                        if query.lower() in content.lower():
                            rel_path = path.relative_to(PYRO_PLATFORM_DIR)
                            results.append(f"{rel_path}: Found '{query}'")
                    except Exception:
                        continue
        except Exception as e:
            return [TextContent(type="text", text=f"Search error: {e}")]
        
        if not results:
            return [TextContent(type="text", text=f"No results found for '{query}'")]
        
        result_text = f"Found {len(results)} matches for '{query}':\n\n" + "\n".join(results[:50])
        return [TextContent(type="text", text=result_text)]
    
    async def _cryptex_lookup(self, args: Dict[str, Any]) -> List[TextContent]:
        """Look up Cryptex entry."""
        if not YARA_CRYPTEX_FILE.exists():
            return [TextContent(type="text", text="Cryptex dictionary not found")]
        
        try:
            with open(YARA_CRYPTEX_FILE, 'r') as f:
                data = json.load(f)
        except Exception as e:
            return [TextContent(type="text", text=f"Error loading dictionary: {e}")]
        
        symbol = args.get("symbol")
        pyro_name = args.get("pyro_name")
        
        for entry in data.get("entries", []):
            if (symbol and entry.get("symbol") == symbol) or \
               (pyro_name and entry.get("pyro_name") == pyro_name):
                result = json.dumps(entry, indent=2)
                return [TextContent(type="text", text=result)]
        
        return [TextContent(type="text", text="Entry not found")]
    
    async def _api_docs(self, args: Dict[str, Any]) -> List[TextContent]:
        """Get API documentation."""
        if not PYRO_PLATFORM_DIR.exists():
            return [TextContent(type="text", text="PYRO Platform directory not found")]
        
        endpoint = args.get("endpoint", "")
        component = args.get("component", "")
        
        # Search for API documentation
        docs = []
        for pattern in ["**/*API*.md", "**/*api*.md", "**/README.md", "**/docs/**/*.md"]:
            for doc_path in PYRO_PLATFORM_DIR.rglob(pattern):
                if doc_path.is_file():
                    try:
                        content = doc_path.read_text(encoding='utf-8', errors='ignore')
                        if endpoint and endpoint.lower() in content.lower():
                            docs.append(f"{doc_path.relative_to(PYRO_PLATFORM_DIR)}:\n{content[:500]}")
                        elif component and component.lower() in content.lower():
                            docs.append(f"{doc_path.relative_to(PYRO_PLATFORM_DIR)}:\n{content[:500]}")
                        elif not endpoint and not component:
                            docs.append(f"{doc_path.relative_to(PYRO_PLATFORM_DIR)}")
                    except Exception:
                        continue
        
        if not docs:
            return [TextContent(type="text", text="No API documentation found")]
        
        result = f"Found {len(docs)} documentation files:\n\n" + "\n\n".join(docs[:10])
        return [TextContent(type="text", text=result)]
    
    async def _integration_points(self, args: Dict[str, Any]) -> List[TextContent]:
        """Find integration points."""
        component = args.get("component", "")
        
        integration_points = []
        
        # Analyze PYRO Platform structure
        if PYRO_PLATFORM_DIR.exists():
            # Look for YARA-related files
            for pattern in ["**/*yara*", "**/*YARA*", "**/*cryptex*", "**/*Cryptex*"]:
                for path in PYRO_PLATFORM_DIR.rglob(pattern):
                    if path.is_file():
                        rel_path = path.relative_to(PYRO_PLATFORM_DIR)
                        integration_points.append(f"YARA/Cryptex reference: {rel_path}")
        
        # Check Cryptex dictionary for PYRO references
        if YARA_CRYPTEX_FILE.exists():
            try:
                with open(YARA_CRYPTEX_FILE, 'r') as f:
                    cryptex_data = json.load(f)
                
                # Look for PYRO-related entries
                for entry in cryptex_data.get("entries", []):
                    if "pyro" in entry.get("pyro_name", "").lower():
                        integration_points.append(
                            f"Cryptex entry: {entry.get('symbol')} → {entry.get('pyro_name')}"
                        )
            except Exception:
                pass
        
        if not integration_points:
            return [TextContent(type="text", text="No integration points found")]
        
        result = f"Found {len(integration_points)} integration points:\n\n" + "\n".join(integration_points[:30])
        return [TextContent(type="text", text=result)]
    
    async def _structure_analysis(self, args: Dict[str, Any]) -> List[TextContent]:
        """Analyze PYRO Platform structure."""
        if not PYRO_PLATFORM_DIR.exists():
            return [TextContent(type="text", text="PYRO Platform directory not found")]
        
        depth = args.get("depth", 2)
        
        structure = []
        structure.append(f"PYRO Platform Structure (depth={depth}):\n")
        structure.append("=" * 60)
        
        def analyze_dir(directory: Path, current_depth: int, max_depth: int):
            if current_depth > max_depth:
                return
            
            try:
                items = sorted(directory.iterdir())
                for item in items[:20]:  # Limit items
                    indent = "  " * current_depth
                    if item.is_dir():
                        structure.append(f"{indent}📁 {item.name}/")
                        if current_depth < max_depth:
                            analyze_dir(item, current_depth + 1, max_depth)
                    elif item.is_file():
                        structure.append(f"{indent}📄 {item.name}")
            except Exception:
                pass
        
        analyze_dir(PYRO_PLATFORM_DIR, 0, depth)
        
        return [TextContent(type="text", text="\n".join(structure))]
    
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
            print("MCP SDK not available. Running in standalone mode.")
            print("Install with: pip install mcp")
            while True:
                await asyncio.sleep(1)


async def main():
    """Main entry point."""
    server = PyroPlatformMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())

