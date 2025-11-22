"""
Unified MCP Client - Connects to both YARA and PYRO Platform MCP servers.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional, Any

# Import both MCP server APIs
try:
    from mcp_server.api import CryptexAPI, SourceFileAPI
    YARA_MCP_AVAILABLE = True
except ImportError:
    YARA_MCP_AVAILABLE = False

try:
    from mcp_server_pyro.api import PyroPlatformAPI
    PYRO_MCP_AVAILABLE = True
except ImportError:
    PYRO_MCP_AVAILABLE = False


class UnifiedMCPClient:
    """Unified client for both YARA and PYRO Platform MCP servers."""
    
    def __init__(self):
        self.yara_api = CryptexAPI() if YARA_MCP_AVAILABLE else None
        self.yara_source = SourceFileAPI() if YARA_MCP_AVAILABLE else None
        self.pyro_api = PyroPlatformAPI() if PYRO_MCP_AVAILABLE else None
    
    def get_cryptex_entry(self, symbol: str = None, pyro_name: str = None) -> Optional[Dict]:
        """Get Cryptex entry from YARA dictionary."""
        if self.yara_api:
            return self.yara_api.lookup(symbol=symbol, pyro_name=pyro_name)
        return None
    
    def search_yara_codebase(self, query: str) -> List[str]:
        """Search YARA codebase."""
        if self.yara_source:
            files = self.yara_source.list_source_files()
            results = []
            for file_path in files[:50]:  # Limit search
                content = self.yara_source.read_source_file(file_path)
                if content and query.lower() in content.lower():
                    results.append(file_path)
            return results
        return []
    
    def search_pyro_codebase(self, query: str, file_type: str = None) -> List[Dict]:
        """Search PYRO Platform codebase."""
        if self.pyro_api:
            return self.pyro_api.search_codebase(query, file_type)
        return []
    
    def find_integration_points(self) -> Dict[str, Any]:
        """Find integration points between YARA Cryptex and PYRO Platform."""
        integration_points = {
            "yara_functions": [],
            "pyro_references": [],
            "suggested_integrations": []
        }
        
        # Get YARA Cryptex entries
        if self.yara_api:
            yara_entries = self.yara_api.list_entries()
            integration_points["yara_functions"] = [
                {
                    "symbol": e.get("symbol"),
                    "codename": e.get("pyro_name"),
                    "summary": e.get("summary")
                }
                for e in yara_entries[:20]  # Sample
            ]
        
        # Search PYRO for YARA references
        if self.pyro_api:
            pyro_refs = self.pyro_api.search_codebase("yara")
            integration_points["pyro_references"] = [
                {
                    "file": ref.get("file"),
                    "matches": ref.get("matches")
                }
                for ref in pyro_refs[:10]
            ]
        
        # Suggest integrations
        if integration_points["yara_functions"] and integration_points["pyro_references"]:
            integration_points["suggested_integrations"] = [
                {
                    "yara_function": func["codename"],
                    "pyro_component": ref["file"],
                    "type": "potential_integration"
                }
                for func in integration_points["yara_functions"][:5]
                for ref in integration_points["pyro_references"][:2]
            ]
        
        return integration_points
    
    def get_unified_stats(self) -> Dict[str, Any]:
        """Get statistics from both systems."""
        stats = {
            "yara": {},
            "pyro": {},
            "integration": {}
        }
        
        if self.yara_api:
            stats["yara"] = self.yara_api.get_stats()
        
        if self.pyro_api:
            structure = self.pyro_api.get_pyro_structure()
            stats["pyro"] = {
                "total_files": structure.get("total_files", 0),
                "directories": len(structure.get("directories", [])),
                "file_types": list(structure.get("files_by_type", {}).keys())
            }
        
        integration = self.find_integration_points()
        stats["integration"] = {
            "yara_functions_available": len(integration.get("yara_functions", [])),
            "pyro_references": len(integration.get("pyro_references", [])),
            "suggested_integrations": len(integration.get("suggested_integrations", []))
        }
        
        return stats


def get_unified_client():
    """Get unified MCP client instance."""
    return UnifiedMCPClient()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Unified MCP Client")
    parser.add_argument("--stats", action="store_true", help="Show unified statistics")
    parser.add_argument("--integration", action="store_true", help="Find integration points")
    parser.add_argument("--search-yara", type=str, help="Search YARA codebase")
    parser.add_argument("--search-pyro", type=str, help="Search PYRO codebase")
    
    args = parser.parse_args()
    
    client = UnifiedMCPClient()
    
    if args.stats:
        stats = client.get_unified_stats()
        print(json.dumps(stats, indent=2))
    elif args.integration:
        points = client.find_integration_points()
        print(json.dumps(points, indent=2))
    elif args.search_yara:
        results = client.search_yara_codebase(args.search_yara)
        print(f"Found {len(results)} files:")
        for r in results:
            print(f"  {r}")
    elif args.search_pyro:
        results = client.search_pyro_codebase(args.search_pyro)
        print(f"Found {len(results)} files:")
        for r in results:
            print(f"  {r.get('file')}: {r.get('matches')} matches")

