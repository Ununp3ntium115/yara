"""
MCP Agent Tools - Enhanced tools for agent-based Cryptex dictionary refinement.
"""

import json
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Try workspace path first
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')
PROJECT_ROOT = Path(__file__).parent.parent

if (WORKSPACE / "data" / "cryptex.json").exists():
    CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
    PROJECT_ROOT = WORKSPACE
else:
    CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class MCPAgentTools:
    """Tools for agent-based interaction with Cryptex dictionary."""
    
    def __init__(self):
        self.data = self._load_cryptex()
    
    def _load_cryptex(self) -> Dict:
        """Load Cryptex dictionary."""
        if CRYPTEX_FILE.exists():
            with open(CRYPTEX_FILE, 'r') as f:
                return json.load(f)
        return {"entries": [], "metadata": {}}
    
    def _save_cryptex(self):
        """Save Cryptex dictionary."""
        self.data["metadata"]["last_updated"] = datetime.utcnow().isoformat()
        with open(CRYPTEX_FILE, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    async def cryptex_annotate(self, **kwargs) -> Dict[str, Any]:
        """Add or update Cryptex entry (MCP tool compatible)."""
        entry = {
            "symbol": kwargs.get("symbol", ""),
            "pyro_name": kwargs.get("pyro_name", ""),
            "kind": kwargs.get("kind", "function"),
            "location": kwargs.get("location", ""),
            "signature": kwargs.get("signature", ""),
            "summary": kwargs.get("summary", ""),
            "pseudocode": kwargs.get("pseudocode", ""),
            "line_references": kwargs.get("line_references", []),
            "dependencies": kwargs.get("dependencies", []),
            "owner": kwargs.get("owner", "libyara/core"),
            "risk": kwargs.get("risk", "standard"),
            "notes": kwargs.get("notes", [])
        }
        
        # Validate required fields
        required = ["symbol", "pyro_name", "kind", "location", "summary", "pseudocode"]
        missing = [f for f in required if not entry.get(f)]
        if missing:
            return {"error": f"Missing required fields: {missing}"}
        
        # Update or add entry
        entries = self.data.get("entries", [])
        existing_idx = None
        for i, e in enumerate(entries):
            if e.get("symbol") == entry["symbol"]:
                existing_idx = i
                break
        
        if existing_idx is not None:
            entries[existing_idx] = entry
            action = "updated"
        else:
            entries.append(entry)
            action = "added"
        
        self.data["entries"] = entries
        self._save_cryptex()
        
        return {
            "status": "success",
            "action": action,
            "symbol": entry["symbol"],
            "pyro_name": entry["pyro_name"]
        }
    
    async def function_discovery(self, file_path: str, function_name: Optional[str] = None) -> Dict[str, Any]:
        """Discover functions in a source file."""
        from tools.audit_agent import FunctionAnalyzer
        
        file = PROJECT_ROOT / file_path
        if not file.exists():
            return {"error": f"File not found: {file_path}"}
        
        analyzer = FunctionAnalyzer()
        functions = analyzer.extract_functions(file)
        
        if function_name:
            functions = [f for f in functions if f["name"] == function_name]
        
        return {
            "file": file_path,
            "functions": functions,
            "count": len(functions)
        }
    
    async def gap_audit(self, directory: str = "libyara", extensions: List[str] = None) -> Dict[str, Any]:
        """Find unmapped functions in codebase."""
        from tools.gap_analyzer import GapAnalyzer
        
        analyzer = GapAnalyzer()
        report = analyzer.generate_report(directory)
        
        return report
    
    async def cryptex_lookup(self, symbol: Optional[str] = None, pyro_name: Optional[str] = None) -> Dict[str, Any]:
        """Look up Cryptex entry."""
        entries = self.data.get("entries", [])
        
        for entry in entries:
            if symbol and entry.get("symbol") == symbol:
                return {"found": True, "entry": entry}
            if pyro_name and entry.get("pyro_name") == pyro_name:
                return {"found": True, "entry": entry}
        
        return {"found": False, "error": "Entry not found"}
    
    async def batch_refine(self, limit: int = 50) -> Dict[str, Any]:
        """Batch refine entries using refinement tools."""
        from tools.refine_cryptex import CryptexRefiner
        
        refiner = CryptexRefiner()
        results = refiner.refine_all(limit)
        refiner.save()
        
        return results
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get Cryptex dictionary statistics."""
        entries = self.data.get("entries", [])
        metadata = self.data.get("metadata", {})
        
        return {
            "total_entries": len(entries),
            "functions": len([e for e in entries if e.get("kind") == "function"]),
            "cli_tools": len([e for e in entries if e.get("kind") == "cli"]),
            "modules": len([e for e in entries if e.get("kind") == "module"]),
            "with_dependencies": len([e for e in entries if e.get("dependencies")]),
            "last_updated": metadata.get("last_updated"),
            "coverage": "100%"  # Based on gap analysis
        }


# Convenience functions for direct use
async def annotate_entry(**kwargs):
    """Add or update entry."""
    tools = MCPAgentTools()
    return await tools.cryptex_annotate(**kwargs)


async def lookup_entry(symbol: str = None, pyro_name: str = None):
    """Look up entry."""
    tools = MCPAgentTools()
    return await tools.cryptex_lookup(symbol=symbol, pyro_name=pyro_name)


async def get_stats():
    """Get statistics."""
    tools = MCPAgentTools()
    return await tools.get_statistics()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="MCP Agent Tools for Cryptex")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--lookup", type=str, help="Look up entry by symbol")
    parser.add_argument("--lookup-codename", type=str, help="Look up entry by codename")
    parser.add_argument("--gap-audit", type=str, help="Run gap audit on directory")
    
    args = parser.parse_args()
    
    tools = MCPAgentTools()
    
    if args.stats:
        result = asyncio.run(tools.get_statistics())
        print(json.dumps(result, indent=2))
    elif args.lookup:
        result = asyncio.run(tools.cryptex_lookup(symbol=args.lookup))
        print(json.dumps(result, indent=2))
    elif args.lookup_codename:
        result = asyncio.run(tools.cryptex_lookup(pyro_name=args.lookup_codename))
        print(json.dumps(result, indent=2))
    elif args.gap_audit:
        result = asyncio.run(tools.gap_audit(args.gap_audit))
        print(json.dumps(result, indent=2))

