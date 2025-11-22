"""
Direct API access to MCP server functionality.
Use this when MCP SDK is not available or for direct integration.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

PROJECT_ROOT = Path(__file__).parent.parent
CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class CryptexAPI:
    """Direct API for Cryptex dictionary operations."""
    
    def __init__(self, cryptex_file: Path = None):
        self.cryptex_file = cryptex_file or CRYPTEX_FILE
        self._ensure_data_dir()
    
    def _ensure_data_dir(self):
        """Ensure data directory exists."""
        self.cryptex_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.cryptex_file.exists():
            self._initialize()
    
    def _initialize(self):
        """Initialize empty Cryptex dictionary."""
        data = {
            "version": "0.1.0",
            "entries": [],
            "metadata": {
                "total_functions": 0,
                "total_modules": 0,
                "last_updated": None
            }
        }
        self.save(data)
    
    def load(self) -> Dict:
        """Load Cryptex dictionary."""
        if not self.cryptex_file.exists():
            self._initialize()
        with open(self.cryptex_file, 'r') as f:
            return json.load(f)
    
    def save(self, data: Dict):
        """Save Cryptex dictionary."""
        with open(self.cryptex_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_entry(self, entry: Dict) -> bool:
        """Add or update a Cryptex entry."""
        data = self.load()
        
        # Check if entry exists
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
        data["metadata"]["last_updated"] = datetime.utcnow().isoformat()
        
        self.save(data)
        return action == "added"
    
    def lookup(self, symbol: str = None, pyro_name: str = None) -> Optional[Dict]:
        """Look up entry by symbol or pyro_name."""
        data = self.load()
        for entry in data["entries"]:
            if symbol and entry["symbol"] == symbol:
                return entry
            if pyro_name and entry["pyro_name"] == pyro_name:
                return entry
        return None
    
    def list_entries(self, kind: str = None) -> List[Dict]:
        """List all entries, optionally filtered by kind."""
        data = self.load()
        entries = data.get("entries", [])
        if kind:
            return [e for e in entries if e.get("kind") == kind]
        return entries
    
    def get_stats(self) -> Dict:
        """Get dictionary statistics."""
        data = self.load()
        entries = data.get("entries", [])
        return {
            "total_entries": len(entries),
            "functions": len([e for e in entries if e.get("kind") == "function"]),
            "modules": len([e for e in entries if e.get("kind") == "module"]),
            "structs": len([e for e in entries if e.get("kind") == "struct"]),
            "last_updated": data.get("metadata", {}).get("last_updated")
        }


class SourceFileAPI:
    """API for accessing YARA source files."""
    
    def __init__(self, project_root: Path = None):
        self.project_root = project_root or PROJECT_ROOT
        self.libyara_dir = self.project_root / "libyara"
        self.cli_dir = self.project_root / "cli"
        self.rules_dir = self.project_root / "yara-rules"
    
    def read_source_file(self, rel_path: str) -> Optional[str]:
        """Read a source file by relative path."""
        file_path = self.project_root / rel_path
        if file_path.exists() and file_path.is_file():
            try:
                return file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                return None
        return None
    
    def list_source_files(self, pattern: str = "**/*.c") -> List[str]:
        """List all source files matching pattern."""
        files = []
        for path in self.libyara_dir.rglob(pattern):
            rel_path = path.relative_to(self.project_root)
            files.append(str(rel_path))
        return files
    
    def list_header_files(self) -> List[str]:
        """List all header files."""
        files = []
        for path in self.libyara_dir.rglob("**/*.h"):
            rel_path = path.relative_to(self.project_root)
            files.append(str(rel_path))
        return files


# Convenience functions
def annotate_entry(**kwargs) -> bool:
    """Add or update a Cryptex entry."""
    api = CryptexAPI()
    return api.add_entry(kwargs)


def lookup_entry(symbol: str = None, pyro_name: str = None) -> Optional[Dict]:
    """Look up a Cryptex entry."""
    api = CryptexAPI()
    return api.lookup(symbol=symbol, pyro_name=pyro_name)


def get_stats() -> Dict:
    """Get Cryptex dictionary statistics."""
    api = CryptexAPI()
    return api.get_stats()

