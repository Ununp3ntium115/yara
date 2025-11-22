"""
Direct API access to PYRO Platform MCP server functionality.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any

PROJECT_ROOT = Path(__file__).parent.parent
PYRO_PLATFORM_DIR = PROJECT_ROOT / "pyro-platform"
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')

if (WORKSPACE / "data" / "cryptex.json").exists():
    YARA_CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
else:
    YARA_CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class PyroPlatformAPI:
    """Direct API for PYRO Platform MCP server operations."""
    
    def __init__(self):
        self.pyro_dir = PYRO_PLATFORM_DIR
        self.cryptex_file = YARA_CRYPTEX_FILE
    
    def read_source_file(self, rel_path: str) -> Optional[str]:
        """Read a PYRO Platform source file."""
        file_path = self.pyro_dir / rel_path
        if file_path.exists() and file_path.is_file():
            try:
                return file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                return None
        return None
    
    def list_source_files(self, pattern: str = "**/*.py") -> List[str]:
        """List PYRO Platform source files."""
        if not self.pyro_dir.exists():
            return []
        
        files = []
        try:
            for path in self.pyro_dir.rglob(pattern):
                if path.is_file():
                    rel_path = path.relative_to(self.pyro_dir)
                    files.append(str(rel_path))
        except Exception:
            pass
        
        return files
    
    def search_codebase(self, query: str, file_type: str = None) -> List[Dict]:
        """Search PYRO Platform codebase."""
        if not self.pyro_dir.exists():
            return []
        
        results = []
        pattern = f"**/*{file_type}" if file_type else "**/*"
        
        try:
            for path in self.pyro_dir.rglob(pattern):
                if path.is_file():
                    try:
                        content = path.read_text(encoding='utf-8', errors='ignore')
                        if query.lower() in content.lower():
                            rel_path = path.relative_to(self.pyro_dir)
                            # Find line numbers
                            lines = content.split('\n')
                            matching_lines = [
                                i + 1 for i, line in enumerate(lines)
                                if query.lower() in line.lower()
                            ]
                            results.append({
                                "file": str(rel_path),
                                "matches": len(matching_lines),
                                "sample_lines": matching_lines[:5]
                            })
                    except Exception:
                        continue
        except Exception:
            pass
        
        return results
    
    def get_cryptex_entry(self, symbol: str = None, pyro_name: str = None) -> Optional[Dict]:
        """Get Cryptex entry."""
        if not self.cryptex_file.exists():
            return None
        
        try:
            with open(self.cryptex_file, 'r') as f:
                data = json.load(f)
            
            for entry in data.get("entries", []):
                if symbol and entry.get("symbol") == symbol:
                    return entry
                if pyro_name and entry.get("pyro_name") == pyro_name:
                    return entry
        except Exception:
            pass
        
        return None
    
    def get_pyro_structure(self, max_depth: int = 2) -> Dict:
        """Get PYRO Platform directory structure."""
        if not self.pyro_dir.exists():
            return {"error": "PYRO Platform directory not found"}
        
        structure = {
            "root": str(self.pyro_dir),
            "directories": [],
            "files_by_type": {}
        }
        
        try:
            for item in self.pyro_dir.rglob("*"):
                if item.is_dir():
                    rel_path = str(item.relative_to(self.pyro_dir))
                    depth = rel_path.count('/') + rel_path.count('\\')
                    if depth <= max_depth:
                        structure["directories"].append(rel_path)
                elif item.is_file():
                    suffix = item.suffix or "no-ext"
                    if suffix not in structure["files_by_type"]:
                        structure["files_by_type"][suffix] = []
                    rel_path = str(item.relative_to(self.pyro_dir))
                    depth = rel_path.count('/') + rel_path.count('\\')
                    if depth <= max_depth:
                        structure["files_by_type"][suffix].append(rel_path)
        except Exception as e:
            structure["error"] = str(e)
        
        return structure


# Convenience functions
def search_pyro_codebase(query: str, file_type: str = None) -> List[Dict]:
    """Search PYRO Platform codebase."""
    api = PyroPlatformAPI()
    return api.search_codebase(query, file_type)


def get_pyro_structure(max_depth: int = 2) -> Dict:
    """Get PYRO Platform structure."""
    api = PyroPlatformAPI()
    return api.get_pyro_structure(max_depth)


def get_cryptex_from_pyro(symbol: str = None, pyro_name: str = None) -> Optional[Dict]:
    """Get Cryptex entry via PYRO API."""
    api = PyroPlatformAPI()
    return api.get_cryptex_entry(symbol, pyro_name)

