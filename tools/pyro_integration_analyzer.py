"""
PYRO Platform Integration Analyzer
Analyzes PYRO Platform codebase to find integration points with YARA Cryptex.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict

PROJECT_ROOT = Path(__file__).parent.parent
PYRO_PLATFORM_DIR = PROJECT_ROOT / "pyro-platform"
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')

if (WORKSPACE / "data" / "cryptex.json").exists():
    YARA_CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
else:
    YARA_CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class PyroIntegrationAnalyzer:
    """Analyzes PYRO Platform for YARA/Cryptex integration points."""
    
    def __init__(self):
        self.pyro_dir = PYRO_PLATFORM_DIR
        self.cryptex_data = self._load_cryptex()
        self.integration_points = []
    
    def _load_cryptex(self) -> Dict:
        """Load Cryptex dictionary."""
        if YARA_CRYPTEX_FILE.exists():
            with open(YARA_CRYPTEX_FILE, 'r') as f:
                return json.load(f)
        return {"entries": []}
    
    def find_yara_references(self) -> List[Dict]:
        """Find YARA references in PYRO Platform."""
        if not self.pyro_dir.exists():
            return []
        
        references = []
        
        # Search patterns
        patterns = [
            r'\byara\b',
            r'\bYARA\b',
            r'\bcryptex\b',
            r'\bCryptex\b',
            r'yr_\w+',  # YARA function patterns
        ]
        
        for pattern in patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            
            for file_path in self.pyro_dir.rglob("*"):
                if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts', '.rs', '.md']:
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        matches = regex.findall(content)
                        
                        if matches:
                            references.append({
                                "file": str(file_path.relative_to(self.pyro_dir)),
                                "pattern": pattern,
                                "matches": list(set(matches))[:10],  # Limit matches
                                "line_count": len(content.split('\n'))
                            })
                    except Exception:
                        continue
        
        return references
    
    def find_api_endpoints(self) -> List[Dict]:
        """Find API endpoints in PYRO Platform."""
        if not self.pyro_dir.exists():
            return []
        
        endpoints = []
        
        # Common API patterns
        api_patterns = [
            r'@app\.(get|post|put|delete|patch)\s*\(["\']([^"\']+)["\']',
            r'router\.(get|post|put|delete|patch)\s*\(["\']([^"\']+)["\']',
            r'\.route\s*\(["\']([^"\']+)["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in api_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            
            for file_path in self.pyro_dir.rglob("*.py"):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    matches = regex.finditer(content)
                    
                    for match in matches:
                        endpoints.append({
                            "file": str(file_path.relative_to(self.pyro_dir)),
                            "method": match.group(1) if len(match.groups()) > 0 else "unknown",
                            "path": match.group(2) if len(match.groups()) > 1 else match.group(1),
                            "line": content[:match.start()].count('\n') + 1
                        })
                except Exception:
                    continue
        
        return endpoints
    
    def map_cryptex_to_pyro(self) -> Dict:
        """Map Cryptex entries to potential PYRO Platform integration points."""
        cryptex_entries = self.cryptex_data.get("entries", [])
        yara_refs = self.find_yara_references()
        api_endpoints = self.find_api_endpoints()
        
        mapping = {
            "cryptex_entries": len(cryptex_entries),
            "yara_references": len(yara_refs),
            "api_endpoints": len(api_endpoints),
            "integration_suggestions": []
        }
        
        # Find potential integration points
        for entry in cryptex_entries[:20]:  # Sample
            symbol = entry.get("symbol", "")
            codename = entry.get("pyro_name", "")
            
            # Check if symbol is referenced
            for ref in yara_refs:
                if symbol.lower() in str(ref.get("matches", [])).lower():
                    mapping["integration_suggestions"].append({
                        "cryptex_entry": symbol,
                        "codename": codename,
                        "pyro_reference": ref["file"],
                        "type": "code_reference"
                    })
        
        return mapping
    
    def analyze_structure(self) -> Dict:
        """Analyze PYRO Platform structure."""
        if not self.pyro_dir.exists():
            return {"error": "PYRO Platform directory not found"}
        
        structure = {
            "root": str(self.pyro_dir),
            "directories": [],
            "file_types": defaultdict(int),
            "total_files": 0
        }
        
        try:
            for item in self.pyro_dir.rglob("*"):
                if item.is_file():
                    structure["file_types"][item.suffix] += 1
                    structure["total_files"] += 1
                elif item.is_dir():
                    if item not in structure["directories"]:
                        structure["directories"].append(str(item.relative_to(self.pyro_dir)))
        except Exception as e:
            structure["error"] = str(e)
        
        return structure
    
    def generate_integration_report(self) -> str:
        """Generate comprehensive integration report."""
        report = []
        report.append("=" * 60)
        report.append("PYRO Platform - YARA Cryptex Integration Analysis")
        report.append("=" * 60)
        report.append("")
        
        # Structure analysis
        structure = self.analyze_structure()
        report.append("PYRO Platform Structure:")
        report.append(f"  Total files: {structure.get('total_files', 0)}")
        report.append(f"  File types: {dict(structure.get('file_types', {}))}")
        report.append("")
        
        # YARA references
        yara_refs = self.find_yara_references()
        report.append(f"YARA References Found: {len(yara_refs)}")
        for ref in yara_refs[:10]:
            report.append(f"  {ref['file']}: {len(ref['matches'])} matches")
        report.append("")
        
        # API endpoints
        endpoints = self.find_api_endpoints()
        report.append(f"API Endpoints Found: {len(endpoints)}")
        for ep in endpoints[:10]:
            report.append(f"  {ep['method'].upper()} {ep['path']} ({ep['file']})")
        report.append("")
        
        # Integration mapping
        mapping = self.map_cryptex_to_pyro()
        report.append("Integration Suggestions:")
        report.append(f"  Cryptex entries: {mapping['cryptex_entries']}")
        report.append(f"  YARA references: {mapping['yara_references']}")
        report.append(f"  API endpoints: {mapping['api_endpoints']}")
        report.append(f"  Suggested integrations: {len(mapping['integration_suggestions'])}")
        report.append("")
        
        report.append("=" * 60)
        
        return "\n".join(report)


def analyze_pyro_integration():
    """Convenience function to analyze integration."""
    analyzer = PyroIntegrationAnalyzer()
    return analyzer.generate_integration_report()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze PYRO Platform integration")
    parser.add_argument("--report", action="store_true", help="Generate full report")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    
    args = parser.parse_args()
    
    analyzer = PyroIntegrationAnalyzer()
    
    if args.json:
        result = {
            "structure": analyzer.analyze_structure(),
            "yara_references": analyzer.find_yara_references(),
            "api_endpoints": analyzer.find_api_endpoints(),
            "integration_mapping": analyzer.map_cryptex_to_pyro()
        }
        print(json.dumps(result, indent=2))
    else:
        print(analyzer.generate_integration_report())

