"""
Gap Analyzer - Finds functions not yet in Cryptex dictionary.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict

# Try workspace path first
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')
PROJECT_ROOT = Path(__file__).parent.parent

if (WORKSPACE / "data" / "cryptex.json").exists():
    CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
    PROJECT_ROOT = WORKSPACE
else:
    CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class GapAnalyzer:
    """Analyzes codebase to find unmapped functions."""
    
    def __init__(self):
        self.cryptex_data = self._load_cryptex()
        self.mapped_symbols = self._get_mapped_symbols()
    
    def _load_cryptex(self) -> Dict:
        """Load Cryptex dictionary."""
        if CRYPTEX_FILE.exists():
            with open(CRYPTEX_FILE, 'r') as f:
                return json.load(f)
        return {"entries": []}
    
    def _get_mapped_symbols(self) -> Set[str]:
        """Get set of all mapped symbols."""
        return {e.get("symbol", "") for e in self.cryptex_data.get("entries", []) if e.get("symbol")}
    
    def find_functions_in_file(self, file_path: Path) -> List[Dict]:
        """Find all functions in a source file."""
        if not file_path.exists():
            return []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return []
        
        functions = []
        lines = content.split('\n')
        
        # Pattern to match function definitions
        pattern = re.compile(
            r'^(static\s+)?(inline\s+)?(\w+\s+)*(\w+)\s*\([^)]*\)\s*\{',
            re.MULTILINE
        )
        
        for match in pattern.finditer(content):
            func_name = match.group(4) if match.lastindex >= 4 else None
            if not func_name:
                continue
            
            # Skip keywords
            if func_name in ['typedef', 'struct', 'enum', 'union', 'if', 'while', 'for', 'switch']:
                continue
            
            start_line = content[:match.start()].count('\n') + 1
            signature_line = lines[start_line - 1].strip()
            
            functions.append({
                "name": func_name,
                "start_line": start_line,
                "signature": signature_line,
                "file": str(file_path.relative_to(PROJECT_ROOT))
            })
        
        return functions
    
    def analyze_directory(self, directory: Path, extensions: List[str] = None) -> Dict:
        """Analyze directory for unmapped functions."""
        if extensions is None:
            extensions = [".c"]
        
        unmapped = []
        by_file = defaultdict(list)
        
        for ext in extensions:
            for file_path in directory.rglob(f"*{ext}"):
                functions = self.find_functions_in_file(file_path)
                
                for func in functions:
                    if func["name"] not in self.mapped_symbols:
                        unmapped.append(func)
                        by_file[func["file"]].append(func)
        
        return {
            "total_unmapped": len(unmapped),
            "files_with_gaps": len(by_file),
            "unmapped_functions": unmapped[:100],  # Limit to first 100
            "by_file": {k: v[:10] for k, v in list(by_file.items())[:20]}  # Limit
        }
    
    def generate_report(self, directory: str = "libyara") -> Dict:
        """Generate gap analysis report."""
        dir_path = PROJECT_ROOT / directory
        
        if not dir_path.exists():
            return {"error": f"Directory not found: {directory}"}
        
        results = self.analyze_directory(dir_path)
        
        return {
            "directory": directory,
            "mapped_functions": len(self.mapped_symbols),
            "unmapped_functions": results["total_unmapped"],
            "coverage_percent": round(
                (len(self.mapped_symbols) / (len(self.mapped_symbols) + results["total_unmapped"]) * 100)
                if (len(self.mapped_symbols) + results["total_unmapped"]) > 0 else 100,
                2
            ),
            "files_with_gaps": results["files_with_gaps"],
            "sample_unmapped": results["unmapped_functions"][:20]
        }


def analyze_gaps(directory: str = "libyara"):
    """Convenience function to analyze gaps."""
    analyzer = GapAnalyzer()
    return analyzer.generate_report(directory)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze gaps in Cryptex dictionary")
    parser.add_argument("--directory", default="libyara", help="Directory to analyze")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    
    args = parser.parse_args()
    
    analyzer = GapAnalyzer()
    report = analyzer.generate_report(args.directory)
    
    if args.json:
        import json
        print(json.dumps(report, indent=2))
    else:
        print("=" * 60)
        print("Gap Analysis Report")
        print("=" * 60)
        print(f"Directory: {report.get('directory', 'N/A')}")
        print(f"Mapped functions: {report.get('mapped_functions', 0)}")
        print(f"Unmapped functions: {report.get('unmapped_functions', 0)}")
        print(f"Coverage: {report.get('coverage_percent', 0)}%")
        print(f"Files with gaps: {report.get('files_with_gaps', 0)}")
        
        if report.get('sample_unmapped'):
            print("\nSample unmapped functions:")
            for func in report['sample_unmapped'][:10]:
                print(f"  {func['name']:30} in {func['file']}:{func['start_line']}")

