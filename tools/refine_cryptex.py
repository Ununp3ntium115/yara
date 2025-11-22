"""
Cryptex Dictionary Refinement Tool
Improves pseudocode, adds dependencies, and validates entries.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime

# Try workspace path first, then project root
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')
PROJECT_ROOT = Path(__file__).parent.parent

# Check which path exists
if (WORKSPACE / "data" / "cryptex.json").exists():
    CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
    PROJECT_ROOT = WORKSPACE
else:
    CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class CryptexRefiner:
    """Refines Cryptex dictionary entries with better pseudocode and dependencies."""
    
    def __init__(self, cryptex_file: Path = None):
        self.cryptex_file = cryptex_file or CRYPTEX_FILE
        self.data = self._load_cryptex()
        self.symbol_map = self._build_symbol_map()
    
    def _load_cryptex(self) -> Dict:
        """Load Cryptex dictionary."""
        if self.cryptex_file.exists():
            with open(self.cryptex_file, 'r') as f:
                return json.load(f)
        return {"entries": [], "metadata": {}}
    
    def _build_symbol_map(self) -> Dict[str, Dict]:
        """Build symbol lookup map."""
        return {e["symbol"]: e for e in self.data.get("entries", [])}
    
    def extract_dependencies(self, entry: Dict) -> List[str]:
        """Extract function dependencies from signature and pseudocode."""
        dependencies = set()
        symbol = entry["symbol"]
        location = entry.get("location", "")
        
        # Read source file to find function calls
        file_path = PROJECT_ROOT / location
        if file_path.exists():
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Find function body
                func_pattern = re.compile(
                    rf'\b{symbol}\s*\([^)]*\)\s*\{{',
                    re.MULTILINE
                )
                match = func_pattern.search(content)
                
                if match:
                    # Extract function body
                    start = match.end()
                    brace_count = 1
                    end = start
                    
                    for i in range(start, len(content)):
                        if content[i] == '{':
                            brace_count += 1
                        elif content[i] == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                end = i
                                break
                    
                    func_body = content[start:end]
                    
                    # Find function calls (yr_*, pe_*, etc.)
                    call_pattern = re.compile(r'\b(yr_\w+|pe_\w+|elf_\w+|dotnet_\w+)\s*\(')
                    calls = call_pattern.findall(func_body)
                    
                    for call in calls:
                        func_name = call.rstrip('(')
                        # Check if it's in our dictionary
                        if func_name in self.symbol_map:
                            codename = self.symbol_map[func_name].get("pyro_name")
                            if codename:
                                dependencies.add(codename)
            except Exception as e:
                pass
        
        return sorted(list(dependencies))
    
    def improve_pseudocode(self, entry: Dict) -> str:
        """Generate improved pseudocode based on function analysis."""
        symbol = entry["symbol"]
        signature = entry.get("signature", "")
        location = entry.get("location", "")
        
        # Read source file for better analysis
        file_path = PROJECT_ROOT / location
        if not file_path.exists():
            return entry.get("pseudocode", "")
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            # Find function
            func_pattern = re.compile(
                rf'\b{symbol}\s*\([^)]*\)\s*\{{',
                re.MULTILINE
            )
            match = func_pattern.search(content)
            
            if not match:
                return entry.get("pseudocode", "")
            
            start_line = content[:match.start()].count('\n') + 1
            func_start = match.end()
            
            # Extract function body
            brace_count = 1
            func_end = func_start
            for i in range(func_start, len(content)):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        func_end = i
                        break
            
            func_body = content[func_start:func_end]
            func_lines = func_body.split('\n')
            
            # Generate pseudocode
            pseudocode_lines = []
            
            # Extract parameters
            if '(' in signature and ')' in signature:
                params = signature.split('(')[1].split(')')[0]
                param_list = [p.strip().split()[-1] for p in params.split(',') if p.strip()]
                pseudocode_lines.append(f"function {symbol}({', '.join(param_list[:5])}):")
            else:
                pseudocode_lines.append(f"function {symbol}():")
            
            # Analyze function body
            in_if = False
            in_loop = False
            indent = 1
            
            for line in func_lines[:30]:  # Limit to first 30 lines
                stripped = line.strip()
                if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                    continue
                
                # Detect control structures
                if re.match(r'if\s*\(', stripped):
                    condition = stripped.split('(', 1)[1].split(')', 1)[0] if ')' in stripped else 'condition'
                    pseudocode_lines.append("    " * indent + f"if {condition}:")
                    in_if = True
                    indent += 1
                elif re.match(r'else\s*\{?', stripped):
                    indent = max(1, indent - 1)
                    pseudocode_lines.append("    " * indent + "else:")
                    indent += 1
                elif re.match(r'(for|while)\s*\(', stripped):
                    loop_type = 'for' if 'for' in stripped else 'while'
                    pseudocode_lines.append("    " * indent + f"{loop_type} condition:")
                    in_loop = True
                    indent += 1
                elif 'return' in stripped:
                    value = stripped.split('return', 1)[1].strip().rstrip(';')
                    pseudocode_lines.append("    " * indent + f"return {value}")
                elif re.match(r'\w+\s*=\s*\w+', stripped):
                    # Assignment
                    parts = stripped.split('=', 1)
                    left = parts[0].strip()
                    right = parts[1].split(';')[0].strip()
                    pseudocode_lines.append("    " * indent + f"{left} = {right}")
                elif stripped.endswith('}'):
                    if indent > 1:
                        indent -= 1
            
            if len(pseudocode_lines) == 1:
                # Fallback to template-based
                pseudocode_lines.append("    # See source code for implementation")
                pseudocode_lines.append(f"    # Location: {location}:{start_line}")
            
            return '\n'.join(pseudocode_lines[:15])  # Limit length
        
        except Exception as e:
            return entry.get("pseudocode", "")
    
    def refine_entry(self, entry: Dict) -> Dict:
        """Refine a single entry."""
        refined = entry.copy()
        
        # Improve pseudocode
        improved_pseudocode = self.improve_pseudocode(entry)
        if improved_pseudocode:
            refined["pseudocode"] = improved_pseudocode
        
        # Extract dependencies
        dependencies = self.extract_dependencies(entry)
        if dependencies:
            refined["dependencies"] = dependencies
        
        return refined
    
    def refine_all(self, limit: Optional[int] = None) -> Dict:
        """Refine all entries in the dictionary."""
        entries = self.data.get("entries", [])
        refined_count = 0
        
        print(f"Refining {len(entries)} entries...")
        
        for i, entry in enumerate(entries):
            if limit and i >= limit:
                break
            
            refined = self.refine_entry(entry)
            
            # Check if anything changed
            if (refined.get("pseudocode") != entry.get("pseudocode") or
                refined.get("dependencies") != entry.get("dependencies")):
                entries[i] = refined
                refined_count += 1
                
                if refined_count % 10 == 0:
                    print(f"  Refined {refined_count} entries...")
        
        self.data["entries"] = entries
        self.data["metadata"]["last_updated"] = datetime.utcnow().isoformat()
        
        return {
            "total_entries": len(entries),
            "refined": refined_count,
            "with_dependencies": len([e for e in entries if e.get("dependencies")]),
            "with_improved_pseudocode": len([e for e in entries if len(e.get("pseudocode", "")) > 50])
        }
    
    def save(self):
        """Save refined dictionary."""
        with open(self.cryptex_file, 'w') as f:
            json.dump(self.data, f, indent=2)
        print(f"✓ Saved refined dictionary to {self.cryptex_file}")


def refine_cryptex(limit: Optional[int] = None):
    """Convenience function to refine Cryptex dictionary."""
    refiner = CryptexRefiner()
    results = refiner.refine_all(limit)
    refiner.save()
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Refine Cryptex dictionary entries")
    parser.add_argument("--limit", type=int, help="Limit number of entries to refine")
    parser.add_argument("--entry", type=str, help="Refine specific entry by symbol")
    
    args = parser.parse_args()
    
    refiner = CryptexRefiner()
    
    if args.entry:
        # Refine specific entry
        entries = refiner.data.get("entries", [])
        for i, entry in enumerate(entries):
            if entry["symbol"] == args.entry:
                print(f"Refining entry: {args.entry}")
                refined = refiner.refine_entry(entry)
                entries[i] = refined
                refiner.data["entries"] = entries
                refiner.save()
                print(f"✓ Refined: {args.entry}")
                print(f"  Dependencies: {refined.get('dependencies', [])}")
                break
        else:
            print(f"Entry not found: {args.entry}")
    else:
        # Refine all
        results = refiner.refine_all(args.limit)
        refiner.save()
        print("\n" + "=" * 60)
        print("Refinement Results:")
        print("=" * 60)
        print(f"Total entries: {results['total_entries']}")
        print(f"Refined: {results['refined']}")
        print(f"With dependencies: {results['with_dependencies']}")
        print(f"With improved pseudocode: {results['with_improved_pseudocode']}")

