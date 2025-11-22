"""
Agent-based audit tool for analyzing YARA functions and generating Cryptex entries.
This tool uses the MCP server to discover functions and create dictionary entries.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).parent.parent


class FunctionAnalyzer:
    """Analyzes C source files to extract function information."""
    
    def __init__(self):
        self.function_pattern = re.compile(
            r'^(\w+\s+)*?'  # Return type and qualifiers
            r'(\w+)\s*'     # Function name
            r'\([^)]*\)'    # Parameters
            r'\s*\{',       # Opening brace
            re.MULTILINE
        )
    
    def extract_functions(self, file_path: Path) -> List[Dict]:
        """Extract function definitions from a C source file."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return []
        
        functions = []
        lines = content.split('\n')
        
        for match in self.function_pattern.finditer(content):
            func_name = match.group(2) if match.lastindex >= 2 else None
            if not func_name:
                continue
            
            # Skip if it's a typedef or struct definition
            if func_name in ['typedef', 'struct', 'enum', 'union', 'if', 'while', 'for', 'switch']:
                continue
            
            # Find function start line
            start_line = content[:match.start()].count('\n') + 1
            signature_line = lines[start_line - 1].strip()
            
            # Try to find end of function (matching braces)
            brace_count = 1
            end_line = start_line
            for i in range(start_line, len(lines)):
                line = lines[i]
                brace_count += line.count('{') - line.count('}')
                if brace_count == 0:
                    end_line = i + 1
                    break
            
            # Extract function body for analysis
            func_body = '\n'.join(lines[start_line - 1:end_line])
            
            functions.append({
                "name": func_name,
                "start_line": start_line,
                "end_line": end_line,
                "signature": signature_line,
                "body": func_body,
                "file": str(file_path.relative_to(PROJECT_ROOT))
            })
        
        return functions
    
    def analyze_function(self, func: Dict) -> Dict:
        """Analyze a function to extract pseudocode and dependencies."""
        body = func.get("body", "")
        signature = func.get("signature", "")
        
        # Extract dependencies (function calls)
        call_pattern = re.compile(r'\b(\w+)\s*\(')
        calls = set(call_pattern.findall(body))
        
        # Filter out common C library calls and keywords
        filtered_calls = {
            c for c in calls 
            if c not in ['if', 'while', 'for', 'switch', 'return', 'sizeof', 'malloc', 'free', 'printf']
            and not c.startswith('yr_')  # Will be handled separately
        }
        
        # Generate simple pseudocode based on structure
        pseudocode = self._generate_pseudocode(body, signature)
        
        return {
            "dependencies": sorted(filtered_calls),
            "pseudocode": pseudocode,
            "complexity": self._estimate_complexity(body)
        }
    
    def _generate_pseudocode(self, body: str, signature: str) -> str:
        """Generate pseudocode representation of function."""
        lines = body.split('\n')
        pseudocode_lines = []
        
        # Simple heuristics for pseudocode generation
        for line in lines[:20]:  # Limit to first 20 lines for pseudocode
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            
            # Simplify common patterns
            if 'if (' in stripped:
                condition = stripped.split('if (', 1)[1].split(')', 1)[0] if ')' in stripped else 'condition'
                pseudocode_lines.append(f"if {condition}:")
            elif 'return' in stripped:
                value = stripped.split('return', 1)[1].strip().rstrip(';')
                pseudocode_lines.append(f"return {value}")
            elif '=' in stripped and not stripped.startswith('='):
                # Assignment
                left, right = stripped.split('=', 1)
                left = left.strip()
                right = right.split(';')[0].strip()
                pseudocode_lines.append(f"{left} = {right}")
            elif any(keyword in stripped for keyword in ['for', 'while']):
                pseudocode_lines.append(f"# {stripped.split('{')[0].strip()}")
        
        if not pseudocode_lines:
            return f"# Function implementation: {signature.split('{')[0].strip()}"
        
        return '\n'.join(pseudocode_lines[:10])  # Limit pseudocode length
    
    def _estimate_complexity(self, body: str) -> str:
        """Estimate function complexity."""
        lines = len([l for l in body.split('\n') if l.strip()])
        if lines < 20:
            return "low"
        elif lines < 100:
            return "medium"
        else:
            return "high"


class CryptexGenerator:
    """Generates Cryptex dictionary entries from function analysis."""
    
    def __init__(self):
        self.naming_rules = {
            'yr_initialize': 'BlackFlag-Bootstrap',
            'yr_finalize': 'BlackFlag-LastLight',
            'yr_compiler': 'InkSlinger',
            'yr_rules_scan': 'Molotov-Sweep',
            'yr_scanner': 'DeadDrop',
            'cli/yara': 'Cathedral-Broadcast',
            'module': 'IronCurtain',
        }
    
    def generate_pyro_name(self, symbol: str, kind: str, location: str) -> str:
        """Generate anarchist codename for a symbol."""
        # Check naming rules first
        for pattern, prefix in self.naming_rules.items():
            if pattern in symbol or pattern in location:
                if kind == "function":
                    # Extract action from function name
                    action = symbol.split('_')[-1] if '_' in symbol else symbol
                    return f"{prefix}-{action.title()}"
                return prefix
        
        # Default naming based on kind and location
        if kind == "function":
            parts = symbol.split('_')
            if len(parts) > 1:
                domain = parts[1].title() if len(parts) > 1 else "Core"
                action = parts[-1].title()
                return f"Pyro-{domain}-{action}"
        
        return f"Pyro-{symbol.title()}"
    
    def create_entry(self, func: Dict, analysis: Dict) -> Dict:
        """Create a Cryptex dictionary entry from function analysis."""
        location = func["file"]
        symbol = func["name"]
        kind = "function"
        
        # Determine owner/component
        if "modules/" in location:
            owner = f"libyara/modules/{location.split('modules/')[1].split('/')[0]}"
        elif "cli/" in location:
            owner = "cli"
        else:
            owner = "libyara/core"
        
        # Generate summary
        signature = func.get("signature", "")
        summary = self._generate_summary(symbol, signature, func.get("body", ""))
        
        return {
            "symbol": symbol,
            "pyro_name": self.generate_pyro_name(symbol, kind, location),
            "kind": kind,
            "location": location,
            "signature": signature,
            "summary": summary,
            "pseudocode": analysis.get("pseudocode", ""),
            "line_references": [
                {
                    "file": location,
                    "start": func["start_line"],
                    "end": func["end_line"]
                }
            ],
            "dependencies": analysis.get("dependencies", []),
            "owner": owner,
            "risk": self._assess_risk(symbol, location),
            "notes": []
        }
    
    def _generate_summary(self, symbol: str, signature: str, body: str) -> str:
        """Generate a concise summary of what the function does."""
        # Try to extract from comments
        lines = body.split('\n')
        for line in lines[:5]:
            if '//' in line or '/*' in line:
                comment = line.split('//')[1].strip() if '//' in line else line.split('/*')[1].split('*/')[0].strip()
                if comment and len(comment) < 160:
                    return comment
        
        # Fallback: infer from name and signature
        if 'init' in symbol.lower():
            return f"Initializes {symbol.replace('yr_', '').replace('_', ' ')}"
        elif 'scan' in symbol.lower():
            return f"Scans target using {symbol.replace('yr_', '').replace('_', ' ')}"
        elif 'compile' in symbol.lower():
            return f"Compiles YARA rules using {symbol.replace('yr_', '').replace('_', ' ')}"
        else:
            return f"Implements {symbol.replace('yr_', '').replace('_', ' ')} functionality"
    
    def _assess_risk(self, symbol: str, location: str) -> str:
        """Assess risk level of function."""
        critical_patterns = ['init', 'finalize', 'scan', 'compile', 'exec']
        if any(p in symbol.lower() for p in critical_patterns):
            return "critical"
        elif 'module' in location:
            return "high"
        else:
            return "standard"


async def audit_file(file_path: Path, output_file: Optional[Path] = None) -> List[Dict]:
    """Audit a single file and generate Cryptex entries."""
    analyzer = FunctionAnalyzer()
    generator = CryptexGenerator()
    
    print(f"Analyzing {file_path}...")
    functions = analyzer.extract_functions(file_path)
    
    entries = []
    for func in functions:
        analysis = analyzer.analyze_function(func)
        entry = generator.create_entry(func, analysis)
        entries.append(entry)
        print(f"  ✓ {entry['symbol']} → {entry['pyro_name']}")
    
    if output_file:
        # Load existing dictionary
        if output_file.exists():
            with open(output_file, 'r') as f:
                data = json.load(f)
        else:
            data = {"version": "0.1.0", "entries": [], "metadata": {}}
        
        # Merge entries (avoid duplicates)
        existing_symbols = {e["symbol"] for e in data["entries"]}
        for entry in entries:
            if entry["symbol"] not in existing_symbols:
                data["entries"].append(entry)
            else:
                # Update existing
                for i, e in enumerate(data["entries"]):
                    if e["symbol"] == entry["symbol"]:
                        data["entries"][i] = entry
                        break
        
        # Update metadata
        data["metadata"]["total_functions"] = len([e for e in data["entries"] if e["kind"] == "function"])
        data["metadata"]["last_updated"] = __import__('datetime').datetime.utcnow().isoformat()
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n✓ Updated Cryptex dictionary: {len(entries)} entries")
    
    return entries


async def audit_directory(directory: Path, output_file: Path, extensions: List[str] = None):
    """Audit all source files in a directory."""
    if extensions is None:
        extensions = [".c"]
    
    files = []
    for ext in extensions:
        files.extend(directory.rglob(f"*{ext}"))
    
    print(f"Found {len(files)} files to audit in {directory}")
    
    all_entries = []
    for file_path in files:
        entries = await audit_file(file_path, output_file)
        all_entries.extend(entries)
    
    return all_entries


async def main():
    """Main entry point for audit agent."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Audit YARA codebase and generate Cryptex entries")
    parser.add_argument("--file", type=str, help="Single file to audit")
    parser.add_argument("--directory", type=str, default="libyara", help="Directory to audit")
    parser.add_argument("--output", type=str, default="data/cryptex.json", help="Output Cryptex dictionary file")
    parser.add_argument("--extensions", nargs="+", default=[".c"], help="File extensions to analyze")
    
    args = parser.parse_args()
    
    output_file = PROJECT_ROOT / args.output
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    if args.file:
        file_path = PROJECT_ROOT / args.file
        await audit_file(file_path, output_file)
    else:
        directory = PROJECT_ROOT / args.directory
        await audit_directory(directory, output_file, args.extensions)


if __name__ == "__main__":
    asyncio.run(main())

