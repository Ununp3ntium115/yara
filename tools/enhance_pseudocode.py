"""
Enhance pseudocode quality by analyzing function implementations.
"""

import json
import re
from pathlib import Path
from typing import Dict, List

# Try workspace path first
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')
PROJECT_ROOT = Path(__file__).parent.parent

if (WORKSPACE / "data" / "cryptex.json").exists():
    CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
    PROJECT_ROOT = WORKSPACE
else:
    CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class PseudocodeEnhancer:
    """Enhances pseudocode by analyzing actual implementations."""
    
    def __init__(self):
        self.data = self._load_cryptex()
    
    def _load_cryptex(self) -> Dict:
        """Load Cryptex dictionary."""
        if CRYPTEX_FILE.exists():
            with open(CRYPTEX_FILE, 'r') as f:
                return json.load(f)
        return {"entries": []}
    
    def analyze_function_body(self, entry: Dict) -> str:
        """Analyze function body to generate better pseudocode."""
        symbol = entry.get("symbol", "")
        location = entry.get("location", "")
        file_path = PROJECT_ROOT / location
        
        if not file_path.exists():
            return entry.get("pseudocode", "")
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            # Find function
            func_pattern = re.compile(
                rf'\b{re.escape(symbol)}\s*\([^)]*\)\s*\{{',
                re.MULTILINE
            )
            match = func_pattern.search(content)
            
            if not match:
                return entry.get("pseudocode", "")
            
            start_pos = match.end()
            func_start_line = content[:match.start()].count('\n') + 1
            
            # Extract function body
            brace_count = 1
            func_end_pos = start_pos
            for i in range(start_pos, len(content)):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        func_end_pos = i
                        break
            
            func_body = content[start_pos:func_end_pos]
            func_lines = func_body.split('\n')
            
            # Generate enhanced pseudocode
            pseudocode = self._generate_from_body(func_body, symbol, entry)
            return pseudocode
            
        except Exception as e:
            return entry.get("pseudocode", "")
    
    def _generate_from_body(self, body: str, symbol: str, entry: Dict) -> str:
        """Generate pseudocode from function body."""
        lines = []
        
        # Extract parameters from signature
        signature = entry.get("signature", "")
        if '(' in signature and ')' in signature:
            params = signature.split('(')[1].split(')')[0]
            param_list = [p.strip().split()[-1] for p in params.split(',') if p.strip() and p.strip() != 'void']
            if param_list:
                lines.append(f"function {symbol}({', '.join(param_list[:5])}):")
            else:
                lines.append(f"function {symbol}():")
        else:
            lines.append(f"function {symbol}():")
        
        # Analyze control flow
        body_lower = body.lower()
        
        # Check for common patterns
        if 'return' in body_lower and 'error' in body_lower:
            lines.append("    if error condition:")
            lines.append("        return error_code")
        
        if 'if' in body_lower:
            lines.append("    if condition:")
            lines.append("        perform action")
        
        if 'for' in body_lower or 'while' in body_lower:
            lines.append("    for each item:")
            lines.append("        process item")
        
        if 'malloc' in body_lower or 'calloc' in body_lower:
            lines.append("    allocate memory")
            lines.append("    if allocation fails:")
            lines.append("        return error")
        
        if 'free' in body_lower:
            lines.append("    if pointer is not null:")
            lines.append("        free memory")
            lines.append("        set pointer to null")
        
        # Add summary based on function name
        if 'init' in symbol.lower() or 'create' in symbol.lower():
            lines.append("    initialize structure")
            lines.append("    set default values")
            lines.append("    return success")
        elif 'destroy' in symbol.lower() or 'free' in symbol.lower():
            lines.append("    validate input")
            lines.append("    release all resources")
            lines.append("    return success")
        elif 'scan' in symbol.lower():
            lines.append("    iterate through data")
            lines.append("    match patterns")
            lines.append("    invoke callbacks on matches")
            lines.append("    return match count")
        elif 'get' in symbol.lower():
            lines.append("    retrieve value from structure")
            lines.append("    return value")
        elif 'set' in symbol.lower():
            lines.append("    validate input")
            lines.append("    assign value")
            lines.append("    return success")
        else:
            lines.append("    # See source code for implementation")
            lines.append(f"    # Location: {entry.get('location', '')}")
        
        return '\n'.join(lines)
    
    def enhance_entry(self, entry: Dict) -> Dict:
        """Enhance a single entry's pseudocode."""
        enhanced = entry.copy()
        
        # Only enhance if pseudocode is short or generic
        current_pseudocode = entry.get("pseudocode", "")
        if len(current_pseudocode) < 50 or current_pseudocode.startswith("#"):
            enhanced_pseudocode = self.analyze_function_body(entry)
            if enhanced_pseudocode and len(enhanced_pseudocode) > len(current_pseudocode):
                enhanced["pseudocode"] = enhanced_pseudocode
        
        return enhanced
    
    def enhance_all(self, limit: int = None) -> Dict:
        """Enhance all entries."""
        entries = self.data.get("entries", [])
        enhanced_count = 0
        
        print(f"Enhancing pseudocode for {len(entries)} entries...")
        
        for i, entry in enumerate(entries):
            if limit and i >= limit:
                break
            
            enhanced = self.enhance_entry(entry)
            if enhanced.get("pseudocode") != entry.get("pseudocode"):
                entries[i] = enhanced
                enhanced_count += 1
                
                if enhanced_count % 10 == 0:
                    print(f"  Enhanced {enhanced_count} entries...")
        
        self.data["entries"] = entries
        return {
            "total": len(entries),
            "enhanced": enhanced_count
        }
    
    def save(self):
        """Save enhanced dictionary."""
        from datetime import datetime
        self.data["metadata"]["last_updated"] = datetime.utcnow().isoformat()
        
        with open(CRYPTEX_FILE, 'w') as f:
            json.dump(self.data, f, indent=2)
        print(f"✓ Saved enhanced dictionary to {CRYPTEX_FILE}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhance pseudocode in Cryptex dictionary")
    parser.add_argument("--limit", type=int, help="Limit number of entries to enhance")
    parser.add_argument("--entry", type=str, help="Enhance specific entry by symbol")
    
    args = parser.parse_args()
    
    enhancer = PseudocodeEnhancer()
    
    if args.entry:
        entries = enhancer.data.get("entries", [])
        for i, entry in enumerate(entries):
            if entry["symbol"] == args.entry:
                print(f"Enhancing entry: {args.entry}")
                enhanced = enhancer.enhance_entry(entry)
                entries[i] = enhanced
                enhancer.data["entries"] = entries
                enhancer.save()
                print(f"✓ Enhanced: {args.entry}")
                print(f"\nNew pseudocode:\n{enhanced.get('pseudocode', '')}")
                break
        else:
            print(f"Entry not found: {args.entry}")
    else:
        results = enhancer.enhance_all(args.limit)
        enhancer.save()
        print("\n" + "=" * 60)
        print("Enhancement Results:")
        print("=" * 60)
        print(f"Total entries: {results['total']}")
        print(f"Enhanced: {results['enhanced']}")

