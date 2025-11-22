"""
Sample audit script - analyzes YARA functions and creates Cryptex entries.
This version works with the workspace directory structure.
"""

import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# Workspace path (where Cursor stores files)
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')
PROJECT_ROOT = WORKSPACE
LIBYARA_DIR = PROJECT_ROOT / "libyara"
DATA_DIR = PROJECT_ROOT / "data"
CRYPTEX_FILE = DATA_DIR / "cryptex.json"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)


def extract_functions(file_path: Path) -> List[Dict]:
    """Extract function definitions from a C source file."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []
    
    functions = []
    lines = content.split('\n')
    
    # Pattern to match function definitions
    pattern = re.compile(
        r'^(\w+\s+)*?'  # Return type
        r'(\w+)\s*'     # Function name
        r'\([^)]*\)'    # Parameters
        r'\s*\{',       # Opening brace
        re.MULTILINE
    )
    
    for match in pattern.finditer(content):
        func_name = match.group(2) if match.lastindex >= 2 else None
        if not func_name:
            continue
        
        # Skip keywords
        if func_name in ['typedef', 'struct', 'enum', 'union', 'if', 'while', 'for', 'switch']:
            continue
        
        start_line = content[:match.start()].count('\n') + 1
        signature_line = lines[start_line - 1].strip()
        
        # Find function end (simple brace matching)
        brace_count = 1
        end_line = start_line
        for i in range(start_line, len(lines)):
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0:
                end_line = i + 1
                break
        
        functions.append({
            "name": func_name,
            "start_line": start_line,
            "end_line": end_line,
            "signature": signature_line,
            "file": str(file_path.relative_to(PROJECT_ROOT))
        })
    
    return functions


def generate_pseudocode(func: Dict) -> str:
    """Generate pseudocode from function signature and context."""
    symbol = func["name"]
    sig = func["signature"]
    
    # Extract return type and parameters
    if '(' in sig and ')' in sig:
        params = sig.split('(')[1].split(')')[0]
        param_list = [p.strip() for p in params.split(',') if p.strip()]
    else:
        param_list = []
    
    # Generate basic pseudocode based on function name patterns
    pseudocode_lines = [f"function {symbol}(" + ", ".join(param_list[:3]) + "):"]
    
    if 'create' in symbol.lower() or 'init' in symbol.lower():
        pseudocode_lines.append("    allocate memory for object")
        pseudocode_lines.append("    initialize fields")
        pseudocode_lines.append("    return object")
    elif 'destroy' in symbol.lower() or 'free' in symbol.lower():
        pseudocode_lines.append("    if object is null: return")
        pseudocode_lines.append("    free all allocated resources")
        pseudocode_lines.append("    set object to null")
    elif 'scan' in symbol.lower():
        pseudocode_lines.append("    for each chunk in data:")
        pseudocode_lines.append("        match patterns against chunk")
        pseudocode_lines.append("        if match found: invoke callback")
        pseudocode_lines.append("    return match count")
    elif 'compile' in symbol.lower():
        pseudocode_lines.append("    parse input rules")
        pseudocode_lines.append("    build abstract syntax tree")
        pseudocode_lines.append("    generate bytecode")
        pseudocode_lines.append("    return compiled rules")
    elif 'get' in symbol.lower():
        pseudocode_lines.append("    retrieve value from structure")
        pseudocode_lines.append("    return value")
    elif 'set' in symbol.lower():
        pseudocode_lines.append("    validate input")
        pseudocode_lines.append("    assign value to structure field")
        pseudocode_lines.append("    return success")
    else:
        pseudocode_lines.append(f"    # Implementation at {func['file']}:{func['start_line']}")
        pseudocode_lines.append("    # See source code for details")
    
    return "\n".join(pseudocode_lines)


def generate_pyro_name(symbol: str, location: str) -> str:
    """Generate anarchist codename."""
    naming_rules = {
        'yr_initialize': 'BlackFlag-Bootstrap',
        'yr_finalize': 'BlackFlag-LastLight',
        'yr_compiler': 'InkSlinger',
        'yr_rules_scan': 'Molotov-Sweep',
        'yr_scanner': 'DeadDrop',
    }
    
    for pattern, prefix in naming_rules.items():
        if pattern in symbol or pattern in location:
            action = symbol.split('_')[-1].title() if '_' in symbol else symbol
            return f"{prefix}-{action}"
    
    # Default naming
    if '_' in symbol:
        parts = symbol.split('_')
        domain = parts[1].title() if len(parts) > 1 else "Core"
        action = parts[-1].title()
        return f"Pyro-{domain}-{action}"
    
    return f"Pyro-{symbol.title()}"


def generate_summary(symbol: str, signature: str) -> str:
    """Generate function summary."""
    # Remove common prefixes
    clean_name = symbol.replace('yr_', '').replace('_yr_', '').replace('_', ' ')
    
    if 'init' in symbol.lower() or 'create' in symbol.lower():
        return f"Creates/initializes {clean_name}"
    elif 'destroy' in symbol.lower() or 'free' in symbol.lower():
        return f"Destroys/frees {clean_name} resources"
    elif 'scan' in symbol.lower():
        return f"Scans target data using {clean_name}"
    elif 'compile' in symbol.lower():
        return f"Compiles YARA rules via {clean_name}"
    elif 'add' in symbol.lower():
        return f"Adds {clean_name} to collection"
    elif 'get' in symbol.lower():
        return f"Retrieves {clean_name} value"
    elif 'set' in symbol.lower():
        return f"Sets {clean_name} value"
    elif 'execute' in symbol.lower() or 'exec' in symbol.lower():
        return f"Executes {clean_name} operation"
    else:
        return f"Implements {clean_name} functionality"


def create_entry(func: Dict) -> Dict:
    """Create Cryptex dictionary entry."""
    location = func["file"]
    symbol = func["name"]
    
    # Determine owner
    if "modules/" in location:
        owner = f"libyara/modules/{location.split('modules/')[1].split('/')[0]}"
    elif "cli/" in location:
        owner = "cli"
    else:
        owner = "libyara/core"
    
    return {
        "symbol": symbol,
        "pyro_name": generate_pyro_name(symbol, location),
        "kind": "function",
        "location": location,
        "signature": func["signature"],
        "summary": generate_summary(symbol, func["signature"]),
        "pseudocode": generate_pseudocode(func),
        "line_references": [
            {
                "file": location,
                "start": func["start_line"],
                "end": func["end_line"]
            }
        ],
        "dependencies": [],
        "owner": owner,
        "risk": "critical" if any(p in symbol.lower() for p in ['init', 'scan', 'compile']) else "standard",
        "notes": []
    }


def main():
    """Main audit function."""
    print("=" * 60)
    print("YARA Cryptex Dictionary - Initial Audit")
    print("=" * 60)
    
    # Find source files
    source_files = list(LIBYARA_DIR.rglob("*.c"))
    print(f"\nFound {len(source_files)} C source files")
    
    # Load or create Cryptex dictionary
    if CRYPTEX_FILE.exists():
        with open(CRYPTEX_FILE, 'r') as f:
            data = json.load(f)
        existing_symbols = {e["symbol"] for e in data.get("entries", [])}
        print(f"Existing entries: {len(existing_symbols)}")
    else:
        data = {
            "version": "0.1.0",
            "entries": [],
            "metadata": {
                "total_functions": 0,
                "total_modules": 0,
                "last_updated": None
            }
        }
        existing_symbols = set()
    
    # Process all files
    print("\nProcessing files...")
    new_entries = 0
    updated_entries = 0
    
    for file_path in source_files:  # Process all files
        print(f"  Analyzing {file_path.name}...")
        functions = extract_functions(file_path)
        
        for func in functions:
            entry = create_entry(func)
            
            if entry["symbol"] in existing_symbols:
                # Update existing
                for i, e in enumerate(data["entries"]):
                    if e["symbol"] == entry["symbol"]:
                        data["entries"][i] = entry
                        updated_entries += 1
                        break
            else:
                # Add new
                data["entries"].append(entry)
                existing_symbols.add(entry["symbol"])
                new_entries += 1
                print(f"    ✓ {entry['symbol']} → {entry['pyro_name']}")
    
    # Update metadata
    data["metadata"]["total_functions"] = len([e for e in data["entries"] if e["kind"] == "function"])
    data["metadata"]["last_updated"] = datetime.utcnow().isoformat()
    
    # Save
    with open(CRYPTEX_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    
    print("\n" + "=" * 60)
    print(f"✓ Audit complete!")
    print(f"  New entries: {new_entries}")
    print(f"  Updated entries: {updated_entries}")
    print(f"  Total entries: {len(data['entries'])}")
    print(f"  Dictionary saved to: {CRYPTEX_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()

