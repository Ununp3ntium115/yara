"""
Audit CLI tools (yara.c, yarac.c) and add to Cryptex dictionary.
"""

import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# Workspace path
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')
PROJECT_ROOT = WORKSPACE
CLI_DIR = PROJECT_ROOT / "cli"
DATA_DIR = PROJECT_ROOT / "data"
CRYPTEX_FILE = DATA_DIR / "cryptex.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)


def extract_functions(file_path: Path) -> List[Dict]:
    """Extract function definitions from CLI source files."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []
    
    functions = []
    lines = content.split('\n')
    
    # Pattern to match function definitions (including static, main, etc.)
    pattern = re.compile(
        r'^(static\s+)?(inline\s+)?(int|void|char|const\s+char|bool|YR_\w+|\w+\s*\*)\s+'  # Return type
        r'(\w+)\s*'     # Function name
        r'\([^)]*\)'    # Parameters
        r'\s*\{',       # Opening brace
        re.MULTILINE
    )
    
    for match in pattern.finditer(content):
        func_name = match.group(4) if match.lastindex >= 4 else None
        if not func_name:
            continue
        
        # Skip keywords and macros
        if func_name in ['typedef', 'struct', 'enum', 'union', 'if', 'while', 'for', 'switch', 'return', 'sizeof']:
            continue
        
        start_line = content[:match.start()].count('\n') + 1
        signature_line = lines[start_line - 1].strip()
        
        # Find function end
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


def generate_pyro_name(symbol: str, location: str) -> str:
    """Generate anarchist codename for CLI functions."""
    # Special naming for CLI entry points
    if symbol == '_tmain' or symbol == 'main':
        if 'yara.c' in location:
            return 'Cathedral-Broadcast'
        elif 'yarac.c' in location:
            return 'Cathedral-Forge'
    
    # CLI-specific prefixes
    if 'callback' in symbol.lower():
        return f'Switchboard-{symbol.split("_")[-1].title()}'
    elif 'scan' in symbol.lower():
        return f'Switchboard-Scan-{symbol.split("_")[-1].title()}'
    elif 'print' in symbol.lower():
        return f'Switchboard-Print-{symbol.split("_")[-1].title()}'
    elif 'load' in symbol.lower() or 'unload' in symbol.lower():
        return f'Switchboard-{symbol.split("_")[-1].title()}'
    elif 'thread' in symbol.lower():
        return f'Switchboard-Thread-{symbol.split("_")[-1].title()}'
    
    # Default CLI naming
    parts = symbol.split('_')
    if len(parts) > 1:
        action = parts[-1].title()
        return f'Switchboard-{action}'
    
    return f'Switchboard-{symbol.title()}'


def generate_summary(symbol: str, signature: str, location: str) -> str:
    """Generate function summary."""
    if symbol == '_tmain' or symbol == 'main':
        if 'yara.c' in location:
            return "Main entry point for YARA CLI scanner - parses arguments, loads rules, and scans targets"
        elif 'yarac.c' in location:
            return "Main entry point for YARA compiler - compiles rules and saves to binary format"
    
    clean_name = symbol.replace('_', ' ')
    
    if 'callback' in symbol.lower():
        return f"Callback function for {clean_name}"
    elif 'scan' in symbol.lower():
        return f"Scans target using {clean_name}"
    elif 'print' in symbol.lower():
        return f"Prints {clean_name} output"
    elif 'load' in symbol.lower():
        return f"Loads {clean_name} data"
    elif 'thread' in symbol.lower():
        return f"Thread function for {clean_name}"
    else:
        return f"Implements {clean_name} functionality"


def generate_pseudocode(func: Dict) -> str:
    """Generate pseudocode for CLI functions."""
    symbol = func["name"]
    sig = func["signature"]
    
    if symbol == '_tmain' or symbol == 'main':
        if 'yara.c' in func["file"]:
            return """function main(argc, argv):
    parse command line arguments
    initialize YARA library
    load rules (compiled or source)
    create scanner
    if target is directory:
        scan directory recursively
    elif target is file:
        scan single file
    elif target is PID:
        scan process memory
    print results
    cleanup and exit"""
        elif 'yarac.c' in func["file"]:
            return """function main(argc, argv):
    parse command line arguments
    initialize YARA library
    create compiler
    compile rule files
    save compiled rules to output file
    cleanup and exit"""
    
    # Extract parameters
    if '(' in sig and ')' in sig:
        params = sig.split('(')[1].split(')')[0]
        param_list = [p.strip() for p in params.split(',') if p.strip()]
    else:
        param_list = []
    
    pseudocode_lines = [f"function {symbol}(" + ", ".join(param_list[:3]) + "):"]
    
    if 'callback' in symbol.lower():
        pseudocode_lines.append("    process match data")
        pseudocode_lines.append("    format output")
        pseudocode_lines.append("    return status")
    elif 'scan' in symbol.lower():
        pseudocode_lines.append("    open target file/directory")
        pseudocode_lines.append("    iterate through files")
        pseudocode_lines.append("    invoke scanner for each file")
        pseudocode_lines.append("    handle errors")
    elif 'print' in symbol.lower():
        pseudocode_lines.append("    format output string")
        pseudocode_lines.append("    write to stdout/stderr")
    elif 'thread' in symbol.lower():
        pseudocode_lines.append("    while files in queue:")
        pseudocode_lines.append("        pop file from queue")
        pseudocode_lines.append("        scan file")
        pseudocode_lines.append("        report results")
    else:
        pseudocode_lines.append(f"    # Implementation at {func['file']}:{func['start_line']}")
    
    return "\n".join(pseudocode_lines)


def create_entry(func: Dict) -> Dict:
    """Create Cryptex dictionary entry."""
    location = func["file"]
    symbol = func["name"]
    
    return {
        "symbol": symbol,
        "pyro_name": generate_pyro_name(symbol, location),
        "kind": "cli",
        "location": location,
        "signature": func["signature"],
        "summary": generate_summary(symbol, func["signature"], location),
        "pseudocode": generate_pseudocode(func),
        "line_references": [
            {
                "file": location,
                "start": func["start_line"],
                "end": func["end_line"]
            }
        ],
        "dependencies": [],
        "owner": "cli",
        "risk": "critical" if symbol in ['_tmain', 'main'] else "standard",
        "notes": []
    }


def main():
    """Main audit function."""
    print("=" * 60)
    print("YARA CLI Tools - Cryptex Dictionary Audit")
    print("=" * 60)
    
    # Find CLI source files
    cli_files = list(CLI_DIR.glob("*.c"))
    print(f"\nFound {len(cli_files)} CLI source files")
    
    # Load existing Cryptex dictionary
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
                "total_cli": 0,
                "last_updated": None
            }
        }
        existing_symbols = set()
    
    # Process CLI files
    print("\nProcessing CLI files...")
    new_entries = 0
    updated_entries = 0
    
    for file_path in cli_files:
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
    data["metadata"]["total_cli"] = len([e for e in data["entries"] if e["kind"] == "cli"])
    data["metadata"]["last_updated"] = datetime.utcnow().isoformat()
    
    # Save
    with open(CRYPTEX_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    
    print("\n" + "=" * 60)
    print(f"✓ CLI Audit complete!")
    print(f"  New entries: {new_entries}")
    print(f"  Updated entries: {updated_entries}")
    print(f"  Total CLI entries: {data['metadata']['total_cli']}")
    print(f"  Total dictionary entries: {len(data['entries'])}")
    print(f"  Dictionary saved to: {CRYPTEX_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()

