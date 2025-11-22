"""
Fix duplicate codenames in Cryptex dictionary.
"""

import json
from pathlib import Path
from collections import defaultdict

# Try workspace path first
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')
PROJECT_ROOT = Path(__file__).parent.parent

if (WORKSPACE / "data" / "cryptex.json").exists():
    CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
    PROJECT_ROOT = WORKSPACE
else:
    CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


def fix_duplicate_codenames():
    """Fix duplicate codenames by making them unique."""
    with open(CRYPTEX_FILE, 'r') as f:
        data = json.load(f)
    
    entries = data.get("entries", [])
    
    # Find duplicates
    codename_map = defaultdict(list)
    for i, entry in enumerate(entries):
        codename = entry.get("pyro_name", "")
        if codename:
            codename_map[codename].append(i)
    
    # Fix duplicates
    fixed_count = 0
    for codename, indices in codename_map.items():
        if len(indices) > 1:
            # Keep first one, modify others
            for idx in indices[1:]:
                entry = entries[idx]
                symbol = entry.get("symbol", "")
                location = entry.get("location", "")
                
                # Create unique codename
                if '_' in symbol:
                    parts = symbol.split('_')
                    # Use more parts to make unique
                    if len(parts) >= 3:
                        domain = parts[1]
                        subdomain = parts[2] if len(parts) > 2 else ""
                        action = parts[-1]
                        new_codename = f"Pyro-{domain.title()}-{subdomain.title()}-{action.title()}" if subdomain else f"Pyro-{domain.title()}-{action.title()}"
                    else:
                        new_codename = f"{codename}-{symbol.split('_')[-1].title()}"
                else:
                    new_codename = f"{codename}-{symbol.title()}"
                
                # Ensure uniqueness
                counter = 1
                original_new = new_codename
                while new_codename in [e.get("pyro_name") for e in entries]:
                    new_codename = f"{original_new}-{counter}"
                    counter += 1
                
                entries[idx]["pyro_name"] = new_codename
                fixed_count += 1
                print(f"Fixed: {symbol} → {new_codename} (was {codename})")
    
    # Save
    data["entries"] = entries
    with open(CRYPTEX_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n✓ Fixed {fixed_count} duplicate codenames")
    return fixed_count


if __name__ == "__main__":
    print("=" * 60)
    print("Fixing Duplicate Codenames")
    print("=" * 60)
    fix_duplicate_codenames()

