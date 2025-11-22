"""Show Cryptex dictionary statistics."""

import json
from pathlib import Path

# Workspace path
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')
CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"

if CRYPTEX_FILE.exists():
    with open(CRYPTEX_FILE, 'r') as f:
        data = json.load(f)
    
    print("=" * 60)
    print("Cryptex Dictionary Statistics")
    print("=" * 60)
    print(f"Total Entries: {len(data['entries'])}")
    print(f"Functions: {data['metadata']['total_functions']}")
    print(f"Modules: {data['metadata']['total_modules']}")
    print(f"Last Updated: {data['metadata']['last_updated']}")
    print("\n" + "=" * 60)
    print("Sample Entries (First 20):")
    print("=" * 60)
    
    for i, entry in enumerate(data['entries'][:20], 1):
        file_name = entry['location'].split('\\')[-1] if '\\' in entry['location'] else entry['location'].split('/')[-1]
        print(f"{i:2}. {entry['symbol']:35} → {entry['pyro_name']:35} ({file_name})")
    
    print("\n" + "=" * 60)
    print("Entry Distribution by Component:")
    print("=" * 60)
    
    owners = {}
    for entry in data['entries']:
        owner = entry.get('owner', 'unknown')
        owners[owner] = owners.get(owner, 0) + 1
    
    for owner, count in sorted(owners.items(), key=lambda x: -x[1])[:10]:
        print(f"  {owner:40} {count:4} entries")
else:
    print("Cryptex dictionary not found!")

