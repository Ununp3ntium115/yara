"""
Standalone audit runner - works from any directory.
"""

import asyncio
import sys
from pathlib import Path

# Add tools to path
tools_dir = Path(__file__).parent / "tools"
if tools_dir.exists():
    sys.path.insert(0, str(tools_dir.parent))

# Import and run
from tools.audit_agent import main

if __name__ == "__main__":
    asyncio.run(main())

