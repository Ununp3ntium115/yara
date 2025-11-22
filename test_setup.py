"""
Quick test script to verify the MCP server and audit tools are set up correctly.
"""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")
    try:
        from mcp_server.api import CryptexAPI, SourceFileAPI, get_stats
        print("  ✓ mcp_server.api imported")
    except Exception as e:
        print(f"  ✗ mcp_server.api failed: {e}")
        return False
    
    try:
        from tools.audit_agent import FunctionAnalyzer, CryptexGenerator
        print("  ✓ tools.audit_agent imported")
    except Exception as e:
        print(f"  ✗ tools.audit_agent failed: {e}")
        return False
    
    return True

def test_cryptex_api():
    """Test Cryptex API functionality."""
    print("\nTesting Cryptex API...")
    try:
        from mcp_server.api import CryptexAPI
        
        api = CryptexAPI()
        print("  ✓ CryptexAPI initialized")
        
        # Test adding an entry
        test_entry = {
            "symbol": "test_function",
            "pyro_name": "Test-Codename",
            "kind": "function",
            "location": "test.c",
            "signature": "void test_function(void);",
            "summary": "Test function for validation",
            "pseudocode": "return test_value",
            "line_references": [{"file": "test.c", "start": 1, "end": 5}],
            "dependencies": [],
            "owner": "test",
            "risk": "informational"
        }
        
        api.add_entry(test_entry)
        print("  ✓ Entry added")
        
        # Test lookup
        entry = api.lookup(symbol="test_function")
        if entry and entry["pyro_name"] == "Test-Codename":
            print("  ✓ Lookup works")
        else:
            print("  ✗ Lookup failed")
            return False
        
        # Test stats
        stats = api.get_stats()
        if stats["total_entries"] > 0:
            print(f"  ✓ Stats: {stats['total_entries']} entries")
        else:
            print("  ✗ No entries found")
            return False
        
        return True
    except Exception as e:
        print(f"  ✗ Cryptex API test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_source_api():
    """Test Source File API."""
    print("\nTesting Source File API...")
    try:
        from mcp_server.api import SourceFileAPI
        
        api = SourceFileAPI()
        print("  ✓ SourceFileAPI initialized")
        
        # Test listing files
        files = api.list_source_files()
        if len(files) > 0:
            print(f"  ✓ Found {len(files)} source files")
        else:
            print("  ⚠ No source files found (this is OK if libyara doesn't exist)")
        
        return True
    except Exception as e:
        print(f"  ✗ Source API test failed: {e}")
        return False

def test_audit_tools():
    """Test audit agent tools."""
    print("\nTesting Audit Tools...")
    try:
        from tools.audit_agent import FunctionAnalyzer, CryptexGenerator
        
        analyzer = FunctionAnalyzer()
        print("  ✓ FunctionAnalyzer initialized")
        
        generator = CryptexGenerator()
        print("  ✓ CryptexGenerator initialized")
        
        # Test pseudocode generation
        test_body = """
        if (condition) {
            return value;
        }
        """
        pseudocode = analyzer._generate_pseudocode(test_body, "int test(void)")
        if pseudocode:
            print("  ✓ Pseudocode generation works")
        else:
            print("  ⚠ Pseudocode generation returned empty")
        
        return True
    except Exception as e:
        print(f"  ✗ Audit tools test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("YARA MCP Server & Audit Tools - Setup Test")
    print("=" * 60)
    
    results = []
    results.append(("Imports", test_imports()))
    results.append(("Cryptex API", test_cryptex_api()))
    results.append(("Source API", test_source_api()))
    results.append(("Audit Tools", test_audit_tools()))
    
    print("\n" + "=" * 60)
    print("Test Results:")
    print("=" * 60)
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {name}: {status}")
    
    all_passed = all(r[1] for r in results)
    if all_passed:
        print("\n✓ All tests passed! Setup is complete.")
        print("\nNext steps:")
        print("  1. Run: python tools/audit_agent.py --directory libyara")
        print("  2. Review: data/cryptex.json")
        print("  3. Refine entries as needed")
    else:
        print("\n✗ Some tests failed. Please check the errors above.")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())

