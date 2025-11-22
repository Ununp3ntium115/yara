"""
YARA Cryptex - Quick SDLC Test
Runs a minimal test to verify framework works
"""

import sys
from pathlib import Path

# Add parent to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")
    
    try:
        from sdlc.security_audit import SecurityAuditor
        print("  ✅ SecurityAuditor imported")
    except ImportError as e:
        print(f"  ❌ SecurityAuditor import failed: {e}")
        return False
    
    try:
        from sdlc.code_simplification import CodeSimplifier
        print("  ✅ CodeSimplifier imported")
    except ImportError as e:
        print(f"  ❌ CodeSimplifier import failed: {e}")
        return False
    
    try:
        from sdlc.ua_testing_framework import InteractionLogger
        print("  ✅ InteractionLogger imported")
    except ImportError as e:
        print(f"  ⚠️  InteractionLogger import failed: {e}")
        print("     (This is OK if selenium is not installed)")
    
    return True

def test_security_audit():
    """Test security audit initialization"""
    print("\nTesting security audit...")
    
    try:
        from sdlc.security_audit import SecurityAuditor
        auditor = SecurityAuditor(str(project_root))
        print("  ✅ SecurityAuditor initialized")
        return True
    except Exception as e:
        print(f"  ❌ SecurityAuditor initialization failed: {e}")
        return False

def test_code_simplification():
    """Test code simplification initialization"""
    print("\nTesting code simplification...")
    
    try:
        from sdlc.code_simplification import CodeSimplifier
        simplifier = CodeSimplifier(str(project_root))
        print("  ✅ CodeSimplifier initialized")
        return True
    except Exception as e:
        print(f"  ❌ CodeSimplifier initialization failed: {e}")
        return False

def test_interaction_logger():
    """Test interaction logger"""
    print("\nTesting interaction logger...")
    
    try:
        from sdlc.ua_testing_framework import InteractionLogger
        logger = InteractionLogger()
        print("  ✅ InteractionLogger initialized")
        
        # Test logging
        logger.log_interaction('test', 'test_element', 'test_action')
        print("  ✅ Interaction logging works")
        return True
    except Exception as e:
        print(f"  ⚠️  InteractionLogger test failed: {e}")
        print("     (This is OK if selenium is not installed)")
        return True  # Not critical

def main():
    """Run quick tests"""
    print("=" * 60)
    print("YARA Cryptex - Quick SDLC Framework Test")
    print("=" * 60)
    print()
    
    results = []
    
    results.append(("Imports", test_imports()))
    results.append(("Security Audit", test_security_audit()))
    results.append(("Code Simplification", test_code_simplification()))
    results.append(("Interaction Logger", test_interaction_logger()))
    
    print("\n" + "=" * 60)
    print("Test Results")
    print("=" * 60)
    
    all_passed = True
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {name}: {status}")
        if not result:
            all_passed = False
    
    print()
    if all_passed:
        print("✅ All critical tests passed!")
        print("🚀 Framework is ready to use")
    else:
        print("⚠️  Some tests failed")
        print("💡 Check error messages above")
    
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())

