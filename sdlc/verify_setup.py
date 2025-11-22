"""
YARA Cryptex - SDLC Framework Setup Verification
Verifies all components are ready for SDLC cycles
"""

import sys
import subprocess
from pathlib import Path

def check_python_packages():
    """Check if required Python packages are installed"""
    required = ['selenium', 'requests', 'radon', 'bandit']
    missing = []
    
    for package in required:
        try:
            __import__(package)
            print(f"  ✅ {package}")
        except ImportError:
            missing.append(package)
            print(f"  ❌ {package} - MISSING")
    
    return missing

def check_rust_toolchain():
    """Check if Rust toolchain is available"""
    try:
        result = subprocess.run(['rustc', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"  ✅ Rust: {result.stdout.strip()}")
            return True
        else:
            print("  ❌ Rust: Not found")
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  ❌ Rust: Not found")
        return False

def check_chrome():
    """Check if Chrome is available"""
    import platform
    
    if platform.system() == 'Windows':
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe")
            chrome_path = winreg.QueryValue(key, None)
            print(f"  ✅ Chrome: Found at {chrome_path}")
            return True
        except:
            print("  ⚠️  Chrome: Could not verify (may still work)")
            return False
    else:
        # Linux/macOS check
        result = subprocess.run(['which', 'google-chrome'], capture_output=True)
        if result.returncode == 0:
            print("  ✅ Chrome: Found")
            return True
        else:
            print("  ⚠️  Chrome: Could not verify")
            return False

def check_binaries():
    """Check if Rust binaries are built"""
    project_root = Path(__file__).parent.parent
    binaries = [
        project_root / "rust" / "cryptex-cli" / "target" / "release" / "cryptex.exe",
        project_root / "rust" / "cryptex-api" / "target" / "release" / "cryptex-api.exe",
    ]
    
    found = 0
    for binary in binaries:
        if binary.exists():
            print(f"  ✅ {binary.name}")
            found += 1
        else:
            print(f"  ⚠️  {binary.name} - Not built (will build during cycle)")
    
    return found

def check_directories():
    """Check if required directories exist"""
    project_root = Path(__file__).parent.parent
    dirs = [
        project_root / "sdlc" / "cycles",
        project_root / "ua_logs" / "screenshots",
        project_root / "sdlc" / "reports",
    ]
    
    for dir_path in dirs:
        dir_path.mkdir(parents=True, exist_ok=True)
        print(f"  ✅ {dir_path.relative_to(project_root)}")
    
    return True

def main():
    """Run complete setup verification"""
    print("=" * 60)
    print("YARA Cryptex - SDLC Framework Setup Verification")
    print("=" * 60)
    print()
    
    print("[1/5] Checking Python packages...")
    missing = check_python_packages()
    if missing:
        print(f"\n⚠️  Missing packages. Install with:")
        print(f"   pip install {' '.join(missing)}")
    print()
    
    print("[2/5] Checking Rust toolchain...")
    rust_ok = check_rust_toolchain()
    print()
    
    print("[3/5] Checking Chrome browser...")
    chrome_ok = check_chrome()
    print()
    
    print("[4/5] Checking Rust binaries...")
    binaries_found = check_binaries()
    print()
    
    print("[5/5] Checking directories...")
    check_directories()
    print()
    
    print("=" * 60)
    print("Verification Summary")
    print("=" * 60)
    
    issues = []
    if missing:
        issues.append(f"Missing Python packages: {', '.join(missing)}")
    if not rust_ok:
        issues.append("Rust toolchain not found")
    if not chrome_ok:
        issues.append("Chrome browser not verified")
    
    if issues:
        print("⚠️  Issues found:")
        for issue in issues:
            print(f"   - {issue}")
        print()
        print("💡 Fix issues before running SDLC cycles")
    else:
        print("✅ All checks passed!")
        print()
        print("🚀 Ready to run SDLC cycles!")
        print("   Run: .\\sdlc\\start_ua_session.ps1")
    
    print("=" * 60)
    
    return len(issues) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

