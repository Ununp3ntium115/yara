"""
Cryptex Dictionary Validation Tool
Validates entries for completeness, consistency, and quality.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict

# Try workspace path first, then project root
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')
PROJECT_ROOT = Path(__file__).parent.parent

# Check which path exists
if (WORKSPACE / "data" / "cryptex.json").exists():
    CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
    PROJECT_ROOT = WORKSPACE
else:
    CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class CryptexValidator:
    """Validates Cryptex dictionary entries."""
    
    def __init__(self, cryptex_file: Path = None):
        self.cryptex_file = cryptex_file or CRYPTEX_FILE
        self.data = self._load_cryptex()
        self.issues = []
        self.warnings = []
    
    def _load_cryptex(self) -> Dict:
        """Load Cryptex dictionary."""
        if self.cryptex_file.exists():
            with open(self.cryptex_file, 'r') as f:
                return json.load(f)
        return {"entries": [], "metadata": {}}
    
    def validate_entry(self, entry: Dict, index: int) -> List[str]:
        """Validate a single entry."""
        issues = []
        
        # Required fields
        required_fields = ['symbol', 'pyro_name', 'kind', 'location', 'summary', 'pseudocode']
        for field in required_fields:
            if not entry.get(field):
                issues.append(f"Entry {index}: Missing required field '{field}'")
        
        # Field validation
        if entry.get('symbol') and not entry['symbol'].strip():
            issues.append(f"Entry {index}: Empty symbol name")
        
        if entry.get('pyro_name') and not entry['pyro_name'].strip():
            issues.append(f"Entry {index}: Empty codename")
        
        if entry.get('summary') and len(entry['summary']) > 160:
            issues.append(f"Entry {index}: Summary exceeds 160 characters")
        
        if entry.get('pseudocode') and len(entry['pseudocode']) < 10:
            self.warnings.append(f"Entry {index} ({entry.get('symbol')}): Pseudocode seems too short")
        
        # Line references validation
        line_refs = entry.get('line_references', [])
        if line_refs:
            for ref in line_refs:
                if 'file' not in ref or 'start' not in ref or 'end' not in ref:
                    issues.append(f"Entry {index}: Invalid line reference format")
                elif ref.get('start', 0) > ref.get('end', 0):
                    issues.append(f"Entry {index}: Line reference start > end")
        
        # Risk level validation
        valid_risks = ['critical', 'high', 'standard', 'informational']
        if entry.get('risk') and entry['risk'] not in valid_risks:
            issues.append(f"Entry {index}: Invalid risk level '{entry.get('risk')}'")
        
        # Kind validation
        valid_kinds = ['function', 'struct', 'module', 'cli', 'rule', 'script']
        if entry.get('kind') and entry['kind'] not in valid_kinds:
            issues.append(f"Entry {index}: Invalid kind '{entry.get('kind')}'")
        
        return issues
    
    def validate_uniqueness(self) -> List[str]:
        """Check for duplicate symbols and codenames."""
        issues = []
        symbols = defaultdict(list)
        codenames = defaultdict(list)
        
        for i, entry in enumerate(self.data.get("entries", [])):
            symbol = entry.get("symbol")
            codename = entry.get("pyro_name")
            
            if symbol:
                symbols[symbol].append(i)
            if codename:
                codenames[codename].append(i)
        
        # Check duplicate symbols
        for symbol, indices in symbols.items():
            if len(indices) > 1:
                issues.append(f"Duplicate symbol '{symbol}' at indices: {indices}")
        
        # Check duplicate codenames
        for codename, indices in codenames.items():
            if len(indices) > 1:
                issues.append(f"Duplicate codename '{codename}' at indices: {indices}")
        
        return issues
    
    def validate_dependencies(self) -> List[str]:
        """Validate that dependencies exist."""
        issues = []
        symbols = {e.get("symbol"): e.get("pyro_name") for e in self.data.get("entries", [])}
        codenames = set(symbols.values())
        
        for i, entry in enumerate(self.data.get("entries", [])):
            deps = entry.get("dependencies", [])
            for dep in deps:
                # Check if dependency is a codename or symbol
                if dep not in codenames and dep not in symbols:
                    self.warnings.append(
                        f"Entry {i} ({entry.get('symbol')}): "
                        f"Dependency '{dep}' not found in dictionary"
                    )
        
        return issues
    
    def validate_file_references(self) -> List[str]:
        """Validate that referenced files exist."""
        issues = []
        
        for i, entry in enumerate(self.data.get("entries", [])):
            location = entry.get("location", "")
            if location:
                file_path = PROJECT_ROOT / location
                if not file_path.exists():
                    issues.append(
                        f"Entry {i} ({entry.get('symbol')}): "
                        f"Referenced file does not exist: {location}"
                    )
        
        return issues
    
    def validate_all(self) -> Dict:
        """Run all validation checks."""
        print("=" * 60)
        print("Cryptex Dictionary Validation")
        print("=" * 60)
        
        entries = self.data.get("entries", [])
        print(f"\nValidating {len(entries)} entries...\n")
        
        # Validate each entry
        for i, entry in enumerate(entries):
            issues = self.validate_entry(entry, i)
            self.issues.extend(issues)
        
        # Validate uniqueness
        print("Checking uniqueness...")
        uniqueness_issues = self.validate_uniqueness()
        self.issues.extend(uniqueness_issues)
        
        # Validate dependencies
        print("Validating dependencies...")
        dep_issues = self.validate_dependencies()
        self.issues.extend(dep_issues)
        
        # Validate file references
        print("Validating file references...")
        file_issues = self.validate_file_references()
        self.issues.extend(file_issues)
        
        # Generate report
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate validation report."""
        total_entries = len(self.data.get("entries", []))
        critical_issues = len(self.issues)
        warnings_count = len(self.warnings)
        
        report = {
            "total_entries": total_entries,
            "critical_issues": critical_issues,
            "warnings": warnings_count,
            "issues": self.issues[:50],  # Limit to first 50
            "warnings_list": self.warnings[:50],  # Limit to first 50
            "status": "PASS" if critical_issues == 0 else "FAIL"
        }
        
        return report
    
    def print_report(self):
        """Print validation report."""
        report = self.validate_all()
        
        print("\n" + "=" * 60)
        print("Validation Report")
        print("=" * 60)
        print(f"Total entries: {report['total_entries']}")
        print(f"Critical issues: {report['critical_issues']}")
        print(f"Warnings: {report['warnings']}")
        print(f"Status: {report['status']}")
        
        if report['critical_issues'] > 0:
            print("\nCritical Issues:")
            for issue in report['issues'][:20]:
                print(f"  ⚠ {issue}")
        
        if report['warnings'] > 0:
            print("\nWarnings:")
            for warning in report['warnings_list'][:20]:
                print(f"  ⚠ {warning}")
        
        print("\n" + "=" * 60)


def validate_cryptex():
    """Convenience function to validate Cryptex dictionary."""
    validator = CryptexValidator()
    validator.print_report()
    return validator.generate_report()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate Cryptex dictionary")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    
    args = parser.parse_args()
    
    validator = CryptexValidator()
    
    if args.json:
        report = validator.validate_all()
        import json
        print(json.dumps(report, indent=2))
    else:
        validator.print_report()

