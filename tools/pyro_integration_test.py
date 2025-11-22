"""
Integration test for YARA Cryptex - PYRO Platform connection.
"""

import json
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).parent.parent
PYRO_PLATFORM_DIR = PROJECT_ROOT / "pyro-platform"
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')

if (WORKSPACE / "data" / "cryptex.json").exists():
    YARA_CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
else:
    YARA_CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class IntegrationTester:
    """Test YARA Cryptex - PYRO Platform integration."""
    
    def __init__(self):
        self.yara_cryptex = self._load_yara_cryptex()
        self.pyro_dict_file = PYRO_PLATFORM_DIR / "pyro" / "src" / "integrations" / "yara" / "cryptex" / "yara_cryptex_dictionary.json"
    
    def _load_yara_cryptex(self) -> Dict:
        """Load YARA Cryptex dictionary."""
        if YARA_CRYPTEX_FILE.exists():
            with open(YARA_CRYPTEX_FILE, 'r') as f:
                return json.load(f)
        return {"entries": []}
    
    def test_dictionary_export(self) -> Dict:
        """Test if dictionary was exported correctly."""
        results = {
            "test": "dictionary_export",
            "passed": False,
            "details": {}
        }
        
        if not self.pyro_dict_file.exists():
            results["details"]["error"] = "Dictionary file not found"
            return results
        
        try:
            with open(self.pyro_dict_file, 'r') as f:
                exported = json.load(f)
            
            yara_entries = self.yara_cryptex.get("entries", [])
            exported_entries = exported.get("entries", [])
            
            results["details"]["yara_entries"] = len(yara_entries)
            results["details"]["exported_entries"] = len(exported_entries)
            results["details"]["match"] = len(yara_entries) == len(exported_entries)
            
            # Check sample entries
            if yara_entries and exported_entries:
                sample_yara = yara_entries[0]
                sample_exported = exported_entries[0]
                
                results["details"]["sample_match"] = (
                    sample_yara.get("symbol") == sample_exported.get("symbol") and
                    sample_yara.get("pyro_name") == sample_exported.get("pyro_name")
                )
            
            results["passed"] = (
                results["details"]["match"] and
                results["details"].get("sample_match", False)
            )
            
        except Exception as e:
            results["details"]["error"] = str(e)
        
        return results
    
    def test_rust_code_generation(self) -> Dict:
        """Test if Rust code was generated."""
        results = {
            "test": "rust_code_generation",
            "passed": False,
            "details": {}
        }
        
        rust_file = PYRO_PLATFORM_DIR / "pyro" / "src" / "integrations" / "yara" / "cryptex" / "yara_cryptex_dictionary.rs"
        
        if not rust_file.exists():
            results["details"]["error"] = "Rust file not found"
            return results
        
        try:
            content = rust_file.read_text(encoding='utf-8')
            
            results["details"]["file_size"] = len(content)
            results["details"]["has_struct"] = "struct CryptexEntry" in content
            results["details"]["has_impl"] = "impl YaraCryptexDictionary" in content
            results["details"]["has_lookup"] = "lookup_codename" in content
            results["details"]["has_entries"] = "get_all_entries" in content
            
            results["passed"] = all([
                results["details"]["has_struct"],
                results["details"]["has_impl"],
                results["details"]["has_lookup"],
                results["details"]["has_entries"]
            ])
            
        except Exception as e:
            results["details"]["error"] = str(e)
        
        return results
    
    def test_module_file(self) -> Dict:
        """Test if module file exists."""
        results = {
            "test": "module_file",
            "passed": False,
            "details": {}
        }
        
        mod_file = PYRO_PLATFORM_DIR / "pyro" / "src" / "integrations" / "yara" / "cryptex" / "mod.rs"
        
        if not mod_file.exists():
            results["details"]["error"] = "Module file not found"
            return results
        
        try:
            content = mod_file.read_text(encoding='utf-8')
            
            results["details"]["has_mod"] = "mod yara_cryptex_dictionary" in content
            results["details"]["has_pub_use"] = "pub use" in content
            
            results["passed"] = results["details"]["has_mod"] and results["details"]["has_pub_use"]
            
        except Exception as e:
            results["details"]["error"] = str(e)
        
        return results
    
    def test_frontend_component(self) -> Dict:
        """Test if frontend component was generated."""
        results = {
            "test": "frontend_component",
            "passed": False,
            "details": {}
        }
        
        component_file = PYRO_PLATFORM_DIR / "frontend-svelte" / "src" / "routes" / "tools" / "yara" / "cryptex" / "+page.svelte"
        
        if not component_file.exists():
            results["details"]["error"] = "Frontend component not found"
            return results
        
        try:
            content = component_file.read_text(encoding='utf-8')
            
            results["details"]["file_size"] = len(content)
            results["details"]["has_script"] = "<script>" in content
            results["details"]["has_cryptex_api"] = "cryptexAPI" in content
            results["details"]["has_template"] = "<div class=\"cryptex-browser\">" in content
            results["details"]["has_style"] = "<style>" in content
            
            results["passed"] = all([
                results["details"]["has_script"],
                results["details"]["has_cryptex_api"],
                results["details"]["has_template"],
                results["details"]["has_style"]
            ])
            
        except Exception as e:
            results["details"]["error"] = str(e)
        
        return results
    
    def run_all_tests(self) -> Dict:
        """Run all integration tests."""
        tests = [
            self.test_dictionary_export(),
            self.test_rust_code_generation(),
            self.test_module_file(),
            self.test_frontend_component()
        ]
        
        passed = sum(1 for t in tests if t["passed"])
        total = len(tests)
        
        return {
            "summary": {
                "total_tests": total,
                "passed": passed,
                "failed": total - passed,
                "success_rate": f"{(passed / total * 100):.1f}%"
            },
            "tests": tests
        }


def run_integration_tests():
    """Run integration tests."""
    tester = IntegrationTester()
    return tester.run_all_tests()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test YARA Cryptex - PYRO Platform integration")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    
    args = parser.parse_args()
    
    tester = IntegrationTester()
    results = tester.run_all_tests()
    
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("=" * 60)
        print("YARA Cryptex - PYRO Platform Integration Tests")
        print("=" * 60)
        print()
        print(f"Total Tests: {results['summary']['total_tests']}")
        print(f"Passed: {results['summary']['passed']}")
        print(f"Failed: {results['summary']['failed']}")
        print(f"Success Rate: {results['summary']['success_rate']}")
        print()
        
        for test in results["tests"]:
            status = "PASS" if test["passed"] else "FAIL"
            print(f"{status}: {test['test']}")
            if not test["passed"]:
                print(f"  Error: {test['details'].get('error', 'Unknown error')}")
        print()
        print("=" * 60)

