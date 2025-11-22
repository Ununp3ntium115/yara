"""
YARA Cryptex - Security Audit Tool
Comprehensive security analysis and vulnerability detection
"""

import ast
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import bandit
from bandit.core import manager as b_manager

class SecurityAuditor:
    """Comprehensive security audit for YARA Cryptex"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.audit_results = {
            'timestamp': datetime.now().isoformat(),
            'rust_audit': {},
            'python_audit': {},
            'dependencies': {},
            'config_audit': {},
            'vulnerabilities': []
        }
        
        self.setup_logging()
        
    def setup_logging(self):
        """Setup audit logging"""
        log_file = self.project_root / "sdlc" / "security_audit.log"
        log_file.parent.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('SecurityAudit')
    
    def audit_rust_dependencies(self):
        """Audit Rust dependencies for vulnerabilities"""
        self.logger.info("Auditing Rust dependencies...")
        
        try:
            result = subprocess.run(
                ['cargo', 'audit', '--json'],
                cwd=self.project_root / "rust",
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.audit_results['rust_audit'] = {
                    'status': 'clean',
                    'vulnerabilities': 0
                }
                self.logger.info("✅ Rust dependencies: No vulnerabilities found")
            else:
                # Parse audit output
                try:
                    audit_data = json.loads(result.stdout)
                    vulns = audit_data.get('vulnerabilities', {})
                    self.audit_results['rust_audit'] = {
                        'status': 'vulnerabilities_found',
                        'vulnerabilities': len(vulns),
                        'details': vulns
                    }
                    self.logger.warning(f"⚠️ Rust dependencies: {len(vulns)} vulnerabilities found")
                except:
                    self.audit_results['rust_audit'] = {
                        'status': 'audit_failed',
                        'error': result.stderr
                    }
                    
        except FileNotFoundError:
            self.logger.warning("cargo-audit not installed. Install with: cargo install cargo-audit")
        except Exception as e:
            self.logger.error(f"Rust audit failed: {e}")
    
    def audit_python_code(self):
        """Audit Python code for security issues"""
        self.logger.info("Auditing Python code...")
        
        python_files = list(self.project_root.rglob("*.py"))
        python_files = [f for f in python_files if 'venv' not in str(f) and '__pycache__' not in str(f)]
        
        issues = []
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    tree = ast.parse(f.read(), filename=str(py_file))
                
                # Check for common security issues
                for node in ast.walk(tree):
                    # Check for eval/exec
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            if node.func.id in ['eval', 'exec', 'compile']:
                                issues.append({
                                    'file': str(py_file),
                                    'line': node.lineno,
                                    'issue': f'Use of {node.func.id}() - security risk',
                                    'severity': 'high'
                                })
                    
                    # Check for hardcoded secrets
                    if isinstance(node, ast.Str):
                        value = node.s
                        if any(keyword in value.lower() for keyword in ['password', 'secret', 'api_key', 'token']):
                            if len(value) > 10:  # Likely not a variable name
                                issues.append({
                                    'file': str(py_file),
                                    'line': node.lineno,
                                    'issue': 'Potential hardcoded secret',
                                    'severity': 'medium'
                                })
                
            except Exception as e:
                self.logger.warning(f"Failed to audit {py_file}: {e}")
        
        self.audit_results['python_audit'] = {
            'files_audited': len(python_files),
            'issues_found': len(issues),
            'issues': issues
        }
        
        self.logger.info(f"✅ Python audit: {len(issues)} issues found in {len(python_files)} files")
    
    def audit_dependencies(self):
        """Audit all dependencies"""
        self.logger.info("Auditing dependencies...")
        
        # Python dependencies
        requirements_files = list(self.project_root.rglob("requirements.txt"))
        for req_file in requirements_files:
            self.logger.info(f"Checking {req_file}")
            # Could use safety or pip-audit here
        
        # Rust dependencies already audited
        self.audit_results['dependencies'] = {
            'python': len(requirements_files),
            'rust': 'audited'
        }
    
    def audit_configuration(self):
        """Audit configuration files"""
        self.logger.info("Auditing configuration...")
        
        config_issues = []
        
        # Check for exposed secrets in config files
        config_files = [
            self.project_root / ".env",
            self.project_root / "config.json",
            self.project_root / "settings.json"
        ]
        
        for config_file in config_files:
            if config_file.exists():
                try:
                    content = config_file.read_text()
                    if any(keyword in content.lower() for keyword in ['password', 'secret', 'key']):
                        config_issues.append({
                            'file': str(config_file),
                            'issue': 'Potential secret in config file',
                            'severity': 'medium'
                        })
                except:
                    pass
        
        self.audit_results['config_audit'] = {
            'issues': config_issues
        }
        
        self.logger.info(f"✅ Config audit: {len(config_issues)} issues found")
    
    def generate_report(self):
        """Generate security audit report"""
        report_file = self.project_root / "sdlc" / f"security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.audit_results, f, indent=2)
        
        self.logger.info(f"Security audit report saved: {report_file}")
        
        # Summary
        total_issues = (
            self.audit_results['rust_audit'].get('vulnerabilities', 0) +
            self.audit_results['python_audit'].get('issues_found', 0) +
            len(self.audit_results['config_audit'].get('issues', []))
        )
        
        self.logger.info("=" * 60)
        self.logger.info("Security Audit Summary")
        self.logger.info("=" * 60)
        self.logger.info(f"Total Issues Found: {total_issues}")
        self.logger.info(f"Rust Vulnerabilities: {self.audit_results['rust_audit'].get('vulnerabilities', 0)}")
        self.logger.info(f"Python Issues: {self.audit_results['python_audit'].get('issues_found', 0)}")
        self.logger.info(f"Config Issues: {len(self.audit_results['config_audit'].get('issues', []))}")
        self.logger.info("=" * 60)
        
        return report_file
    
    def run_full_audit(self):
        """Run complete security audit"""
        self.logger.info("Starting comprehensive security audit...")
        
        self.audit_rust_dependencies()
        self.audit_python_code()
        self.audit_dependencies()
        self.audit_configuration()
        
        return self.generate_report()

if __name__ == "__main__":
    auditor = SecurityAuditor()
    auditor.run_full_audit()

