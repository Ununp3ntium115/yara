"""
YARA Cryptex - Code Simplification Analyzer
Identifies complexity, redundancy, and simplification opportunities
"""

import ast
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import radon.complexity
from radon.metrics import mi_visit

class CodeSimplifier:
    """Analyze and simplify code"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'rust_analysis': {},
            'python_analysis': {},
            'complexity_issues': [],
            'redundancy_issues': [],
            'simplification_opportunities': []
        }
        
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging"""
        log_file = self.project_root / "sdlc" / "code_simplification.log"
        log_file.parent.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('CodeSimplifier')
    
    def analyze_python_complexity(self):
        """Analyze Python code complexity"""
        self.logger.info("Analyzing Python code complexity...")
        
        python_files = list(self.project_root.rglob("*.py"))
        python_files = [f for f in python_files if 'venv' not in str(f) and '__pycache__' not in str(f)]
        
        complexity_issues = []
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                # Calculate complexity
                try:
                    complexity = radon.complexity.cc_visit(code)
                    mi_score = mi_visit(code, multi=True)
                    
                    # Check for high complexity
                    for item in complexity:
                        if item.complexity > 10:
                            complexity_issues.append({
                                'file': str(py_file),
                                'function': item.name,
                                'complexity': item.complexity,
                                'line': item.lineno,
                                'maintainability': mi_score,
                                'recommendation': 'Consider refactoring to reduce complexity'
                            })
                except:
                    pass
                
            except Exception as e:
                self.logger.warning(f"Failed to analyze {py_file}: {e}")
        
        self.analysis_results['python_analysis'] = {
            'files_analyzed': len(python_files),
            'complexity_issues': len(complexity_issues),
            'issues': complexity_issues
        }
        
        self.logger.info(f"✅ Python analysis: {len(complexity_issues)} complexity issues found")
    
    def find_redundant_code(self):
        """Find redundant code patterns"""
        self.logger.info("Finding redundant code...")
        
        python_files = list(self.project_root.rglob("*.py"))
        python_files = [f for f in python_files if 'venv' not in str(f) and '__pycache__' not in str(f)]
        
        # Simple pattern matching for common redundancies
        redundant_patterns = []
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                # Check for duplicate code blocks
                seen_blocks = {}
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    if len(stripped) > 20:  # Significant line
                        if stripped in seen_blocks:
                            redundant_patterns.append({
                                'file': str(py_file),
                                'line': i + 1,
                                'pattern': stripped[:50],
                                'duplicate_of': seen_blocks[stripped]
                            })
                        else:
                            seen_blocks[stripped] = i + 1
                
            except Exception as e:
                self.logger.warning(f"Failed to check {py_file}: {e}")
        
        self.analysis_results['redundancy_issues'] = redundant_patterns
        self.logger.info(f"✅ Redundancy check: {len(redundant_patterns)} potential duplicates found")
    
    def identify_simplification_opportunities(self):
        """Identify code simplification opportunities"""
        self.logger.info("Identifying simplification opportunities...")
        
        opportunities = []
        
        # Check Rust code for simplification
        rust_files = list((self.project_root / "rust").rglob("*.rs"))
        
        for rust_file in rust_files[:10]:  # Sample first 10
            try:
                with open(rust_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for long functions
                lines = content.split('\n')
                in_function = False
                function_start = 0
                brace_count = 0
                
                for i, line in enumerate(lines):
                    if 'fn ' in line and '{' in line:
                        in_function = True
                        function_start = i
                        brace_count = line.count('{') - line.count('}')
                    elif in_function:
                        brace_count += line.count('{') - line.count('}')
                        if brace_count == 0:
                            function_length = i - function_start
                            if function_length > 100:
                                opportunities.append({
                                    'file': str(rust_file),
                                    'line': function_start + 1,
                                    'issue': f'Long function ({function_length} lines)',
                                    'recommendation': 'Consider breaking into smaller functions'
                                })
                            in_function = False
                
            except Exception as e:
                self.logger.warning(f"Failed to analyze {rust_file}: {e}")
        
        self.analysis_results['simplification_opportunities'] = opportunities
        self.logger.info(f"✅ Simplification: {len(opportunities)} opportunities identified")
    
    def generate_report(self):
        """Generate simplification report"""
        report_file = self.project_root / "sdlc" / f"code_simplification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.analysis_results, f, indent=2)
        
        self.logger.info(f"Code simplification report saved: {report_file}")
        
        # Summary
        total_issues = (
            self.analysis_results['python_analysis'].get('complexity_issues', 0) +
            len(self.analysis_results['redundancy_issues']) +
            len(self.analysis_results['simplification_opportunities'])
        )
        
        self.logger.info("=" * 60)
        self.logger.info("Code Simplification Summary")
        self.logger.info("=" * 60)
        self.logger.info(f"Total Issues: {total_issues}")
        self.logger.info(f"Complexity Issues: {self.analysis_results['python_analysis'].get('complexity_issues', 0)}")
        self.logger.info(f"Redundancy Issues: {len(self.analysis_results['redundancy_issues'])}")
        self.logger.info(f"Simplification Opportunities: {len(self.analysis_results['simplification_opportunities'])}")
        self.logger.info("=" * 60)
        
        return report_file
    
    def run_full_analysis(self):
        """Run complete code simplification analysis"""
        self.logger.info("Starting code simplification analysis...")
        
        self.analyze_python_complexity()
        self.find_redundant_code()
        self.identify_simplification_opportunities()
        
        return self.generate_report()

if __name__ == "__main__":
    simplifier = CodeSimplifier()
    simplifier.run_full_analysis()

