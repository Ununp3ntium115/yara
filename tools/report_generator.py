#!/usr/bin/env python3
"""
YARA Cryptex - Comprehensive Report Generator
Generates HTML, PDF, and JSON reports from scan results, test results, and system status
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import argparse

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

class ReportGenerator:
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def load_scan_results(self, scan_file: Path) -> Dict:
        """Load scan results from JSON file"""
        try:
            with open(scan_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading scan results: {e}")
            return {}
    
    def load_test_results(self, test_dir: Path) -> List[Dict]:
        """Load all test result files"""
        results = []
        if not test_dir.exists():
            return results
        
        for result_file in test_dir.glob("result_*.json"):
            try:
                with open(result_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    data['rule_name'] = result_file.stem.replace('result_', '')
                    results.append(data)
            except Exception as e:
                print(f"[!] Error loading {result_file}: {e}")
        
        return results
    
    def load_audit_report(self, audit_file: Path) -> Dict:
        """Load audit report"""
        try:
            with open(audit_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading audit report: {e}")
            return {}
    
    def generate_summary_stats(self, scan_results: Dict, test_results: List[Dict], audit_report: Dict) -> Dict:
        """Generate summary statistics"""
        stats = {
            "timestamp": datetime.now().isoformat(),
            "scan": {
                "total_scanned": scan_results.get("total_scanned", 0),
                "total_matches": scan_results.get("total_matches", 0),
                "matches": len(scan_results.get("matches", [])),
            },
            "tests": {
                "total_tests": len(test_results),
                "successful": sum(1 for r in test_results if r.get("total_matches") is not None),
                "failed": sum(1 for r in test_results if "error" in r),
            },
            "system": {
                "status": audit_report.get("summary", {}).get("status", "Unknown"),
                "total_issues": audit_report.get("summary", {}).get("total_issues", 0),
                "components": {
                    "rust": len(audit_report.get("rust", {}).get("crates", {})),
                    "redb": "OK" if not audit_report.get("redb", {}).get("issues") else "Issues",
                    "node_red": len(audit_report.get("node_red", {}).get("nodes", {})),
                    "svelte": len(audit_report.get("svelte", {}).get("components", {})),
                }
            }
        }
        return stats
    
    def generate_html_report(self, stats: Dict, scan_results: Dict, test_results: List[Dict], audit_report: Dict) -> str:
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YARA Cryptex - Comprehensive Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-left: 10px;
            border-left: 4px solid #3498db;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            font-size: 14px;
            opacity: 0.9;
            margin-bottom: 10px;
        }
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
        }
        .section {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 6px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #3498db;
            color: white;
            font-weight: 600;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge-success { background: #27ae60; color: white; }
        .badge-warning { background: #f39c12; color: white; }
        .badge-error { background: #e74c3c; color: white; }
        .badge-info { background: #3498db; color: white; }
        .timestamp {
            color: #7f8c8d;
            font-size: 14px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>YARA Cryptex - Comprehensive Report</h1>
        <div class="timestamp">Generated: {{ stats.timestamp }}</div>
        
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="stat-card">
                <h3>Files Scanned</h3>
                <div class="value">{{ stats.scan.total_scanned }}</div>
            </div>
            <div class="stat-card">
                <h3>Matches Found</h3>
                <div class="value">{{ stats.scan.total_matches }}</div>
            </div>
            <div class="stat-card">
                <h3>Rules Tested</h3>
                <div class="value">{{ stats.tests.total_tests }}</div>
            </div>
            <div class="stat-card">
                <h3>System Status</h3>
                <div class="value">{{ stats.system.status }}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Scan Results</h2>
            <p><strong>Total Scanned:</strong> {{ stats.scan.total_scanned }}</p>
            <p><strong>Total Matches:</strong> {{ stats.scan.total_matches }}</p>
            {% if scan_results.matches %}
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Rule</th>
                        <th>Tags</th>
                    </tr>
                </thead>
                <tbody>
                    {% for match in scan_results.matches[:20] %}
                    <tr>
                        <td>{{ match.file }}</td>
                        <td>{{ match.rule }}</td>
                        <td>{{ match.tags|join(', ') if match.tags else 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No matches found.</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Test Results</h2>
            <p><strong>Total Tests:</strong> {{ stats.tests.total_tests }}</p>
            <p><strong>Successful:</strong> {{ stats.tests.successful }}</p>
            <p><strong>Failed:</strong> {{ stats.tests.failed }}</p>
            {% if test_results %}
            <table>
                <thead>
                    <tr>
                        <th>Rule</th>
                        <th>Status</th>
                        <th>Matches</th>
                        <th>Scanned</th>
                    </tr>
                </thead>
                <tbody>
                    {% for test in test_results[:20] %}
                    <tr>
                        <td>{{ test.rule_name }}</td>
                        <td>
                            {% if test.total_matches is not none %}
                            <span class="badge badge-success">Success</span>
                            {% elif test.error %}
                            <span class="badge badge-error">Error</span>
                            {% else %}
                            <span class="badge badge-warning">Warning</span>
                            {% endif %}
                        </td>
                        <td>{{ test.total_matches or 0 }}</td>
                        <td>{{ test.total_scanned or 0 }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>System Status</h2>
            <p><strong>Overall Status:</strong> 
                <span class="badge {% if stats.system.status == '[OK] COMPLETE' %}badge-success{% else %}badge-warning{% endif %}">
                    {{ stats.system.status }}
                </span>
            </p>
            <p><strong>Total Issues:</strong> {{ stats.system.total_issues }}</p>
            <h3>Components</h3>
            <ul>
                <li><strong>Rust:</strong> {{ stats.system.components.rust }} crates</li>
                <li><strong>redb:</strong> {{ stats.system.components.redb }}</li>
                <li><strong>Node-RED:</strong> {{ stats.system.components.node_red }} nodes</li>
                <li><strong>Svelte:</strong> {{ stats.system.components.svelte }} components</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                {% if stats.scan.total_matches > 0 %}
                <li>Review {{ stats.scan.total_matches }} matches found in scan results</li>
                {% endif %}
                {% if stats.tests.failed > 0 %}
                <li>Investigate {{ stats.tests.failed }} failed test(s)</li>
                {% endif %}
                {% if stats.system.total_issues > 0 %}
                <li>Address {{ stats.system.total_issues }} system issue(s)</li>
                {% endif %}
                {% if stats.scan.total_matches == 0 and stats.tests.failed == 0 and stats.system.total_issues == 0 %}
                <li>✅ System is operating normally - no issues detected</li>
                {% endif %}
            </ul>
        </div>
    </div>
</body>
</html>
        """
        
        if JINJA2_AVAILABLE:
            template = Template(html_template)
            return template.render(
                stats=stats,
                scan_results=scan_results,
                test_results=test_results,
                audit_report=audit_report
            )
        else:
            # Simple string replacement if Jinja2 not available
            html = html_template
            html = html.replace("{{ stats.timestamp }}", stats.get("timestamp", ""))
            html = html.replace("{{ stats.scan.total_scanned }}", str(stats.get("scan", {}).get("total_scanned", 0)))
            html = html.replace("{{ stats.scan.total_matches }}", str(stats.get("scan", {}).get("total_matches", 0)))
            html = html.replace("{{ stats.tests.total_tests }}", str(stats.get("tests", {}).get("total_tests", 0)))
            html = html.replace("{{ stats.system.status }}", stats.get("system", {}).get("status", "Unknown"))
            return html
    
    def generate_json_report(self, stats: Dict, scan_results: Dict, test_results: List[Dict], audit_report: Dict) -> Dict:
        """Generate JSON report"""
        return {
            "report_metadata": {
                "generated_at": stats["timestamp"],
                "version": "1.0",
                "report_type": "comprehensive"
            },
            "summary": stats,
            "scan_results": scan_results,
            "test_results": test_results,
            "system_audit": audit_report
        }
    
    def save_report(self, content: str, filename: str, format: str = "html"):
        """Save report to file"""
        output_file = self.output_dir / f"{filename}_{self.timestamp}.{format}"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        return output_file
    
    def generate_comprehensive_report(self, 
                                     scan_file: Optional[Path] = None,
                                     test_dir: Optional[Path] = None,
                                     audit_file: Optional[Path] = None,
                                     formats: List[str] = ["html", "json"]):
        """Generate comprehensive report from all sources"""
        print("[*] Generating comprehensive report...")
        
        # Load data
        scan_results = {}
        if scan_file and scan_file.exists():
            print(f"[*] Loading scan results from: {scan_file}")
            scan_results = self.load_scan_results(scan_file)
        
        test_results = []
        if test_dir and test_dir.exists():
            print(f"[*] Loading test results from: {test_dir}")
            test_results = self.load_test_results(test_dir)
        
        audit_report = {}
        if audit_file and audit_file.exists():
            print(f"[*] Loading audit report from: {audit_file}")
            audit_report = self.load_audit_report(audit_file)
        
        # Generate statistics
        stats = self.generate_summary_stats(scan_results, test_results, audit_report)
        
        # Generate reports in requested formats
        generated_files = []
        
        if "html" in formats:
            print("[*] Generating HTML report...")
            html_content = self.generate_html_report(stats, scan_results, test_results, audit_report)
            html_file = self.save_report(html_content, "comprehensive_report", "html")
            generated_files.append(html_file)
            print(f"[+] HTML report saved: {html_file}")
        
        if "json" in formats:
            print("[*] Generating JSON report...")
            json_report = self.generate_json_report(stats, scan_results, test_results, audit_report)
            json_file = self.save_report(json.dumps(json_report, indent=2), "comprehensive_report", "json")
            generated_files.append(json_file)
            print(f"[+] JSON report saved: {json_file}")
        
        print(f"\n[+] Report generation complete!")
        print(f"[*] Generated {len(generated_files)} file(s)")
        
        return generated_files


def main():
    parser = argparse.ArgumentParser(description="Generate comprehensive YARA Cryptex reports")
    parser.add_argument("--scan-results", type=Path, help="Path to scan results JSON file")
    parser.add_argument("--test-results", type=Path, default=Path("test_rules"), help="Path to test results directory")
    parser.add_argument("--audit-report", type=Path, default=Path("audit_report.json"), help="Path to audit report JSON")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"), help="Output directory for reports")
    parser.add_argument("--format", nargs="+", choices=["html", "json", "pdf"], default=["html", "json"], help="Report formats to generate")
    
    args = parser.parse_args()
    
    generator = ReportGenerator(output_dir=args.output_dir)
    generator.generate_comprehensive_report(
        scan_file=args.scan_results,
        test_dir=args.test_results,
        audit_file=args.audit_report,
        formats=args.format
    )


if __name__ == "__main__":
    main()

