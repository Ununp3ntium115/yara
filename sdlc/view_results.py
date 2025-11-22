"""
YARA Cryptex - SDLC Results Viewer
View and analyze SDLC cycle results
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

class ResultsViewer:
    """View and analyze SDLC results"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.sdlc_dir = self.project_root / "sdlc"
        self.ua_logs_dir = self.project_root / "ua_logs"
    
    def find_latest_report(self, pattern: str, directory: Path) -> Optional[Path]:
        """Find latest report matching pattern"""
        reports = list(directory.glob(pattern))
        if reports:
            return max(reports, key=lambda p: p.stat().st_mtime)
        return None
    
    def load_json(self, file_path: Path) -> Optional[Dict]:
        """Load JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"  ⚠️  Error loading {file_path.name}: {e}")
            return None
    
    def view_security_audit(self):
        """View security audit results"""
        print("\n" + "=" * 60)
        print("Security Audit Results")
        print("=" * 60)
        
        report = self.find_latest_report("security_audit_*.json", self.sdlc_dir)
        if not report:
            print("  ⚠️  No security audit reports found")
            return
        
        data = self.load_json(report)
        if not data:
            return
        
        print(f"\n📄 Report: {report.name}")
        print(f"📅 Timestamp: {data.get('timestamp', 'Unknown')}")
        
        # Rust audit
        rust_audit = data.get('rust_audit', {})
        if rust_audit:
            print(f"\n🔧 Rust Dependencies:")
            status = rust_audit.get('status', 'unknown')
            vulns = rust_audit.get('vulnerabilities', 0)
            if status == 'clean':
                print(f"  ✅ Status: Clean ({vulns} vulnerabilities)")
            else:
                print(f"  ⚠️  Status: {status} ({vulns} vulnerabilities)")
        
        # Python audit
        python_audit = data.get('python_audit', {})
        if python_audit:
            files = python_audit.get('files_audited', 0)
            issues = python_audit.get('issues_found', 0)
            print(f"\n🐍 Python Code:")
            print(f"  📁 Files audited: {files}")
            print(f"  ⚠️  Issues found: {issues}")
            
            if issues > 0:
                print(f"\n  Issues:")
                for issue in python_audit.get('issues', [])[:5]:
                    print(f"    • {issue.get('file', 'Unknown')}:{issue.get('line', '?')}")
                    print(f"      {issue.get('issue', 'Unknown issue')} ({issue.get('severity', 'unknown')})")
                if issues > 5:
                    print(f"    ... and {issues - 5} more")
        
        # Config audit
        config_audit = data.get('config_audit', {})
        if config_audit:
            config_issues = len(config_audit.get('issues', []))
            if config_issues > 0:
                print(f"\n⚙️  Configuration:")
                print(f"  ⚠️  Issues found: {config_issues}")
    
    def view_code_simplification(self):
        """View code simplification results"""
        print("\n" + "=" * 60)
        print("Code Simplification Results")
        print("=" * 60)
        
        report = self.find_latest_report("code_simplification_*.json", self.sdlc_dir)
        if not report:
            print("  ⚠️  No code simplification reports found")
            return
        
        data = self.load_json(report)
        if not data:
            return
        
        print(f"\n📄 Report: {report.name}")
        print(f"📅 Timestamp: {data.get('timestamp', 'Unknown')}")
        
        # Python analysis
        python_analysis = data.get('python_analysis', {})
        if python_analysis:
            files = python_analysis.get('files_analyzed', 0)
            issues = python_analysis.get('complexity_issues', 0)
            print(f"\n🐍 Python Code Analysis:")
            print(f"  📁 Files analyzed: {files}")
            print(f"  ⚠️  Complexity issues: {issues}")
            
            if issues > 0:
                print(f"\n  High Complexity Functions:")
                for issue in python_analysis.get('issues', [])[:5]:
                    print(f"    • {issue.get('file', 'Unknown')}:{issue.get('line', '?')}")
                    print(f"      {issue.get('function', 'Unknown')} - Complexity: {issue.get('complexity', '?')}")
                if issues > 5:
                    print(f"    ... and {issues - 5} more")
        
        # Redundancy
        redundancy = len(data.get('redundancy_issues', []))
        if redundancy > 0:
            print(f"\n🔄 Redundancy:")
            print(f"  ⚠️  Potential duplicates: {redundancy}")
        
        # Simplification opportunities
        opportunities = len(data.get('simplification_opportunities', []))
        if opportunities > 0:
            print(f"\n✨ Simplification Opportunities:")
            print(f"  💡 {opportunities} opportunities identified")
    
    def view_ua_interactions(self):
        """View UA interaction logs"""
        print("\n" + "=" * 60)
        print("UA Interaction Logs")
        print("=" * 60)
        
        log_file = self.find_latest_report("interactions_*.json", self.ua_logs_dir)
        if not log_file:
            print("  ⚠️  No interaction logs found")
            return
        
        data = self.load_json(log_file)
        if not data:
            return
        
        print(f"\n📄 Log: {log_file.name}")
        
        if isinstance(data, list):
            total = len(data)
            print(f"📊 Total interactions: {total}")
            
            # Count by type
            types = {}
            for interaction in data:
                itype = interaction.get('type', 'unknown')
                types[itype] = types.get(itype, 0) + 1
            
            print(f"\n📈 Interaction Types:")
            for itype, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
                print(f"  • {itype}: {count}")
            
            # Show recent interactions
            print(f"\n🕐 Recent Interactions (last 5):")
            for interaction in data[-5:]:
                timestamp = interaction.get('timestamp', 'Unknown')
                itype = interaction.get('type', 'unknown')
                element = interaction.get('element', 'unknown')
                action = interaction.get('action', 'unknown')
                print(f"  • [{timestamp}] {itype} - {element} - {action}")
    
    def view_screenshots(self):
        """View screenshot information"""
        print("\n" + "=" * 60)
        print("Screenshots")
        print("=" * 60)
        
        screenshots_dir = self.ua_logs_dir / "screenshots"
        if not screenshots_dir.exists():
            print("  ⚠️  Screenshots directory not found")
            return
        
        screenshots = list(screenshots_dir.glob("*.png"))
        if not screenshots:
            print("  ⚠️  No screenshots found")
            return
        
        print(f"\n📸 Total screenshots: {len(screenshots)}")
        print(f"\n🕐 Recent screenshots (last 5):")
        for screenshot in sorted(screenshots, key=lambda p: p.stat().st_mtime, reverse=True)[:5]:
            size = screenshot.stat().st_size / 1024  # KB
            mtime = datetime.fromtimestamp(screenshot.stat().st_mtime)
            print(f"  • {screenshot.name}")
            print(f"    Size: {size:.1f} KB | Time: {mtime.strftime('%Y-%m-%d %H:%M:%S')}")
    
    def view_cycle_report(self):
        """View SDLC cycle report"""
        print("\n" + "=" * 60)
        print("SDLC Cycle Report")
        print("=" * 60)
        
        cycles_dir = self.sdlc_dir / "cycles"
        if not cycles_dir.exists():
            print("  ⚠️  Cycles directory not found")
            return
        
        report = self.find_latest_report("cycle_*.json", cycles_dir)
        if not report:
            print("  ⚠️  No cycle reports found")
            return
        
        data = self.load_json(report)
        if not data:
            return
        
        print(f"\n📄 Report: {report.name}")
        print(f"🔄 Cycle: {data.get('cycle_number', 'Unknown')}")
        print(f"📅 Start: {data.get('start_time', 'Unknown')}")
        print(f"📅 End: {data.get('end_time', 'Unknown')}")
        duration = data.get('duration', 0)
        print(f"⏱️  Duration: {duration:.1f} seconds")
        
        print(f"\n📋 Steps:")
        for step in data.get('steps', []):
            step_name = step.get('step', 'unknown')
            status = step.get('status', 'unknown')
            if status == 'completed':
                print(f"  ✅ {step_name}")
            elif status == 'failed':
                print(f"  ❌ {step_name}")
                if 'error' in step:
                    print(f"     Error: {step['error']}")
            else:
                print(f"  ⚠️  {step_name}: {status}")
    
    def view_all(self):
        """View all results"""
        print("\n" + "=" * 80)
        print("YARA Cryptex - SDLC Results Summary")
        print("=" * 80)
        
        self.view_cycle_report()
        self.view_security_audit()
        self.view_code_simplification()
        self.view_ua_interactions()
        self.view_screenshots()
        
        print("\n" + "=" * 80)
        print("Summary Complete")
        print("=" * 80)
        print("\n💡 Tip: Run SDLC cycles to generate more results")
        print("   .\\sdlc\\run_first_cycle.ps1")

def main():
    """Main entry point"""
    viewer = ResultsViewer()
    viewer.view_all()

if __name__ == "__main__":
    main()

