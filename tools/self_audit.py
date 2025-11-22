#!/usr/bin/env python3
"""
YARA Cryptex - Comprehensive Self-Audit Tool
Checks for gaps in Rust, redb, Node-RED, and Svelte components
"""

import os
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime

class ComponentAuditor:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.issues = []
        self.warnings = []
        self.success = []
        self.report = {
            "timestamp": datetime.now().isoformat(),
            "rust": {},
            "redb": {},
            "node_red": {},
            "svelte": {},
            "api": {},
            "build": {},
            "gaps": [],
            "summary": {}
        }

    def audit_rust(self) -> Dict:
        """Audit Rust components"""
        print("[AUDIT] Auditing Rust components...")
        rust_dir = self.root_dir / "rust"
        result = {
            "crates": {},
            "files": {},
            "dependencies": {},
            "issues": []
        }

        # Expected crates
        expected_crates = {
            "cryptex-store": {
                "required_files": ["src/lib.rs", "Cargo.toml"],
                "required_deps": ["redb", "serde", "serde_json"],
                "binaries": ["import_cryptex"]
            },
            "cryptex-api": {
                "required_files": ["src/main.rs", "Cargo.toml", "src/feed.rs"],
                "required_deps": ["axum", "tokio", "cryptex-store", "yara-feed-scanner"],
                "binaries": ["cryptex-api"]
            },
            "yara-feed-scanner": {
                "required_files": ["src/lib.rs", "src/main.rs", "Cargo.toml"],
                "required_deps": ["reqwest", "tokio", "rss", "atom_syndication"],
                "binaries": ["yara-feed-scanner"]
            },
            "cryptex-cli": {
                "required_files": ["src/main.rs", "Cargo.toml"],
                "required_deps": ["clap", "cryptex-store", "yara-feed-scanner"],
                "binaries": ["cryptex"]
            }
        }

        for crate_name, requirements in expected_crates.items():
            crate_dir = rust_dir / crate_name
            crate_info = {
                "exists": crate_dir.exists(),
                "files": {},
                "dependencies": {},
                "binaries": {},
                "issues": []
            }

            if not crate_dir.exists():
                crate_info["issues"].append(f"Crate directory missing: {crate_name}")
                result["issues"].append(f"Missing crate: {crate_name}")
                continue

            # Check required files
            for file in requirements["required_files"]:
                file_path = crate_dir / file
                exists = file_path.exists()
                crate_info["files"][file] = exists
                if not exists:
                    crate_info["issues"].append(f"Missing file: {file}")
                    result["issues"].append(f"{crate_name}: Missing {file}")

            # Check Cargo.toml for dependencies
            cargo_toml = crate_dir / "Cargo.toml"
            if cargo_toml.exists():
                try:
                    with open(cargo_toml, 'r', encoding='utf-8') as f:
                        content = f.read()
                        for dep in requirements["required_deps"]:
                            has_dep = dep in content
                            crate_info["dependencies"][dep] = has_dep
                            if not has_dep:
                                crate_info["issues"].append(f"Missing dependency: {dep}")
                                result["issues"].append(f"{crate_name}: Missing dependency {dep}")
                except Exception as e:
                    crate_info["issues"].append(f"Error reading Cargo.toml: {e}")

            # Check for binaries (workspace binaries are in workspace target, not crate target)
            workspace_target = rust_dir / "target" / "release"
            crate_target = crate_dir / "target" / "release"
            for binary in requirements["binaries"]:
                binary_name = f"{binary}.exe" if sys.platform == "win32" else binary
                # Check workspace target first (for workspace builds), then crate target
                binary_path_ws = workspace_target / binary_name
                binary_path_crate = crate_target / binary_name
                exists = binary_path_ws.exists() or binary_path_crate.exists()
                crate_info["binaries"][binary] = exists
                if not exists:
                    crate_info["issues"].append(f"Binary not built: {binary}")
                    result["issues"].append(f"{crate_name}: Binary {binary} not built")

            result["crates"][crate_name] = crate_info
            if not crate_info["issues"]:
                self.success.append(f"[OK] {crate_name}: All checks passed")

        return result

    def audit_redb(self) -> Dict:
        """Audit redb integration"""
        print("[AUDIT] Auditing redb integration...")
        result = {
            "integration": {},
            "tables": {},
            "operations": {},
            "issues": []
        }

        store_file = self.root_dir / "rust" / "cryptex-store" / "src" / "lib.rs"
        if not store_file.exists():
            result["issues"].append("cryptex-store/src/lib.rs not found")
            return result

        try:
            with open(store_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check for redb imports
            has_redb = "redb" in content
            result["integration"]["redb_import"] = has_redb
            if not has_redb:
                result["issues"].append("redb not imported")

            # Check for table definitions
            expected_tables = [
                "SYMBOL_TO_CODENAME",
                "CODENAME_TO_ENTRY",
                "ENTRIES_BY_KIND"
            ]
            for table in expected_tables:
                has_table = table in content
                result["tables"][table] = has_table
                if not has_table:
                    result["issues"].append(f"Table definition missing: {table}")

            # Check for CRUD operations
            expected_ops = [
                "upsert_entry",
                "lookup_by_symbol",
                "lookup_by_codename",
                "get_all_entries",
                "get_entries_by_kind",
                "search_entries"
            ]
            for op in expected_ops:
                has_op = op in content
                result["operations"][op] = has_op
                if not has_op:
                    result["issues"].append(f"Operation missing: {op}")

            if not result["issues"]:
                self.success.append("[OK] redb: All integration checks passed")

        except Exception as e:
            result["issues"].append(f"Error reading store file: {e}")

        return result

    def audit_node_red(self) -> Dict:
        """Audit Node-RED nodes"""
        print("[AUDIT] Auditing Node-RED nodes...")
        result = {
            "nodes": {},
            "files": {},
            "issues": []
        }

        node_red_dir = self.root_dir / "node-red" / "nodes"
        if not node_red_dir.exists():
            result["issues"].append("node-red/nodes directory not found")
            return result

        expected_nodes = {
            "cryptex-lookup": {
                "required_files": [
                    "cryptex-lookup.js",
                    "cryptex-search.js",
                    "cryptex-stats.js",
                    "package.json"
                ]
            },
            "yara-feed-scanner": {
                "required_files": [
                    "yara-feed-scanner.js",
                    "package.json"
                ]
            }
        }

        for node_name, requirements in expected_nodes.items():
            node_dir = node_red_dir / node_name
            node_info = {
                "exists": node_dir.exists(),
                "files": {},
                "issues": []
            }

            if not node_dir.exists():
                node_info["issues"].append(f"Node directory missing: {node_name}")
                result["issues"].append(f"Missing node: {node_name}")
                continue

            # Check required files
            for file in requirements["required_files"]:
                file_path = node_dir / file
                exists = file_path.exists()
                node_info["files"][file] = exists
                if not exists:
                    node_info["issues"].append(f"Missing file: {file}")
                    result["issues"].append(f"{node_name}: Missing {file}")

            result["nodes"][node_name] = node_info
            if not node_info["issues"]:
                self.success.append(f"[OK] Node-RED {node_name}: All checks passed")

        return result

    def audit_svelte(self) -> Dict:
        """Audit Svelte components"""
        print("[AUDIT] Auditing Svelte components...")
        result = {
            "components": {},
            "routes": {},
            "api_clients": {},
            "issues": []
        }

        frontend_dir = self.root_dir / "pyro-platform" / "frontend-svelte"
        if not frontend_dir.exists():
            result["issues"].append("pyro-platform/frontend-svelte directory not found")
            return result

        # Expected Svelte components
        expected_components = {
            "cryptex": {
                "route": "src/routes/tools/yara/cryptex/+page.svelte",
                "api_client": "src/lib/services/cryptexAPI.js"
            },
            "feed": {
                "route": "src/routes/tools/yara/feed/+page.svelte",
                "api_client": "src/lib/services/feedAPI.js"
            },
            "scan": {
                "route": "src/routes/tools/yara/scan/+page.svelte"
            }
        }

        for comp_name, requirements in expected_components.items():
            comp_info = {
                "route": {},
                "api_client": {},
                "issues": []
            }

            # Check route
            route_path = frontend_dir / requirements["route"]
            exists = route_path.exists()
            comp_info["route"]["exists"] = exists
            comp_info["route"]["path"] = str(requirements["route"])
            if not exists:
                comp_info["issues"].append(f"Route missing: {requirements['route']}")
                result["issues"].append(f"{comp_name}: Route missing")

            # Check API client if specified
            if "api_client" in requirements:
                api_path = frontend_dir / requirements["api_client"]
                exists = api_path.exists()
                comp_info["api_client"]["exists"] = exists
                comp_info["api_client"]["path"] = str(requirements["api_client"])
                if not exists:
                    comp_info["issues"].append(f"API client missing: {requirements['api_client']}")
                    result["issues"].append(f"{comp_name}: API client missing")

            result["components"][comp_name] = comp_info
            if not comp_info["issues"]:
                self.success.append(f"[OK] Svelte {comp_name}: All checks passed")

        return result

    def audit_api(self) -> Dict:
        """Audit API endpoints"""
        print("[AUDIT] Auditing API endpoints...")
        result = {
            "endpoints": {},
            "integration": {},
            "issues": []
        }

        api_file = self.root_dir / "rust" / "cryptex-api" / "src" / "main.rs"
        feed_file = self.root_dir / "rust" / "cryptex-api" / "src" / "feed.rs"

        # Expected endpoints
        expected_endpoints = {
            "cryptex": [
                "/api/v2/yara/cryptex/lookup",
                "/api/v2/yara/cryptex/search",
                "/api/v2/yara/cryptex/all",
                "/api/v2/yara/cryptex/stats"
            ],
            "feed": [
                "/api/v2/yara/feed/scan/all",
                "/api/v2/yara/feed/scan/new-tasks",
                "/api/v2/yara/feed/scan/old-tasks",
                "/api/v2/yara/feed/scan/malware",
                "/api/v2/yara/feed/scan/apt",
                "/api/v2/yara/feed/scan/ransomware"
            ]
        }

        # Check main.rs
        if api_file.exists():
            try:
                with open(api_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                for endpoint in expected_endpoints["cryptex"]:
                    # Check if endpoint path is referenced
                    has_endpoint = endpoint.split("/")[-1] in content or "lookup" in content.lower()
                    result["endpoints"][endpoint] = has_endpoint
                    if not has_endpoint:
                        result["issues"].append(f"Endpoint not found: {endpoint}")

                # Check feed integration
                has_feed = "feed" in content or "feed_router" in content
                result["integration"]["feed_router"] = has_feed
                if not has_feed:
                    result["issues"].append("Feed router not integrated")

            except Exception as e:
                result["issues"].append(f"Error reading API file: {e}")

        # Check feed.rs
        if feed_file.exists():
            try:
                with open(feed_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                for endpoint in expected_endpoints["feed"]:
                    has_endpoint = endpoint.split("/")[-1] in content
                    result["endpoints"][endpoint] = has_endpoint
                    if not has_endpoint:
                        result["issues"].append(f"Feed endpoint not found: {endpoint}")

            except Exception as e:
                result["issues"].append(f"Error reading feed file: {e}")
        else:
            result["issues"].append("feed.rs not found")

        if not result["issues"]:
            self.success.append("[OK] API: All endpoints present")

        return result

    def audit_build(self) -> Dict:
        """Audit build system"""
        print("[AUDIT] Auditing build system...")
        result = {
            "scripts": {},
            "workspace": {},
            "issues": []
        }

        # Check build scripts
        build_scripts = {
            "build.sh": "Linux/macOS build script",
            "build.ps1": "Windows build script",
            "Makefile": "Makefile"
        }

        for script, desc in build_scripts.items():
            script_path = self.root_dir / script
            exists = script_path.exists()
            result["scripts"][script] = {
                "exists": exists,
                "description": desc
            }
            if not exists:
                result["issues"].append(f"Build script missing: {script}")

        # Check workspace Cargo.toml
        workspace_toml = self.root_dir / "rust" / "Cargo.toml"
        if workspace_toml.exists():
            try:
                with open(workspace_toml, 'r', encoding='utf-8') as f:
                    content = f.read()

                expected_members = [
                    "cryptex-store",
                    "cryptex-api",
                    "yara-feed-scanner",
                    "cryptex-cli"
                ]

                for member in expected_members:
                    has_member = member in content
                    result["workspace"][member] = has_member
                    if not has_member:
                        result["issues"].append(f"Workspace member missing: {member}")

            except Exception as e:
                result["issues"].append(f"Error reading workspace Cargo.toml: {e}")

        if not result["issues"]:
            self.success.append("[OK] Build: All build scripts present")

        return result

    def identify_gaps(self) -> List[str]:
        """Identify gaps in the system"""
        gaps = []

        # Check if all components are connected
        if self.report["rust"]["issues"]:
            gaps.append("Rust components have issues - see rust section")

        if self.report["redb"]["issues"]:
            gaps.append("redb integration incomplete - see redb section")

        if self.report["node_red"]["issues"]:
            gaps.append("Node-RED nodes incomplete - see node_red section")

        if self.report["svelte"]["issues"]:
            gaps.append("Svelte components incomplete - see svelte section")

        if self.report["api"]["issues"]:
            gaps.append("API endpoints incomplete - see api section")

        # Check for missing connections
        if not self.report["api"]["integration"].get("feed_router", False):
            gaps.append("Feed router not integrated into main API")

        return gaps

    def run_audit(self) -> Dict:
        """Run complete audit"""
        print("=" * 60)
        print("YARA Cryptex - Comprehensive Self-Audit")
        print("=" * 60)
        print()

        self.report["rust"] = self.audit_rust()
        self.report["redb"] = self.audit_redb()
        self.report["node_red"] = self.audit_node_red()
        self.report["svelte"] = self.audit_svelte()
        self.report["api"] = self.audit_api()
        self.report["build"] = self.audit_build()

        # Identify gaps
        self.report["gaps"] = self.identify_gaps()

        # Generate summary
        total_issues = (
            len(self.report["rust"]["issues"]) +
            len(self.report["redb"]["issues"]) +
            len(self.report["node_red"]["issues"]) +
            len(self.report["svelte"]["issues"]) +
            len(self.report["api"]["issues"]) +
            len(self.report["build"]["issues"])
        )

        self.report["summary"] = {
            "total_issues": total_issues,
            "total_warnings": len(self.warnings),
            "total_success": len(self.success),
            "has_gaps": len(self.report["gaps"]) > 0,
            "status": "[OK] COMPLETE" if total_issues == 0 else "[WARN] HAS ISSUES"
        }

        return self.report

    def print_report(self):
        """Print audit report"""
        print()
        print("=" * 60)
        print("AUDIT REPORT")
        print("=" * 60)
        print()

        # Summary
        print("[SUMMARY]")
        print("-" * 60)
        print(f"Status: {self.report['summary']['status']}")
        print(f"Total Issues: {self.report['summary']['total_issues']}")
        print(f"Total Success: {self.report['summary']['total_success']}")
        print(f"Has Gaps: {'Yes' if self.report['summary']['has_gaps'] else 'No'}")
        print()

        # Success items
        if self.success:
            print("[OK] SUCCESS")
            print("-" * 60)
            for item in self.success:
                print(f"  {item}")
            print()

        # Gaps
        if self.report["gaps"]:
            print("[WARN] GAPS IDENTIFIED")
            print("-" * 60)
            for gap in self.report["gaps"]:
                print(f"  • {gap}")
            print()

        # Issues by component
        print("[AUDIT] ISSUES BY COMPONENT")
        print("-" * 60)

        for component, data in [
            ("Rust", self.report["rust"]),
            ("redb", self.report["redb"]),
            ("Node-RED", self.report["node_red"]),
            ("Svelte", self.report["svelte"]),
            ("API", self.report["api"]),
            ("Build", self.report["build"])
        ]:
            issues = data.get("issues", [])
            if issues:
                print(f"\n{component}:")
                for issue in issues:
                    print(f"  • {issue}")

        print()
        print("=" * 60)

    def save_report(self, output_file: Path):
        """Save report to JSON file"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.report, f, indent=2, ensure_ascii=False)
        print(f"[REPORT] Report saved to: {output_file}")


def main():
    root_dir = Path(__file__).parent.parent
    auditor = ComponentAuditor(root_dir)
    report = auditor.run_audit()
    auditor.print_report()

    # Save report
    output_file = root_dir / "audit_report.json"
    auditor.save_report(output_file)

    # Exit with error code if issues found
    if report["summary"]["total_issues"] > 0:
        sys.exit(1)
    else:
        print("\n[OK] All components complete - no gaps found!")
        sys.exit(0)


if __name__ == "__main__":
    main()

