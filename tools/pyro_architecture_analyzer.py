"""
PYRO Platform Architecture Analyzer
Analyzes PYRO Platform structure to understand integration points with YARA Cryptex.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict

PROJECT_ROOT = Path(__file__).parent.parent
PYRO_PLATFORM_DIR = PROJECT_ROOT / "pyro-platform"


class PyroArchitectureAnalyzer:
    """Analyzes PYRO Platform architecture."""
    
    def __init__(self):
        self.pyro_dir = PYRO_PLATFORM_DIR
        self.components = {}
        self.api_endpoints = []
        self.services = []
    
    def analyze_structure(self) -> Dict:
        """Analyze overall platform structure."""
        if not self.pyro_dir.exists():
            return {"error": "PYRO Platform directory not found"}
        
        structure = {
            "root": str(self.pyro_dir),
            "top_level_dirs": [],
            "file_distribution": defaultdict(int),
            "languages": defaultdict(int),
            "components": {}
        }
        
        try:
            # Analyze top-level directories
            for item in self.pyro_dir.iterdir():
                if item.is_dir():
                    structure["top_level_dirs"].append(item.name)
                    # Analyze component
                    component_info = self._analyze_component(item)
                    if component_info:
                        structure["components"][item.name] = component_info
                elif item.is_file():
                    suffix = item.suffix.lower()
                    structure["file_distribution"][suffix] += 1
                    if suffix in ['.py', '.rs', '.js', '.ts']:
                        structure["languages"][suffix[1:]] += 1
        
        except Exception as e:
            structure["error"] = str(e)
        
        return structure
    
    def _analyze_component(self, component_dir: Path) -> Dict:
        """Analyze a component directory."""
        info = {
            "files": 0,
            "languages": defaultdict(int),
            "has_api": False,
            "has_docs": False,
            "has_config": False
        }
        
        try:
            for item in component_dir.rglob("*"):
                if item.is_file():
                    info["files"] += 1
                    suffix = item.suffix.lower()
                    if suffix in ['.py', '.rs', '.js', '.ts']:
                        info["languages"][suffix[1:]] += 1
                    if 'api' in item.name.lower() or 'endpoint' in item.name.lower():
                        info["has_api"] = True
                    if item.suffix == '.md':
                        info["has_docs"] = True
                    if item.suffix in ['.json', '.yaml', '.toml', '.config']:
                        info["has_config"] = True
        except Exception:
            pass
        
        return dict(info) if info["files"] > 0 else None
    
    def find_services(self) -> List[Dict]:
        """Find service definitions in PYRO Platform."""
        if not self.pyro_dir.exists():
            return []
        
        services = []
        
        # Look for service patterns
        service_patterns = [
            r'class\s+(\w+Service)',
            r'class\s+(\w+Server)',
            r'async\s+fn\s+(\w+_service)',
            r'pub\s+struct\s+(\w+Service)',
        ]
        
        for pattern in service_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            
            for file_path in self.pyro_dir.rglob("*.py"):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    matches = regex.finditer(content)
                    
                    for match in matches:
                        services.append({
                            "name": match.group(1),
                            "file": str(file_path.relative_to(self.pyro_dir)),
                            "type": "service"
                        })
                except Exception:
                    continue
            
            # Also check Rust files
            for file_path in self.pyro_dir.rglob("*.rs"):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    matches = regex.finditer(content)
                    
                    for match in matches:
                        services.append({
                            "name": match.group(1),
                            "file": str(file_path.relative_to(self.pyro_dir)),
                            "type": "service"
                        })
                except Exception:
                    continue
        
        return services
    
    def find_api_routes(self) -> List[Dict]:
        """Find API route definitions."""
        if not self.pyro_dir.exists():
            return []
        
        routes = []
        
        # Common API patterns
        route_patterns = [
            (r'@app\.(get|post|put|delete|patch)\s*\(["\']([^"\']+)["\']', 'flask'),
            (r'router\.(get|post|put|delete|patch)\s*\(["\']([^"\']+)["\']', 'fastapi'),
            (r'\.route\s*\(["\']([^"\']+)["\']', 'generic'),
            (r'endpoint\s*[:=]\s*["\']([^"\']+)["\']', 'generic'),
        ]
        
        for pattern, framework in route_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            
            for file_path in self.pyro_dir.rglob("*.py"):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    lines = content.split('\n')
                    
                    for match in regex.finditer(content):
                        line_num = content[:match.start()].count('\n') + 1
                        method = match.group(1) if len(match.groups()) > 0 else "GET"
                        path = match.group(2) if len(match.groups()) > 1 else match.group(1)
                        
                        routes.append({
                            "method": method.upper(),
                            "path": path,
                            "file": str(file_path.relative_to(self.pyro_dir)),
                            "line": line_num,
                            "framework": framework
                        })
                except Exception:
                    continue
        
        return routes
    
    def find_mcp_servers(self) -> List[Dict]:
        """Find MCP server configurations."""
        if not self.pyro_dir.exists():
            return []
        
        mcp_servers = []
        
        # Look for MCP configuration files
        mcp_config_files = list(self.pyro_dir.rglob("mcp*.json")) + \
                          list(self.pyro_dir.rglob("*mcp*.json"))
        
        for config_file in mcp_config_files:
            try:
                content = config_file.read_text(encoding='utf-8', errors='ignore')
                config = json.loads(content)
                
                mcp_servers.append({
                    "config_file": str(config_file.relative_to(self.pyro_dir)),
                    "servers": config if isinstance(config, dict) else {}
                })
            except Exception:
                # Try to parse as text
                if "mcp" in content.lower() or "server" in content.lower():
                    mcp_servers.append({
                        "config_file": str(config_file.relative_to(self.pyro_dir)),
                        "type": "text_config"
                    })
        
        return mcp_servers
    
    def generate_architecture_report(self) -> str:
        """Generate comprehensive architecture report."""
        report = []
        report.append("=" * 60)
        report.append("PYRO Platform Architecture Analysis")
        report.append("=" * 60)
        report.append("")
        
        # Structure analysis
        structure = self.analyze_structure()
        report.append("Platform Structure:")
        report.append(f"  Top-level directories: {len(structure.get('top_level_dirs', []))}")
        for dir_name in structure.get('top_level_dirs', [])[:10]:
            report.append(f"    - {dir_name}")
        report.append("")
        
        report.append("Languages Detected:")
        for lang, count in structure.get('languages', {}).items():
            report.append(f"  {lang}: {count} files")
        report.append("")
        
        # Services
        services = self.find_services()
        report.append(f"Services Found: {len(services)}")
        for service in services[:10]:
            report.append(f"  {service['name']} ({service['file']})")
        report.append("")
        
        # API Routes
        routes = self.find_api_routes()
        report.append(f"API Routes Found: {len(routes)}")
        for route in routes[:10]:
            report.append(f"  {route['method']} {route['path']} ({route['file']})")
        report.append("")
        
        # MCP Servers
        mcp_servers = self.find_mcp_servers()
        report.append(f"MCP Server Configs: {len(mcp_servers)}")
        for mcp in mcp_servers:
            report.append(f"  {mcp['config_file']}")
        report.append("")
        
        # Components
        components = structure.get('components', {})
        report.append(f"Components Analyzed: {len(components)}")
        for comp_name, comp_info in list(components.items())[:10]:
            report.append(f"  {comp_name}:")
            report.append(f"    Files: {comp_info.get('files', 0)}")
            report.append(f"    Languages: {dict(comp_info.get('languages', {}))}")
            report.append(f"    Has API: {comp_info.get('has_api', False)}")
        report.append("")
        
        report.append("=" * 60)
        
        return "\n".join(report)


def analyze_pyro_architecture():
    """Convenience function to analyze architecture."""
    analyzer = PyroArchitectureAnalyzer()
    return analyzer.generate_architecture_report()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze PYRO Platform architecture")
    parser.add_argument("--report", action="store_true", help="Generate full report")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    
    args = parser.parse_args()
    
    analyzer = PyroArchitectureAnalyzer()
    
    if args.json:
        result = {
            "structure": analyzer.analyze_structure(),
            "services": analyzer.find_services(),
            "api_routes": analyzer.find_api_routes(),
            "mcp_servers": analyzer.find_mcp_servers()
        }
        print(json.dumps(result, indent=2))
    else:
        print(analyzer.generate_architecture_report())

