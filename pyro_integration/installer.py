"""
R-YARA PYRO Platform Installer

Installs R-YARA as a component on PYRO Platform workers, APIs, and endpoints.
"""

import os
import sys
import json
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class RYaraInstaller:
    """
    Installer for R-YARA components on PYRO Platform.

    Handles:
    - Worker installation and configuration
    - API endpoint registration
    - Service discovery setup
    - Configuration deployment
    """

    def __init__(self, pyro_root: str = None, config: Dict[str, Any] = None):
        self.pyro_root = Path(pyro_root) if pyro_root else self._find_pyro_root()
        self.config = config or {}
        self.ryara_root = Path(__file__).parent.parent
        self.installed_components: List[str] = []

    def _find_pyro_root(self) -> Optional[Path]:
        """Find PYRO Platform root directory"""
        # Check environment variable
        if "PYRO_ROOT" in os.environ:
            return Path(os.environ["PYRO_ROOT"])

        # Check common locations
        locations = [
            Path.home() / "PYRO_Platform_Ignition",
            Path.home() / "pyro",
            Path("/opt/pyro"),
            Path.cwd() / "PYRO_Platform_Ignition",
        ]

        for loc in locations:
            if loc.exists() and (loc / "pyro.json").exists():
                return loc

        return None

    def check_prerequisites(self) -> Dict[str, bool]:
        """Check installation prerequisites"""
        checks = {
            "python_version": sys.version_info >= (3, 8),
            "pyro_root_exists": self.pyro_root is not None and self.pyro_root.exists(),
            "ryara_root_exists": self.ryara_root.exists(),
            "rust_toolchain": self._check_rust(),
            "yara_binary": self._check_yara(),
        }
        return checks

    def _check_rust(self) -> bool:
        """Check if Rust toolchain is available"""
        try:
            result = subprocess.run(
                ["cargo", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_yara(self) -> bool:
        """Check if YARA binary is available"""
        try:
            result = subprocess.run(
                ["yara", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def install_all(self) -> Dict[str, Any]:
        """Install all R-YARA components"""
        results = {
            "success": True,
            "components": [],
            "errors": []
        }

        # Check prerequisites
        prereqs = self.check_prerequisites()
        if not all(prereqs.values()):
            failed = [k for k, v in prereqs.items() if not v]
            results["success"] = False
            results["errors"].append(f"Prerequisites failed: {failed}")
            return results

        # Install components
        try:
            self.install_rust_backend()
            results["components"].append("rust_backend")
        except Exception as e:
            results["errors"].append(f"Rust backend: {e}")

        try:
            self.install_python_package()
            results["components"].append("python_package")
        except Exception as e:
            results["errors"].append(f"Python package: {e}")

        try:
            self.install_workers()
            results["components"].append("workers")
        except Exception as e:
            results["errors"].append(f"Workers: {e}")

        try:
            self.install_mcp_server()
            results["components"].append("mcp_server")
        except Exception as e:
            results["errors"].append(f"MCP server: {e}")

        try:
            self.register_endpoints()
            results["components"].append("endpoints")
        except Exception as e:
            results["errors"].append(f"Endpoints: {e}")

        results["success"] = len(results["errors"]) == 0
        return results

    def install_rust_backend(self):
        """Build and install Rust backend"""
        logger.info("Installing Rust backend...")
        rust_dir = self.ryara_root / "rust"

        if not rust_dir.exists():
            raise FileNotFoundError("Rust directory not found")

        # Build release
        result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=rust_dir,
            capture_output=True,
            timeout=600
        )

        if result.returncode != 0:
            raise RuntimeError(f"Cargo build failed: {result.stderr.decode()}")

        # Copy binaries to PYRO bin directory
        if self.pyro_root:
            bin_dir = self.pyro_root / "bin"
            bin_dir.mkdir(exist_ok=True)

            binaries = [
                "r-yara-cli",
                "r-yara-api",
                "r-yara-feed-scanner"
            ]

            for binary in binaries:
                src = rust_dir / "target" / "release" / binary
                if src.exists():
                    dst = bin_dir / binary
                    shutil.copy2(src, dst)
                    os.chmod(dst, 0o755)
                    logger.info(f"Installed {binary} to {dst}")

        self.installed_components.append("rust_backend")

    def install_python_package(self):
        """Install Python package"""
        logger.info("Installing Python package...")

        # Install in development mode
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", str(self.ryara_root)],
            capture_output=True,
            timeout=300
        )

        if result.returncode != 0:
            # Try without -e flag
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", str(self.ryara_root)],
                capture_output=True,
                timeout=300
            )

        self.installed_components.append("python_package")

    def install_workers(self):
        """Install worker configurations"""
        logger.info("Installing workers...")

        if not self.pyro_root:
            logger.warning("PYRO root not found, skipping worker installation")
            return

        workers_dir = self.pyro_root / "workers" / "r-yara"
        workers_dir.mkdir(parents=True, exist_ok=True)

        # Create worker configuration
        worker_config = {
            "name": "r-yara",
            "version": "0.1.0",
            "workers": [
                {
                    "type": "scanner",
                    "module": "pyro_integration.workers.scanner",
                    "class": "ScannerWorker",
                    "capabilities": ["scan_file", "scan_data", "validate_rule", "compile_rules"]
                },
                {
                    "type": "transcoder",
                    "module": "pyro_integration.workers.transcoder",
                    "class": "TranscoderWorker",
                    "capabilities": ["transcode", "dictionary_lookup"]
                }
            ],
            "config": {
                "max_concurrent_tasks": 4,
                "heartbeat_interval_ms": 30000,
                "task_timeout_ms": 60000
            }
        }

        config_path = workers_dir / "config.json"
        with open(config_path, 'w') as f:
            json.dump(worker_config, f, indent=2)

        logger.info(f"Worker configuration saved to {config_path}")
        self.installed_components.append("workers")

    def install_mcp_server(self):
        """Install MCP server configuration"""
        logger.info("Installing MCP server...")

        if not self.pyro_root:
            logger.warning("PYRO root not found, skipping MCP server installation")
            return

        mcp_dir = self.pyro_root / "mcp" / "servers"
        mcp_dir.mkdir(parents=True, exist_ok=True)

        # Create MCP server configuration
        mcp_config = {
            "name": "r-yara",
            "version": "0.1.0",
            "command": sys.executable,
            "args": ["-m", "mcp_server_ryara.server"],
            "cwd": str(self.ryara_root),
            "env": {
                "PYTHONPATH": str(self.ryara_root)
            },
            "tools": [
                "r-yara-lookup",
                "r-yara-search",
                "r-yara-scan-feeds",
                "r-yara-validate-rule",
                "r-yara-transcode",
                "r-yara-stream-rules",
                "r-yara-stats"
            ],
            "resources": [
                "r-yara://dictionary",
                "r-yara://rules/*",
                "r-yara://config"
            ]
        }

        config_path = mcp_dir / "r-yara.json"
        with open(config_path, 'w') as f:
            json.dump(mcp_config, f, indent=2)

        logger.info(f"MCP server configuration saved to {config_path}")
        self.installed_components.append("mcp_server")

    def register_endpoints(self):
        """Register API endpoints with PYRO Platform"""
        logger.info("Registering API endpoints...")

        if not self.pyro_root:
            logger.warning("PYRO root not found, skipping endpoint registration")
            return

        api_dir = self.pyro_root / "api" / "routes"
        api_dir.mkdir(parents=True, exist_ok=True)

        # Create endpoint registration
        endpoints_config = {
            "name": "r-yara",
            "version": "0.1.0",
            "base_path": "/api/v2/r-yara",
            "endpoints": [
                {"path": "/health", "method": "GET", "handler": "health"},
                {"path": "/dictionary/lookup", "method": "GET", "handler": "dictionary_lookup"},
                {"path": "/dictionary/search", "method": "GET", "handler": "dictionary_search"},
                {"path": "/dictionary/stats", "method": "GET", "handler": "dictionary_stats"},
                {"path": "/scan/file", "method": "POST", "handler": "scan_file"},
                {"path": "/scan/data", "method": "POST", "handler": "scan_data"},
                {"path": "/rules/validate", "method": "POST", "handler": "validate_rule"},
                {"path": "/rules/compile", "method": "POST", "handler": "compile_rules"},
                {"path": "/transcode/encode", "method": "POST", "handler": "transcode_encode"},
                {"path": "/transcode/decode", "method": "POST", "handler": "transcode_decode"},
                {"path": "/feed/scan/{use_case}", "method": "POST", "handler": "feed_scan"},
                {"path": "/worker/task", "method": "POST", "handler": "submit_task"},
                {"path": "/worker/task/{task_id}", "method": "GET", "handler": "get_task_status"},
            ],
            "websocket": [
                {"path": "/stream/rules", "handler": "stream_rules"},
                {"path": "/stream/worker", "handler": "stream_worker"}
            ]
        }

        config_path = api_dir / "r-yara.json"
        with open(config_path, 'w') as f:
            json.dump(endpoints_config, f, indent=2)

        logger.info(f"Endpoint configuration saved to {config_path}")
        self.installed_components.append("endpoints")

    def create_config_file(self, output_path: str = None) -> str:
        """Create R-YARA configuration file"""
        config = {
            "api": {
                "host": "0.0.0.0",
                "port": 8080,
                "prefix": "/api/v2/r-yara"
            },
            "worker": {
                "max_concurrent_tasks": 4,
                "heartbeat_interval_ms": 30000,
                "task_timeout_ms": 60000
            },
            "stream": {
                "chunk_size": 4096,
                "max_connections": 100
            },
            "storage": {
                "dictionary_path": "data/dictionary.redb",
                "rules_path": "data/rules",
                "cache_path": "data/cache"
            },
            "pyro": {
                "ws_url": None,
                "auth_token": None,
                "enabled": True
            }
        }

        if output_path:
            path = Path(output_path)
        else:
            path = self.ryara_root / "config" / "r-yara.json"

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(config, f, indent=2)

        return str(path)

    def uninstall(self) -> Dict[str, Any]:
        """Uninstall R-YARA components"""
        results = {
            "success": True,
            "removed": [],
            "errors": []
        }

        if self.pyro_root:
            # Remove worker config
            try:
                workers_dir = self.pyro_root / "workers" / "r-yara"
                if workers_dir.exists():
                    shutil.rmtree(workers_dir)
                    results["removed"].append("workers")
            except Exception as e:
                results["errors"].append(f"Workers: {e}")

            # Remove MCP config
            try:
                mcp_config = self.pyro_root / "mcp" / "servers" / "r-yara.json"
                if mcp_config.exists():
                    mcp_config.unlink()
                    results["removed"].append("mcp_server")
            except Exception as e:
                results["errors"].append(f"MCP server: {e}")

            # Remove API config
            try:
                api_config = self.pyro_root / "api" / "routes" / "r-yara.json"
                if api_config.exists():
                    api_config.unlink()
                    results["removed"].append("endpoints")
            except Exception as e:
                results["errors"].append(f"Endpoints: {e}")

            # Remove binaries
            try:
                bin_dir = self.pyro_root / "bin"
                for binary in ["r-yara-cli", "r-yara-api", "r-yara-feed-scanner"]:
                    path = bin_dir / binary
                    if path.exists():
                        path.unlink()
                results["removed"].append("binaries")
            except Exception as e:
                results["errors"].append(f"Binaries: {e}")

        results["success"] = len(results["errors"]) == 0
        return results

    def get_status(self) -> Dict[str, Any]:
        """Get installation status"""
        status = {
            "installed": False,
            "pyro_root": str(self.pyro_root) if self.pyro_root else None,
            "ryara_root": str(self.ryara_root),
            "components": {},
            "prerequisites": self.check_prerequisites()
        }

        if self.pyro_root and self.pyro_root.exists():
            # Check each component
            status["components"]["workers"] = (
                self.pyro_root / "workers" / "r-yara" / "config.json"
            ).exists()
            status["components"]["mcp_server"] = (
                self.pyro_root / "mcp" / "servers" / "r-yara.json"
            ).exists()
            status["components"]["endpoints"] = (
                self.pyro_root / "api" / "routes" / "r-yara.json"
            ).exists()
            status["components"]["binaries"] = (
                self.pyro_root / "bin" / "r-yara-cli"
            ).exists()

            status["installed"] = any(status["components"].values())

        return status


def install(pyro_root: str = None):
    """Install R-YARA to PYRO Platform"""
    installer = RYaraInstaller(pyro_root)
    return installer.install_all()


def uninstall(pyro_root: str = None):
    """Uninstall R-YARA from PYRO Platform"""
    installer = RYaraInstaller(pyro_root)
    return installer.uninstall()


def status(pyro_root: str = None):
    """Get R-YARA installation status"""
    installer = RYaraInstaller(pyro_root)
    return installer.get_status()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="R-YARA PYRO Platform Installer")
    parser.add_argument("action", choices=["install", "uninstall", "status"])
    parser.add_argument("--pyro-root", help="PYRO Platform root directory")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.action == "install":
        result = install(args.pyro_root)
        print(json.dumps(result, indent=2))
    elif args.action == "uninstall":
        result = uninstall(args.pyro_root)
        print(json.dumps(result, indent=2))
    elif args.action == "status":
        result = status(args.pyro_root)
        print(json.dumps(result, indent=2))
