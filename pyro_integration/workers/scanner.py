"""
R-YARA Scanner Worker

Worker implementation for YARA rule scanning tasks.
"""

import asyncio
import json
import subprocess
import tempfile
import os
from typing import Dict, Any, List, Optional
from pathlib import Path

from .base import RYaraWorker
from ..shared.protocol import WorkerTask, TaskResult, TaskType


class ScannerWorker(RYaraWorker):
    """
    Scanner worker for YARA rule matching.

    Handles:
    - File scanning with YARA rules
    - Memory/data scanning
    - Rule compilation and validation
    """

    @property
    def worker_type(self) -> str:
        return "r-yara-scanner"

    @property
    def capabilities(self) -> list:
        return [
            TaskType.SCAN_FILE.value,
            TaskType.SCAN_DATA.value,
            TaskType.VALIDATE_RULE.value,
            TaskType.COMPILE_RULES.value
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._yara_binary = self._find_yara_binary()
        self._yarac_binary = self._find_yarac_binary()

    def _find_yara_binary(self) -> Optional[str]:
        """Find YARA binary in PATH or known locations"""
        locations = [
            "yara",  # In PATH
            "/usr/bin/yara",
            "/usr/local/bin/yara",
            str(Path(__file__).parent.parent.parent / "yara"),
        ]
        for loc in locations:
            try:
                result = subprocess.run(
                    [loc, "--version"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return loc
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        return None

    def _find_yarac_binary(self) -> Optional[str]:
        """Find YARAC binary in PATH or known locations"""
        locations = [
            "yarac",  # In PATH
            "/usr/bin/yarac",
            "/usr/local/bin/yarac",
            str(Path(__file__).parent.parent.parent / "yarac"),
        ]
        for loc in locations:
            try:
                result = subprocess.run(
                    [loc, "--version"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return loc
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        return None

    async def process_task(self, task: WorkerTask) -> TaskResult:
        """Process a scanner task"""
        if task.task_type == TaskType.SCAN_FILE:
            return await self._scan_file(task)
        elif task.task_type == TaskType.SCAN_DATA:
            return await self._scan_data(task)
        elif task.task_type == TaskType.VALIDATE_RULE:
            return await self._validate_rule(task)
        elif task.task_type == TaskType.COMPILE_RULES:
            return await self._compile_rules(task)
        else:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=f"Unknown task type: {task.task_type}"
            )

    async def _scan_file(self, task: WorkerTask) -> TaskResult:
        """Scan a file with YARA rules"""
        if not self._yara_binary:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="YARA binary not found"
            )

        file_path = task.payload.get("file_path")
        rules = task.payload.get("rules")
        rules_file = task.payload.get("rules_file")

        if not file_path:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="Missing file_path in payload"
            )

        if not rules and not rules_file:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="Missing rules or rules_file in payload"
            )

        try:
            # Create temp file for rules if provided inline
            temp_rules_file = None
            if rules:
                temp_rules_file = tempfile.NamedTemporaryFile(
                    mode='w',
                    suffix='.yar',
                    delete=False
                )
                temp_rules_file.write(rules)
                temp_rules_file.close()
                rules_file = temp_rules_file.name

            # Run YARA scan
            cmd = [self._yara_binary, "-s", "-m", rules_file, file_path]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # Clean up temp file
            if temp_rules_file:
                os.unlink(temp_rules_file.name)

            # Parse results
            matches = self._parse_yara_output(stdout.decode())

            return TaskResult(
                task_id=task.task_id,
                success=True,
                data={
                    "matches": matches,
                    "match_count": len(matches),
                    "file_path": file_path
                }
            )

        except Exception as e:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e)
            )

    async def _scan_data(self, task: WorkerTask) -> TaskResult:
        """Scan raw data with YARA rules"""
        if not self._yara_binary:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="YARA binary not found"
            )

        data = task.payload.get("data")
        rules = task.payload.get("rules")
        rules_file = task.payload.get("rules_file")

        if not data:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="Missing data in payload"
            )

        if not rules and not rules_file:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="Missing rules or rules_file in payload"
            )

        try:
            # Create temp file for data
            temp_data_file = tempfile.NamedTemporaryFile(
                mode='wb',
                delete=False
            )
            if isinstance(data, str):
                temp_data_file.write(data.encode())
            else:
                temp_data_file.write(data)
            temp_data_file.close()

            # Create temp file for rules if provided inline
            temp_rules_file = None
            if rules:
                temp_rules_file = tempfile.NamedTemporaryFile(
                    mode='w',
                    suffix='.yar',
                    delete=False
                )
                temp_rules_file.write(rules)
                temp_rules_file.close()
                rules_file = temp_rules_file.name

            # Run YARA scan
            cmd = [self._yara_binary, "-s", "-m", rules_file, temp_data_file.name]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # Clean up temp files
            os.unlink(temp_data_file.name)
            if temp_rules_file:
                os.unlink(temp_rules_file.name)

            # Parse results
            matches = self._parse_yara_output(stdout.decode())

            return TaskResult(
                task_id=task.task_id,
                success=True,
                data={
                    "matches": matches,
                    "match_count": len(matches)
                }
            )

        except Exception as e:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e)
            )

    async def _validate_rule(self, task: WorkerTask) -> TaskResult:
        """Validate YARA rule syntax"""
        if not self._yarac_binary:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="YARAC binary not found"
            )

        rule_content = task.payload.get("rule")
        if not rule_content:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="Missing rule in payload"
            )

        try:
            # Create temp files
            temp_rule_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.yar',
                delete=False
            )
            temp_rule_file.write(rule_content)
            temp_rule_file.close()

            temp_output = tempfile.NamedTemporaryFile(
                suffix='.yarc',
                delete=False
            )
            temp_output.close()

            # Try to compile
            cmd = [self._yarac_binary, temp_rule_file.name, temp_output.name]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # Clean up
            os.unlink(temp_rule_file.name)
            if os.path.exists(temp_output.name):
                os.unlink(temp_output.name)

            if process.returncode == 0:
                return TaskResult(
                    task_id=task.task_id,
                    success=True,
                    data={"valid": True, "message": "Rule is valid"}
                )
            else:
                return TaskResult(
                    task_id=task.task_id,
                    success=True,
                    data={
                        "valid": False,
                        "errors": stderr.decode().strip().split('\n')
                    }
                )

        except Exception as e:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e)
            )

    async def _compile_rules(self, task: WorkerTask) -> TaskResult:
        """Compile YARA rules to binary format"""
        if not self._yarac_binary:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="YARAC binary not found"
            )

        rules = task.payload.get("rules")
        output_path = task.payload.get("output_path")

        if not rules:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="Missing rules in payload"
            )

        try:
            # Create temp file for rules
            temp_rule_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.yar',
                delete=False
            )
            temp_rule_file.write(rules)
            temp_rule_file.close()

            # Use provided output path or temp file
            if not output_path:
                temp_output = tempfile.NamedTemporaryFile(
                    suffix='.yarc',
                    delete=False
                )
                temp_output.close()
                output_path = temp_output.name

            # Compile
            cmd = [self._yarac_binary, temp_rule_file.name, output_path]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # Clean up source
            os.unlink(temp_rule_file.name)

            if process.returncode == 0:
                # Read compiled rules if temp file
                compiled_data = None
                if task.payload.get("return_data", False):
                    with open(output_path, 'rb') as f:
                        import base64
                        compiled_data = base64.b64encode(f.read()).decode()

                return TaskResult(
                    task_id=task.task_id,
                    success=True,
                    data={
                        "compiled": True,
                        "output_path": output_path,
                        "compiled_data": compiled_data
                    }
                )
            else:
                return TaskResult(
                    task_id=task.task_id,
                    success=False,
                    error=stderr.decode().strip()
                )

        except Exception as e:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e)
            )

    def _parse_yara_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse YARA scan output"""
        matches = []
        current_match = None

        for line in output.strip().split('\n'):
            if not line:
                continue

            # Match line format: rule_name [tag1,tag2] file_path
            if not line.startswith('0x'):
                parts = line.split()
                if len(parts) >= 2:
                    rule_name = parts[0]
                    # Extract tags if present
                    tags = []
                    if '[' in line and ']' in line:
                        tag_start = line.index('[') + 1
                        tag_end = line.index(']')
                        tags = [t.strip() for t in line[tag_start:tag_end].split(',')]

                    current_match = {
                        "rule": rule_name,
                        "tags": tags,
                        "strings": []
                    }
                    matches.append(current_match)
            else:
                # String match line format: 0xOFFSET:$identifier: content
                if current_match and ':' in line:
                    parts = line.split(':', 2)
                    if len(parts) >= 2:
                        current_match["strings"].append({
                            "offset": parts[0],
                            "identifier": parts[1],
                            "data": parts[2] if len(parts) > 2 else ""
                        })

        return matches


def create_scanner_worker(**kwargs) -> ScannerWorker:
    """Factory function to create a scanner worker"""
    return ScannerWorker(**kwargs)
