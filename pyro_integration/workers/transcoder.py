"""
R-YARA Transcoder Worker

Worker implementation for YARA rule transcoding (codename conversion).
"""

import asyncio
import json
import subprocess
import tempfile
import os
import re
from typing import Dict, Any, List, Optional
from pathlib import Path

from .base import RYaraWorker
from ..shared.protocol import WorkerTask, TaskResult, TaskType


class TranscoderWorker(RYaraWorker):
    """
    Transcoder worker for R-YARA codename operations.

    Handles:
    - Encode rules with codenames (obfuscation)
    - Decode rules from codenames (deobfuscation)
    - Dictionary lookups
    - Batch transcoding operations
    """

    @property
    def worker_type(self) -> str:
        return "r-yara-transcoder"

    @property
    def capabilities(self) -> list:
        return [
            TaskType.TRANSCODE.value,
            TaskType.DICTIONARY_LOOKUP.value
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cli_binary = self._find_ryara_cli()
        self._dictionary_cache: Dict[str, str] = {}
        self._reverse_cache: Dict[str, str] = {}

    def _find_ryara_cli(self) -> Optional[str]:
        """Find R-YARA CLI binary"""
        locations = [
            "r-yara-cli",
            str(Path(__file__).parent.parent.parent / "rust" / "target" / "release" / "r-yara-cli"),
            str(Path(__file__).parent.parent.parent / "rust" / "target" / "debug" / "r-yara-cli"),
            "/usr/local/bin/r-yara-cli",
        ]
        for loc in locations:
            try:
                result = subprocess.run(
                    [loc, "--help"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return loc
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        return None

    async def process_task(self, task: WorkerTask) -> TaskResult:
        """Process a transcoder task"""
        if task.task_type == TaskType.TRANSCODE:
            return await self._transcode(task)
        elif task.task_type == TaskType.DICTIONARY_LOOKUP:
            return await self._dictionary_lookup(task)
        else:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=f"Unknown task type: {task.task_type}"
            )

    async def _transcode(self, task: WorkerTask) -> TaskResult:
        """Transcode YARA rules (encode/decode codenames)"""
        rule_content = task.payload.get("rule")
        direction = task.payload.get("direction", "encode")  # encode or decode

        if not rule_content:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="Missing rule in payload"
            )

        try:
            if direction == "encode":
                result = await self._encode_rule(rule_content)
            else:
                result = await self._decode_rule(rule_content)

            return TaskResult(
                task_id=task.task_id,
                success=True,
                data={
                    "original": rule_content,
                    "transcoded": result["transcoded"],
                    "mappings": result["mappings"],
                    "direction": direction
                }
            )
        except Exception as e:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e)
            )

    async def _encode_rule(self, rule_content: str) -> Dict[str, Any]:
        """Encode a rule with codenames"""
        # If CLI is available, use it
        if self._cli_binary:
            return await self._encode_with_cli(rule_content)

        # Fallback to Python implementation
        return self._encode_with_python(rule_content)

    async def _decode_rule(self, rule_content: str) -> Dict[str, Any]:
        """Decode a rule from codenames"""
        # If CLI is available, use it
        if self._cli_binary:
            return await self._decode_with_cli(rule_content)

        # Fallback to Python implementation
        return self._decode_with_python(rule_content)

    async def _encode_with_cli(self, rule_content: str) -> Dict[str, Any]:
        """Encode using R-YARA CLI"""
        temp_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.yar',
            delete=False
        )
        temp_file.write(rule_content)
        temp_file.close()

        try:
            process = await asyncio.create_subprocess_exec(
                self._cli_binary, "encode", temp_file.name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise Exception(stderr.decode())

            result = json.loads(stdout.decode())
            return {
                "transcoded": result.get("encoded", ""),
                "mappings": result.get("mappings", {})
            }
        finally:
            os.unlink(temp_file.name)

    async def _decode_with_cli(self, rule_content: str) -> Dict[str, Any]:
        """Decode using R-YARA CLI"""
        temp_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.yar',
            delete=False
        )
        temp_file.write(rule_content)
        temp_file.close()

        try:
            process = await asyncio.create_subprocess_exec(
                self._cli_binary, "decode", temp_file.name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise Exception(stderr.decode())

            result = json.loads(stdout.decode())
            return {
                "transcoded": result.get("decoded", ""),
                "mappings": result.get("mappings", {})
            }
        finally:
            os.unlink(temp_file.name)

    def _encode_with_python(self, rule_content: str) -> Dict[str, Any]:
        """Encode using Python (fallback)"""
        # Simple encoding: replace identifiers with codenames
        mappings = {}
        transcoded = rule_content

        # Find rule names
        rule_pattern = r'rule\s+(\w+)'
        for match in re.finditer(rule_pattern, rule_content):
            original = match.group(1)
            if original not in mappings:
                codename = self._generate_codename(original)
                mappings[original] = codename

        # Find string identifiers
        string_pattern = r'\$(\w+)\s*='
        for match in re.finditer(string_pattern, rule_content):
            original = f"${match.group(1)}"
            if original not in mappings:
                codename = self._generate_codename(original)
                mappings[original] = codename

        # Apply mappings
        for original, codename in mappings.items():
            transcoded = transcoded.replace(original, codename)

        return {
            "transcoded": transcoded,
            "mappings": mappings
        }

    def _decode_with_python(self, rule_content: str) -> Dict[str, Any]:
        """Decode using Python (fallback)"""
        # Simple decoding: look up codenames in reverse cache
        mappings = {}
        transcoded = rule_content

        # Find potential codenames (format: R_XXXX or similar)
        codename_pattern = r'R_[A-Z0-9]{4,8}'
        for match in re.finditer(codename_pattern, rule_content):
            codename = match.group(0)
            if codename in self._reverse_cache:
                original = self._reverse_cache[codename]
                mappings[codename] = original
                transcoded = transcoded.replace(codename, original)

        return {
            "transcoded": transcoded,
            "mappings": mappings
        }

    def _generate_codename(self, identifier: str) -> str:
        """Generate a codename for an identifier"""
        import hashlib
        # Generate hash-based codename
        hash_val = hashlib.md5(identifier.encode()).hexdigest()[:6].upper()
        codename = f"R_{hash_val}"

        # Cache the mapping
        self._dictionary_cache[identifier] = codename
        self._reverse_cache[codename] = identifier

        return codename

    async def _dictionary_lookup(self, task: WorkerTask) -> TaskResult:
        """Look up entries in the dictionary"""
        query = task.payload.get("query")
        lookup_type = task.payload.get("type", "codename")  # codename or symbol

        if not query:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error="Missing query in payload"
            )

        try:
            # Try CLI first
            if self._cli_binary:
                result = await self._lookup_with_cli(query, lookup_type)
            else:
                result = self._lookup_with_cache(query, lookup_type)

            return TaskResult(
                task_id=task.task_id,
                success=True,
                data=result
            )
        except Exception as e:
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e)
            )

    async def _lookup_with_cli(self, query: str, lookup_type: str) -> Dict[str, Any]:
        """Look up using R-YARA CLI"""
        process = await asyncio.create_subprocess_exec(
            self._cli_binary, "lookup", query,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            return {"found": False, "query": query}

        try:
            return json.loads(stdout.decode())
        except json.JSONDecodeError:
            return {
                "found": True,
                "query": query,
                "result": stdout.decode().strip()
            }

    def _lookup_with_cache(self, query: str, lookup_type: str) -> Dict[str, Any]:
        """Look up in local cache"""
        if lookup_type == "codename":
            if query in self._reverse_cache:
                return {
                    "found": True,
                    "codename": query,
                    "symbol": self._reverse_cache[query]
                }
        else:
            if query in self._dictionary_cache:
                return {
                    "found": True,
                    "symbol": query,
                    "codename": self._dictionary_cache[query]
                }

        return {"found": False, "query": query}

    async def load_dictionary(self, dictionary_path: str):
        """Load dictionary from file"""
        try:
            with open(dictionary_path, 'r') as f:
                data = json.load(f)

            for entry in data.get("entries", []):
                symbol = entry.get("symbol")
                codename = entry.get("codename")
                if symbol and codename:
                    self._dictionary_cache[symbol] = codename
                    self._reverse_cache[codename] = symbol
        except Exception as e:
            raise Exception(f"Failed to load dictionary: {e}")


def create_transcoder_worker(**kwargs) -> TranscoderWorker:
    """Factory function to create a transcoder worker"""
    return TranscoderWorker(**kwargs)
