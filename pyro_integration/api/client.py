"""
R-YARA API Client

Client for communicating with R-YARA API endpoints.
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result from a YARA scan operation"""
    success: bool
    matches: List[Dict[str, Any]]
    match_count: int
    error: Optional[str] = None
    execution_time_ms: Optional[int] = None


@dataclass
class TranscodeResult:
    """Result from a transcode operation"""
    success: bool
    transcoded: str
    mappings: Dict[str, str]
    direction: str
    error: Optional[str] = None


@dataclass
class DictionaryEntry:
    """Dictionary entry"""
    symbol: str
    codename: str
    category: Optional[str] = None
    description: Optional[str] = None


class RYaraClient:
    """
    Client for R-YARA API.

    Supports both HTTP REST API and WebSocket streaming.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_prefix: str = "/api/v2/r-yara",
        auth_token: Optional[str] = None
    ):
        self.base_url = base_url.rstrip('/')
        self.api_prefix = api_prefix
        self.auth_token = auth_token
        self._session = None
        self._ws_connection = None

    @property
    def _headers(self) -> Dict[str, str]:
        """Get request headers"""
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    async def _get_session(self):
        """Get or create aiohttp session"""
        if self._session is None:
            try:
                import aiohttp
                self._session = aiohttp.ClientSession()
            except ImportError:
                raise RuntimeError("aiohttp is required for async HTTP requests")
        return self._session

    async def close(self):
        """Close the client session"""
        if self._session:
            await self._session.close()
            self._session = None
        if self._ws_connection:
            await self._ws_connection.close()
            self._ws_connection = None

    def _build_url(self, endpoint: str) -> str:
        """Build full URL for endpoint"""
        return f"{self.base_url}{self.api_prefix}{endpoint}"

    # Dictionary Operations

    async def lookup(self, query: str) -> Optional[DictionaryEntry]:
        """Look up a symbol or codename in the dictionary"""
        session = await self._get_session()
        url = self._build_url(f"/dictionary/lookup?query={query}")

        async with session.get(url, headers=self._headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("found"):
                    return DictionaryEntry(
                        symbol=data.get("symbol", ""),
                        codename=data.get("codename", ""),
                        category=data.get("category"),
                        description=data.get("description")
                    )
            return None

    async def search(self, query: str, limit: int = 50) -> List[DictionaryEntry]:
        """Search the dictionary"""
        session = await self._get_session()
        url = self._build_url(f"/dictionary/search?q={query}&limit={limit}")

        async with session.get(url, headers=self._headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return [
                    DictionaryEntry(
                        symbol=entry.get("symbol", ""),
                        codename=entry.get("codename", ""),
                        category=entry.get("category"),
                        description=entry.get("description")
                    )
                    for entry in data.get("results", [])
                ]
            return []

    async def get_dictionary_stats(self) -> Dict[str, Any]:
        """Get dictionary statistics"""
        session = await self._get_session()
        url = self._build_url("/dictionary/stats")

        async with session.get(url, headers=self._headers) as resp:
            if resp.status == 200:
                return await resp.json()
            return {}

    # Scanning Operations

    async def scan_file(
        self,
        file_path: str,
        rules: Optional[str] = None,
        rules_file: Optional[str] = None
    ) -> ScanResult:
        """Scan a file with YARA rules"""
        session = await self._get_session()
        url = self._build_url("/scan/file")

        payload = {"file_path": file_path}
        if rules:
            payload["rules"] = rules
        if rules_file:
            payload["rules_file"] = rules_file

        async with session.post(url, json=payload, headers=self._headers) as resp:
            data = await resp.json()
            return ScanResult(
                success=data.get("success", False),
                matches=data.get("matches", []),
                match_count=data.get("match_count", 0),
                error=data.get("error"),
                execution_time_ms=data.get("execution_time_ms")
            )

    async def scan_data(
        self,
        data: bytes,
        rules: Optional[str] = None,
        rules_file: Optional[str] = None
    ) -> ScanResult:
        """Scan raw data with YARA rules"""
        session = await self._get_session()
        url = self._build_url("/scan/data")

        import base64
        payload = {"data": base64.b64encode(data).decode()}
        if rules:
            payload["rules"] = rules
        if rules_file:
            payload["rules_file"] = rules_file

        async with session.post(url, json=payload, headers=self._headers) as resp:
            data = await resp.json()
            return ScanResult(
                success=data.get("success", False),
                matches=data.get("matches", []),
                match_count=data.get("match_count", 0),
                error=data.get("error"),
                execution_time_ms=data.get("execution_time_ms")
            )

    async def validate_rule(self, rule: str) -> Dict[str, Any]:
        """Validate a YARA rule"""
        session = await self._get_session()
        url = self._build_url("/rules/validate")

        async with session.post(url, json={"rule": rule}, headers=self._headers) as resp:
            return await resp.json()

    # Transcode Operations

    async def encode(self, rule: str) -> TranscodeResult:
        """Encode a rule with codenames"""
        session = await self._get_session()
        url = self._build_url("/transcode/encode")

        async with session.post(url, json={"rule": rule}, headers=self._headers) as resp:
            data = await resp.json()
            return TranscodeResult(
                success=data.get("success", False),
                transcoded=data.get("transcoded", ""),
                mappings=data.get("mappings", {}),
                direction="encode",
                error=data.get("error")
            )

    async def decode(self, rule: str) -> TranscodeResult:
        """Decode a rule from codenames"""
        session = await self._get_session()
        url = self._build_url("/transcode/decode")

        async with session.post(url, json={"rule": rule}, headers=self._headers) as resp:
            data = await resp.json()
            return TranscodeResult(
                success=data.get("success", False),
                transcoded=data.get("transcoded", ""),
                mappings=data.get("mappings", {}),
                direction="decode",
                error=data.get("error")
            )

    # Feed Scanning

    async def scan_feeds(self, use_case: str = "all") -> Dict[str, Any]:
        """Scan web feeds for YARA rules"""
        session = await self._get_session()
        url = self._build_url(f"/feed/scan/{use_case}")

        async with session.post(url, headers=self._headers) as resp:
            return await resp.json()

    # Streaming

    async def stream_rules(self, callback):
        """Stream rules via WebSocket"""
        try:
            import websockets
        except ImportError:
            raise RuntimeError("websockets is required for streaming")

        ws_url = self.base_url.replace("http://", "ws://").replace("https://", "wss://")
        ws_url = f"{ws_url}{self.api_prefix}/stream/rules"

        headers = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        async with websockets.connect(ws_url, extra_headers=headers) as ws:
            self._ws_connection = ws
            try:
                async for message in ws:
                    data = json.loads(message)
                    await callback(data)
            finally:
                self._ws_connection = None

    # Worker Operations

    async def submit_task(self, task_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a task to the worker queue"""
        session = await self._get_session()
        url = self._build_url("/worker/task")

        async with session.post(
            url,
            json={"task_type": task_type, "payload": payload},
            headers=self._headers
        ) as resp:
            return await resp.json()

    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get status of a submitted task"""
        session = await self._get_session()
        url = self._build_url(f"/worker/task/{task_id}")

        async with session.get(url, headers=self._headers) as resp:
            return await resp.json()


# Synchronous wrapper for non-async contexts
class RYaraClientSync:
    """Synchronous wrapper for RYaraClient"""

    def __init__(self, *args, **kwargs):
        self._client = RYaraClient(*args, **kwargs)

    def _run(self, coro):
        """Run a coroutine synchronously"""
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        return loop.run_until_complete(coro)

    def lookup(self, query: str) -> Optional[DictionaryEntry]:
        return self._run(self._client.lookup(query))

    def search(self, query: str, limit: int = 50) -> List[DictionaryEntry]:
        return self._run(self._client.search(query, limit))

    def scan_file(self, file_path: str, **kwargs) -> ScanResult:
        return self._run(self._client.scan_file(file_path, **kwargs))

    def validate_rule(self, rule: str) -> Dict[str, Any]:
        return self._run(self._client.validate_rule(rule))

    def encode(self, rule: str) -> TranscodeResult:
        return self._run(self._client.encode(rule))

    def decode(self, rule: str) -> TranscodeResult:
        return self._run(self._client.decode(rule))

    def close(self):
        self._run(self._client.close())
