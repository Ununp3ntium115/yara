"""
R-YARA API Server

Lightweight API server for R-YARA operations.
"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional, Callable
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

from ..shared.config import RYaraConfig
from ..workers import create_scanner_worker, create_transcoder_worker

logger = logging.getLogger(__name__)


class RYaraAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for R-YARA API"""

    def __init__(self, *args, server_instance=None, **kwargs):
        self.server_instance = server_instance
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        logger.info(f"{self.address_string()} - {format % args}")

    def _send_json_response(self, data: Dict[str, Any], status: int = 200):
        """Send JSON response"""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_error_response(self, message: str, status: int = 400):
        """Send error response"""
        self._send_json_response({"error": message, "success": False}, status)

    def _get_json_body(self) -> Dict[str, Any]:
        """Get JSON body from request"""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            return json.loads(body.decode())
        return {}

    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        """Handle GET requests"""
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path.endswith("/health"):
            self._send_json_response({"status": "healthy", "service": "r-yara"})

        elif path.endswith("/dictionary/stats"):
            self._handle_dictionary_stats()

        elif "/dictionary/lookup" in path:
            q = query.get("query", [""])[0]
            self._handle_dictionary_lookup(q)

        elif "/dictionary/search" in path:
            q = query.get("q", [""])[0]
            limit = int(query.get("limit", ["50"])[0])
            self._handle_dictionary_search(q, limit)

        else:
            self._send_error_response("Not found", 404)

    def do_POST(self):
        """Handle POST requests"""
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._get_json_body()
        except json.JSONDecodeError:
            self._send_error_response("Invalid JSON")
            return

        if "/scan/file" in path:
            self._handle_scan_file(body)

        elif "/scan/data" in path:
            self._handle_scan_data(body)

        elif "/rules/validate" in path:
            self._handle_validate_rule(body)

        elif "/transcode/encode" in path:
            self._handle_transcode(body, "encode")

        elif "/transcode/decode" in path:
            self._handle_transcode(body, "decode")

        elif "/feed/scan" in path:
            use_case = path.split("/")[-1] if "/" in path else "all"
            self._handle_feed_scan(use_case)

        elif "/worker/task" in path:
            self._handle_submit_task(body)

        else:
            self._send_error_response("Not found", 404)

    def _handle_dictionary_stats(self):
        """Handle dictionary stats request"""
        # TODO: Integrate with actual dictionary store
        self._send_json_response({
            "total_entries": 0,
            "categories": {},
            "status": "not_loaded"
        })

    def _handle_dictionary_lookup(self, query: str):
        """Handle dictionary lookup request"""
        if not query:
            self._send_error_response("Missing query parameter")
            return
        # TODO: Integrate with actual dictionary store
        self._send_json_response({"found": False, "query": query})

    def _handle_dictionary_search(self, query: str, limit: int):
        """Handle dictionary search request"""
        # TODO: Integrate with actual dictionary store
        self._send_json_response({"results": [], "query": query, "count": 0})

    def _handle_scan_file(self, body: Dict[str, Any]):
        """Handle file scan request"""
        file_path = body.get("file_path")
        if not file_path:
            self._send_error_response("Missing file_path")
            return

        # Use scanner worker
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            scanner = create_scanner_worker()
            from ..shared.protocol import WorkerTask, TaskType
            task = WorkerTask(
                task_id="sync-scan",
                task_type=TaskType.SCAN_FILE,
                payload=body
            )
            result = loop.run_until_complete(scanner.process_task(task))
            self._send_json_response({
                "success": result.success,
                "matches": result.data.get("matches", []) if result.data else [],
                "match_count": result.data.get("match_count", 0) if result.data else 0,
                "error": result.error
            })
        finally:
            loop.close()

    def _handle_scan_data(self, body: Dict[str, Any]):
        """Handle data scan request"""
        data = body.get("data")
        if not data:
            self._send_error_response("Missing data")
            return

        # Decode base64 if needed
        import base64
        try:
            decoded_data = base64.b64decode(data)
            body["data"] = decoded_data
        except Exception:
            pass  # Assume already decoded or string

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            scanner = create_scanner_worker()
            from ..shared.protocol import WorkerTask, TaskType
            task = WorkerTask(
                task_id="sync-scan-data",
                task_type=TaskType.SCAN_DATA,
                payload=body
            )
            result = loop.run_until_complete(scanner.process_task(task))
            self._send_json_response({
                "success": result.success,
                "matches": result.data.get("matches", []) if result.data else [],
                "match_count": result.data.get("match_count", 0) if result.data else 0,
                "error": result.error
            })
        finally:
            loop.close()

    def _handle_validate_rule(self, body: Dict[str, Any]):
        """Handle rule validation request"""
        rule = body.get("rule")
        if not rule:
            self._send_error_response("Missing rule")
            return

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            scanner = create_scanner_worker()
            from ..shared.protocol import WorkerTask, TaskType
            task = WorkerTask(
                task_id="sync-validate",
                task_type=TaskType.VALIDATE_RULE,
                payload={"rule": rule}
            )
            result = loop.run_until_complete(scanner.process_task(task))
            self._send_json_response({
                "success": result.success,
                "valid": result.data.get("valid", False) if result.data else False,
                "errors": result.data.get("errors", []) if result.data else [],
                "error": result.error
            })
        finally:
            loop.close()

    def _handle_transcode(self, body: Dict[str, Any], direction: str):
        """Handle transcode request"""
        rule = body.get("rule")
        if not rule:
            self._send_error_response("Missing rule")
            return

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            transcoder = create_transcoder_worker()
            from ..shared.protocol import WorkerTask, TaskType
            task = WorkerTask(
                task_id="sync-transcode",
                task_type=TaskType.TRANSCODE,
                payload={"rule": rule, "direction": direction}
            )
            result = loop.run_until_complete(transcoder.process_task(task))
            self._send_json_response({
                "success": result.success,
                "transcoded": result.data.get("transcoded", "") if result.data else "",
                "mappings": result.data.get("mappings", {}) if result.data else {},
                "direction": direction,
                "error": result.error
            })
        finally:
            loop.close()

    def _handle_feed_scan(self, use_case: str):
        """Handle feed scan request"""
        # TODO: Integrate with feed scanner
        self._send_json_response({
            "success": True,
            "use_case": use_case,
            "rules": [],
            "rule_count": 0,
            "message": "Feed scanning not yet implemented in API server"
        })

    def _handle_submit_task(self, body: Dict[str, Any]):
        """Handle task submission"""
        task_type = body.get("task_type")
        payload = body.get("payload", {})

        if not task_type:
            self._send_error_response("Missing task_type")
            return

        import uuid
        task_id = str(uuid.uuid4())

        self._send_json_response({
            "success": True,
            "task_id": task_id,
            "status": "queued",
            "message": "Task queued for processing"
        })


class RYaraAPIServer:
    """
    R-YARA API Server.

    Provides HTTP REST API for R-YARA operations.
    """

    def __init__(self, config: RYaraConfig = None, host: str = "0.0.0.0", port: int = 8080):
        self.config = config or RYaraConfig.from_env()
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, blocking: bool = True):
        """Start the API server"""
        def handler(*args, **kwargs):
            return RYaraAPIHandler(*args, server_instance=self, **kwargs)

        self._server = HTTPServer((self.host, self.port), handler)
        logger.info(f"R-YARA API server starting on {self.host}:{self.port}")

        if blocking:
            self._server.serve_forever()
        else:
            self._thread = threading.Thread(target=self._server.serve_forever)
            self._thread.daemon = True
            self._thread.start()

    def stop(self):
        """Stop the API server"""
        if self._server:
            self._server.shutdown()
            self._server = None
            logger.info("R-YARA API server stopped")

    def __enter__(self):
        self.start(blocking=False)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


def run_server(host: str = "0.0.0.0", port: int = 8080):
    """Run the API server"""
    server = RYaraAPIServer(host=host, port=port)
    try:
        server.start(blocking=True)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    run_server(host, port)
