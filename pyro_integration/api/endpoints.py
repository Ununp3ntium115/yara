"""
R-YARA API Endpoints

Defines API endpoints for integration with web frameworks.
"""

from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass


@dataclass
class Endpoint:
    """API endpoint definition"""
    path: str
    method: str
    handler: str
    description: str
    request_schema: Optional[Dict[str, Any]] = None
    response_schema: Optional[Dict[str, Any]] = None


# R-YARA API Endpoints
ENDPOINTS = [
    # Health
    Endpoint(
        path="/api/v2/r-yara/health",
        method="GET",
        handler="health_check",
        description="Health check endpoint"
    ),

    # Dictionary
    Endpoint(
        path="/api/v2/r-yara/dictionary/lookup",
        method="GET",
        handler="dictionary_lookup",
        description="Look up a symbol or codename",
        request_schema={"query": "string"}
    ),
    Endpoint(
        path="/api/v2/r-yara/dictionary/search",
        method="GET",
        handler="dictionary_search",
        description="Search dictionary entries",
        request_schema={"q": "string", "limit": "integer"}
    ),
    Endpoint(
        path="/api/v2/r-yara/dictionary/stats",
        method="GET",
        handler="dictionary_stats",
        description="Get dictionary statistics"
    ),

    # Scanning
    Endpoint(
        path="/api/v2/r-yara/scan/file",
        method="POST",
        handler="scan_file",
        description="Scan a file with YARA rules",
        request_schema={
            "file_path": "string",
            "rules": "string (optional)",
            "rules_file": "string (optional)"
        }
    ),
    Endpoint(
        path="/api/v2/r-yara/scan/data",
        method="POST",
        handler="scan_data",
        description="Scan raw data with YARA rules",
        request_schema={
            "data": "string (base64)",
            "rules": "string (optional)",
            "rules_file": "string (optional)"
        }
    ),

    # Rules
    Endpoint(
        path="/api/v2/r-yara/rules/validate",
        method="POST",
        handler="validate_rule",
        description="Validate YARA rule syntax",
        request_schema={"rule": "string"}
    ),
    Endpoint(
        path="/api/v2/r-yara/rules/compile",
        method="POST",
        handler="compile_rules",
        description="Compile YARA rules to binary format",
        request_schema={"rules": "string", "output_path": "string (optional)"}
    ),

    # Transcoding
    Endpoint(
        path="/api/v2/r-yara/transcode/encode",
        method="POST",
        handler="transcode_encode",
        description="Encode rule with codenames",
        request_schema={"rule": "string"}
    ),
    Endpoint(
        path="/api/v2/r-yara/transcode/decode",
        method="POST",
        handler="transcode_decode",
        description="Decode rule from codenames",
        request_schema={"rule": "string"}
    ),

    # Feed Scanning
    Endpoint(
        path="/api/v2/r-yara/feed/scan/all",
        method="POST",
        handler="scan_feeds_all",
        description="Scan all feeds for YARA rules"
    ),
    Endpoint(
        path="/api/v2/r-yara/feed/scan/malware",
        method="POST",
        handler="scan_feeds_malware",
        description="Scan malware-focused feeds"
    ),
    Endpoint(
        path="/api/v2/r-yara/feed/scan/apt",
        method="POST",
        handler="scan_feeds_apt",
        description="Scan APT-focused feeds"
    ),
    Endpoint(
        path="/api/v2/r-yara/feed/scan/ransomware",
        method="POST",
        handler="scan_feeds_ransomware",
        description="Scan ransomware-focused feeds"
    ),

    # Worker
    Endpoint(
        path="/api/v2/r-yara/worker/task",
        method="POST",
        handler="submit_task",
        description="Submit a task to worker queue",
        request_schema={"task_type": "string", "payload": "object"}
    ),
    Endpoint(
        path="/api/v2/r-yara/worker/task/{task_id}",
        method="GET",
        handler="get_task_status",
        description="Get task status"
    ),

    # Streaming (WebSocket)
    Endpoint(
        path="/api/v2/r-yara/stream/rules",
        method="WS",
        handler="stream_rules",
        description="WebSocket endpoint for rule streaming"
    ),
    Endpoint(
        path="/api/v2/r-yara/stream/worker",
        method="WS",
        handler="stream_worker",
        description="WebSocket endpoint for worker communication"
    ),
]


def get_openapi_spec() -> Dict[str, Any]:
    """Generate OpenAPI specification for R-YARA API"""
    paths = {}

    for endpoint in ENDPOINTS:
        if endpoint.method == "WS":
            continue  # Skip WebSocket endpoints

        path_item = {
            endpoint.method.lower(): {
                "summary": endpoint.description,
                "operationId": endpoint.handler,
                "tags": ["r-yara"],
                "responses": {
                    "200": {
                        "description": "Successful response",
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"}
                            }
                        }
                    }
                }
            }
        }

        if endpoint.request_schema:
            if endpoint.method == "GET":
                path_item[endpoint.method.lower()]["parameters"] = [
                    {
                        "name": k,
                        "in": "query",
                        "schema": {"type": v}
                    }
                    for k, v in endpoint.request_schema.items()
                ]
            else:
                path_item[endpoint.method.lower()]["requestBody"] = {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    k: {"type": "string"}
                                    for k in endpoint.request_schema.keys()
                                }
                            }
                        }
                    }
                }

        paths[endpoint.path] = path_item

    return {
        "openapi": "3.0.0",
        "info": {
            "title": "R-YARA API",
            "version": "0.1.0",
            "description": "R-YARA YARA rule management and scanning API"
        },
        "paths": paths,
        "tags": [
            {"name": "r-yara", "description": "R-YARA operations"}
        ]
    }


def create_router(framework: str = "fastapi"):
    """
    Create a router for the specified framework.

    Supports: fastapi, flask, aiohttp
    """
    if framework == "fastapi":
        return _create_fastapi_router()
    elif framework == "flask":
        return _create_flask_blueprint()
    elif framework == "aiohttp":
        return _create_aiohttp_routes()
    else:
        raise ValueError(f"Unsupported framework: {framework}")


def _create_fastapi_router():
    """Create FastAPI router"""
    try:
        from fastapi import APIRouter, HTTPException
        from pydantic import BaseModel
    except ImportError:
        raise ImportError("FastAPI is required: pip install fastapi")

    router = APIRouter(prefix="/api/v2/r-yara", tags=["r-yara"])

    @router.get("/health")
    async def health():
        return {"status": "healthy", "service": "r-yara"}

    @router.get("/dictionary/lookup")
    async def dictionary_lookup(query: str):
        # TODO: Implement
        return {"found": False, "query": query}

    @router.get("/dictionary/search")
    async def dictionary_search(q: str, limit: int = 50):
        # TODO: Implement
        return {"results": [], "query": q, "count": 0}

    @router.get("/dictionary/stats")
    async def dictionary_stats():
        # TODO: Implement
        return {"total_entries": 0}

    class ScanFileRequest(BaseModel):
        file_path: str
        rules: Optional[str] = None
        rules_file: Optional[str] = None

    @router.post("/scan/file")
    async def scan_file(request: ScanFileRequest):
        # TODO: Implement
        return {"success": True, "matches": [], "match_count": 0}

    class ValidateRuleRequest(BaseModel):
        rule: str

    @router.post("/rules/validate")
    async def validate_rule(request: ValidateRuleRequest):
        # TODO: Implement
        return {"valid": True}

    class TranscodeRequest(BaseModel):
        rule: str

    @router.post("/transcode/encode")
    async def transcode_encode(request: TranscodeRequest):
        # TODO: Implement
        return {"transcoded": request.rule, "mappings": {}}

    @router.post("/transcode/decode")
    async def transcode_decode(request: TranscodeRequest):
        # TODO: Implement
        return {"transcoded": request.rule, "mappings": {}}

    return router


def _create_flask_blueprint():
    """Create Flask blueprint"""
    try:
        from flask import Blueprint, request, jsonify
    except ImportError:
        raise ImportError("Flask is required: pip install flask")

    bp = Blueprint("r_yara", __name__, url_prefix="/api/v2/r-yara")

    @bp.route("/health")
    def health():
        return jsonify({"status": "healthy", "service": "r-yara"})

    @bp.route("/dictionary/lookup")
    def dictionary_lookup():
        query = request.args.get("query", "")
        return jsonify({"found": False, "query": query})

    @bp.route("/dictionary/search")
    def dictionary_search():
        q = request.args.get("q", "")
        return jsonify({"results": [], "query": q, "count": 0})

    @bp.route("/scan/file", methods=["POST"])
    def scan_file():
        data = request.get_json()
        return jsonify({"success": True, "matches": [], "match_count": 0})

    @bp.route("/rules/validate", methods=["POST"])
    def validate_rule():
        data = request.get_json()
        return jsonify({"valid": True})

    @bp.route("/transcode/encode", methods=["POST"])
    def transcode_encode():
        data = request.get_json()
        return jsonify({"transcoded": data.get("rule", ""), "mappings": {}})

    @bp.route("/transcode/decode", methods=["POST"])
    def transcode_decode():
        data = request.get_json()
        return jsonify({"transcoded": data.get("rule", ""), "mappings": {}})

    return bp


def _create_aiohttp_routes():
    """Create aiohttp routes"""
    try:
        from aiohttp import web
    except ImportError:
        raise ImportError("aiohttp is required: pip install aiohttp")

    routes = web.RouteTableDef()

    @routes.get("/api/v2/r-yara/health")
    async def health(request):
        return web.json_response({"status": "healthy", "service": "r-yara"})

    @routes.get("/api/v2/r-yara/dictionary/lookup")
    async def dictionary_lookup(request):
        query = request.query.get("query", "")
        return web.json_response({"found": False, "query": query})

    @routes.get("/api/v2/r-yara/dictionary/search")
    async def dictionary_search(request):
        q = request.query.get("q", "")
        return web.json_response({"results": [], "query": q, "count": 0})

    @routes.post("/api/v2/r-yara/scan/file")
    async def scan_file(request):
        data = await request.json()
        return web.json_response({"success": True, "matches": [], "match_count": 0})

    @routes.post("/api/v2/r-yara/rules/validate")
    async def validate_rule(request):
        data = await request.json()
        return web.json_response({"valid": True})

    @routes.post("/api/v2/r-yara/transcode/encode")
    async def transcode_encode(request):
        data = await request.json()
        return web.json_response({"transcoded": data.get("rule", ""), "mappings": {}})

    @routes.post("/api/v2/r-yara/transcode/decode")
    async def transcode_decode(request):
        data = await request.json()
        return web.json_response({"transcoded": data.get("rule", ""), "mappings": {}})

    return routes
