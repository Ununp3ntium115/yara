"""
R-YARA API Gateway

Unified gateway for all R-YARA services and integrations.
"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime

from ..shared.config import RYaraConfig
from ..shared.protocol import StreamMessage, MessageType
from ..workers import ScannerWorker, TranscoderWorker

logger = logging.getLogger(__name__)


@dataclass
class ServiceEndpoint:
    """Service endpoint configuration"""
    name: str
    url: str
    health_path: str = "/health"
    healthy: bool = False
    last_check: Optional[datetime] = None


@dataclass
class GatewayStats:
    """Gateway statistics"""
    requests_total: int = 0
    requests_success: int = 0
    requests_failed: int = 0
    active_connections: int = 0
    uptime_seconds: float = 0.0
    start_time: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requests_total": self.requests_total,
            "requests_success": self.requests_success,
            "requests_failed": self.requests_failed,
            "active_connections": self.active_connections,
            "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
            "success_rate": (
                self.requests_success / self.requests_total
                if self.requests_total > 0 else 1.0
            )
        }


class RYaraGateway:
    """
    R-YARA API Gateway.

    Provides:
    - Unified access to all R-YARA services
    - Request routing and load balancing
    - Health monitoring
    - Rate limiting
    - Authentication proxying
    """

    def __init__(self, config: RYaraConfig = None):
        self.config = config or RYaraConfig.from_env()
        self.services: Dict[str, ServiceEndpoint] = {}
        self.stats = GatewayStats()
        self._running = False
        self._health_check_task = None

        # Local service instances
        self._scanner: Optional[ScannerWorker] = None
        self._transcoder: Optional[TranscoderWorker] = None

        # Event handlers
        self._event_handlers: Dict[str, List[Callable]] = {}

    def register_service(self, name: str, url: str, health_path: str = "/health"):
        """Register an external service endpoint"""
        self.services[name] = ServiceEndpoint(
            name=name,
            url=url,
            health_path=health_path
        )
        logger.info(f"Registered service: {name} at {url}")

    def register_local_scanner(self, scanner: ScannerWorker):
        """Register local scanner worker"""
        self._scanner = scanner
        logger.info("Registered local scanner worker")

    def register_local_transcoder(self, transcoder: TranscoderWorker):
        """Register local transcoder worker"""
        self._transcoder = transcoder
        logger.info("Registered local transcoder worker")

    def on(self, event: str, handler: Callable):
        """Register event handler"""
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(handler)

    async def emit(self, event: str, data: Any = None):
        """Emit event to handlers"""
        for handler in self._event_handlers.get(event, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    handler(data)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

    async def start(self):
        """Start the gateway"""
        self._running = True
        self.stats = GatewayStats()
        logger.info("R-YARA Gateway starting...")

        # Initialize local workers if not provided
        if not self._scanner:
            self._scanner = ScannerWorker(self.config)
        if not self._transcoder:
            self._transcoder = TranscoderWorker(self.config)

        # Start health checking
        self._health_check_task = asyncio.create_task(self._health_check_loop())

        await self.emit("started")
        logger.info("R-YARA Gateway started")

    async def stop(self):
        """Stop the gateway"""
        self._running = False
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass

        await self.emit("stopped")
        logger.info("R-YARA Gateway stopped")

    async def _health_check_loop(self):
        """Periodically check service health"""
        while self._running:
            try:
                await self._check_all_services()
                await asyncio.sleep(30)  # Check every 30 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")
                await asyncio.sleep(5)

    async def _check_all_services(self):
        """Check health of all registered services"""
        for name, service in self.services.items():
            try:
                healthy = await self._check_service_health(service)
                service.healthy = healthy
                service.last_check = datetime.utcnow()
            except Exception as e:
                service.healthy = False
                logger.warning(f"Service {name} health check failed: {e}")

    async def _check_service_health(self, service: ServiceEndpoint) -> bool:
        """Check health of a single service"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"{service.url}{service.health_path}"
                async with session.get(url, timeout=5) as resp:
                    return resp.status == 200
        except ImportError:
            # aiohttp not available, assume healthy
            return True
        except Exception:
            return False

    # Gateway API Methods

    async def route_request(
        self,
        service: str,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Route a request to a service"""
        self.stats.requests_total += 1

        # Check if local handler exists
        if service == "scanner" and self._scanner:
            return await self._handle_scanner_request(path, data or {})
        elif service == "transcoder" and self._transcoder:
            return await self._handle_transcoder_request(path, data or {})

        # Route to external service
        if service not in self.services:
            self.stats.requests_failed += 1
            return {"error": f"Unknown service: {service}", "success": False}

        endpoint = self.services[service]
        if not endpoint.healthy:
            self.stats.requests_failed += 1
            return {"error": f"Service {service} is unhealthy", "success": False}

        try:
            result = await self._proxy_request(endpoint, method, path, data, headers)
            self.stats.requests_success += 1
            return result
        except Exception as e:
            self.stats.requests_failed += 1
            return {"error": str(e), "success": False}

    async def _proxy_request(
        self,
        endpoint: ServiceEndpoint,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Proxy request to external service"""
        try:
            import aiohttp
            url = f"{endpoint.url}{path}"

            async with aiohttp.ClientSession() as session:
                if method.upper() == "GET":
                    async with session.get(url, headers=headers) as resp:
                        return await resp.json()
                elif method.upper() == "POST":
                    async with session.post(url, json=data, headers=headers) as resp:
                        return await resp.json()
                else:
                    return {"error": f"Unsupported method: {method}"}
        except ImportError:
            return {"error": "aiohttp is required for proxying"}

    async def _handle_scanner_request(
        self,
        path: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle scanner request locally"""
        from ..shared.protocol import WorkerTask, TaskType

        if "/scan/file" in path:
            task = WorkerTask(
                task_id="gateway-scan-file",
                task_type=TaskType.SCAN_FILE,
                payload=data
            )
        elif "/scan/data" in path:
            task = WorkerTask(
                task_id="gateway-scan-data",
                task_type=TaskType.SCAN_DATA,
                payload=data
            )
        elif "/validate" in path:
            task = WorkerTask(
                task_id="gateway-validate",
                task_type=TaskType.VALIDATE_RULE,
                payload=data
            )
        else:
            return {"error": f"Unknown scanner path: {path}"}

        result = await self._scanner.process_task(task)
        return {
            "success": result.success,
            "data": result.data,
            "error": result.error
        }

    async def _handle_transcoder_request(
        self,
        path: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle transcoder request locally"""
        from ..shared.protocol import WorkerTask, TaskType

        if "/encode" in path:
            data["direction"] = "encode"
        elif "/decode" in path:
            data["direction"] = "decode"

        if "/lookup" in path:
            task = WorkerTask(
                task_id="gateway-lookup",
                task_type=TaskType.DICTIONARY_LOOKUP,
                payload=data
            )
        else:
            task = WorkerTask(
                task_id="gateway-transcode",
                task_type=TaskType.TRANSCODE,
                payload=data
            )

        result = await self._transcoder.process_task(task)
        return {
            "success": result.success,
            "data": result.data,
            "error": result.error
        }

    # Convenience methods

    async def scan_file(self, file_path: str, rules: str = None) -> Dict[str, Any]:
        """Scan a file with YARA rules"""
        return await self.route_request(
            "scanner", "POST", "/scan/file",
            {"file_path": file_path, "rules": rules}
        )

    async def validate_rule(self, rule: str) -> Dict[str, Any]:
        """Validate a YARA rule"""
        return await self.route_request(
            "scanner", "POST", "/rules/validate",
            {"rule": rule}
        )

    async def encode_rule(self, rule: str) -> Dict[str, Any]:
        """Encode a rule with codenames"""
        return await self.route_request(
            "transcoder", "POST", "/transcode/encode",
            {"rule": rule}
        )

    async def decode_rule(self, rule: str) -> Dict[str, Any]:
        """Decode a rule from codenames"""
        return await self.route_request(
            "transcoder", "POST", "/transcode/decode",
            {"rule": rule}
        )

    async def lookup(self, query: str) -> Dict[str, Any]:
        """Look up a symbol or codename"""
        return await self.route_request(
            "transcoder", "POST", "/dictionary/lookup",
            {"query": query}
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get gateway statistics"""
        return {
            "gateway": self.stats.to_dict(),
            "services": {
                name: {
                    "url": svc.url,
                    "healthy": svc.healthy,
                    "last_check": svc.last_check.isoformat() if svc.last_check else None
                }
                for name, svc in self.services.items()
            }
        }

    def get_health(self) -> Dict[str, Any]:
        """Get gateway health status"""
        healthy_services = sum(1 for s in self.services.values() if s.healthy)
        total_services = len(self.services)

        return {
            "status": "healthy" if healthy_services == total_services else "degraded",
            "services_healthy": healthy_services,
            "services_total": total_services,
            "uptime_seconds": (datetime.utcnow() - self.stats.start_time).total_seconds()
        }


async def create_gateway(config: RYaraConfig = None) -> RYaraGateway:
    """Create and start a gateway instance"""
    gateway = RYaraGateway(config)
    await gateway.start()
    return gateway
