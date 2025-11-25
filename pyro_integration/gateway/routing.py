"""
R-YARA Gateway Routing

Request routing and load balancing for R-YARA services.
"""

import re
import asyncio
from typing import Dict, Any, Optional, List, Callable, Pattern
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class LoadBalanceStrategy(str, Enum):
    """Load balancing strategies"""
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED = "weighted"


@dataclass
class Route:
    """Route definition"""
    pattern: str
    service: str
    methods: List[str] = field(default_factory=lambda: ["GET", "POST"])
    priority: int = 0
    middleware: List[Callable] = field(default_factory=list)
    _compiled: Optional[Pattern] = field(default=None, init=False)

    def __post_init__(self):
        # Convert pattern to regex
        # Replace {param} with named capture groups
        regex_pattern = re.sub(r'\{(\w+)\}', r'(?P<\1>[^/]+)', self.pattern)
        self._compiled = re.compile(f'^{regex_pattern}$')

    def matches(self, path: str, method: str) -> Optional[Dict[str, str]]:
        """Check if route matches path and method"""
        if method.upper() not in self.methods:
            return None

        match = self._compiled.match(path)
        if match:
            return match.groupdict()
        return None


@dataclass
class ServiceInstance:
    """Service instance for load balancing"""
    url: str
    weight: int = 1
    connections: int = 0
    healthy: bool = True


class Router:
    """
    Request router with pattern matching and load balancing.
    """

    def __init__(self, strategy: LoadBalanceStrategy = LoadBalanceStrategy.ROUND_ROBIN):
        self.routes: List[Route] = []
        self.services: Dict[str, List[ServiceInstance]] = {}
        self.strategy = strategy
        self._round_robin_index: Dict[str, int] = {}
        self._global_middleware: List[Callable] = []

    def add_route(
        self,
        pattern: str,
        service: str,
        methods: List[str] = None,
        priority: int = 0,
        middleware: List[Callable] = None
    ):
        """Add a route"""
        route = Route(
            pattern=pattern,
            service=service,
            methods=methods or ["GET", "POST"],
            priority=priority,
            middleware=middleware or []
        )
        self.routes.append(route)
        # Sort by priority (higher first)
        self.routes.sort(key=lambda r: r.priority, reverse=True)
        logger.debug(f"Added route: {pattern} -> {service}")

    def add_service_instance(self, service: str, url: str, weight: int = 1):
        """Add a service instance for load balancing"""
        if service not in self.services:
            self.services[service] = []
            self._round_robin_index[service] = 0

        self.services[service].append(ServiceInstance(
            url=url,
            weight=weight
        ))
        logger.debug(f"Added service instance: {service} -> {url}")

    def use(self, middleware: Callable):
        """Add global middleware"""
        self._global_middleware.append(middleware)

    def match(self, path: str, method: str) -> Optional[tuple]:
        """Match a path to a route"""
        for route in self.routes:
            params = route.matches(path, method)
            if params is not None:
                return route, params
        return None

    def get_service_url(self, service: str) -> Optional[str]:
        """Get URL for a service using load balancing"""
        instances = self.services.get(service, [])
        healthy_instances = [i for i in instances if i.healthy]

        if not healthy_instances:
            return None

        if self.strategy == LoadBalanceStrategy.ROUND_ROBIN:
            return self._round_robin_select(service, healthy_instances)
        elif self.strategy == LoadBalanceStrategy.RANDOM:
            return self._random_select(healthy_instances)
        elif self.strategy == LoadBalanceStrategy.LEAST_CONNECTIONS:
            return self._least_connections_select(healthy_instances)
        elif self.strategy == LoadBalanceStrategy.WEIGHTED:
            return self._weighted_select(healthy_instances)

        return healthy_instances[0].url

    def _round_robin_select(
        self,
        service: str,
        instances: List[ServiceInstance]
    ) -> str:
        """Round-robin selection"""
        index = self._round_robin_index.get(service, 0)
        selected = instances[index % len(instances)]
        self._round_robin_index[service] = (index + 1) % len(instances)
        return selected.url

    def _random_select(self, instances: List[ServiceInstance]) -> str:
        """Random selection"""
        import random
        return random.choice(instances).url

    def _least_connections_select(self, instances: List[ServiceInstance]) -> str:
        """Least connections selection"""
        return min(instances, key=lambda i: i.connections).url

    def _weighted_select(self, instances: List[ServiceInstance]) -> str:
        """Weighted random selection"""
        import random
        total_weight = sum(i.weight for i in instances)
        r = random.uniform(0, total_weight)
        cumulative = 0
        for instance in instances:
            cumulative += instance.weight
            if r <= cumulative:
                return instance.url
        return instances[-1].url

    async def route(
        self,
        path: str,
        method: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Route a request"""
        # Match route
        result = self.match(path, method)
        if not result:
            return {"error": "No matching route", "status": 404}

        route, params = result

        # Build request context
        context = {
            "path": path,
            "method": method,
            "params": params,
            "data": data or {},
            "headers": headers or {},
            "route": route
        }

        # Apply global middleware
        for middleware in self._global_middleware:
            try:
                if asyncio.iscoroutinefunction(middleware):
                    context = await middleware(context)
                else:
                    context = middleware(context)
            except Exception as e:
                return {"error": f"Middleware error: {e}", "status": 500}

        # Apply route middleware
        for middleware in route.middleware:
            try:
                if asyncio.iscoroutinefunction(middleware):
                    context = await middleware(context)
                else:
                    context = middleware(context)
            except Exception as e:
                return {"error": f"Route middleware error: {e}", "status": 500}

        # Get service URL
        service_url = self.get_service_url(route.service)
        if not service_url:
            return {"error": f"No healthy instance for {route.service}", "status": 503}

        # Forward request
        try:
            return await self._forward_request(
                service_url,
                path,
                method,
                context.get("data"),
                context.get("headers")
            )
        except Exception as e:
            return {"error": str(e), "status": 500}

    async def _forward_request(
        self,
        service_url: str,
        path: str,
        method: str,
        data: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Forward request to service"""
        try:
            import aiohttp
            url = f"{service_url}{path}"

            async with aiohttp.ClientSession() as session:
                if method.upper() == "GET":
                    async with session.get(url, headers=headers, timeout=30) as resp:
                        return await resp.json()
                elif method.upper() == "POST":
                    async with session.post(
                        url, json=data, headers=headers, timeout=30
                    ) as resp:
                        return await resp.json()
                elif method.upper() == "PUT":
                    async with session.put(
                        url, json=data, headers=headers, timeout=30
                    ) as resp:
                        return await resp.json()
                elif method.upper() == "DELETE":
                    async with session.delete(url, headers=headers, timeout=30) as resp:
                        return await resp.json()
                else:
                    return {"error": f"Unsupported method: {method}"}
        except ImportError:
            return {"error": "aiohttp is required for request forwarding"}
        except Exception as e:
            return {"error": str(e)}


def create_default_router() -> Router:
    """Create router with default R-YARA routes"""
    router = Router()

    # Dictionary routes
    router.add_route("/api/v2/r-yara/dictionary/lookup", "dictionary")
    router.add_route("/api/v2/r-yara/dictionary/search", "dictionary")
    router.add_route("/api/v2/r-yara/dictionary/stats", "dictionary")

    # Scanner routes
    router.add_route("/api/v2/r-yara/scan/file", "scanner", methods=["POST"])
    router.add_route("/api/v2/r-yara/scan/data", "scanner", methods=["POST"])
    router.add_route("/api/v2/r-yara/rules/validate", "scanner", methods=["POST"])
    router.add_route("/api/v2/r-yara/rules/compile", "scanner", methods=["POST"])

    # Transcoder routes
    router.add_route("/api/v2/r-yara/transcode/encode", "transcoder", methods=["POST"])
    router.add_route("/api/v2/r-yara/transcode/decode", "transcoder", methods=["POST"])

    # Feed scanner routes
    router.add_route("/api/v2/r-yara/feed/scan/{use_case}", "feed-scanner", methods=["POST"])

    # Worker routes
    router.add_route("/api/v2/r-yara/worker/task", "worker", methods=["POST"])
    router.add_route("/api/v2/r-yara/worker/task/{task_id}", "worker")

    return router
