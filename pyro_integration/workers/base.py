"""
R-YARA Base Worker

Base class for all R-YARA workers that integrate with PYRO Platform.
"""

import asyncio
import json
import uuid
import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Callable
from datetime import datetime

from ..shared.protocol import (
    StreamMessage, WorkerTask, TaskResult, WorkerRegistration,
    MessageType, TaskType
)
from ..shared.config import RYaraConfig

logger = logging.getLogger(__name__)


class RYaraWorker(ABC):
    """
    Base class for R-YARA workers.

    Implements the PYRO Platform worker protocol for:
    - Registration with platform
    - Task reception and processing
    - Result reporting
    - Heartbeat maintenance
    """

    def __init__(self, config: RYaraConfig = None, worker_id: str = None):
        self.config = config or RYaraConfig.from_env()
        self.worker_id = worker_id or f"r-yara-{uuid.uuid4().hex[:8]}"
        self.running = False
        self.current_tasks: Dict[str, WorkerTask] = {}
        self._ws_connection = None
        self._heartbeat_task = None

    @property
    @abstractmethod
    def worker_type(self) -> str:
        """Worker type identifier"""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> list:
        """List of task types this worker can handle"""
        pass

    @abstractmethod
    async def process_task(self, task: WorkerTask) -> TaskResult:
        """Process a single task"""
        pass

    def get_registration(self) -> WorkerRegistration:
        """Get worker registration message"""
        return WorkerRegistration(
            worker_id=self.worker_id,
            worker_type=self.worker_type,
            capabilities=self.capabilities,
            max_concurrent_tasks=self.config.worker.max_concurrent_tasks,
            version="0.1.0"
        )

    async def connect(self):
        """Connect to PYRO Platform"""
        if not self.config.pyro.pyro_ws_url:
            logger.warning("No PYRO WebSocket URL configured, running in standalone mode")
            return

        try:
            import websockets
            self._ws_connection = await websockets.connect(
                self.config.pyro.pyro_ws_url,
                extra_headers={
                    "Authorization": f"Bearer {self.config.pyro.auth_token}"
                } if self.config.pyro.auth_token else {}
            )
            logger.info(f"Connected to PYRO Platform at {self.config.pyro.pyro_ws_url}")

            # Send registration
            registration = self.get_registration()
            await self._ws_connection.send(json.dumps({
                "type": "worker_register",
                "data": json.loads(registration.to_json())
            }))
            logger.info(f"Worker {self.worker_id} registered with PYRO Platform")

        except ImportError:
            logger.warning("websockets package not installed, running in standalone mode")
        except Exception as e:
            logger.error(f"Failed to connect to PYRO Platform: {e}")

    async def disconnect(self):
        """Disconnect from PYRO Platform"""
        if self._ws_connection:
            await self._ws_connection.close()
            self._ws_connection = None
            logger.info("Disconnected from PYRO Platform")

    async def _heartbeat_loop(self):
        """Send periodic heartbeats"""
        while self.running:
            try:
                if self._ws_connection:
                    await self._ws_connection.send(json.dumps({
                        "type": "heartbeat",
                        "worker_id": self.worker_id,
                        "timestamp": datetime.utcnow().isoformat(),
                        "active_tasks": len(self.current_tasks)
                    }))
                await asyncio.sleep(self.config.worker.heartbeat_interval_ms / 1000)
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(5)

    async def _receive_tasks(self):
        """Receive and process tasks from PYRO Platform"""
        while self.running:
            try:
                if self._ws_connection:
                    message = await self._ws_connection.recv()
                    data = json.loads(message)

                    if data.get("type") == "task_assign":
                        task = WorkerTask.from_json(json.dumps(data.get("task", {})))
                        asyncio.create_task(self._handle_task(task))
            except Exception as e:
                logger.error(f"Task receive error: {e}")
                await asyncio.sleep(1)

    async def _handle_task(self, task: WorkerTask):
        """Handle a single task"""
        self.current_tasks[task.task_id] = task
        start_time = datetime.utcnow()

        try:
            logger.info(f"Processing task {task.task_id} ({task.task_type.value})")
            result = await asyncio.wait_for(
                self.process_task(task),
                timeout=task.timeout_ms / 1000
            )
        except asyncio.TimeoutError:
            result = TaskResult(
                task_id=task.task_id,
                success=False,
                error="Task timed out"
            )
        except Exception as e:
            result = TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e)
            )

        # Calculate execution time
        execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        result.execution_time_ms = int(execution_time)

        # Send result
        await self._send_result(result)

        # Clean up
        del self.current_tasks[task.task_id]

    async def _send_result(self, result: TaskResult):
        """Send task result to PYRO Platform"""
        if self._ws_connection:
            await self._ws_connection.send(json.dumps({
                "type": "task_result",
                "worker_id": self.worker_id,
                "result": json.loads(result.to_json())
            }))
            logger.info(f"Sent result for task {result.task_id}")

    async def run(self):
        """Run the worker"""
        self.running = True
        logger.info(f"Starting R-YARA worker {self.worker_id}")

        # Connect to PYRO Platform
        await self.connect()

        # Start heartbeat
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        # Main task receive loop
        try:
            if self._ws_connection:
                await self._receive_tasks()
            else:
                # Standalone mode - just keep running
                while self.running:
                    await asyncio.sleep(1)
        finally:
            self.running = False
            if self._heartbeat_task:
                self._heartbeat_task.cancel()
            await self.disconnect()

    async def stop(self):
        """Stop the worker"""
        self.running = False
        await self.disconnect()

    # Convenience method for standalone task processing
    async def execute_task(self, task: WorkerTask) -> TaskResult:
        """Execute a task directly (standalone mode)"""
        return await self.process_task(task)
