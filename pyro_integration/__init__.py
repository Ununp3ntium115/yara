"""
R-YARA PYRO Platform Integration Package

This package provides R-YARA capabilities as an installable component
for PYRO Platform workers, APIs, and endpoints.

Components:
- workers/    - Worker implementations for distributed processing
- api/        - API client and server components
- gateway/    - API gateway for unified access
- shared/     - Shared utilities and protocols
"""

__version__ = "0.1.0"
__pyro_component__ = "r-yara"

from .shared.protocol import StreamMessage, WorkerTask, TaskType
from .shared.config import RYaraConfig

__all__ = [
    "StreamMessage",
    "WorkerTask",
    "TaskType",
    "RYaraConfig",
]
