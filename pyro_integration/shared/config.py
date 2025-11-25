"""
R-YARA Configuration for PYRO Platform Integration

Centralized configuration for all R-YARA components.
"""

import os
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, Any, List


@dataclass
class APIConfig:
    """API server configuration"""
    host: str = "0.0.0.0"
    port: int = 3006
    base_path: str = "/api/v2/r-yara"
    enable_cors: bool = True
    cors_origins: List[str] = field(default_factory=lambda: ["*"])


@dataclass
class WorkerConfig:
    """Worker configuration"""
    max_concurrent_tasks: int = 4
    heartbeat_interval_ms: int = 30000
    task_timeout_ms: int = 60000
    retry_delay_ms: int = 5000
    max_retries: int = 3


@dataclass
class StreamConfig:
    """Streaming configuration"""
    chunk_size: int = 65536  # 64KB chunks
    buffer_size: int = 1048576  # 1MB buffer
    heartbeat_interval_ms: int = 10000
    reconnect_delay_ms: int = 5000


@dataclass
class StorageConfig:
    """Storage configuration"""
    data_dir: str = "data"
    rules_dir: str = "rules"
    database_file: str = "r-yara.db"
    cache_size_mb: int = 256


@dataclass
class PyroIntegrationConfig:
    """PYRO Platform integration configuration"""
    pyro_api_url: Optional[str] = None
    pyro_ws_url: Optional[str] = None
    auth_token: Optional[str] = None
    component_id: str = "r-yara"
    register_on_startup: bool = True


@dataclass
class RYaraConfig:
    """
    Complete R-YARA configuration.

    Can be loaded from environment variables, JSON file, or defaults.
    """
    api: APIConfig = field(default_factory=APIConfig)
    worker: WorkerConfig = field(default_factory=WorkerConfig)
    stream: StreamConfig = field(default_factory=StreamConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    pyro: PyroIntegrationConfig = field(default_factory=PyroIntegrationConfig)

    # Runtime flags
    debug: bool = False
    log_level: str = "INFO"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON"""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str):
        """Save configuration to file"""
        with open(path, 'w') as f:
            f.write(self.to_json())

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'RYaraConfig':
        """Create from dictionary"""
        return cls(
            api=APIConfig(**d.get('api', {})),
            worker=WorkerConfig(**d.get('worker', {})),
            stream=StreamConfig(**d.get('stream', {})),
            storage=StorageConfig(**d.get('storage', {})),
            pyro=PyroIntegrationConfig(**d.get('pyro', {})),
            debug=d.get('debug', False),
            log_level=d.get('log_level', 'INFO')
        )

    @classmethod
    def from_json(cls, json_str: str) -> 'RYaraConfig':
        """Create from JSON string"""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def load(cls, path: str) -> 'RYaraConfig':
        """Load configuration from file"""
        with open(path) as f:
            return cls.from_json(f.read())

    @classmethod
    def from_env(cls) -> 'RYaraConfig':
        """Load configuration from environment variables"""
        config = cls()

        # API config
        config.api.host = os.environ.get('RYARA_API_HOST', config.api.host)
        config.api.port = int(os.environ.get('RYARA_API_PORT', config.api.port))

        # Worker config
        config.worker.max_concurrent_tasks = int(
            os.environ.get('RYARA_WORKER_MAX_TASKS', config.worker.max_concurrent_tasks)
        )

        # Storage config
        config.storage.data_dir = os.environ.get('RYARA_DATA_DIR', config.storage.data_dir)
        config.storage.database_file = os.environ.get('RYARA_DB_FILE', config.storage.database_file)

        # PYRO integration
        config.pyro.pyro_api_url = os.environ.get('PYRO_API_URL')
        config.pyro.pyro_ws_url = os.environ.get('PYRO_WS_URL')
        config.pyro.auth_token = os.environ.get('PYRO_AUTH_TOKEN')

        # Runtime flags
        config.debug = os.environ.get('RYARA_DEBUG', '').lower() in ('true', '1', 'yes')
        config.log_level = os.environ.get('RYARA_LOG_LEVEL', config.log_level)

        return config

    @classmethod
    def default(cls) -> 'RYaraConfig':
        """Create default configuration"""
        return cls()

    def ensure_directories(self):
        """Create necessary directories"""
        Path(self.storage.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.storage.data_dir, self.storage.rules_dir).mkdir(parents=True, exist_ok=True)

    def get_database_path(self) -> str:
        """Get full database path"""
        return str(Path(self.storage.data_dir) / self.storage.database_file)

    def get_rules_path(self) -> str:
        """Get full rules directory path"""
        return str(Path(self.storage.data_dir) / self.storage.rules_dir)
