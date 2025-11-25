"""
R-YARA Communication Protocol

Defines message formats for streaming and worker communication.
Compatible with PYRO Platform messaging system.
"""

import json
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime


class MessageType(str, Enum):
    """Types of stream messages"""
    RULE_START = "rule_start"
    RULE_CHUNK = "rule_chunk"
    RULE_END = "rule_end"
    MATCH = "match"
    ERROR = "error"
    HEARTBEAT = "heartbeat"
    ACK = "ack"
    TASK_ASSIGN = "task_assign"
    TASK_RESULT = "task_result"
    WORKER_REGISTER = "worker_register"
    WORKER_STATUS = "worker_status"


class TaskType(str, Enum):
    """Types of worker tasks"""
    SCAN_FILE = "scan_file"
    SCAN_DIRECTORY = "scan_directory"
    TRANSCODE_RULE = "transcode_rule"
    VALIDATE_RULE = "validate_rule"
    STREAM_RULES = "stream_rules"
    LOOKUP_DICTIONARY = "lookup_dictionary"
    FEED_SCAN = "feed_scan"


@dataclass
class StreamMessage:
    """
    Message format for R-YARA streaming protocol.

    Used for real-time rule streaming and match reporting.
    """
    type: MessageType
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Rule streaming fields
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    data: Optional[bytes] = None
    checksum: Optional[str] = None

    # Match fields
    file_path: Optional[str] = None
    offset: Optional[int] = None
    matched_strings: Optional[List[str]] = None

    # Error fields
    error_code: Optional[int] = None
    error_message: Optional[str] = None

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to JSON"""
        d = asdict(self)
        d['type'] = self.type.value
        # Convert bytes to base64 if present
        if d.get('data') and isinstance(d['data'], bytes):
            import base64
            d['data'] = base64.b64encode(d['data']).decode('utf-8')
        return json.dumps(d)

    @classmethod
    def from_json(cls, json_str: str) -> 'StreamMessage':
        """Deserialize from JSON"""
        d = json.loads(json_str)
        d['type'] = MessageType(d['type'])
        # Convert base64 back to bytes if present
        if d.get('data') and isinstance(d['data'], str):
            import base64
            d['data'] = base64.b64decode(d['data'])
        return cls(**d)

    @classmethod
    def heartbeat(cls) -> 'StreamMessage':
        """Create a heartbeat message"""
        return cls(type=MessageType.HEARTBEAT)

    @classmethod
    def error(cls, code: int, message: str) -> 'StreamMessage':
        """Create an error message"""
        return cls(
            type=MessageType.ERROR,
            error_code=code,
            error_message=message
        )

    @classmethod
    def rule_start(cls, rule_id: str, rule_name: str) -> 'StreamMessage':
        """Create a rule start message"""
        return cls(
            type=MessageType.RULE_START,
            rule_id=rule_id,
            rule_name=rule_name
        )

    @classmethod
    def rule_chunk(cls, rule_id: str, data: bytes) -> 'StreamMessage':
        """Create a rule chunk message"""
        return cls(
            type=MessageType.RULE_CHUNK,
            rule_id=rule_id,
            data=data
        )

    @classmethod
    def rule_end(cls, rule_id: str, checksum: str) -> 'StreamMessage':
        """Create a rule end message"""
        return cls(
            type=MessageType.RULE_END,
            rule_id=rule_id,
            checksum=checksum
        )

    @classmethod
    def match(cls, rule_id: str, file_path: str, offset: int,
              matched_strings: List[str] = None) -> 'StreamMessage':
        """Create a match message"""
        return cls(
            type=MessageType.MATCH,
            rule_id=rule_id,
            file_path=file_path,
            offset=offset,
            matched_strings=matched_strings or []
        )


@dataclass
class WorkerTask:
    """
    Task assignment for R-YARA workers.

    Sent from PYRO Platform to R-YARA workers for processing.
    """
    task_id: str
    task_type: TaskType
    priority: int = 5  # 1-10, higher = more urgent
    timeout_ms: int = 60000  # Default 1 minute

    # Task-specific payload
    payload: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    assigned_to: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3

    def to_json(self) -> str:
        """Serialize to JSON"""
        d = asdict(self)
        d['task_type'] = self.task_type.value
        return json.dumps(d)

    @classmethod
    def from_json(cls, json_str: str) -> 'WorkerTask':
        """Deserialize from JSON"""
        d = json.loads(json_str)
        d['task_type'] = TaskType(d['task_type'])
        return cls(**d)

    @classmethod
    def scan_file(cls, task_id: str, file_path: str, rules: List[str] = None,
                  priority: int = 5) -> 'WorkerTask':
        """Create a file scan task"""
        return cls(
            task_id=task_id,
            task_type=TaskType.SCAN_FILE,
            priority=priority,
            payload={
                "file_path": file_path,
                "rules": rules or []
            }
        )

    @classmethod
    def transcode_rule(cls, task_id: str, rule_content: str,
                       direction: str = "to_codename") -> 'WorkerTask':
        """Create a rule transcoding task"""
        return cls(
            task_id=task_id,
            task_type=TaskType.TRANSCODE_RULE,
            payload={
                "rule_content": rule_content,
                "direction": direction
            }
        )

    @classmethod
    def feed_scan(cls, task_id: str, use_case: str = "all",
                  priority: int = 3) -> 'WorkerTask':
        """Create a feed scan task"""
        return cls(
            task_id=task_id,
            task_type=TaskType.FEED_SCAN,
            priority=priority,
            payload={
                "use_case": use_case
            }
        )


@dataclass
class TaskResult:
    """
    Result from a worker task execution.
    """
    task_id: str
    success: bool
    completed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Result data
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    # Metrics
    execution_time_ms: Optional[int] = None

    def to_json(self) -> str:
        """Serialize to JSON"""
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_str: str) -> 'TaskResult':
        """Deserialize from JSON"""
        return cls(**json.loads(json_str))


@dataclass
class WorkerRegistration:
    """
    Worker registration message for PYRO Platform.
    """
    worker_id: str
    worker_type: str = "r-yara"
    capabilities: List[str] = field(default_factory=list)
    max_concurrent_tasks: int = 4

    # Worker metadata
    hostname: Optional[str] = None
    version: str = "0.1.0"
    registered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_json(self) -> str:
        """Serialize to JSON"""
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_str: str) -> 'WorkerRegistration':
        """Deserialize from JSON"""
        return cls(**json.loads(json_str))

    @classmethod
    def default(cls, worker_id: str) -> 'WorkerRegistration':
        """Create a default R-YARA worker registration"""
        import socket
        return cls(
            worker_id=worker_id,
            capabilities=[
                "scan_file",
                "scan_directory",
                "transcode_rule",
                "validate_rule",
                "stream_rules",
                "lookup_dictionary",
                "feed_scan"
            ],
            hostname=socket.gethostname()
        )
