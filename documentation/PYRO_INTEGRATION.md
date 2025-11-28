# R-YARA PYRO Platform Integration

Complete guide for integrating R-YARA with PYRO Platform.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Components](#components)
4. [API Gateway](#api-gateway)
5. [WebSocket Streaming](#websocket-streaming)
6. [Worker System](#worker-system)
7. [Task Queue](#task-queue)
8. [Configuration](#configuration)
9. [Deployment](#deployment)
10. [Examples](#examples)

## Overview

R-YARA PYRO integration provides a complete platform solution for distributed YARA scanning with:

- **API Gateway**: Unified access to R-YARA services
- **WebSocket Streaming**: Real-time rule and result streaming
- **Worker Pool**: Distributed scanning across multiple workers
- **Task Queue**: Async job processing and coordination
- **PYRO Connection**: Native PYRO Platform integration

### Key Features

- **Scalability**: Horizontal scaling with worker pools
- **Real-time**: WebSocket streaming for live updates
- **Reliability**: Task queue with retry and error handling
- **Security**: PYRO signature verification and authentication
- **Monitoring**: Built-in metrics and health checks

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PYRO Platform                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐        ┌─────────────┐       ┌─────────────┐ │
│  │   Client    │───────▶│   Gateway   │──────▶│  Workers    │ │
│  │ (Browser/   │  HTTP  │             │  WS   │  (Scan/     │ │
│  │   API)      │  WS    │             │       │  Transcode) │ │
│  └─────────────┘        └──────┬──────┘       └──────┬──────┘ │
│                                │                      │         │
│                                │                      │         │
│                         ┌──────▼──────────────────────▼──────┐ │
│                         │       Task Queue                   │ │
│                         │  (Async Job Processing)            │ │
│                         └──────┬─────────────────────────────┘ │
│                                │                               │
│                         ┌──────▼──────┐                       │
│                         │  R-YARA     │                       │
│                         │   Store     │                       │
│                         │  (Database) │                       │
│                         └─────────────┘                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Component Interaction

```
Client Request
      │
      ▼
┌─────────────┐
│   Gateway   │  Authenticate, route, load balance
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Task Queue  │  Queue task, assign to worker
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Worker    │  Execute scan, compile, etc.
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Store     │  Persist results, cache rules
└──────┬──────┘
       │
       ▼
   Return Results (via WebSocket or HTTP)
```

### Data Flow

```
1. Client submits task via HTTP POST
2. Gateway validates request
3. Task queued in TaskQueue
4. Worker picks up task
5. Worker executes R-YARA operation
6. Results sent via WebSocket stream
7. Final result returned via HTTP response
```

## Components

### 1. r-yara-pyro Crate

Main integration library providing all PYRO Platform functionality.

**Location**: `/rust/r-yara-pyro`

**Modules**:
- `protocol`: Message types and streaming protocols
- `config`: Configuration management
- `workers`: Worker implementations
- `api`: API server and client
- `gateway`: API gateway
- `task_queue`: Async task queue
- `pyro_connection`: PYRO Platform connectivity
- `hashing`: Cryptographic hashing (PYRO signatures)

### 2. Gateway

Unified API gateway for R-YARA services.

**Features**:
- Request routing
- Load balancing
- Authentication
- Rate limiting
- WebSocket management

### 3. Workers

Distributed workers for parallel processing.

**Worker Types**:
- **ScannerWorker**: File and data scanning
- **TranscoderWorker**: Rule encoding/decoding
- **ValidationWorker**: Rule syntax validation
- **CompilerWorker**: Rule compilation

### 4. Task Queue

Async job queue for distributed processing.

**Features**:
- Task prioritization
- Retry logic
- Dead letter queue
- Task monitoring

## API Gateway

### Starting the Gateway

```bash
# Start gateway
r-yara-pyro gateway --port 8080 --workers 4

# With custom config
r-yara-pyro gateway --config gateway.toml
```

### Gateway Endpoints

#### Health Check

```bash
GET /health
```

**Response**:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "workers": {
    "total": 4,
    "active": 3,
    "idle": 1
  },
  "uptime_seconds": 3600
}
```

#### Metrics

```bash
GET /metrics
```

**Response**:
```json
{
  "requests_total": 12345,
  "requests_per_second": 42.5,
  "average_response_time_ms": 125,
  "active_connections": 23,
  "queue_depth": 5
}
```

#### Submit Scan Task

```bash
POST /api/v2/r-yara/tasks/scan
```

**Request**:
```json
{
  "task_type": "scan_file",
  "data": {
    "rules": "rule Test { ... }",
    "target": "base64_encoded_file_data"
  },
  "priority": "normal",
  "timeout": 30
}
```

**Response**:
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "websocket_url": "ws://localhost:8080/ws/550e8400-e29b-41d4-a716-446655440000"
}
```

#### Get Task Status

```bash
GET /api/v2/r-yara/tasks/{task_id}
```

**Response**:
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "result": {
    "matches": [...]
  },
  "started_at": "2025-01-15T10:30:00Z",
  "completed_at": "2025-01-15T10:30:05Z"
}
```

## WebSocket Streaming

### Connecting to WebSocket

```javascript
// JavaScript example
const ws = new WebSocket('ws://localhost:8080/ws/task_id');

ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    console.log('Received:', message);

    switch (message.message_type) {
        case 'rule_start':
            console.log('Starting rule:', message.rule_name);
            break;
        case 'match':
            console.log('Match found:', message.data);
            break;
        case 'rule_end':
            console.log('Completed rule:', message.rule_name);
            break;
        case 'error':
            console.error('Error:', message.error);
            break;
    }
};

ws.onclose = () => {
    console.log('Connection closed');
};
```

### Message Types

#### RuleStart

Signals beginning of a rule scan.

```json
{
  "message_type": "rule_start",
  "timestamp": "2025-01-15T10:30:00Z",
  "rule_id": "rule_123",
  "rule_name": "MalwareDetection",
  "metadata": {
    "author": "Security Team",
    "description": "Detects malware"
  }
}
```

#### Match

Reports a rule match.

```json
{
  "message_type": "match",
  "timestamp": "2025-01-15T10:30:01Z",
  "rule_name": "MalwareDetection",
  "data": {
    "file": "sample.bin",
    "offset": 1024,
    "matched_data": "suspicious_pattern"
  }
}
```

#### RuleChunk

Streams large rule data in chunks.

```json
{
  "message_type": "rule_chunk",
  "timestamp": "2025-01-15T10:30:02Z",
  "rule_id": "rule_123",
  "chunk_index": 0,
  "total_chunks": 5,
  "data": "chunk_data_base64"
}
```

#### RuleEnd

Signals completion of a rule scan.

```json
{
  "message_type": "rule_end",
  "timestamp": "2025-01-15T10:30:05Z",
  "rule_id": "rule_123",
  "rule_name": "MalwareDetection",
  "metadata": {
    "matches": 3,
    "scan_time_ms": 5000
  }
}
```

#### Error

Reports an error.

```json
{
  "message_type": "error",
  "timestamp": "2025-01-15T10:30:03Z",
  "error": "Failed to parse rule: syntax error at line 5",
  "metadata": {
    "line": 5,
    "column": 12
  }
}
```

#### Heartbeat

Keep-alive ping.

```json
{
  "message_type": "heartbeat",
  "timestamp": "2025-01-15T10:30:10Z"
}
```

### Rust WebSocket Client

```rust
use tokio_tungstenite::connect_async;
use futures_util::StreamExt;
use r_yara_pyro::protocol::StreamMessage;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = "ws://localhost:8080/ws/task_id";
    let (ws_stream, _) = connect_async(url).await?;

    let (_, mut read) = ws_stream.split();

    while let Some(msg) = read.next().await {
        let msg = msg?;
        let text = msg.to_text()?;
        let message: StreamMessage = serde_json::from_str(text)?;

        match message.message_type {
            MessageType::Match => {
                println!("Match: {:?}", message.data);
            }
            MessageType::Error => {
                eprintln!("Error: {:?}", message.error);
            }
            _ => {}
        }
    }

    Ok(())
}
```

## Worker System

### Worker Types

#### ScannerWorker

Performs YARA scanning operations.

```rust
use r_yara_pyro::workers::ScannerWorker;

let worker = ScannerWorker::new("scanner-1");
worker.start().await?;
```

**Capabilities**:
- Scan files with compiled rules
- Scan raw data
- Stream results via WebSocket
- Handle large files efficiently

#### TranscoderWorker

Encodes/decodes YARA rules.

```rust
use r_yara_pyro::workers::TranscoderWorker;

let worker = TranscoderWorker::new("transcoder-1");
worker.start().await?;
```

**Capabilities**:
- Encode rules to binary format
- Decode binary to text format
- Validate encoding integrity

### Worker Configuration

```toml
# worker.toml

[worker]
id = "scanner-1"
type = "scanner"
concurrency = 4
heartbeat_interval = 10  # seconds

[connection]
gateway_url = "http://localhost:8080"
ws_url = "ws://localhost:8080/ws"
reconnect_delay = 5  # seconds

[limits]
max_file_size = 104857600  # 100 MB
timeout = 300  # 5 minutes
```

### Starting Workers

```bash
# Start scanner worker
r-yara-pyro worker scanner --id scanner-1 --concurrency 4

# Start transcoder worker
r-yara-pyro worker transcoder --id transcoder-1

# Start with config
r-yara-pyro worker --config worker.toml
```

### Worker Pool

```rust
use r_yara_pyro::workers::{WorkerPool, ScannerWorker};

let pool = WorkerPool::new();

// Add workers
for i in 0..4 {
    let worker = ScannerWorker::new(&format!("scanner-{}", i));
    pool.add_worker(worker).await;
}

// Start all workers
pool.start_all().await?;

// Shutdown
pool.shutdown().await?;
```

## Task Queue

### Task Types

```rust
pub enum TaskType {
    ScanFile,
    ScanData,
    ValidateRule,
    CompileRules,
    Transcode,
    DictionaryLookup,
    StreamRules,
    ScanFeeds,
}
```

### Creating Tasks

```rust
use r_yara_pyro::task_queue::{TaskQueue, WorkerTask, TaskType};
use uuid::Uuid;

let queue = TaskQueue::new();

let task = WorkerTask {
    task_id: Uuid::new_v4(),
    task_type: TaskType::ScanFile,
    priority: 5,
    data: serde_json::json!({
        "rules": "rule Test { ... }",
        "target": "/path/to/file"
    }),
    timeout: Some(30),
    retries: 3,
};

queue.enqueue(task).await?;
```

### Processing Tasks

```rust
use r_yara_pyro::task_queue::TaskQueue;

let queue = TaskQueue::new();

// Worker loop
loop {
    if let Some(task) = queue.dequeue().await? {
        println!("Processing task: {}", task.task_id);

        // Execute task
        match execute_task(&task).await {
            Ok(result) => {
                queue.complete(task.task_id, result).await?;
            }
            Err(e) => {
                queue.fail(task.task_id, e.to_string()).await?;
            }
        }
    }
}
```

### Task Priorities

- **0-2**: Low priority (background tasks)
- **3-5**: Normal priority (default)
- **6-8**: High priority (urgent tasks)
- **9-10**: Critical priority (immediate processing)

## Configuration

### Gateway Configuration

```toml
# gateway.toml

[server]
host = "0.0.0.0"
port = 8080
workers = 4

[security]
enable_auth = true
api_key_header = "X-API-Key"
cors_origins = ["http://localhost:3000"]

[limits]
max_request_size = 10485760  # 10 MB
rate_limit_per_minute = 100
max_concurrent_connections = 1000

[websocket]
heartbeat_interval = 10
max_message_size = 1048576  # 1 MB

[database]
path = "cryptex.db"
```

### Worker Configuration

```toml
# worker.toml

[worker]
id = "scanner-1"
type = "scanner"
concurrency = 4

[gateway]
url = "http://localhost:8080"
auth_token = "secret_token"

[resources]
max_memory_mb = 2048
max_cpu_percent = 80

[timeouts]
task_timeout = 300
idle_timeout = 600
```

### Environment Variables

```bash
# Gateway
export RYARA_GATEWAY_PORT=8080
export RYARA_GATEWAY_HOST=0.0.0.0
export RYARA_DATABASE_PATH=/var/lib/r-yara/cryptex.db

# Worker
export RYARA_WORKER_ID=scanner-1
export RYARA_WORKER_TYPE=scanner
export RYARA_GATEWAY_URL=http://localhost:8080

# Security
export RYARA_API_KEY=your_api_key_here
export RYARA_ENABLE_AUTH=true
```

## Deployment

### Docker Deployment

#### Dockerfile

```dockerfile
FROM rust:1.70 as builder

WORKDIR /app
COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/r-yara-pyro /usr/local/bin/

EXPOSE 8080
CMD ["r-yara-pyro", "gateway"]
```

#### Docker Compose

```yaml
# docker-compose.yml

version: '3.8'

services:
  gateway:
    build: .
    ports:
      - "8080:8080"
    environment:
      - RYARA_GATEWAY_PORT=8080
      - RYARA_DATABASE_PATH=/data/cryptex.db
    volumes:
      - ./data:/data

  scanner-worker-1:
    build: .
    command: r-yara-pyro worker scanner --id scanner-1
    environment:
      - RYARA_GATEWAY_URL=http://gateway:8080
      - RYARA_WORKER_ID=scanner-1
    depends_on:
      - gateway

  scanner-worker-2:
    build: .
    command: r-yara-pyro worker scanner --id scanner-2
    environment:
      - RYARA_GATEWAY_URL=http://gateway:8080
      - RYARA_WORKER_ID=scanner-2
    depends_on:
      - gateway

  transcoder-worker:
    build: .
    command: r-yara-pyro worker transcoder --id transcoder-1
    environment:
      - RYARA_GATEWAY_URL=http://gateway:8080
      - RYARA_WORKER_ID=transcoder-1
    depends_on:
      - gateway
```

### Kubernetes Deployment

```yaml
# gateway-deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: r-yara-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: r-yara-gateway
  template:
    metadata:
      labels:
        app: r-yara-gateway
    spec:
      containers:
      - name: gateway
        image: r-yara-pyro:latest
        ports:
        - containerPort: 8080
        env:
        - name: RYARA_GATEWAY_PORT
          value: "8080"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: r-yara-gateway
spec:
  selector:
    app: r-yara-gateway
  ports:
  - port: 8080
    targetPort: 8080
  type: LoadBalancer
```

## Examples

### Example 1: Submit Scan Task

```python
import requests
import websocket
import json

# Submit task
response = requests.post('http://localhost:8080/api/v2/r-yara/tasks/scan', json={
    "task_type": "scan_file",
    "data": {
        "rules": "rule Test { strings: $a = \"malware\" condition: $a }",
        "target": "base64_encoded_file"
    }
})

task = response.json()
task_id = task['task_id']
ws_url = task['websocket_url']

# Connect to WebSocket
ws = websocket.create_connection(ws_url)

# Receive messages
while True:
    msg = json.loads(ws.recv())
    print(f"Message: {msg['message_type']}")

    if msg['message_type'] == 'match':
        print(f"Match found: {msg['data']}")
    elif msg['message_type'] == 'rule_end':
        break

ws.close()
```

### Example 2: Worker Implementation

```rust
use r_yara_pyro::workers::{Worker, WorkerTask};
use async_trait::async_trait;

struct CustomWorker {
    id: String,
}

#[async_trait]
impl Worker for CustomWorker {
    async fn process(&self, task: WorkerTask) -> anyhow::Result<serde_json::Value> {
        println!("Processing task: {}", task.task_id);

        // Custom processing logic
        match task.task_type {
            TaskType::ScanFile => {
                // Perform scan
                Ok(serde_json::json!({
                    "matches": []
                }))
            }
            _ => Err(anyhow::anyhow!("Unsupported task type"))
        }
    }

    fn id(&self) -> &str {
        &self.id
    }
}
```

### Example 3: API Integration

```javascript
// JavaScript API client
class RYaraClient {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }

    async submitScan(rules, target) {
        const response = await fetch(`${this.baseUrl}/api/v2/r-yara/tasks/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                task_type: 'scan_file',
                data: { rules, target }
            })
        });

        return await response.json();
    }

    async getTaskStatus(taskId) {
        const response = await fetch(`${this.baseUrl}/api/v2/r-yara/tasks/${taskId}`);
        return await response.json();
    }

    connectWebSocket(taskId, onMessage) {
        const ws = new WebSocket(`ws://${this.baseUrl}/ws/${taskId}`);
        ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            onMessage(message);
        };
        return ws;
    }
}

// Usage
const client = new RYaraClient('localhost:8080');

const task = await client.submitScan(rules, target);
const ws = client.connectWebSocket(task.task_id, (msg) => {
    console.log('Received:', msg);
});
```

## Monitoring and Observability

### Prometheus Metrics

```bash
# Endpoint
GET /metrics

# Example metrics
ryara_requests_total{method="POST",endpoint="/scan"} 12345
ryara_request_duration_seconds{quantile="0.5"} 0.125
ryara_active_workers{type="scanner"} 4
ryara_queue_depth{priority="normal"} 5
```

### Health Checks

```bash
# Liveness probe
GET /health/live

# Readiness probe
GET /health/ready
```

## See Also

- [Getting Started](GETTING_STARTED.md)
- [Architecture](ARCHITECTURE.md)
- [API Reference](API_REFERENCE.md)
- [CLI Guide](CLI_GUIDE.md)
