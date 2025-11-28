# R-YARA Packaging

This directory contains scripts and configurations for packaging R-YARA for various deployment scenarios:

- **Static binaries** for standalone deployment
- **Docker images** for containerized environments
- **Bootable ISO images** for air-gapped or bare-metal scanning

## Quick Start

### Build Static Binary

```bash
./build-static.sh
```

This creates a fully static binary that runs on any Linux system without dependencies.

### Build Docker Image

```bash
./build-docker.sh
```

Creates a minimal Docker image (~50MB) with R-YARA scanner and Fire Hydrant API.

### Build Bootable ISO

```bash
./build-iso.sh
```

Creates a bootable ISO image for offline/air-gapped YARA scanning environments.

## Deployment Options

### 1. Static Binary Deployment

Copy the static binary to your target system:

```bash
scp dist/r-yara-scanner target-host:/usr/local/bin/
ssh target-host 'r-yara-scanner --help'
```

### 2. Docker Deployment

```bash
# Run scanner
docker run -v /data:/data r-yara scan /data --rules /rules

# Run Fire Hydrant API
docker run -p 8080:8080 r-yara server

# Run with rules mounted
docker run -p 8080:8080 -v /path/to/rules:/rules r-yara server --rules-dir /rules
```

### 3. ISO Boot Deployment

1. Write ISO to USB drive:
   ```bash
   sudo dd if=r-yara-scanner.iso of=/dev/sdX bs=4M status=progress
   ```

2. Boot target system from USB

3. R-YARA scanner starts automatically with:
   - Web UI on port 8080
   - CLI available via SSH (port 22)
   - Automatic network configuration via DHCP

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RYARA_PORT` | API server port | 8080 |
| `RYARA_HOST` | API server host | 0.0.0.0 |
| `RYARA_RULES_DIR` | Default rules directory | /rules |
| `RYARA_DATA_DIR` | Database/cache directory | /var/lib/r-yara |
| `RYARA_LOG_LEVEL` | Log level (debug/info/warn/error) | info |

### Config File

Create `/etc/r-yara/config.json`:

```json
{
  "api": {
    "host": "0.0.0.0",
    "port": 8080
  },
  "scanner": {
    "rules_dir": "/rules",
    "max_file_size": 104857600,
    "timeout_ms": 30000
  },
  "database": {
    "path": "/var/lib/r-yara/scans.db"
  }
}
```

## Files

- `build-static.sh` - Build static Linux binary
- `build-docker.sh` - Build Docker image
- `build-iso.sh` - Build bootable ISO
- `Dockerfile` - Docker image definition
- `iso/` - ISO build files
- `dist/` - Output directory for built artifacts
