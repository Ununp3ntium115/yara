#!/bin/bash
# Build R-YARA Docker image
#
# Usage: ./build-docker.sh [tag]
#   tag: Docker image tag (default: r-yara:latest)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Image configuration
IMAGE_NAME="${1:-r-yara}"
IMAGE_TAG="${2:-latest}"
FULL_TAG="$IMAGE_NAME:$IMAGE_TAG"

echo "=============================================="
echo "R-YARA Docker Image Builder"
echo "=============================================="
echo "Image: $FULL_TAG"
echo ""

cd "$PROJECT_ROOT"

# Build the image
echo "Building Docker image..."
docker build \
    -t "$FULL_TAG" \
    -f "$SCRIPT_DIR/Dockerfile" \
    .

# Show image info
echo ""
echo "Build complete!"
docker images "$IMAGE_NAME"

# Show image size
SIZE=$(docker images "$FULL_TAG" --format "{{.Size}}")
echo ""
echo "Image size: $SIZE"

# Optionally run tests
echo ""
echo "Testing image..."
docker run --rm "$FULL_TAG" --help || true

echo ""
echo "=============================================="
echo "Docker image ready: $FULL_TAG"
echo ""
echo "Usage examples:"
echo ""
echo "  # Run Fire Hydrant API server"
echo "  docker run -p 8080:8080 $FULL_TAG server"
echo ""
echo "  # Scan a file"
echo "  docker run -v /path/to/files:/data $FULL_TAG r-yara scan /data/file.exe --rules 'rule Test { condition: true }'"
echo ""
echo "  # Run with mounted rules"
echo "  docker run -p 8080:8080 -v /path/to/rules:/rules $FULL_TAG server"
echo ""
echo "  # Interactive shell"
echo "  docker run -it --entrypoint /bin/sh $FULL_TAG"
echo "=============================================="
