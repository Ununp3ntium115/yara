#!/bin/bash
# Build static R-YARA binaries for Linux deployment
#
# This script builds fully static binaries that work on any Linux system
# without requiring any runtime dependencies.
#
# Usage: ./build-static.sh [target]
#   target: x86_64-unknown-linux-musl (default)
#           aarch64-unknown-linux-musl

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_ROOT/rust"
DIST_DIR="$SCRIPT_DIR/dist"

# Default target
TARGET="${1:-x86_64-unknown-linux-musl}"

echo "=============================================="
echo "R-YARA Static Binary Builder"
echo "=============================================="
echo "Target: $TARGET"
echo "Output: $DIST_DIR"
echo ""

# Create output directory
mkdir -p "$DIST_DIR"

# Check if we have the target installed
if ! rustup target list --installed | grep -q "$TARGET"; then
    echo "Installing Rust target: $TARGET"
    rustup target add "$TARGET"
fi

# Check for musl-gcc (required for musl targets)
if [[ "$TARGET" == *"musl"* ]]; then
    if ! command -v musl-gcc &> /dev/null; then
        echo "Warning: musl-gcc not found. Installing musl-tools..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y musl-tools
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y musl-gcc musl-libc-static
        elif command -v apk &> /dev/null; then
            apk add musl-dev
        else
            echo "Error: Please install musl-tools manually"
            exit 1
        fi
    fi
fi

echo "Building R-YARA binaries..."
cd "$RUST_DIR"

# Build with optimizations for static linking
RUSTFLAGS="-C target-feature=+crt-static" cargo build \
    --release \
    --target "$TARGET" \
    --package r-yara-cli \
    --package r-yara-pyro

# Copy binaries to dist
echo "Copying binaries to $DIST_DIR..."

TARGET_DIR="$RUST_DIR/target/$TARGET/release"

if [[ -f "$TARGET_DIR/r-yara-cli" ]]; then
    cp "$TARGET_DIR/r-yara-cli" "$DIST_DIR/r-yara"
    chmod +x "$DIST_DIR/r-yara"
    echo "  -> r-yara (CLI scanner)"
fi

if [[ -f "$TARGET_DIR/r-yara-pyro" ]]; then
    cp "$TARGET_DIR/r-yara-pyro" "$DIST_DIR/r-yara-server"
    chmod +x "$DIST_DIR/r-yara-server"
    echo "  -> r-yara-server (Fire Hydrant API)"
fi

# Strip binaries for smaller size
echo "Stripping binaries..."
if command -v strip &> /dev/null; then
    strip "$DIST_DIR/r-yara" 2>/dev/null || true
    strip "$DIST_DIR/r-yara-server" 2>/dev/null || true
fi

# Show binary info
echo ""
echo "Build complete! Binaries:"
ls -lh "$DIST_DIR/"

# Verify they're static
echo ""
echo "Verifying static linking..."
for binary in "$DIST_DIR/r-yara" "$DIST_DIR/r-yara-server"; do
    if [[ -f "$binary" ]]; then
        if ldd "$binary" 2>&1 | grep -q "not a dynamic executable\|statically linked"; then
            echo "  ✓ $(basename $binary) is statically linked"
        else
            echo "  ! $(basename $binary) may have dynamic dependencies"
            ldd "$binary" 2>&1 | head -5
        fi
    fi
done

echo ""
echo "=============================================="
echo "Static binaries ready in: $DIST_DIR"
echo ""
echo "To test:"
echo "  $DIST_DIR/r-yara --help"
echo "  $DIST_DIR/r-yara-server --help"
echo "=============================================="
