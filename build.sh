#!/bin/bash
# Build script for YARA Cryptex - Creates executables for all platforms

set -e

echo "=========================================="
echo "YARA Cryptex Build System"
echo "=========================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build directory
BUILD_DIR="build"
mkdir -p "$BUILD_DIR"

# Build Rust components
echo -e "${BLUE}Building Rust components...${NC}"
cd rust

# Build cryptex-store
echo "Building cryptex-store..."
cd cryptex-store
cargo build --release
cd ..

# Build cryptex-api
echo "Building cryptex-api..."
cd cryptex-api
cargo build --release
cd ..

# Build yara-feed-scanner
echo "Building yara-feed-scanner..."
cd yara-feed-scanner
cargo build --release
cd ..

# Build cryptex-cli
echo "Building cryptex-cli..."
cd cryptex-cli
cargo build --release
cd ..

cd ..

# Copy binaries
echo -e "${BLUE}Copying binaries...${NC}"
mkdir -p "$BUILD_DIR/bin"

# Detect OS and copy appropriate binaries
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    cp rust/cryptex-store/target/release/import_cryptex "$BUILD_DIR/bin/"
    cp rust/cryptex-store/target/release/export_cryptex "$BUILD_DIR/bin/"
    cp rust/cryptex-api/target/release/cryptex-api "$BUILD_DIR/bin/"
    cp rust/yara-feed-scanner/target/release/yara-feed-scanner "$BUILD_DIR/bin/"
    cp rust/cryptex-cli/target/release/cryptex "$BUILD_DIR/bin/"
    echo -e "${GREEN}Linux binaries built!${NC}"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    cp rust/cryptex-store/target/release/import_cryptex "$BUILD_DIR/bin/"
    cp rust/cryptex-store/target/release/export_cryptex "$BUILD_DIR/bin/"
    cp rust/cryptex-api/target/release/cryptex-api "$BUILD_DIR/bin/"
    cp rust/yara-feed-scanner/target/release/yara-feed-scanner "$BUILD_DIR/bin/"
    cp rust/cryptex-cli/target/release/cryptex "$BUILD_DIR/bin/"
    echo -e "${GREEN}macOS binaries built!${NC}"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    cp rust/cryptex-store/target/release/import_cryptex.exe "$BUILD_DIR/bin/"
    cp rust/cryptex-store/target/release/export_cryptex.exe "$BUILD_DIR/bin/"
    cp rust/cryptex-api/target/release/cryptex-api.exe "$BUILD_DIR/bin/"
    cp rust/yara-feed-scanner/target/release/yara-feed-scanner.exe "$BUILD_DIR/bin/"
    cp rust/cryptex-cli/target/release/cryptex.exe "$BUILD_DIR/bin/"
    echo -e "${GREEN}Windows binaries built!${NC}"
fi

# Copy data files
echo -e "${BLUE}Copying data files...${NC}"
mkdir -p "$BUILD_DIR/data"
cp data/cryptex.json "$BUILD_DIR/data/" 2>/dev/null || true

# Copy documentation
echo -e "${BLUE}Copying documentation...${NC}"
mkdir -p "$BUILD_DIR/docs"
cp *.md "$BUILD_DIR/docs/" 2>/dev/null || true

echo -e "${GREEN}Build complete!${NC}"
echo "Binaries are in: $BUILD_DIR/bin/"
