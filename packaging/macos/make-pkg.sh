#!/bin/bash
# Create macOS package for YARA Cryptex

set -e

PACKAGE_NAME="yara-cryptex"
VERSION="0.1.0"

echo "Creating macOS package..."

# Build first
./build.sh

# Create package structure
PKG_ROOT="pkg-root"
rm -rf "$PKG_ROOT"
mkdir -p "$PKG_ROOT/usr/local/bin"
mkdir -p "$PKG_ROOT/etc/yara-cryptex"
mkdir -p "$PKG_ROOT/Library/Application Support/YARA Cryptex"

# Copy binaries
cp build/bin/cryptex "$PKG_ROOT/usr/local/bin/"
cp build/bin/cryptex-api "$PKG_ROOT/usr/local/bin/"
cp build/bin/yara-feed-scanner "$PKG_ROOT/usr/local/bin/"
cp build/bin/import_cryptex "$PKG_ROOT/usr/local/bin/"
cp build/bin/export_cryptex "$PKG_ROOT/usr/local/bin/"

# Copy data
cp data/cryptex.json "$PKG_ROOT/etc/yara-cryptex/"

# Create package info
mkdir -p "$PKG_ROOT/Resources"
cat > "$PKG_ROOT/Resources/package_info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.pyro.yara-cryptex</string>
    <key>CFBundleName</key>
    <string>YARA Cryptex</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
</dict>
</plist>
EOF

# Build package
pkgbuild --root "$PKG_ROOT" \
         --identifier com.pyro.yara-cryptex \
         --version "$VERSION" \
         --install-location / \
         "${PACKAGE_NAME}-${VERSION}.pkg"

echo "Package created: ${PACKAGE_NAME}-${VERSION}.pkg"

