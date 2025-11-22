#!/bin/bash
# Create Debian package for YARA Cryptex

set -e

PACKAGE_NAME="yara-cryptex"
VERSION="0.1.0"
ARCH="amd64"

echo "Creating Debian package..."

# Create package structure
DEB_DIR="deb-package"
rm -rf "$DEB_DIR"
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/usr/bin"
mkdir -p "$DEB_DIR/usr/lib/yara-cryptex"
mkdir -p "$DEB_DIR/etc/yara-cryptex"
mkdir -p "$DEB_DIR/usr/share/doc/yara-cryptex"

# Copy control file
cp packaging/deb/control "$DEB_DIR/DEBIAN/"

# Build binaries first
./build.sh

# Copy binaries
cp build/bin/cryptex "$DEB_DIR/usr/bin/"
cp build/bin/cryptex-api "$DEB_DIR/usr/bin/"
cp build/bin/yara-feed-scanner "$DEB_DIR/usr/bin/"
cp build/bin/import_cryptex "$DEB_DIR/usr/bin/"
cp build/bin/export_cryptex "$DEB_DIR/usr/bin/"

# Copy data
cp data/cryptex.json "$DEB_DIR/etc/yara-cryptex/"

# Copy documentation
cp README.md "$DEB_DIR/usr/share/doc/yara-cryptex/"
cp LICENSE "$DEB_DIR/usr/share/doc/yara-cryptex/" 2>/dev/null || true

# Create postinst script
cat > "$DEB_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
# Post-installation script
/usr/bin/import_cryptex --input /etc/yara-cryptex/cryptex.json --database /var/lib/yara-cryptex/cryptex.db
chmod 644 /var/lib/yara-cryptex/cryptex.db
EOF
chmod +x "$DEB_DIR/DEBIAN/postinst"

# Build package
dpkg-deb --build "$DEB_DIR" "${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"

echo "Package created: ${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"

