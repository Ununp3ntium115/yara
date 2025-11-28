#!/bin/bash
# Build R-YARA Installer Packages
#
# Creates installer packages for various platforms:
#   - DEB (Debian, Ubuntu, Linux Mint)
#   - RPM (RHEL, CentOS, Fedora, openSUSE)
#   - APK (Alpine Linux)
#   - TAR.GZ (Generic Linux)
#
# For Windows packages, see windows/build-msi.ps1
#
# Usage: ./build-packages.sh [target]
#   target: deb, rpm, apk, all (default: all)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$SCRIPT_DIR/dist"
PKG_DIR="$SCRIPT_DIR/pkg"

# Package metadata
PKG_NAME="r-yara"
PKG_VERSION="${VERSION:-0.1.0}"
PKG_RELEASE="1"
PKG_MAINTAINER="R-YARA Team <ryara@example.com>"
PKG_DESCRIPTION="R-YARA - Native Rust YARA Scanner and Fire Hydrant API"
PKG_URL="https://github.com/Ununp3ntium115/yara"
PKG_LICENSE="MIT"

TARGET="${1:-all}"

echo "=============================================="
echo "R-YARA Package Builder"
echo "=============================================="
echo "Version: $PKG_VERSION-$PKG_RELEASE"
echo "Target:  $TARGET"
echo ""

# Create directories
mkdir -p "$DIST_DIR" "$PKG_DIR"

# Build static binaries first
echo "Building static binaries..."
"$SCRIPT_DIR/build-static.sh" x86_64-unknown-linux-musl

# Function to build DEB package
build_deb() {
    echo ""
    echo "Building DEB package..."

    DEB_ROOT="$PKG_DIR/deb-root"
    rm -rf "$DEB_ROOT"
    mkdir -p "$DEB_ROOT"/{DEBIAN,usr/bin,usr/share/doc/$PKG_NAME,etc/r-yara,var/lib/r-yara/rules}

    # Copy binaries
    cp "$DIST_DIR/r-yara" "$DEB_ROOT/usr/bin/"
    cp "$DIST_DIR/r-yara-server" "$DEB_ROOT/usr/bin/"
    chmod 755 "$DEB_ROOT/usr/bin/"*

    # Create config
    cat > "$DEB_ROOT/etc/r-yara/config.json" << 'EOF'
{
  "api": {
    "host": "0.0.0.0",
    "port": 8080
  },
  "scanner": {
    "rules_dir": "/var/lib/r-yara/rules",
    "data_dir": "/var/lib/r-yara"
  }
}
EOF

    # Create sample rules
    cat > "$DEB_ROOT/var/lib/r-yara/rules/sample.yar" << 'EOF'
rule SampleRule {
    meta:
        description = "Sample YARA rule"
    strings:
        $test = "test"
    condition:
        $test
}
EOF

    # Create systemd service file
    mkdir -p "$DEB_ROOT/lib/systemd/system"
    cat > "$DEB_ROOT/lib/systemd/system/r-yara.service" << 'EOF'
[Unit]
Description=R-YARA Fire Hydrant API
After=network.target

[Service]
Type=simple
User=ryara
Group=ryara
ExecStart=/usr/bin/r-yara-server server --config /etc/r-yara/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Create copyright file
    cat > "$DEB_ROOT/usr/share/doc/$PKG_NAME/copyright" << EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: $PKG_NAME
Source: $PKG_URL

Files: *
Copyright: 2024 R-YARA Team
License: MIT
EOF

    # Create control file
    INSTALLED_SIZE=$(du -sk "$DEB_ROOT" | cut -f1)
    cat > "$DEB_ROOT/DEBIAN/control" << EOF
Package: $PKG_NAME
Version: $PKG_VERSION-$PKG_RELEASE
Section: utils
Priority: optional
Architecture: amd64
Installed-Size: $INSTALLED_SIZE
Maintainer: $PKG_MAINTAINER
Description: $PKG_DESCRIPTION
 R-YARA is a native Rust implementation of the YARA pattern matching tool.
 It includes a CLI scanner and the Fire Hydrant API server for network
 scanning and integration with other tools.
Homepage: $PKG_URL
EOF

    # Create postinst script
    cat > "$DEB_ROOT/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

# Create user if doesn't exist
if ! getent passwd ryara > /dev/null; then
    useradd -r -s /bin/false -d /var/lib/r-yara ryara
fi

# Set permissions
chown -R ryara:ryara /var/lib/r-yara

# Enable service
systemctl daemon-reload
systemctl enable r-yara.service 2>/dev/null || true

echo ""
echo "R-YARA installed successfully!"
echo ""
echo "To start the service:"
echo "  sudo systemctl start r-yara"
echo ""
echo "API will be available at: http://localhost:8080"
echo ""
EOF
    chmod 755 "$DEB_ROOT/DEBIAN/postinst"

    # Create prerm script
    cat > "$DEB_ROOT/DEBIAN/prerm" << 'EOF'
#!/bin/sh
set -e
systemctl stop r-yara.service 2>/dev/null || true
systemctl disable r-yara.service 2>/dev/null || true
EOF
    chmod 755 "$DEB_ROOT/DEBIAN/prerm"

    # Create conffiles
    echo "/etc/r-yara/config.json" > "$DEB_ROOT/DEBIAN/conffiles"

    # Build DEB
    DEB_FILE="$DIST_DIR/${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}_amd64.deb"
    dpkg-deb --build "$DEB_ROOT" "$DEB_FILE"

    echo "DEB package created: $DEB_FILE"
    dpkg-deb --info "$DEB_FILE"
}

# Function to build RPM package
build_rpm() {
    echo ""
    echo "Building RPM package..."

    RPM_ROOT="$PKG_DIR/rpm-root"
    rm -rf "$RPM_ROOT"
    mkdir -p "$RPM_ROOT"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

    # Create tarball
    TARBALL_DIR="$PKG_NAME-$PKG_VERSION"
    mkdir -p "$RPM_ROOT/SOURCES/$TARBALL_DIR"/{bin,etc,var/lib/r-yara/rules,lib/systemd/system}

    cp "$DIST_DIR/r-yara" "$RPM_ROOT/SOURCES/$TARBALL_DIR/bin/"
    cp "$DIST_DIR/r-yara-server" "$RPM_ROOT/SOURCES/$TARBALL_DIR/bin/"

    # Create config and service files
    cat > "$RPM_ROOT/SOURCES/$TARBALL_DIR/etc/config.json" << 'EOF'
{
  "api": { "host": "0.0.0.0", "port": 8080 },
  "scanner": { "rules_dir": "/var/lib/r-yara/rules", "data_dir": "/var/lib/r-yara" }
}
EOF

    cat > "$RPM_ROOT/SOURCES/$TARBALL_DIR/lib/systemd/system/r-yara.service" << 'EOF'
[Unit]
Description=R-YARA Fire Hydrant API
After=network.target

[Service]
Type=simple
User=ryara
Group=ryara
ExecStart=/usr/bin/r-yara-server server --config /etc/r-yara/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    # Create tarball
    (cd "$RPM_ROOT/SOURCES" && tar czf "$TARBALL_DIR.tar.gz" "$TARBALL_DIR")

    # Create spec file
    cat > "$RPM_ROOT/SPECS/$PKG_NAME.spec" << EOF
Name:           $PKG_NAME
Version:        $PKG_VERSION
Release:        $PKG_RELEASE%{?dist}
Summary:        $PKG_DESCRIPTION

License:        MIT
URL:            $PKG_URL
Source0:        %{name}-%{version}.tar.gz

%description
R-YARA is a native Rust implementation of the YARA pattern matching tool.
It includes a CLI scanner and the Fire Hydrant API server.

%prep
%setup -q

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/r-yara
mkdir -p %{buildroot}/var/lib/r-yara/rules
mkdir -p %{buildroot}/lib/systemd/system

install -m 755 bin/r-yara %{buildroot}/usr/bin/
install -m 755 bin/r-yara-server %{buildroot}/usr/bin/
install -m 644 etc/config.json %{buildroot}/etc/r-yara/
install -m 644 lib/systemd/system/r-yara.service %{buildroot}/lib/systemd/system/

%pre
getent group ryara >/dev/null || groupadd -r ryara
getent passwd ryara >/dev/null || useradd -r -g ryara -d /var/lib/r-yara -s /sbin/nologin ryara

%post
systemctl daemon-reload
systemctl enable r-yara.service

%preun
systemctl stop r-yara.service || true
systemctl disable r-yara.service || true

%files
/usr/bin/r-yara
/usr/bin/r-yara-server
%config(noreplace) /etc/r-yara/config.json
/lib/systemd/system/r-yara.service
%dir /var/lib/r-yara
%dir /var/lib/r-yara/rules

%changelog
* $(date "+%a %b %d %Y") R-YARA Team - $PKG_VERSION-$PKG_RELEASE
- Initial package
EOF

    # Build RPM
    if command -v rpmbuild &> /dev/null; then
        rpmbuild --define "_topdir $RPM_ROOT" -bb "$RPM_ROOT/SPECS/$PKG_NAME.spec"
        RPM_FILE=$(find "$RPM_ROOT/RPMS" -name "*.rpm" | head -1)
        if [ -n "$RPM_FILE" ]; then
            cp "$RPM_FILE" "$DIST_DIR/"
            echo "RPM package created: $DIST_DIR/$(basename $RPM_FILE)"
        fi
    else
        echo "Warning: rpmbuild not found. RPM spec file created at:"
        echo "  $RPM_ROOT/SPECS/$PKG_NAME.spec"
    fi
}

# Function to build APK package
build_apk() {
    echo ""
    echo "Building APK package..."

    APK_ROOT="$PKG_DIR/apk-root"
    rm -rf "$APK_ROOT"
    mkdir -p "$APK_ROOT"/{pkg,src}

    # Create APKBUILD
    cat > "$APK_ROOT/APKBUILD" << EOF
# Maintainer: $PKG_MAINTAINER
pkgname=$PKG_NAME
pkgver=$PKG_VERSION
pkgrel=$PKG_RELEASE
pkgdesc="$PKG_DESCRIPTION"
url="$PKG_URL"
arch="x86_64"
license="MIT"
depends=""
makedepends=""
source=""
options="!check"

package() {
    mkdir -p "\$pkgdir"/usr/bin
    mkdir -p "\$pkgdir"/etc/r-yara
    mkdir -p "\$pkgdir"/var/lib/r-yara/rules
    mkdir -p "\$pkgdir"/etc/init.d

    install -m 755 "$DIST_DIR/r-yara" "\$pkgdir"/usr/bin/
    install -m 755 "$DIST_DIR/r-yara-server" "\$pkgdir"/usr/bin/

    cat > "\$pkgdir"/etc/r-yara/config.json << 'CONF'
{
  "api": { "host": "0.0.0.0", "port": 8080 },
  "scanner": { "rules_dir": "/var/lib/r-yara/rules", "data_dir": "/var/lib/r-yara" }
}
CONF

    cat > "\$pkgdir"/etc/init.d/r-yara << 'INIT'
#!/sbin/openrc-run
name="R-YARA"
command="/usr/bin/r-yara-server"
command_args="server"
command_background="yes"
pidfile="/run/r-yara.pid"
INIT
    chmod 755 "\$pkgdir"/etc/init.d/r-yara
}
EOF

    echo "APK build file created: $APK_ROOT/APKBUILD"
    echo "To build: cd $APK_ROOT && abuild -r"
}

# Function to build generic tarball
build_tarball() {
    echo ""
    echo "Building generic tarball..."

    TAR_NAME="${PKG_NAME}-${PKG_VERSION}-linux-x86_64"
    TAR_ROOT="$PKG_DIR/$TAR_NAME"
    rm -rf "$TAR_ROOT"
    mkdir -p "$TAR_ROOT"/{bin,etc,rules}

    cp "$DIST_DIR/r-yara" "$TAR_ROOT/bin/"
    cp "$DIST_DIR/r-yara-server" "$TAR_ROOT/bin/"
    chmod 755 "$TAR_ROOT/bin/"*

    cat > "$TAR_ROOT/etc/config.json" << 'EOF'
{
  "api": { "host": "0.0.0.0", "port": 8080 },
  "scanner": { "rules_dir": "./rules", "data_dir": "./data" }
}
EOF

    cat > "$TAR_ROOT/README.txt" << EOF
R-YARA Scanner v$PKG_VERSION
========================

Installation:
  1. Extract to desired location
  2. Add bin/ to PATH or use full path

Usage:
  ./bin/r-yara scan <file>          - Scan a file
  ./bin/r-yara scan -r <dir>        - Scan directory
  ./bin/r-yara-server server        - Start API server

Configuration: etc/config.json
Rules:         rules/
EOF

    # Create tarball
    TAR_FILE="$DIST_DIR/${TAR_NAME}.tar.gz"
    (cd "$PKG_DIR" && tar czf "$TAR_FILE" "$TAR_NAME")

    echo "Tarball created: $TAR_FILE"
}

# Build requested packages
case "$TARGET" in
    deb)
        build_deb
        ;;
    rpm)
        build_rpm
        ;;
    apk)
        build_apk
        ;;
    tarball|tar)
        build_tarball
        ;;
    all)
        build_tarball
        if command -v dpkg-deb &> /dev/null; then
            build_deb
        else
            echo "Skipping DEB (dpkg-deb not found)"
        fi
        build_rpm
        build_apk
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Valid targets: deb, rpm, apk, tarball, all"
        exit 1
        ;;
esac

echo ""
echo "=============================================="
echo "Package build complete!"
echo "=============================================="
ls -lh "$DIST_DIR/"
