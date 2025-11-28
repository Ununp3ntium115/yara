#!/bin/bash
# Create R-YARA Alpine Linux Overlay
#
# This script creates an overlay for Alpine Linux that adds R-YARA
# scanner and automatically starts the Fire Hydrant API on boot.
#
# The overlay can be added to an Alpine Linux ISO to create a
# fully bootable R-YARA scanner system.
#
# Usage: ./alpine-overlay.sh [output-dir]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGING_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${1:-$SCRIPT_DIR/overlay}"

echo "Creating R-YARA Alpine overlay in: $OUTPUT_DIR"

# Create overlay structure
mkdir -p "$OUTPUT_DIR"/{etc/{init.d,local.d,apk},usr/local/bin,opt/r-yara/{rules,data}}

# Copy binaries (if they exist)
if [ -f "$PACKAGING_DIR/dist/r-yara" ]; then
    cp "$PACKAGING_DIR/dist/r-yara" "$OUTPUT_DIR/usr/local/bin/"
    cp "$PACKAGING_DIR/dist/r-yara-server" "$OUTPUT_DIR/usr/local/bin/"
    chmod +x "$OUTPUT_DIR/usr/local/bin/"*
fi

# Create OpenRC init script
cat > "$OUTPUT_DIR/etc/init.d/r-yara" << 'INITSCRIPT'
#!/sbin/openrc-run

name="R-YARA Fire Hydrant API"
description="R-YARA YARA Scanning Service"

command="/usr/local/bin/r-yara-server"
command_args="server --host 0.0.0.0 --port 8080"
command_background="yes"
pidfile="/run/r-yara.pid"
output_log="/var/log/r-yara.log"
error_log="/var/log/r-yara.err"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --owner root:root --mode 0755 /opt/r-yara/data
    checkpath --directory --owner root:root --mode 0755 /opt/r-yara/rules
}
INITSCRIPT
chmod +x "$OUTPUT_DIR/etc/init.d/r-yara"

# Create local startup script
cat > "$OUTPUT_DIR/etc/local.d/r-yara.start" << 'STARTUP'
#!/bin/sh
# R-YARA auto-start script

# Display banner
cat << 'BANNER'

 ____        __   __    _    ____      _
|  _ \ _____ \ \ / /   / \  |  _ \    / \
| |_) |______\ V /   / _ \ | |_) |  / _ \
|  _ <        | |   / ___ \|  _ <  / ___ \
|_| \_\       |_|  /_/   \_\_| \_\/_/   \_\

        Fire Hydrant API - Bootable Edition

BANNER

# Wait for network
sleep 2

# Get IP address
IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [ -z "$IP" ]; then
    IP=$(hostname -i 2>/dev/null | head -1)
fi

echo "========================================"
echo " R-YARA Scanner is ready!"
echo "========================================"
echo ""
echo " Web Interface: http://${IP:-localhost}:8080"
echo " API Docs:      http://${IP:-localhost}:8080/api/v2/r-yara/"
echo ""
echo " CLI Scanner:   r-yara --help"
echo ""
echo "========================================"

# Enable service at boot
rc-update add r-yara default 2>/dev/null || true

# Start service if not running
rc-service r-yara start 2>/dev/null || true
STARTUP
chmod +x "$OUTPUT_DIR/etc/local.d/r-yara.start"

# Create configuration
cat > "$OUTPUT_DIR/opt/r-yara/config.json" << 'CONFIG'
{
  "api": {
    "host": "0.0.0.0",
    "port": 8080,
    "prefix": "/api/v2/r-yara"
  },
  "scanner": {
    "rules_dir": "/opt/r-yara/rules",
    "data_dir": "/opt/r-yara/data",
    "max_file_size": 104857600,
    "timeout_ms": 60000,
    "threads": 4
  },
  "database": {
    "path": "/opt/r-yara/data/scans.db",
    "max_connections": 10
  },
  "logging": {
    "level": "info",
    "file": "/var/log/r-yara.log"
  }
}
CONFIG

# Create sample rules
cat > "$OUTPUT_DIR/opt/r-yara/rules/default.yar" << 'RULES'
/*
 * R-YARA Default Rules
 * ====================
 * These are basic detection rules included with the bootable image.
 * Add your own rules to /opt/r-yara/rules/ or load via API.
 */

rule IsPEFile : type
{
    meta:
        description = "Identifies PE (Windows Portable Executable) files"
        category = "file_type"

    strings:
        $mz = "MZ" at 0

    condition:
        $mz and uint32(uint32(0x3C)) == 0x00004550 // PE signature
}

rule IsELFFile : type
{
    meta:
        description = "Identifies ELF (Executable and Linkable Format) files"
        category = "file_type"

    condition:
        uint32(0) == 0x464C457F // 0x7F + "ELF"
}

rule IsMachO : type
{
    meta:
        description = "Identifies Mach-O (macOS executable) files"
        category = "file_type"

    condition:
        uint32(0) == 0xFEEDFACE or // 32-bit
        uint32(0) == 0xFEEDFACF or // 64-bit
        uint32(0) == 0xBEBAFECA or // Universal 32-bit
        uint32(0) == 0xBFBAFECA    // Universal 64-bit
}

rule SuspiciousStrings : suspicious
{
    meta:
        description = "Detects potentially suspicious strings"
        category = "generic"

    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "/bin/sh" nocase
        $cmd3 = "powershell" nocase
        $net1 = "http://" nocase
        $net2 = "https://" nocase
        $enc1 = "base64" nocase

    condition:
        2 of them
}

rule PackedUPX : packer
{
    meta:
        description = "Detects UPX packed executables"
        category = "packer"

    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX!"

    condition:
        any of them
}
RULES

# Create motd
cat > "$OUTPUT_DIR/etc/motd" << 'MOTD'

Welcome to R-YARA Scanner
=========================

Quick Commands:
  r-yara scan <file>        - Scan a file
  r-yara scan -r <dir>      - Scan directory recursively
  r-yara check <rule>       - Validate YARA rule
  r-yara-server server      - Start Fire Hydrant API

Configuration: /opt/r-yara/config.json
Rules:         /opt/r-yara/rules/
Data:          /opt/r-yara/data/

API Documentation: http://localhost:8080/api/v2/r-yara/

MOTD

# Create overlay tarball
echo ""
echo "Creating overlay tarball..."
OVERLAY_TAR="$SCRIPT_DIR/r-yara-overlay.apkovl.tar.gz"
(cd "$OUTPUT_DIR" && tar czf "$OVERLAY_TAR" .)

echo ""
echo "Overlay created: $OVERLAY_TAR"
echo ""
echo "To use with Alpine Linux:"
echo "  1. Download Alpine Linux ISO (alpine-virt or alpine-standard)"
echo "  2. Copy $OVERLAY_TAR to the same directory as the ISO"
echo "  3. Boot the ISO - it will automatically apply the overlay"
echo ""
echo "Alternatively, extract overlay to Alpine Linux root:"
echo "  tar xzf $OVERLAY_TAR -C /"
echo ""
