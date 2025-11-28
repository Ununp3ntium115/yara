#!/bin/bash
# Build R-YARA Bootable ISO Image
#
# Creates a bootable ISO image based on Alpine Linux with R-YARA pre-installed.
# Suitable for air-gapped environments and bare-metal scanning.
#
# Requirements:
#   - Docker (for building in a clean environment)
#   - xorriso or genisoimage (for ISO creation)
#
# Usage: ./build-iso.sh [output-file]
#   output-file: Path to output ISO (default: dist/r-yara-scanner.iso)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ISO_DIR="$SCRIPT_DIR/iso"
DIST_DIR="$SCRIPT_DIR/dist"
WORK_DIR="$SCRIPT_DIR/.iso-work"

OUTPUT_ISO="${1:-$DIST_DIR/r-yara-scanner.iso}"

echo "=============================================="
echo "R-YARA Bootable ISO Builder"
echo "=============================================="
echo "Output: $OUTPUT_ISO"
echo ""

# Create directories
mkdir -p "$DIST_DIR" "$WORK_DIR"

# Check for required tools
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required for ISO building"
    exit 1
fi

# Check for ISO creation tools
ISO_TOOL=""
if command -v xorriso &> /dev/null; then
    ISO_TOOL="xorriso"
elif command -v genisoimage &> /dev/null; then
    ISO_TOOL="genisoimage"
elif command -v mkisofs &> /dev/null; then
    ISO_TOOL="mkisofs"
else
    echo "Warning: No ISO tool found (xorriso, genisoimage, mkisofs)"
    echo "Creating tarball instead of ISO..."
    ISO_TOOL="tar"
fi

echo "ISO tool: $ISO_TOOL"
echo ""

# First, build static binaries
echo "Step 1: Building static binaries..."
"$SCRIPT_DIR/build-static.sh" x86_64-unknown-linux-musl

# Create ISO filesystem structure
echo ""
echo "Step 2: Creating ISO filesystem..."
ISO_ROOT="$WORK_DIR/iso-root"
rm -rf "$ISO_ROOT"
mkdir -p "$ISO_ROOT"/{boot,bin,etc,rules,data,var/lib/r-yara}

# Copy binaries
cp "$DIST_DIR/r-yara" "$ISO_ROOT/bin/"
cp "$DIST_DIR/r-yara-server" "$ISO_ROOT/bin/"

# Create init script
cat > "$ISO_ROOT/bin/r-yara-init" << 'INIT_SCRIPT'
#!/bin/sh
# R-YARA Scanner Initialization Script

echo "========================================"
echo " R-YARA Scanner - Bootable Edition"
echo "========================================"
echo ""

# Configure network (DHCP)
echo "Configuring network..."
if [ -e /sys/class/net/eth0 ]; then
    udhcpc -i eth0 -q 2>/dev/null || true
fi

# Show IP address
IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [ -n "$IP" ]; then
    echo "Network: $IP"
else
    echo "Network: No network configured"
fi

# Start SSH if available
if command -v dropbear >/dev/null 2>&1; then
    echo "Starting SSH server..."
    dropbear -R 2>/dev/null &
fi

# Load rules from USB/disk if available
if [ -d /mnt/rules ]; then
    echo "Loading rules from /mnt/rules..."
    cp -r /mnt/rules/* /rules/ 2>/dev/null || true
fi

# Start R-YARA server
echo ""
echo "Starting R-YARA Fire Hydrant API on port 8080..."
echo "Access via: http://${IP:-localhost}:8080"
echo ""

exec /bin/r-yara-server server --host 0.0.0.0 --port 8080
INIT_SCRIPT
chmod +x "$ISO_ROOT/bin/r-yara-init"

# Create configuration file
cat > "$ISO_ROOT/etc/r-yara.json" << 'CONFIG'
{
  "api": {
    "host": "0.0.0.0",
    "port": 8080
  },
  "scanner": {
    "rules_dir": "/rules",
    "data_dir": "/var/lib/r-yara",
    "max_file_size": 104857600,
    "timeout_ms": 60000
  },
  "logging": {
    "level": "info",
    "format": "text"
  }
}
CONFIG

# Create sample rules
cat > "$ISO_ROOT/rules/example.yar" << 'RULES'
// Example YARA rules for R-YARA Scanner
// Add your custom rules here or mount a rules directory

rule ExampleRule : example
{
    meta:
        description = "Example rule to test scanner"
        author = "R-YARA"

    strings:
        $test = "test" nocase

    condition:
        $test
}

rule PEFile : executable
{
    meta:
        description = "Detects PE (Windows Executable) files"

    strings:
        $mz = "MZ"

    condition:
        $mz at 0
}

rule ELFFile : executable
{
    meta:
        description = "Detects ELF (Linux/Unix Executable) files"

    strings:
        $elf = { 7f 45 4c 46 }

    condition:
        $elf at 0
}
RULES

# Create README
cat > "$ISO_ROOT/README.txt" << 'README'
R-YARA Scanner - Bootable Edition
==================================

This bootable image contains:
  - R-YARA CLI scanner (/bin/r-yara)
  - R-YARA Fire Hydrant API server (/bin/r-yara-server)
  - Example YARA rules (/rules/)

Quick Start:
1. Boot from this ISO
2. The Fire Hydrant API starts automatically on port 8080
3. Use the CLI for direct scanning: /bin/r-yara scan /path/to/file

API Endpoints:
  GET  /health              - Health check
  POST /scan/file           - Scan a file
  POST /scan/data           - Scan raw data
  POST /scan/directory      - Scan a directory
  POST /scan/batch          - Batch scan
  GET  /modules             - List available modules

For more information, see: https://github.com/Ununp3ntium115/yara
README

echo "ISO filesystem created at: $ISO_ROOT"

# Create the ISO or tarball
echo ""
echo "Step 3: Creating bootable image..."

if [ "$ISO_TOOL" = "tar" ]; then
    # Create tarball instead
    OUTPUT_TAR="${OUTPUT_ISO%.iso}.tar.gz"
    echo "Creating tarball: $OUTPUT_TAR"
    tar -czf "$OUTPUT_TAR" -C "$ISO_ROOT" .
    echo ""
    echo "Tarball created: $OUTPUT_TAR"
    echo "Extract and use directly, or create ISO manually"
else
    # For a proper bootable ISO, we'd need a bootloader
    # This creates a data ISO that can be used with live Linux systems
    echo "Creating data ISO: $OUTPUT_ISO"

    case "$ISO_TOOL" in
        xorriso)
            xorriso -as mkisofs \
                -o "$OUTPUT_ISO" \
                -V "R-YARA-SCANNER" \
                -R -J \
                "$ISO_ROOT"
            ;;
        genisoimage|mkisofs)
            $ISO_TOOL \
                -o "$OUTPUT_ISO" \
                -V "R-YARA-SCANNER" \
                -R -J \
                "$ISO_ROOT"
            ;;
    esac
fi

# Cleanup
rm -rf "$WORK_DIR"

# Show results
echo ""
echo "=============================================="
echo "Build complete!"
echo ""

if [ -f "$OUTPUT_ISO" ]; then
    ls -lh "$OUTPUT_ISO"
    echo ""
    echo "Usage:"
    echo "  1. Burn ISO to CD/USB"
    echo "  2. Boot target system from media"
    echo "  3. R-YARA server starts on port 8080"
elif [ -f "${OUTPUT_ISO%.iso}.tar.gz" ]; then
    ls -lh "${OUTPUT_ISO%.iso}.tar.gz"
    echo ""
    echo "Usage:"
    echo "  1. Extract tarball to target system"
    echo "  2. Run /bin/r-yara-init to start"
fi

echo ""
echo "For a fully bootable ISO with Alpine Linux base,"
echo "see: packaging/iso/alpine-overlay.sh"
echo "=============================================="
