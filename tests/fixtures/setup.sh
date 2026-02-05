#!/bin/bash
# Setup script for obscell-wallet integration tests
# Downloads CKB binary for the current platform

set -e

# Configuration
CKB_VERSION="0.204.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CKB_PATH="$SCRIPT_DIR/ckb"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux";;
        Darwin*) echo "darwin";;
        *)       error "Unsupported OS: $(uname -s)";;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64)  echo "x86_64";;
        amd64)   echo "x86_64";;
        aarch64) echo "aarch64";;
        arm64)   echo "aarch64";;
        *)       error "Unsupported architecture: $(uname -m)";;
    esac
}

# Get platform-specific archive name
get_archive_name() {
    local os=$1
    local arch=$2
    
    if [ "$os" = "linux" ]; then
        echo "ckb_v${CKB_VERSION}_${arch}-unknown-linux-gnu.tar.gz"
    elif [ "$os" = "darwin" ]; then
        echo "ckb_v${CKB_VERSION}_${arch}-apple-darwin.tar.gz"
    else
        error "Unknown OS: $os"
    fi
}

# Main
main() {
    info "Setting up CKB for integration tests..."
    
    # Check if CKB already exists and is correct version
    if [ -f "$CKB_PATH" ]; then
        EXISTING_VERSION=$("$CKB_PATH" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
        if [ "$EXISTING_VERSION" = "$CKB_VERSION" ]; then
            info "CKB v$CKB_VERSION already installed at $CKB_PATH"
            exit 0
        else
            warn "Existing CKB version ($EXISTING_VERSION) differs from required ($CKB_VERSION)"
            info "Downloading correct version..."
        fi
    fi
    
    # Detect platform
    OS=$(detect_os)
    ARCH=$(detect_arch)
    info "Detected platform: $OS-$ARCH"
    
    # Get archive name
    ARCHIVE=$(get_archive_name "$OS" "$ARCH")
    DOWNLOAD_URL="https://github.com/nervosnetwork/ckb/releases/download/v${CKB_VERSION}/${ARCHIVE}"
    
    info "Downloading CKB v$CKB_VERSION..."
    info "URL: $DOWNLOAD_URL"
    
    # Create temp directory
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT
    
    # Download
    if command -v curl &> /dev/null; then
        curl -L -o "$TEMP_DIR/$ARCHIVE" "$DOWNLOAD_URL" || error "Failed to download CKB"
    elif command -v wget &> /dev/null; then
        wget -O "$TEMP_DIR/$ARCHIVE" "$DOWNLOAD_URL" || error "Failed to download CKB"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi
    
    # Extract
    info "Extracting..."
    tar -xzf "$TEMP_DIR/$ARCHIVE" -C "$TEMP_DIR"
    
    # Find and copy CKB binary
    CKB_BINARY=$(find "$TEMP_DIR" -name "ckb" -type f -executable 2>/dev/null | head -1)
    if [ -z "$CKB_BINARY" ]; then
        # Try without executable check (macOS might not preserve it)
        CKB_BINARY=$(find "$TEMP_DIR" -name "ckb" -type f 2>/dev/null | head -1)
    fi
    
    if [ -z "$CKB_BINARY" ]; then
        error "Could not find CKB binary in archive"
    fi
    
    cp "$CKB_BINARY" "$CKB_PATH"
    chmod +x "$CKB_PATH"
    
    # Verify
    INSTALLED_VERSION=$("$CKB_PATH" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
    if [ "$INSTALLED_VERSION" = "$CKB_VERSION" ]; then
        info "Successfully installed CKB v$CKB_VERSION"
        info "Location: $CKB_PATH"
        echo ""
        info "You can now run the integration tests:"
        echo "  cargo test --test integration -- --test-threads=1 --nocapture"
    else
        error "Version mismatch after installation: expected $CKB_VERSION, got $INSTALLED_VERSION"
    fi
}

main "$@"
