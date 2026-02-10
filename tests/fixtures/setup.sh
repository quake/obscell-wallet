#!/bin/bash
# Setup script for obscell-wallet integration tests
# Downloads CKB binary and initializes devnet

set -e

# Configuration
CKB_VERSION="0.204.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CKB_PATH="$SCRIPT_DIR/ckb"
DEVNET_DIR="$SCRIPT_DIR/devnet"
GENESIS_MESSAGE="obscell-wallet-test"

# Miner key for block assembler (controls genesis issued cells)
# Private key: d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc
BA_ARG="0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux";;
        Darwin*) echo "darwin";;
        *)       error "Unsupported OS: $(uname -s)";;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "x86_64";;
        aarch64|arm64)  echo "aarch64";;
        *)              error "Unsupported architecture: $(uname -m)";;
    esac
}

setup_ckb() {
    if [ -f "$CKB_PATH" ]; then
        EXISTING_VERSION=$("$CKB_PATH" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "")
        if [ "$EXISTING_VERSION" = "$CKB_VERSION" ]; then
            info "CKB v$CKB_VERSION already installed"
            return 0
        fi
        warn "CKB version mismatch ($EXISTING_VERSION != $CKB_VERSION), re-downloading..."
    fi

    OS=$(detect_os)
    ARCH=$(detect_arch)
    info "Downloading CKB v$CKB_VERSION for $OS-$ARCH..."

    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT

    if [ "$OS" = "linux" ]; then
        ARCHIVE="ckb_v${CKB_VERSION}_${ARCH}-unknown-linux-gnu.tar.gz"
        curl -L -o "$TEMP_DIR/$ARCHIVE" \
            "https://github.com/nervosnetwork/ckb/releases/download/v${CKB_VERSION}/${ARCHIVE}" \
            || error "Failed to download CKB"
        tar -xzf "$TEMP_DIR/$ARCHIVE" -C "$TEMP_DIR"
    else
        # macOS uses .zip format
        ARCHIVE="ckb_v${CKB_VERSION}_${ARCH}-apple-darwin.zip"
        curl -L -o "$TEMP_DIR/$ARCHIVE" \
            "https://github.com/nervosnetwork/ckb/releases/download/v${CKB_VERSION}/${ARCHIVE}" \
            || error "Failed to download CKB"
        unzip -q "$TEMP_DIR/$ARCHIVE" -d "$TEMP_DIR"
    fi
    
    CKB_BINARY=$(find "$TEMP_DIR" -name "ckb" -type f | head -1)
    [ -z "$CKB_BINARY" ] && error "CKB binary not found in archive"

    cp "$CKB_BINARY" "$CKB_PATH"
    chmod +x "$CKB_PATH"
    info "CKB v$CKB_VERSION installed"
}

setup_devnet() {
    if [ -f "$DEVNET_DIR/ckb.toml" ]; then
        info "Devnet already initialized"
        return 0
    fi

    info "Initializing devnet with genesis message: $GENESIS_MESSAGE"
    mkdir -p "$DEVNET_DIR"
    
    "$CKB_PATH" init \
        -C "$DEVNET_DIR" \
        --chain dev \
        --genesis-message "$GENESIS_MESSAGE" \
        --ba-arg "$BA_ARG" \
        --force

    # Enable IntegrationTest and RichIndexer RPC modules
    # - IntegrationTest: for generate_block/truncate
    # - RichIndexer: for extended indexer capabilities (replaces Indexer)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' 's/modules = \[/modules = ["IntegrationTest", "RichIndexer", /' "$DEVNET_DIR/ckb.toml"
    else
        sed -i 's/modules = \[/modules = ["IntegrationTest", "RichIndexer", /' "$DEVNET_DIR/ckb.toml"
    fi

    # Save miner key for faucet
    cat > "$DEVNET_DIR/miner.key" << 'EOF'
# Miner private key for devnet faucet
# Lock args: 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7
d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc
EOF

    info "Devnet initialized"
}

main() {
    info "Setting up integration test environment..."
    setup_ckb
    setup_devnet
    info "Done! To complete setup:"
    echo ""
    echo "  1. Start CKB node: $CKB_PATH run -C $DEVNET_DIR"
    echo "  2. Run integration tests to deploy contracts:"
    echo "     cargo test --test integration -- --test-threads=1 --nocapture"
    echo ""
    echo "  After running tests once, contracts are deployed and you can use:"
    echo "     cargo run -- --network devnet"
    echo ""
    echo "  Note: Contract addresses in config/devnet.toml and src/config.rs"
    echo "  are deterministic with genesis message '$GENESIS_MESSAGE'"
}

main "$@"
