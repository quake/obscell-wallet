#!/bin/bash
# Setup script for obscell-wallet integration tests
# Downloads CKB binary and creates devnet configuration

set -e

# Configuration
CKB_VERSION="0.204.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CKB_PATH="$SCRIPT_DIR/ckb"
DEVNET_DIR="$SCRIPT_DIR/devnet"

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

# Download and install CKB binary
setup_ckb() {
    # Check if CKB already exists and is correct version
    if [ -f "$CKB_PATH" ]; then
        EXISTING_VERSION=$("$CKB_PATH" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
        if [ "$EXISTING_VERSION" = "$CKB_VERSION" ]; then
            info "CKB v$CKB_VERSION already installed"
            return 0
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
    else
        error "Version mismatch after installation: expected $CKB_VERSION, got $INSTALLED_VERSION"
    fi
}

# Create devnet configuration
setup_devnet() {
    if [ -d "$DEVNET_DIR" ] && [ -f "$DEVNET_DIR/ckb.toml" ]; then
        info "Devnet configuration already exists"
        return 0
    fi
    
    info "Creating devnet configuration..."
    mkdir -p "$DEVNET_DIR/specs"
    
    # Create ckb.toml
    cat > "$DEVNET_DIR/ckb.toml" << 'CKBTOML'
# CKB devnet config for integration tests

data_dir = "data"

[chain]
spec = { file = "specs/dev.toml" }

[logger]
filter = "info"
color = true
log_to_file = true
log_to_stdout = false

[sentry]
dsn = ""

[db]
cache_size = 268435456
options_file = "default.db-options"

[network]
listen_addresses = ["/ip4/0.0.0.0/tcp/8115"]
bootnodes = []
max_peers = 10
max_outbound_peers = 4
ping_interval_secs = 120
ping_timeout_secs = 1200
connect_outbound_interval_secs = 15
upnp = false
discovery_local_address = true
bootnode_mode = false

[rpc]
listen_address = "127.0.0.1:8114"
max_request_body_size = 10485760
# Include IntegrationTest module for generate_block and truncate
modules = ["Net", "Pool", "Miner", "Chain", "Stats", "Subscription", "Experiment", "Debug", "IntegrationTest", "Indexer"]
reject_ill_transactions = true
enable_deprecated_rpc = false

[tx_pool]
max_tx_pool_size = 180_000_000
min_fee_rate = 1_000
min_rbf_rate = 1_500
max_tx_verify_cycles = 70_000_000
max_ancestors_count = 25

[store]
header_cache_size          = 4096
cell_data_cache_size       = 128
block_proposals_cache_size = 30
block_tx_hashes_cache_size = 30
block_uncles_cache_size    = 30

# Block assembler config - uses the miner private key from dev.toml
# Private key: d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc
# Lock args (blake160 of pubkey): c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7
[block_assembler]
code_hash = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
args = "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
hash_type = "type"
message = "0x"
CKBTOML

    # Create default.db-options
    cat > "$DEVNET_DIR/default.db-options" << 'DBOPTIONS'
# This is a RocksDB option file.
#
# For detailed file format spec, please refer to the official documents
# in https://rocksdb.org/docs/
#

[DBOptions]
bytes_per_sync=1048576
max_background_jobs=6
max_total_wal_size=134217728
keep_log_file_num=32

[CFOptions "default"]
level_compaction_dynamic_level_bytes=true
write_buffer_size=8388608
min_write_buffer_number_to_merge=1
max_write_buffer_number=2
max_write_buffer_size_to_maintain=-1
DBOPTIONS

    # Create miner.key
    cat > "$DEVNET_DIR/miner.key" << 'MINERKEY'
# Miner private key for devnet faucet
# This key controls the genesis issued cells (20,000,000,000 CKB)
# Lock args: 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7
d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc
MINERKEY

    # Create specs/dev.toml
    cat > "$DEVNET_DIR/specs/dev.toml" << 'DEVSPEC'
name = "ckb_dev"

[genesis]
version = 0
parent_hash = "0x0000000000000000000000000000000000000000000000000000000000000000"
timestamp = 0
compact_target = 0x20010000
uncles_hash = "0x0000000000000000000000000000000000000000000000000000000000000000"
nonce = "0x0"

[genesis.genesis_cell]
message = "obscell-wallet-test"

[genesis.genesis_cell.lock]
code_hash = "0x0000000000000000000000000000000000000000000000000000000000000000"
args = "0x"
hash_type = "data"

# System cells
[[genesis.system_cells]]
file = { bundled = "specs/cells/secp256k1_blake160_sighash_all" }
create_type_id = true
capacity = 100_000_0000_0000
[[genesis.system_cells]]
file = { bundled = "specs/cells/dao" }
create_type_id = true
capacity = 16_000_0000_0000
[[genesis.system_cells]]
file = { bundled = "specs/cells/secp256k1_data" }
create_type_id = false
capacity = 1_048_617_0000_0000
[[genesis.system_cells]]
file = { bundled = "specs/cells/secp256k1_blake160_multisig_all" }
create_type_id = true
capacity = 100_000_0000_0000

[genesis.system_cells_lock]
code_hash = "0x0000000000000000000000000000000000000000000000000000000000000000"
args = "0x"
hash_type = "data"

# Dep group cells
[[genesis.dep_groups]]
name = "secp256k1_blake160_sighash_all"
files = [
  { bundled = "specs/cells/secp256k1_data" },
  { bundled = "specs/cells/secp256k1_blake160_sighash_all" },
]
[[genesis.dep_groups]]
name = "secp256k1_blake160_multisig_all"
files = [
  { bundled = "specs/cells/secp256k1_data" },
  { bundled = "specs/cells/secp256k1_blake160_multisig_all" },
]

# For first 11 block
[genesis.bootstrap_lock]
code_hash = "0x0000000000000000000000000000000000000000000000000000000000000000"
args = "0x"
hash_type = "type"

# Burn address
[[genesis.issued_cells]]
capacity = 8_400_000_000_00000000
lock.code_hash = "0x0000000000000000000000000000000000000000000000000000000000000000"
lock.args = "0x62e907b15cbf27d5425399ebf6f0fb50ebb88f18"
lock.hash_type = "data"

# Miner address - private key: d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc
# This is the faucet source for integration tests
[[genesis.issued_cells]]
capacity = 20_000_000_000_00000000
lock.code_hash = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
lock.args = "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
lock.hash_type = "type"

# Secondary issued cells
[[genesis.issued_cells]]
capacity = 5_198_735_037_00000000
lock.code_hash = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
lock.args = "0x470dcdc5e44064909650113a274b3b36aecb6dc7"
lock.hash_type = "type"

[params]
initial_primary_epoch_reward = 1_917_808_21917808
secondary_epoch_reward = 613_698_63013698
max_block_cycles = 10_000_000_000
cellbase_maturity = 0
primary_epoch_reward_halving_interval = 8760
epoch_duration_target = 80
genesis_epoch_length = 10
permanent_difficulty_in_dummy = true
starting_block_limiting_dao_withdrawing_lock = 0

[params.hardfork]
ckb2023 = 0

[pow]
func = "Dummy"
DEVSPEC

    info "Devnet configuration created"
}

# Main
main() {
    info "Setting up CKB integration test environment..."
    echo ""
    
    setup_ckb
    echo ""
    
    setup_devnet
    echo ""
    
    info "Setup complete!"
    info "You can now run the integration tests:"
    echo "  cargo test --test integration -- --test-threads=1 --nocapture"
}

main "$@"
