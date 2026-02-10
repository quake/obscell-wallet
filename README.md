# Obscell Wallet

A TUI (Terminal User Interface) wallet for **Obscell privacy tokens** on the [Nervos CKB](https://www.nervos.org/) blockchain.

Obscell enables **confidential transactions** with hidden amounts using **Bulletproofs range proofs** and **stealth addresses** for receiver privacy.

## Features

- **Stealth Addresses**: Generate one-time addresses for each transaction, unlinkable to your public identity
- **Confidential Tokens (CT)**: Transfer tokens with hidden amounts using Pedersen commitments
- **Bulletproofs**: Zero-knowledge range proofs ensure amounts are valid without revealing them
- **Multi-Account Support**: Manage multiple accounts with separate key pairs
- **Token Issuance**: Create new confidential tokens with customizable supply caps
- **Full TUI Interface**: Navigate with keyboard shortcuts, no CLI commands needed

## Architecture

```
src/
├── main.rs           # Entry point
├── app.rs            # App state and UI orchestration
├── cli.rs            # CLI argument parsing (clap)
├── config.rs         # Network and contract configuration
├── tui.rs            # Terminal abstraction (ratatui)
├── components/       # UI components
│   ├── accounts.rs   # Account management view
│   ├── send.rs       # Send CKB/tokens view
│   ├── receive.rs    # Receive address view
│   ├── tokens.rs     # CT token balances and operations
│   └── history.rs    # Transaction history view
├── domain/           # Business logic
│   ├── account.rs    # Account and key management
│   ├── cell.rs       # Cell (UTXO) structures
│   ├── ct.rs         # Confidential token primitives
│   ├── ct_tx_builder.rs  # CT transfer transaction builder
│   ├── ct_mint.rs    # Token genesis and minting
│   ├── ct_info.rs    # Token metadata
│   ├── stealth.rs    # Stealth address cryptography
│   └── tx_builder.rs # Plain CKB transaction builder
└── infra/            # Infrastructure
    ├── rpc.rs        # CKB RPC client
    ├── scanner.rs    # Blockchain scanner for owned cells
    └── store.rs      # LMDB local storage
```

## How It Works

### Stealth Addresses

Each account has two key pairs:
- **View key**: Used to scan the blockchain and identify incoming payments
- **Spend key**: Used to authorize spending of received funds

When sending to someone, a fresh one-time address is derived using ECDH:
1. Sender generates an ephemeral key pair
2. Sender derives a shared secret with recipient's view public key
3. The stealth public key is computed: `P = spend_pub + H(shared_secret) * G`
4. Only the recipient (with the view private key) can identify and spend the funds

### Confidential Tokens

Token amounts are hidden using Pedersen commitments: `C = v*G + r*H`
- `v` is the amount
- `r` is a random blinding factor
- `G, H` are generator points

Bulletproofs range proofs ensure amounts are positive and within valid bounds without revealing the actual values. The cryptographic balance equation `sum(inputs) = sum(outputs)` is verified by the contract.

## Installation

### Prerequisites

- Rust 1.82+ (edition 2024)
- A running CKB node (testnet or devnet)

### Build

```bash
# Clone the repository
git clone https://github.com/quake/obscell-wallet
cd obscell-wallet

# Build release version
cargo build --release

# Run
./target/release/obscell-wallet
```

## Usage

### Command Line Options

```bash
obscell-wallet [OPTIONS]

Options:
  -t, --tick-rate <TICK_RATE>  Tick rate in ticks per second [default: 4.0]
  -f, --frame-rate <FRAME_RATE>  Frame rate in frames per second [default: 60.0]
  -n, --network <NETWORK>      Network to connect to (testnet, mainnet, devnet) [default: testnet]
      --rpc-url <RPC_URL>      Custom RPC URL (overrides network default)
      --data-dir <DATA_DIR>    Data directory path
  -h, --help                   Print help
  -V, --version                Print version
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Switch between tabs |
| `1-5` | Jump to specific tab |
| `↑/↓` or `j/k` | Navigate lists |
| `Enter` | Confirm/Select |
| `Esc` | Cancel/Back |
| `q` | Quit |
| `r` | Rescan blockchain |

### Tabs

1. **Accounts**: Create, import, and switch between accounts
2. **Send**: Send CKB or CT tokens to a stealth address
3. **Receive**: Display your stealth address for receiving funds
4. **Tokens**: View CT balances, create new tokens, mint, and transfer
5. **History**: View transaction history

## Smart Contracts

This wallet interacts with the [Obscell](https://github.com/quake/obscell) smart contracts:

| Contract | Purpose |
|----------|---------|
| `stealth-lock` | Lock script for stealth address ownership verification |
| `ct-token-type` | Type script for confidential token validation with Bulletproofs |
| `ct-info-type` | Type script for token metadata (supply cap, flags) |

## Development

### Run Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_commitment

# Run integration tests (requires devnet)
cargo test --test integration -- --nocapture --test-threads=1
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint
cargo clippy

# Type check
cargo check
```

### Integration Tests

The integration tests require a local CKB devnet:

```bash
# Start devnet (in separate terminal)
ckb init --chain dev && ckb run

# Run integration tests
cargo test --test integration e2e_ct_genesis_mint -- --nocapture --test-threads=1
```

## Configuration

Configuration files are stored in platform-specific directories:
- Linux: `~/.config/obscell-wallet/`
- macOS: `~/Library/Application Support/com.obscell.obscell-wallet/`
- Windows: `%APPDATA%\obscell\obscell-wallet\`

Data (wallet database) is stored in `./data/` by default (in the directory where the TUI is launched).

Or set via environment variables:
- `OBSCELL_WALLET_CONFIG`: Config directory path
- `OBSCELL_WALLET_DATA`: Data directory path (default: `./data/`)

## Dependencies

| Crate | Purpose |
|-------|---------|
| `ratatui` | Terminal UI framework |
| `tokio` | Async runtime |
| `secp256k1` | ECDSA/ECDH cryptography |
| `bulletproofs` | Range proofs for confidential transactions |
| `ckb-sdk` | Nervos CKB blockchain interaction |
| `heed` | LMDB database wrapper |

## License

MIT

## Related

- [Obscell Smart Contracts](https://github.com/quake/obscell) - The on-chain contracts
- [Nervos CKB](https://www.nervos.org/) - The underlying blockchain
- [Bulletproofs](https://crypto.stanford.edu/bulletproofs/) - Range proof system
