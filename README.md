# Obscell Wallet

A TUI (Terminal User Interface) wallet for **Obscell privacy tokens** on the [Nervos CKB](https://www.nervos.org/) blockchain.

Obscell enables **confidential transactions** with hidden amounts using **Bulletproofs range proofs** and **stealth addresses** for receiver privacy.

## Features

- **Stealth Addresses**: Generate one-time addresses for each transaction, unlinkable to your public identity
- **Confidential Tokens (CT)**: Transfer tokens with hidden amounts using Pedersen commitments
- **Bulletproofs**: Zero-knowledge range proofs ensure amounts are valid without revealing them
- **HD Wallet**: BIP39/BIP32 compatible key derivation with encrypted storage
- **Multi-Account Support**: Manage multiple accounts with separate key pairs
- **Token Issuance**: Create new confidential tokens with customizable supply caps
- **Full TUI Interface**: Navigate with keyboard shortcuts, no CLI commands needed

## Installation

### Download Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/quake/obscell-wallet/releases):

- `obscell-wallet-macos-x86_64.zip` - macOS Intel
- `obscell-wallet-macos-aarch64.zip` - macOS Apple Silicon
- `obscell-wallet-linux-x86_64.zip` - Linux x86_64
- `obscell-wallet-windows-x86_64.zip` - Windows x86_64

Each zip contains the binary and a `testnet.toml` configuration file.

### Build from Source

```bash
# Prerequisites: Rust 1.85+ (edition 2024)

git clone https://github.com/quake/obscell-wallet
cd obscell-wallet
cargo build --release
./target/release/obscell-wallet
```

## Usage

### Command Line Options

```
obscell-wallet [OPTIONS]

Options:
  -t, --tick-rate <TICK_RATE>    Tick rate in ticks per second [default: 4]
  -f, --frame-rate <FRAME_RATE>  Frame rate in frames per second [default: 60]
  -n, --network <NETWORK>        Network to connect to (testnet, mainnet, devnet)
      --rpc-url <RPC_URL>        Custom RPC URL (overrides network default)
      --data-dir <DATA_DIR>      Data directory path
  -h, --help                     Print help
  -V, --version                  Print version
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `a/t/s/r/h/g` | Jump to Accounts/Tokens/Send/Receive/History/Settings tab |
| `Tab` / `Shift+Tab` | Switch between tabs |
| `↑/↓` | Navigate lists |
| `Enter` | Confirm/Select |
| `Esc` | Cancel/Back |
| `q` | Quit |

### Tabs

1. **Accounts**: Create, import, and switch between accounts
2. **Tokens**: View CT balances, create new tokens, mint, and transfer
3. **Send**: Send CKB or CT tokens to a stealth address
4. **Receive**: Display your stealth address for receiving funds
5. **History**: View transaction history
6. **Settings**: Network selection and wallet management

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

## Smart Contracts

This wallet interacts with the [Obscell](https://github.com/quake/obscell) smart contracts:

| Contract | Purpose |
|----------|---------|
| `stealth-lock` | Lock script for stealth address ownership verification |
| `ct-token-type` | Type script for confidential token validation with Bulletproofs |
| `ct-info-type` | Type script for token metadata (supply cap, flags) |

## Configuration

**Network config files** are searched in order:
1. `--config-dir/{network}.toml` (if specified via CLI)
2. `./{network}.toml` (current directory)
3. `./config/{network}.toml` (config subdirectory)

**Wallet data** (database, keys) is stored in `./data/{network}/` by default.

Command line options:
- `--data-dir <path>`: Override data directory path (default: `./data`)
- `--config-dir <path>`: Override config directory search path
- `--network <name>`: Select network (testnet, mainnet, devnet)

## Development

```bash
cargo test                     # Run unit tests
cargo test --features test-utils --test integration  # Integration tests (requires devnet)
cargo fmt                      # Format code
cargo clippy                   # Lint
```

## License

MIT

## Related

- [Obscell Smart Contracts](https://github.com/quake/obscell) - The on-chain contracts
- [Nervos CKB](https://www.nervos.org/) - The underlying blockchain
- [Bulletproofs](https://crypto.stanford.edu/bulletproofs/) - Range proof system
