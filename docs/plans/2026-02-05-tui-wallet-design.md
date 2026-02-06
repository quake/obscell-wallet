# TUI Wallet Design

**Date:** 2026-02-05
**Status:** Approved
**Repository:** New separate repo (obscell-wallet)

## Overview

A terminal-based (TUI) wallet for the obscell privacy system on Nervos CKB, supporting:
- **Stealth addresses** - Hide recipients
- **Confidential tokens** - Hide amounts using Bulletproofs
- **Multi-network** - Testnet, mainnet, and local devnet

## Goals

1. Full stealth address support (send, receive, scan)
2. Full CT token support (receive, transfer, mint)
3. Clean TUI using ratatui
4. Persistent storage with LMDB
5. Network switching (testnet/mainnet/devnet)

## Non-Goals

- GUI (desktop/web) - this is TUI only
- Mobile support
- Hardware wallet integration (future consideration)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    TUI Layer (ratatui)                  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐│
│  │Accounts │ │ Send    │ │Receive  │ │ Token Mgmt      ││
│  │Component│ │Component│ │Component│ │ Component       ││
│  └─────────┘ └─────────┘ └─────────┘ └─────────────────┘│
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│                     App Layer                            │
│         Action dispatch, Component orchestration         │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│                   Domain Layer                           │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ stealth.rs  │  │ ct.rs        │  │ account.rs     │  │
│  │ (addresses) │  │ (Bulletproof)│  │ (key mgmt)     │  │
│  └─────────────┘  └──────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│                Infrastructure Layer                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ store.rs    │  │ rpc.rs       │  │ scanner.rs     │  │
│  │ (LMDB)      │  │ (CKB client) │  │ (cell scan)    │  │
│  └─────────────┘  └──────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Project Structure

Based on the official ratatui component template:

```
obscell-wallet/
├── Cargo.toml
├── config/
│   ├── testnet.toml
│   ├── mainnet.toml
│   └── devnet.toml
│
└── src/
    ├── main.rs              # Entry point
    ├── action.rs            # App-wide actions enum
    ├── app.rs               # App state machine, main loop
    ├── cli.rs               # Clap CLI parsing
    ├── config.rs            # Config loading
    ├── errors.rs            # Error types
    ├── logging.rs           # Tracing setup
    ├── tui.rs               # Terminal setup/teardown
    │
    ├── components/          # UI components
    │   ├── mod.rs
    │   ├── accounts.rs
    │   ├── send.rs
    │   ├── receive.rs
    │   ├── tokens.rs
    │   └── transactions.rs
    │
    ├── domain/              # Core logic
    │   ├── mod.rs
    │   ├── stealth.rs       # Stealth address primitives
    │   ├── ct.rs            # CT primitives
    │   ├── account.rs       # Account model
    │   └── cell.rs          # Cell/UTXO model
    │
    └── infra/               # Infrastructure
        ├── mod.rs
        ├── rpc.rs           # CKB RPC client
        ├── store.rs         # LMDB persistence
        └── scanner.rs       # Cell scanning
```

## Data Models

### Account
```rust
pub struct Account {
    pub id: u64,
    pub name: String,
    pub view_key: [u8; 32],      // secp256k1 secret key
    pub spend_key: [u8; 32],     // secp256k1 secret key
    pub ckb_balance: u64,        // shannon
    pub ct_tokens: Vec<CtBalance>,
}

pub struct CtBalance {
    pub token_type_hash: [u8; 32],
    pub cells: Vec<CtCell>,
}
```

### Cells
```rust
pub struct StealthCell {
    pub out_point: OutPoint,
    pub capacity: u64,
    pub stealth_script_args: [u8; 53],  // P (33B) | Q' (20B)
}

pub struct CtCell {
    pub out_point: OutPoint,
    pub commitment: [u8; 32],
    pub encrypted_amount: [u8; 32],
    pub blinding_factor: [u8; 32],  // Local storage only
    pub amount: u64,                 // Decrypted, local only
}
```

### Transaction History
```rust
pub struct TxRecord {
    pub tx_hash: [u8; 32],
    pub tx_type: TxType,
    pub timestamp: i64,
    pub status: TxStatus,
}

pub enum TxType {
    StealthSend { to: String, amount: u64 },
    StealthReceive { amount: u64 },
    CtTransfer { token: [u8; 32], amount: u64 },
    CtMint { token: [u8; 32], amount: u64 },
}
```

## Key Operations

### Cell Scanning (Stealth)

```
1. get_cells(stealth_lock_code_hash, prefix_mode)
   → Returns all cells with stealth-lock

2. For each cell:
   - Extract P (ephemeral pubkey, 33 bytes) from args
   - Extract Q' (pubkey hash, 20 bytes) from args
   - shared_secret = ECDH(view_secret_key, P)
   - derived_key = hash_to_scalar(shared_secret)
   - stealth_pubkey = spend_pubkey + derived_key * G
   - if blake2b(stealth_pubkey)[0..20] == Q':
     → Cell belongs to this wallet
```

### CT Token Receiving

```
For each CT cell with our stealth-lock:
1. Derive shared_secret from ephemeral pubkey + view_key
2. Decrypt encrypted_amount using shared_secret
3. Verify: Commitment == amount*G + blinding_factor*H
4. Store: (commitment, blinding_factor, amount) locally
```

### CT Token Transfer

```
Input: cells with value V_in, blinding factors r_in[]
Output: amounts V_out[] where sum(V_out) == sum(V_in)

1. Generate r_out[] with sum(r_out) == sum(r_in)
2. Compute C_out[i] = V_out[i]*G + r_out[i]*H
3. Generate Bulletproofs range proof
4. Encrypt amounts for recipients
5. Build transaction
```

### CT Token Minting

```
Prerequisites: Own ct-info-type cell with issuer_pubkey

1. Load ct-info cell (total_supply, flags)
2. Verify MINTABLE flag
3. Sign: sign(tx_hash | old_supply | new_supply)
4. mint_commitment = amount * G (zero blinding)
5. Create CT cells with commitments
6. Submit transaction
```

## UI Design

### Layout
```
┌─────────────────────────────────────────────────────────────────┐
│ Obscell Wallet                    [testnet]     Synced: 12345678│
├─────────────────────────────────────────────────────────────────┤
│ [1]Accounts [2]Send [3]Receive [4]Tokens [5]History [q]Quit     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Content area (varies by tab)                                   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ Status: Scanning... 45% | Last block: 12345678                  │
└─────────────────────────────────────────────────────────────────┘
```

### Screens

| Screen | Features |
|--------|----------|
| **Accounts** | List, create, import, export, switch active |
| **Send** | Recipient, amount, asset selection, confirm |
| **Receive** | Show stealth address, generate fresh address |
| **Tokens** | List CT tokens, mint (if issuer), create token |
| **History** | Transaction list, filter, details |

### Key Bindings
- `1-5`: Switch tabs
- `j/k` or `↑/↓`: Navigate
- `Enter`: Select/confirm
- `e`: Edit mode
- `r`: Rescan
- `q`: Quit
- `?`: Help

## Dependencies

```toml
[dependencies]
# TUI
ratatui = "0.29"
crossterm = "0.28"
tokio = { version = "1", features = ["full"] }

# CLI & Config
clap = { version = "4", features = ["derive"] }
directories = "5"

# Crypto
secp256k1 = { version = "0.28", features = ["rand-std", "recovery", "global-context"] }
bulletproofs = { version = "4", default-features = false }
curve25519-dalek = { version = "4", default-features = false }
merlin = "3"
rand = "0.8"

# CKB
ckb-sdk = "5"
ckb-types = "1"
ckb-hash = "1"
ckb-jsonrpc-types = "1"

# Storage
heed = { version = "0.22", features = ["serde", "serde-rmp"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error handling
color-eyre = "0.6"
thiserror = "2"
tracing = "0.1"
tracing-subscriber = "0.3"
```

## Implementation Phases

### Phase 1: MVP (~1-2 weeks) ✅
- [x] Project scaffolding (cargo generate ratatui component)
- [x] Basic TUI shell with tab navigation
- [x] Account management (create, import, list)
- [x] Network config (testnet/mainnet/devnet)
- [x] Cell scanning (stealth-lock only)
- [x] Basic send (CKB to stealth address)

### Phase 2: Full Stealth (~1 week) ✅
- [x] Transaction history persistence
- [x] Receive view with fresh address generation
- [x] LMDB persistence for accounts, cells, cursor

### Phase 3: CT Token Support (~2 weeks) ✅
- [x] CT cell scanning with amount decryption
- [x] CT token balance display
- [x] CT transfer with Bulletproofs
- [x] CT minting (issuer functionality)

### Phase 4: Polish (~1 week) ⚠️ Partial
- [x] Error handling improvements
- [x] Full rescan functionality
- [ ] Configuration (keybindings, RPC endpoints) - keybindings are hardcoded
- [x] Integration tests

## Network Configuration

```toml
# config/testnet.toml
[network]
name = "testnet"
rpc_url = "https://testnet.ckb.dev"
indexer_url = "https://testnet.ckb.dev/indexer"

[contracts]
stealth_lock_code_hash = "0x1d7f12a173ed22df9de1180a0b11e2a4368568017d9cfdfb5658b50c147549d6"
ct_token_code_hash = "0x..."
ct_info_code_hash = "0x..."
ckb_auth_code_hash = "0x..."

[cell_deps]
ckb_auth = { tx_hash = "0x91b7a8e6fdeef45389dee510a1f070dc764855f72b08b24165d9c92ef36ff920", index = 0 }
stealth_lock = { tx_hash = "0x91b7a8e6fdeef45389dee510a1f070dc764855f72b08b24165d9c92ef36ff920", index = 1 }
```

## Security Considerations

1. **Private keys**: Stored encrypted locally, never transmitted
2. **Blinding factors**: Critical for CT - must be persisted securely
3. **Memory**: Clear sensitive data after use
4. **RPC**: Use HTTPS, consider Tor support (future)

## Reference

- [obscell contracts](https://github.com/quake/obscell) - Smart contracts
- [obscell-wallet (GUI)](https://github.com/Rea-Don-Lycn/obscell-wallet) - Reference implementation
- [ratatui templates](https://github.com/ratatui/templates) - TUI framework
- [Bulletproofs paper](https://crypto.stanford.edu/bulletproofs/)
