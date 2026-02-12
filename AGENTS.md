# AGENTS.md - Obscell Wallet

Guidelines for AI coding agents working on this TUI wallet for obscell privacy tokens on Nervos CKB blockchain. Built with Rust using `ratatui`, `tokio`, and various cryptographic libraries.

**Related Repository:** Smart contract code is at https://github.com/quake/obscell

## Build/Test/Lint Commands

```bash
cargo check                    # Type check (fastest)
cargo build                    # Debug build
cargo build --release          # Release build
cargo run -- --network testnet # Run with args

# Unit tests
cargo test                     # All unit tests
cargo test test_commitment     # Single test by name
cargo test domain::ct::tests   # Tests in module
cargo test stealth             # Pattern match
cargo test -- --nocapture      # With output

# Integration tests (require devnet)
cargo test --features test-utils --test integration  # All integration tests
cargo test --features test-utils --test integration e2e_basic_flow  # Single integration test

cargo fmt                      # Format code
cargo fmt -- --check           # Check formatting
cargo clippy                   # Lint
cargo clippy -- -D warnings    # Strict lint (CI mode)
```

## Project Structure

```
src/
├── main.rs           # Entry point, #[tokio::main]
├── app.rs            # App state and UI orchestration
├── action.rs         # Action enum for UI events
├── cli.rs            # CLI parsing (clap)
├── config.rs         # TOML config loading
├── errors.rs         # Panic/error hooks
├── logging.rs        # Tracing setup
├── tui.rs            # Terminal abstraction
├── components/       # UI components (Component trait)
├── domain/           # Business logic (pure, testable)
│   ├── account.rs, cell.rs, ct.rs, stealth.rs, wallet.rs, tx_builder.rs
└── infra/            # Infrastructure (I/O, external)
    ├── rpc.rs, scanner.rs, store.rs

tests/integration/    # Integration tests (require --features test-utils)
```

## Code Style

### Imports (ordered with blank lines between groups)
```rust
// 1. External crates
use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};

// 2. Standard library
use std::path::PathBuf;

// 3. Internal modules
use crate::{config::Config, domain::account::Account};
```

### Naming Conventions
| Element       | Convention       | Example                          |
|---------------|------------------|----------------------------------|
| Types/Structs | PascalCase       | `AccountManager`, `StealthCell`  |
| Functions     | snake_case       | `create_account`, `matches_key`  |
| Constants     | SCREAMING_SNAKE  | `SCAN_CURSOR_KEY`                |
| Modules       | snake_case       | `domain`, `infra`                |
| Enum variants | PascalCase       | `Action::CreateAccount`          |

### Error Handling
- Use `color_eyre::eyre::Result` as standard Result type for application code
- Propagate with `?`, create errors with `eyre!("message")`
- For pure library/domain code: `Result<T, &'static str>` (no dependencies)

```rust
pub fn do_something() -> color_eyre::eyre::Result<()> {
    let value = fallible_op()?;
    if value.is_invalid() {
        return Err(color_eyre::eyre::eyre!("Invalid: {}", value));
    }
    Ok(())
}
```

### Struct Definitions
Derive order: Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyStruct { pub field: String }
```

### Tests (inline with `#[cfg(test)]`)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_feature() {
        let input = prepare();           // Arrange
        let result = func(input);        // Act
        assert_eq!(result, expected);    // Assert
    }
}
```

### Async
- Runtime: `tokio` with `#[tokio::main]` or `#[tokio::test]`
- Channels: `tokio::sync::mpsc`
- Let-chain syntax allowed: `if let Ok(x) = y && condition { ... }`

### Component Pattern
```rust
pub trait Component {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()>;
    fn draw(&mut self, f: &mut Frame, area: Rect);
}
```

## Key Dependencies

| Crate          | Purpose                              |
|----------------|--------------------------------------|
| ratatui        | Terminal UI framework                |
| tokio          | Async runtime                        |
| secp256k1      | ECDSA/ECDH cryptography              |
| bulletproofs   | Range proofs for confidential tx     |
| curve25519-dalek | Ristretto points, scalars          |
| ckb-sdk        | Nervos CKB blockchain interaction    |
| heed           | LMDB database wrapper                |
| color-eyre     | Error handling with context          |

## Adding New Code

**New Component:** Create in `src/components/`, implement `Component` trait, export in mod.rs, wire in app.rs

**New Domain Entity:** Create in `src/domain/`, add Serialize/Deserialize derives, add store methods in `infra/store.rs`

**New Action:** Add variant to `Action` enum in `action.rs`, handle in relevant component's `handle_key_event`

## Cryptographic Patterns

```rust
// Stealth addresses: generate ephemeral key pair for each transaction
let (eph_pub, stealth_pub) = generate_ephemeral_key(&view_pub, &spend_pub);

// CT commitments: Pedersen commitment C = v*G + r*H
let commitment = commit(amount, &blinding);

// Range proofs: prove values are in [0, 2^32)
let (proof, commitments) = prove_range(&[amount], &[blinding])?;
```
