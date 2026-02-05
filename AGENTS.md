# AGENTS.md - Obscell Wallet

Guidelines for AI coding agents working on this TUI wallet for obscell privacy tokens on Nervos CKB blockchain. Built with Rust using `ratatui`, `tokio`, and various cryptographic libraries.

**Related Repository:** Smart contract code is at https://github.com/quake/obscell

## Build/Test/Lint Commands

```bash
cargo check                    # Type check (fastest)
cargo build                    # Debug build
cargo build --release          # Release build
cargo run -- --network testnet # Run with args

cargo test                     # All tests
cargo test test_commitment     # Single test by name
cargo test domain::ct::tests   # Tests in module
cargo test stealth             # Pattern match
cargo test -- --nocapture      # With output

cargo fmt                      # Format code
cargo fmt -- --check           # Check formatting
cargo clippy                   # Lint
cargo clippy -- -D warnings    # Strict lint
```

## Project Structure

```
src/
├── main.rs           # Entry point
├── app.rs            # App state and UI orchestration
├── cli.rs            # CLI parsing (clap)
├── config.rs         # TOML config loading
├── errors.rs         # Panic/error hooks
├── logging.rs        # Tracing setup
├── tui.rs            # Terminal abstraction
├── action.rs         # Action enum for events
├── components/       # UI components (Component trait)
├── domain/           # Business logic
│   ├── account.rs    # Account management
│   ├── cell.rs       # Cell (UTXO) structures
│   ├── ct.rs         # Confidential token primitives
│   └── stealth.rs    # Stealth address crypto
└── infra/            # Infrastructure
    ├── rpc.rs        # CKB RPC client
    ├── scanner.rs    # Blockchain scanner
    └── store.rs      # LMDB storage
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
- Use `color_eyre::eyre::Result` as standard Result type
- Propagate with `?`, create errors with `eyre!("message")`
- For pure library code: `Result<T, &'static str>`

```rust
use color_eyre::eyre::Result;

pub fn do_something() -> Result<()> {
    let value = fallible_op()?;
    if value.is_invalid() {
        return Err(color_eyre::eyre::eyre!("Invalid: {}", value));
    }
    Ok(())
}
```

### Documentation
```rust
//! Module-level docs

/// Function/struct docs
pub fn my_function() {}
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
| clap           | CLI argument parsing                 |
| secp256k1      | ECDSA/ECDH cryptography              |
| bulletproofs   | Range proofs for confidential tx     |
| ckb-sdk        | Nervos CKB blockchain interaction    |
| heed           | LMDB database wrapper                |
| color-eyre     | Error handling with context          |
| tracing        | Structured logging                   |

## Adding New Code

**New Component:** Create in `src/components/`, implement `Component`, export in mod.rs, wire in app.rs

**New Domain Entity:** Create in `src/domain/`, add Serialize/Deserialize, add store methods in `infra/store.rs`
