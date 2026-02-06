# Integration Test Design

**Date:** 2026-02-05
**Status:** Completed ✅

## Overview

End-to-end integration tests for the obscell-wallet, running against a local CKB devnet with real contract deployment.

## Goals

1. Test complete user workflows (create account → scan → send → verify)
2. Use local CKB devnet for realistic testing
3. Smart environment management (reuse existing devnet/contracts)
4. Fast test cycles using CKB integration RPC (generate_block, truncate)

## Non-Goals

- Mock-based testing (we want real chain interaction)
- Testnet/mainnet testing
- CT token flows (Phase 3, will be added later)

## Architecture

```
tests/
├── integration/
│   ├── mod.rs              # Test module entry
│   ├── devnet.rs           # DevNet management (start/stop/detect)
│   ├── contract_deployer.rs # Contract deployment
│   ├── faucet.rs           # Transfer from genesis address
│   └── e2e_basic_flow.rs   # Basic flow test
└── fixtures/
    ├── stealth_lock        # Pre-compiled stealth-lock contract
    ├── ckb_auth             # Pre-compiled ckb-auth contract
    └── devnet/
        ├── ckb.toml        # Devnet config
        ├── specs/
        │   └── dev.toml    # Chain spec (with genesis funds)
        └── miner.key       # Miner private key (for faucet)
```

## State Management Strategy

### Initialization Phase (One-time)

```
Start ckb ---> Deploy contracts ---> generate_block() ---> Record checkpoint
```

### Per Test Case

```
From checkpoint ---> Faucet transfer ---> generate_block() ---> Execute test ---> truncate(checkpoint)
```

### Subsequent Runs

```
Detect node ---> Detect contracts deployed ---> Start from checkpoint
```

**Key Integration RPC Methods:**
- `generate_block()` - Fast block generation to confirm transactions
- `truncate(block_number)` - Rollback to specified height, restore initial state

**Checkpoint Persistence:**
- Stored in `tests/fixtures/devnet/.checkpoint`
- Reused across test runs
- Contains block number after contract deployment

## Test Environment

```rust
struct TestEnv {
    devnet: DevNet,           // Manage ckb process
    checkpoint: u64,          // Block height after contract deployment
    config: Config,           // Config pointing to devnet
}

impl TestEnv {
    fn setup() -> Self;              // Start/detect devnet, deploy contracts
    fn faucet(&self, addr, amount);  // Transfer from genesis address
    fn generate_block(&self);        // Fast block generation
    fn reset(&self);                 // Truncate to checkpoint
}
```

## Test Cases

### Basic Stealth Flow (`e2e_basic_flow.rs`)

```rust
#[test]
fn test_basic_stealth_flow() {
    // 1. Create two accounts (Alice, Bob)
    // 2. Faucet transfer 1000 CKB to Alice's regular CKB address
    // 3. generate_block() to confirm
    // 4. Alice scans, verify received 1000 CKB
    // 5. Alice sends 100 CKB to Bob's stealth address
    // 6. generate_block() to confirm
    // 7. Bob scans, verify received 100 CKB
    // 8. Verify Alice balance ≈ 900 CKB (minus fees)
    // 9. Verify Alice history has 1 send record
    // 10. Verify Bob history has 1 receive record
    // 11. truncate() rollback to checkpoint
}
```

## DevNet Management

### Detection Logic

1. Check `localhost:8114` connectivity
2. If connected, check if contracts are deployed (query specific cells)
3. If contracts found, load checkpoint and proceed with tests

### Startup Logic (if not running)

```bash
ckb init --chain dev -C tests/fixtures/devnet
ckb run -C tests/fixtures/devnet --indexer
```

Integration RPC is enabled by default in dev chain.

### Process Lifecycle

- Process handle retained, not killed after tests (for reuse)
- Data persisted in `tests/fixtures/devnet/data/`

## Faucet Implementation

1. Read `tests/fixtures/devnet/miner.key` for genesis private key
2. Build standard CKB transfer transaction (not stealth)
3. Send to test account's one-time CKB address
4. Call `generate_block()` to confirm

## Configuration

```toml
# Cargo.toml
[dev-dependencies]
tempfile = "3"

[[test]]
name = "integration"
path = "tests/integration/mod.rs"
```

## Running Tests

```bash
# First run (start devnet + deploy contracts + test)
cargo test --test integration

# Subsequent runs (reuse devnet + skip deployment + test)
cargo test --test integration

# Clean environment and restart
rm -rf tests/fixtures/devnet/data && cargo test --test integration
```

## Contract Binaries

Pre-compiled contract binaries stored in `tests/fixtures/`:
- `stealth_lock` - Stealth lock script
- `ckb_auth` - CKB auth library

These need to be manually updated when contracts change.

## Future Extensions

- ~~CT token mint/transfer tests (Phase 3)~~ ✅ Implemented in `e2e_ct_genesis_mint.rs`
- ~~Multi-account scenarios~~ ✅ Implemented in `test_scanner_finds_ct_cells_multi_account`
- Error handling tests (insufficient balance, invalid address)
