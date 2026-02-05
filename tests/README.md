# Integration Tests

End-to-end tests for obscell-wallet running against a local CKB devnet.

## Setup

```bash
cd tests/fixtures
./setup.sh
```

This downloads CKB and initializes a devnet configuration.

## Run Tests

```bash
cargo test --test integration -- --test-threads=1
```

Use `--nocapture` to see detailed output:

```bash
cargo test --test integration -- --test-threads=1 --nocapture
```

## Structure

```
tests/
├── fixtures/
│   ├── setup.sh       # Downloads CKB, initializes devnet
│   ├── stealth-lock   # Compiled stealth-lock contract
│   ├── ckb            # CKB binary (gitignored, created by setup.sh)
│   └── devnet/        # Devnet config and data (gitignored, created by setup.sh)
└── integration/
    ├── mod.rs                # Test harness, shared TestEnv
    ├── devnet.rs             # DevNet manager (start/stop/generate blocks)
    ├── contract_deployer.rs  # Deploy stealth-lock with TYPE_ID
    ├── faucet.rs             # Transfer CKB to test addresses
    └── e2e_basic_flow.rs     # Test cases
```

## Test Cases

| Test | Description |
|------|-------------|
| `test_env_setup` | Verify devnet starts and contract deploys |
| `test_faucet_transfer` | Transfer CKB to a regular address |
| `test_stealth_cell_creation` | Create a stealth cell with encrypted recipient |
| `test_stealth_cell_scanning` | Scan chain and decrypt owned cells |
| `test_multiple_stealth_cells_same_account` | Multiple transfers to same stealth address |

## Notes

- Tests must run with `--test-threads=1` (shared devnet state)
- First run deploys the contract and creates a checkpoint
- Subsequent runs restore from checkpoint for faster execution
- Devnet uses miner key `d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc`
