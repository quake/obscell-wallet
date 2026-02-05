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
│   ├── ckb-auth       # Compiled ckb-auth contract
│   ├── ct-info-type   # Compiled ct-info-type contract
│   ├── ct-token-type  # Compiled ct-token-type contract
│   ├── ckb            # CKB binary (gitignored, created by setup.sh)
│   └── devnet/        # Devnet config and data (gitignored, created by setup.sh)
└── integration/
    ├── mod.rs                # Test harness, shared TestEnv
    ├── devnet.rs             # DevNet manager (start/stop/generate blocks)
    ├── contract_deployer.rs  # Deploy all contracts with TYPE_ID
    ├── faucet.rs             # Transfer CKB to test addresses
    ├── e2e_basic_flow.rs     # Basic stealth cell test cases
    ├── e2e_ct_flow.rs        # CT (confidential token) test cases
    └── e2e_user_flow.rs      # User workflow test cases
```

## Test Cases

### Basic Flow Tests (e2e_basic_flow.rs)

| Test | Description |
|------|-------------|
| `test_env_setup` | Verify devnet starts and contract deploys |
| `test_faucet_transfer` | Transfer CKB to a regular address |
| `test_stealth_cell_creation` | Create a stealth cell with encrypted recipient |
| `test_stealth_cell_scanning` | Scan chain and decrypt owned cells |
| `test_multiple_stealth_cells_same_account` | Multiple transfers to same stealth address |

### CT Flow Tests (e2e_ct_flow.rs)

| Test | Description |
|------|-------------|
| `test_ct_contracts_deployed` | Verify CT contracts are deployed (requires devnet) |
| `test_ct_env_helpers` | Test CT helper methods on TestEnv (requires devnet) |
| `test_pedersen_commitment_properties` | Verify Pedersen commitment properties |
| `test_commitment_homomorphism` | Verify commitment additive homomorphism |
| `test_range_proof_single_value` | Range proof for single value |
| `test_range_proof_multiple_values` | Range proof for multiple values |
| `test_range_proof_edge_cases` | Range proof for zero and max values |
| `test_range_proof_invalid_verification` | Verify invalid proofs are rejected |
| `test_amount_encryption_roundtrip` | Amount encryption/decryption roundtrip |
| `test_amount_decryption_wrong_secret` | Verify wrong secret fails decryption |
| `test_amount_encryption_various_values` | Encryption with various values |
| `test_ct_info_data_serialization` | CT-Info data serialization |
| `test_ct_info_minting_logic` | CT-Info minting supply logic |
| `test_ct_info_args_serialization` | CT-Info args serialization |
| `test_commitment_balance_for_transfer` | Verify commitment balance for transfer |
| `test_mint_commitment_zero_blinding` | Verify mint commitment uses zero blinding |

## Notes

- Tests must run with `--test-threads=1` (shared devnet state)
- First run deploys the contract and creates a checkpoint
- Subsequent runs restore from checkpoint for faster execution
- Devnet uses miner key `d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc`
