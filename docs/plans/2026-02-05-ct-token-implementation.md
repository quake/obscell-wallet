# CT Token Implementation Design

**Date:** 2026-02-05
**Status:** Approved
**Prerequisite:** Devnet deployment of ct-info-type and ct-token-type contracts

## Overview

Add complete CT Token support to obscell-wallet:
1. **CT Scanning** - Scan CT cells belonging to wallet, decrypt amounts
2. **Balance Display** - Show token balances in Tokens tab
3. **CT Transfer** - Build transfers with Bulletproofs range proofs
4. **CT Minting** - Issuer minting functionality

## Data Structures

### CtBalance (new in `domain/cell.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtBalance {
    pub token_type_hash: [u8; 32],
    pub token_name: Option<String>,
    pub total_amount: u64,
    pub cell_count: usize,
}
```

### Store Extensions

New methods:
- `save_ct_cells(account_id, cells)` - Store CT cells
- `get_ct_cells(account_id)` - Get CT cells
- `get_ct_balances(account_id)` - Aggregate balances by token

## Scanner Extensions

### CT Cell Scanning Logic

1. **Lock matching** - Use stealth-lock to find owned cells
2. **Type identification** - Check for ct-token-type script

### New Methods

```rust
impl Scanner {
    pub fn scan_ct_cells(&self, account: &Account) -> Result<Vec<CtCell>>;
    pub fn scan_all(&self, accounts: &[Account]) -> Result<ScanAllResult>;
}

pub struct ScanAllResult {
    pub stealth_results: Vec<AccountScanResult>,
    pub ct_results: Vec<AccountCtScanResult>,
}

pub struct AccountCtScanResult {
    pub account_id: u64,
    pub cells: Vec<CtCell>,
    pub new_cells: Vec<CtCell>,
    pub balances: Vec<CtBalance>,
}
```

### CT Cell Data Extraction

From cell `output_data`:
- commitment: 32 bytes (Pedersen commitment)
- encrypted_amount: 32 bytes

Decryption:
1. Compute shared_secret from view_key + ephemeral pubkey
2. Call `ct::decrypt_amount(encrypted_amount, shared_secret)`
3. Verify commitment = amount*G + blinding*H

## Transaction Building

### CtTxBuilder (new `domain/ct_tx_builder.rs`)

```rust
pub struct CtTxBuilder {
    config: Config,
    inputs: Vec<CtCell>,
    outputs: Vec<CtTxOutput>,
    fee: u64,
}

pub struct CtTxOutput {
    pub stealth_address: Vec<u8>,  // 66 bytes
    pub amount: u64,
}

impl CtTxBuilder {
    pub fn new(config: Config) -> Self;
    pub fn add_output(self, stealth_address: Vec<u8>, amount: u64) -> Self;
    pub fn select_inputs(self, available: &[CtCell], required: u64) -> Result<Self>;
    pub fn build(self, sender: &Account) -> Result<BuiltCtTransaction>;
    pub fn sign(built: BuiltCtTransaction, account: &Account, inputs: &[CtCell]) -> Result<Transaction>;
}
```

### Build Flow

1. Select sufficient CtCells as inputs
2. Generate output commitments:
   - Generate blinding factor for each output
   - Compute `C_out = amount*G + blinding*H`
   - Encrypt amount for recipient
3. Balance blinding factors - `sum(r_in) == sum(r_out)`
4. Generate Bulletproofs - `ct::prove_range(values, blindings)`
5. Build witnesses with range proof and signatures

### CT Mint

```rust
impl CtTxBuilder {
    pub fn build_mint(
        config: Config,
        ct_info_cell: OutPoint,
        mint_amount: u64,
        recipient: Vec<u8>,
        issuer_account: &Account,
    ) -> Result<BuiltCtTransaction>;
}
```

Mint specifics:
- Requires issuer authority (owns ct-info cell)
- mint commitment = `amount * G` (blinding = 0)
- Issuer signature required

## UI Components

### TokensComponent (new `components/tokens.rs`)

```rust
pub struct TokensComponent {
    action_tx: UnboundedSender<Action>,
    account: Option<Account>,
    balances: Vec<CtBalance>,
    ct_cells: Vec<CtCell>,
    selected_index: usize,
    mode: TokensMode,
}

pub enum TokensMode {
    List,
    Transfer,
    Mint,
}
```

### UI Layout

```
┌─ Tokens ─────────────────────────────────────────────────────┐
│  Account: Account 1                                          │
│                                                              │
│  ┌─ Token Balances ────────────────────────────────────────┐ │
│  │ > TOKEN_A     1,234.00000000   (3 cells)                │ │
│  │   TOKEN_B       500.00000000   (1 cell)                 │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  [t] Transfer  [m] Mint (if issuer)  [r] Rescan              │
└──────────────────────────────────────────────────────────────┘
```

### Action Extensions

```rust
pub enum Action {
    // ... existing ...
    TransferToken,
    MintToken,
    SelectToken(usize),
}
```

## File Changes

| File | Change | Description |
|------|--------|-------------|
| `src/domain/cell.rs` | Modify | Add CtBalance |
| `src/domain/ct_tx_builder.rs` | New | CT transaction builder |
| `src/domain/mod.rs` | Modify | Export ct_tx_builder |
| `src/infra/store.rs` | Modify | Add CT cell storage |
| `src/infra/scanner.rs` | Modify | Add CT scanning |
| `src/components/tokens.rs` | New | Tokens tab component |
| `src/components/mod.rs` | Modify | Export tokens |
| `src/action.rs` | Modify | Add CT actions |
| `src/app.rs` | Modify | Integrate TokensComponent |
| `config/devnet.toml` | Modify | Fill CT contract addresses |

## Implementation Phases

### Phase 1: Data Layer
1. Add `CtBalance` to `cell.rs`
2. Add CT cell storage to `store.rs`

### Phase 2: Scanner
3. Extend Scanner for CT cell scanning
4. Implement amount decryption and commitment verification

### Phase 3: Transaction Building
5. Create `ct_tx_builder.rs`
6. Implement CT transfer
7. Implement CT mint

### Phase 4: UI
8. Create `tokens.rs` component
9. Implement List mode
10. Implement Transfer mode
11. Implement Mint mode

### Phase 5: Integration
12. Integrate in `app.rs`
13. Update `devnet.toml`

## Dependencies & Risks

**To confirm:**
- CT contract cell data format (commitment + encrypted_amount layout)
- ct-info cell structure (issuer_pubkey location)
- Contract code_hash and cell_dep after devnet deployment

**Risks:**
1. Contract format not finalized - README says "Working in progress"
2. Bulletproofs compatibility - ensure wallet crate matches contract
