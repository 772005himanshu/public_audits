# Move Audit Report

**Protocol Name:**  
Move - 1

**Auditor:**  
Himanshu

**Email:**  
ydvhimanshu772005@gmail.com

**Discord Username:**  
himanshu0925



## [Critical - 01] Vault Inflation Attack

## Summary
A critical vulnerability exists in the `locking` contract where the first depositor can manipulate the share price to steal all subsequent deposits. By performing a tiny initial deposit and then "donating" tokens to the underlying vault, the attacker inflates the share price. This causes subsequent deposits to round down to zero shares while the attacker retains 100% ownership of the vault's value.

---

## Description
The protocol uses a vault-based share system where users deposit underlying tokens (e.g., USDT) and receive "AET" shares in return. The number of shares minted is determined by the formula:

$$\text{Shares} = \frac{\text{Deposit Amount} \times \text{SCALE}}{\text{Share Price}}$$

The **Share Price** is determined dynamically by the total value of the underlying vault:

$$\text{Share Price} = \frac{\text{Total Vault Value} \times \text{SCALE}}{\text{Total Share Supply}}$$

An attacker can exploit the rounding behavior of integer division in the share calculation. If the share price is inflated such that for a victim's deposit $D$, the expression $(D \times \text{SCALE}) < \text{Share Price}$, then $\text{Shares}$ will equal $0$.

---

## Root Cause
The root cause is the **lack of a minimum share anchor** or **virtual shares** in the `locking::deposit_locked` function. Specifically:
1.  **Initial Minting**: There is no check to ensure a minimum amount of shares is minted during the first deposit.
2.  **Lack of Precision Guard**: The protocol does not enforce a minimum deposit size relative to the current share price, allowing the price to be inflated until precision is lost.

---

## Technical Code Trace

The vulnerability flows through the following function calls:

1.  **Entry Point**: `locking::deposit_locked` (Line 197)
    ```move
    public entry fun deposit_locked(user: &signer, amount: u64, tier: u8) {
        // ... (validation)
        let share_price = MoneyFiBridge::get_lp_price(); // Calls Bridge
        let aet_amount = (((amount as u128) * AET_SCALE) / share_price) as u64; // Vulnerable Math
        // ...
    }
    ```

2.  **Price Fetching**: `moneyfi_adapter::get_lp_price` (Line 369)
    ```move
    public fun get_lp_price(): u128 {
        let token_metadata = object::address_to_object<Metadata>(get_supported_token());
        get_share_price(token_metadata) // Calls internal price logic
    }
    ```

3.  **Underlying Value**: `moneyfi_adapter::get_share_price` (Line 343)
    ```move
    fun get_share_price(asset: Object<Metadata>): u128 {
        let total_value = (vault::estimate_total_fund_value(reserve_address, asset) as u128);
        let current_supply = *fungible_asset::supply(metadata).borrow();
        // Price = (Total_Value * SCALE) / current_supply
        let price = (remaining_amount * AET_SCALE) / current_supply;
        price
    }
    ```

---

## Proof of Concept: Mathematical & Code Execution Trace

This section maps the mathematical exploitation to the specific Move code logic responsible for the vulnerability.

### Phase 1: Attacker Pool Initialization
The attacker becomes the first depositor to establish a 1:1 ratio between assets and shares.

**Move Logic (`locking.move:215`):**
```move
let aet_amount = (((amount as u128) * AET_SCALE) / share_price) as u64;
```

**Calculation:**
*   `amount` = 1
*   `AET_SCALE` = $10^9$
*   `share_price` = $10^9$ (Initial default when supply is 0)
*   **Shares Minted**: $(1 \times 10^9) / 10^9 = \mathbf{1}$ share.

---

### Phase 2: Share Price Inflation (The "Donation")
The attacker "donates" tokens directly to the vault. This increases the numerator in the price formula while keeping the denominator (total shares) at 1.

**Move Logic (`moneyfi_adapter.move:362`):**
```move
let price = (remaining_amount * AET_SCALE) / current_supply;
```

**Calculation:**
*   `remaining_amount` (Vault Value) = $1 + 1,000,000,000$ (Attacker's 1 unit + 1,000 USDT donation)
*   `current_supply` = 1
*   **Resulting Price**: $(1,000,000,001 \times 10^9) / 1 = \mathbf{1,000,000,001,000,000,000}$

---

### Phase 3: The Victim's Precision Loss
A victim attempts a standard deposit, but the inflated price causes their minted shares to round down to zero.

**Move Logic (`locking.move:215`):**
```move
let aet_amount = (((amount as u128) * AET_SCALE) / share_price) as u64;
```

**Calculation:**
*   `amount` (Victim Deposit) = $500,000,000$ (500 USDT)
*   `AET_SCALE` = $10^9$
*   `share_price` = $1,000,000,001,000,000,000$
*   **Shares Minted**:
    $$\text{Shares} = \frac{500,000,000 \times 1,000,000,000}{1,000,000,001,000,000,000} = \mathbf{0.499...}$$
*   **Final Result**: **0 shares** (due to floor rounding in Move integer division).

---

### Phase 4: Attacker Theft Execution
The attacker, still owning 100% of the shares, withdraws the entire vault balance, which now includes the victim's "shareless" deposit.

**Move Logic (`locking.move:626`):**
```move
let amount_to_payout = ((((position.aet_amount as u128) * share_price) / AET_SCALE) as u64);
```

**Calculation:**
*   `position.aet_amount` (Attacker) = 1 share
*   `share_price` (Final) = $((1,000,000,001 + 500,000,000) \times 10^9) / 1 = 1,500,000,001,000,000,000$
*   **Payout**: $(1 \times 1,500,000,001,000,000,000) / 10^9 = \mathbf{1,500,000,001}$ units (~1,500 USDT).
*   **Attacker Profit**: **500 USDT** stolen from the victim.

---

## Remediation
1.  **Virtual Shares**: Burn the first 1,000 shares to the zero address during the first deposit. This makes inflating the share price $1,000 \times$ more expensive.
2.  **Minimum Deposit**: Enforce a `shares > 0` check (which is currently present) but also ensure `shares` meets a minimum threshold for the first depositor.
3.  **Decimal Offset**: Implement an internal scaling factor (e.g., $10^{12}$) to maintain precision even with high share prices.

---

# [High - 01]Yield Leakage in Emergency Unlock

## Summary
A significant yield leakage vulnerability exists in the emergency unlock logic where the protocol fails to recover surplus yield accrued by a user. When a user exits early, they are only entitled to their principal, but the extra shares (representing the yield) remain assigned to the locking contract in the vault instead of being sent to the treasury.

---

## Description
The protocol calculates the user's payout based on the principal amount. When the underlying shares are worth more than the principal (positive yield), the extra value should be forfeited to the protocol.

The amount of shares burned in the vault is determined by the `base_payout` (Principal):

$$\text{Shares to Burn} = \frac{\text{Principal} \times \text{SCALE}}{\text{Share Price}}$$

If the user's original `position.aet_amount` is greater than the `Shares to Burn`, the remaining shares are "orphaned" in the vault assigned to the contract's address, as the user's position record is deleted.

---

## Root Cause
The root cause is the **incomplete share recovery** during emergency exits. Specifically:
1.  **Partial Share Burn**: The bridge only burns a fraction of the user's shares required to fulfill the capped principal payout.
2.  **State Deletion before Recovery**: The user's position record (containing the total share balance) is deleted, losing the reference to the surplus yield shares.

---

## Technical Code Trace

The leakage flows through the following function calls:

1.  **Payout Calculation**: `locking::emergency_unlock` (Line 627)
    ```move
    let base_payout = if (current_value < position.principal) { current_value } else { position.principal };
    ```

2.  **Withdrawal Request**: `locking::emergency_unlock` (Line 633)
    ```move
    // Requested amount is only the principal (base_payout)
    MoneyFiBridge::withdraw(controller_signer, base_payout);
    ```

3.  **Incomplete Burning**: `moneyfi_adapter::withdraw` (Line 328)
    ```move
    // Only enough shares to cover 'amount' (principal) are burned
    let shares_to_burn = ((((amount as u128) * AET_SCALE) / share_price) as u64);
    vault::withdraw(signer::address_of(user), asset, shares_to_burn);
    ```

---

## Proof of Concept: Mathematical & Code Execution Trace

This section maps the yield leakage to the specific Move code logic.

### Phase 1: Position Maturity with Yield
Assume a user has a position with $1,000$ USDT principal and $1,000$ AET shares.
*   Share Price: $1.1$ ($1,100,000,000$)
*   Total Position Value: $1,100$ USDT.

---

### Phase 2: Emergency Unlock calculation
**Move Logic (`locking.move:626`):**
*   `base_payout` = $1,000$ USDT (Principal).

---

### Phase 3: Partial Resource Recovery
**Move Logic (`moneyfi_adapter.move:328`):**
*   $\text{Shares to Burn} = \frac{1,000 \times 10^9}{1.1 \times 10^9} = \mathbf{909.09}$ shares.

---

### Phase 4: Yield Leakage
*   User receives $1,000$ USDT.
*   Remaining Shares: $1,000 - 909 = \mathbf{91}$ shares.
*   **Leakage Value**: $91 \times 1.1 = \mathbf{100}$ USDT.
*   **Result**: $100$ USDT remains in the vault assigned to the contract, but is untracked and lost to the treasury.

---

## Remediation
1.  **Full Share Recovery**: During emergency exits, withdraw the **entire** share balance of the position.
2.  **Treasury Routing**: Send any balance remaining after paying the principal to the user to the protocol treasury address.

---

# [High - 02]Yield Leakage in Guaranteed Emergency Exit 

## Summary
A high-severity yield leakage exists in the `GuaranteedYieldLocking` contract. When a user requests an emergency unlock, the protocol fulfills the withdrawal only for the principal amount. The surplus yield (accrued shares) is never withdrawn from the vault or sent to the treasury, leading to "orphaned" assets in the protocol address across the MoneyFi vault.

---

## Description
In the Guaranteed Yield model, the protocol pays interest upfront (cashback) and expects to keep 100% of the yield generated by the vault. For an emergency exit, the user forfeits their yield. 

The protocol calculates the payout as:
$$\text{Withdrawal Amount} = \text{min}(\text{Principal}, \text{Current Value})$$

However, only this calculated amount is withdrawn from the bridge. The remaining AET shares of the user's position are not accounted for or recovered.

---

## Root Cause
The root cause is the **failure to recover surplus shares** in the `request_emergency_unlock_guaranteed` function. Specifically:
1.  **Restricted Withdrawal**: The contract only requests the `base_payout` from the bridge.
2.  **No Cleanup**: There is no mechanism to "skim" the remaining shares in the vault that belonged to the now-deleted position.

---

## Technical Code Trace

The logic fails in the following flow:

1.  **Value Calculation**: `GuaranteedYieldLocking.move:719`
    ```move
    let current_value = ((position.aet_amount as u128) * share_price / AET_SCALE) as u64;
    ```
2.  **Payout Capping**: `GuaranteedYieldLocking.move:723`
    ```move
    let base_payout = if (current_value < principal) { current_value } else { principal };
    ```
3.  **Partial Request**: `GuaranteedYieldLocking.move:741`
    ```move
    // Only the principal is requested for withdrawal
    MoneyFiBridge::request(&controller_signer, base_payout, share_price);
    ```
4.  **Position Deletion**: `GuaranteedYieldLocking.move:765`
    ```move
    user_positions.positions.swap_remove(index); // Position is gone, yield is orphaned
    ```

---

## Proof of Concept: Mathematical & Code Execution Trace

### Phase 1: High Yield Accrual
*   User Principal: $1,000$ USDT
*   Shares (`aet_amount`): $1,000$ AET
*   Vault Price: $1.2$ ($1,200,000,000$)

---

### Phase 2: Emergency Exit Logic
User requests emergency unlock.
**Move Logic (`GuaranteedYieldLocking.move:719`):**
*   `current_value` = $(1,000 \times 1.2) = 1,200$ USDT.
*   `base_payout` = **$1,000$ USDT** (Capped at principal).

---

### Phase 3: Share Burn Calculation
The bridge calculates how many shares to burn to fulfill $1,000$ USDT.
**Move Logic (`moneyfi_adapter.move:328`):**
*   $\text{Shares to Burn} = \frac{1,000 \times 10^9}{1.2 \times 10^9} = \mathbf{833.33}$ shares.

---

### Phase 4: Permanent Protocol Loss
The protocol fails to recover the remaining shares.
*   User's original shares: $1,000$ AET.
*   Shares burned for payout: $833$ AET.
*   **Orphaned Shares**: $1,000 - 833 = \mathbf{167}$ AET.
*   **Value of Leakage**: $167 \times 1.2 = \mathbf{200}$ USDT.
*   **Consequence**: $200$ USDT of profit is trapped in the vault and cannot be accessed by the treasury.

---

## Remediation
1.  **Consolidated Withdrawal**: Withdraw the **entire** value of `position.aet_amount` from the bridge during emergency unlock.
2.  **Treasury Split**: Send the principal (minus clawback) to the user and the **entire remainder** (yield + clawback) to the protocol treasury.

---


# [High - 03] Precision Loss Dust Stealing 

## Summary
A high-severity vulnerability allows an attacker to "steal" small amounts of assets from the vault by exploiting rounding gaps. By repeatedly requesting micro-withdrawals that result in zero shares burned, an attacker can drain the vault's liquidity while keeping their share balance intact.

---

## Description
The number of shares burned during a withdrawal is rounded down. If the withdrawal amount is small enough that its share value is less than 1, the burn count becomes 0.

$$\text{Shares to Burn} = \text{floor}\left(\frac{\text{Amount} \times \text{SCALE}}{\text{Share Price}}\right)$$

If $\text{Amount} \times \text{SCALE} < \text{Share Price}$, then $\text{Shares to Burn} = 0$.

---

## Root Cause
The root cause is the **lack of a minimum burn enforcement**. Specifically:
1.  **Floor Rounding**: Integer division always rounds down, favoring the withdrawer over the vault.
2.  **No Minimum Withdrawal**: The protocol allows withdrawals of any size, even those that don't represent a full share.

---

## Technical Code Trace

1.  **Withdrawal Trigger**: `locking::withdraw` (Line 600+)
2.  **Burn Calculation**: `moneyfi_adapter::withdraw` (Line 328)
    ```move
    let shares_to_burn = ((((amount as u128) * AET_SCALE) / share_price) as u64);
    // If (amount * SCALE) < share_price, this result is 0
    ```
3.  **State Update**: `vault::withdraw` (Line 332)
    ```move
    vault::withdraw(user_address, asset, 0); // No shared removed
    ```

---

## Proof of Concept: Mathematical & Code Execution Trace

### Phase 1: High Share Price Environment
Assume the vault has performed well or has been inflated.
*   Share Price: $2.0$ ($2,000,000,000$)
*   `AET_SCALE`: $10^9$

---

### Phase 2: Micro-Withdrawal
The attacker requests a withdrawal of 1 unit (1 micro-USDT).
**Move Logic (`moneyfi_adapter.move:328`):**
```move
let shares_to_burn = (1 * 1,000,000,000) / 2,000,000,000;
// shares_to_burn = 0.5 -> ROUNDS TO 0
```

---

### Phase 3: Asset Drain
The attacker receives the tokens but loses no shares.
*   User receives: $1$ unit
*   User shares burned: $0$

---

### Phase 4: Velocity Attack
The attacker repeats this 1 million times in a loop.
*   Result: **1,000,000 units stolen** (1 USDT).
*   Cost: **0 shares**.
*   **Total Loss**: Unlimited, restricted only by transaction gas costs and block limits.

---

## Remediation
1.  **Minimum Burn**: Require `assert!(shares_to_burn > 0)` or enforce a minimum withdrawal amount.
2.  **Ceil Rounding**: Use "Round Up" logic for burning shares: `shares = (amount * SCALE + share_price - 1) / share_price`.

---

# [Medium - 01] Broken Yield Reconstruction in Event Logs 

## Summary
A medium-severity logic error in the `withdraw_emergency_guaranteed` function makes it impossible to correctly log forfeited yield. Due to a circular calculation that uses the capped withdrawal amount to "recalculate" the original value, the `yield_forfeited` field in the event will always be zero when yield actually occurred.

---

## Description
Events are critical for off-chain accounting and protocol transparency. The `GuaranteedEmergencyUnlock` event includes a `yield_forfeited` field to track protocol profit. However, the logic used to reconstruct this value is mathematically flawed because it derives the "original share price" from the "capped withdrawal amount."

---

## Root Cause
The root cause is **circular dependency** in the event reconstruction logic. Specifically:
1.  **Loss of Original Price**: The contract does not store the share price used during the `request` phase.
2.  **Invalid Assumption**: Line 824 assumes that the `withdrawal_amount` (which is capped) can be used to recover the `share_price` of the total position.

---

## Technical Code Trace

1.  **Circular Price Recovery**: `GuaranteedYieldLocking.move:824`
    ```move
    let share_price_at_request = ((pending.withdrawal_amount as u128) * AET_SCALE) / (pending.position.aet_amount as u128);
    ```
2.  **Identity Function Logic**: `GuaranteedYieldLocking.move:825`
    ```move
    let original_current_value = ((pending.position.aet_amount as u128) * share_price_at_request / AET_SCALE) as u64;
    ```
3.  **Result**: `original_current_value` will mathematically ALWAYS equal `pending.withdrawal_amount`.

---

## Proof of Concept: Mathematical & Code Execution Trace

### Phase 1: Request with Yield
*   `aet_amount` = $1,000$
*   Actual Price = $1.2$
*   `withdrawal_amount` (Capped) = $1,000$ (Principal)

---

### Phase 2: Event Logic Execution
The contract tries to find the original value.
**Move Logic (`GuaranteedYieldLocking.move:824`):**
*   `share_price_at_request` = $\frac{1,000 \times 10^9}{1,000} = \mathbf{1.0}$ (Incorrect, was matched to principal, not vault).

---

### Phase 3: False Yield Calculation
**Move Logic (`GuaranteedYieldLocking.move:825`):**
*   `original_current_value` = $(1,000 \times 1.0) / 1 = \mathbf{1,000}$ USDT.
**Resulting Event Field:**
*   `yield_forfeited` = $1,000 - 1,000 = \mathbf{0}$.

**Impact**: Even though 200 USDT was forfeited to the contract, the protocol reports "0 yield forfeited", breaking all off-chain analytical tools and treasury audits.

---

## Remediation
1.  **State Storage**: Add a `share_price` field to the `PendingUnlock` struct to preserve the actual price at the time of the request.
2.  **Simplified Yield Calc**: Calculate and store the `yield_forfeited` directly during the `request` phase and pass it into the `PendingUnlock` struct.

---


# [Medium - 02] Division by Zero DoS in Position Logic 

## Summary
A medium-severity denial-of-service vulnerability exists where internal accounting functions can abort due to division by zero. This occurs when a user has a position with zero shares (a state possible via CRIT-01), making it impossible to perform further actions or view position details.

---

## Description
Several functions calculate weighted averages or ratios using `position.aet_amount` or `total_shares` as the divisor. If these values are zero, Move will abort the transaction.

$$\text{Weighted Price} = \frac{\text{Total Weight}}{\text{Total Shares}}$$

If `Total Shares = 0`, the operation fails.

---

## Root Cause
The root cause is **missing non-zero validation** on divisors. Specifically:
1.  **Assumed Supply**: The code assumes that if a position exists, it must have a non-zero share balance.

---

## Technical Code Trace

1.  **Weighted Price**: `locking.move:313`
    ```move
    let weighted_remaining = ((old_weight + new_weight) / total_principal) as u64;
    ```
2.  **View Total Value**: `locking.move:571`
    ```move
    ((total_aet as u128) * share_price / AET_SCALE) as u64
    ```

---

## Proof of Concept: Mathematical & Code Execution Trace

### Phase 1: Create Shareless Position
Attacker exploits CRIT-01 to make a user deposit result in 0 shares.
*   User has a `LockPosition` record.
*   `position.aet_amount = 0`.

---

### Phase 2: Action Trigger
The user (or an updater) tries to extend the lock or add to the position.
**Move Logic (`locking.move:313`):**
```move
let total_principal = old_principal + new_deposit;
// ... logic ...
weighted_remaining = (weight) / total_principal;
```

---

### Phase 3: Transaction Abort
If the `total_principal` or related share balances are handled incorrectly in aggregated view functions:
*   **Abort Error**: `ARITHMETIC_ERROR` (Division by Zero).
*   **Impact**: User interface shows "Error", and the user cannot interact with the position to recover funds or withdraw what's left.

---

## Remediation
1.  **Non-Zero Sanity Checks**: Add `assert!(shares > 0)` in all calculation helpers.
2.  **Graceful Degeneracy**: Allow 0-supply states to return default values instead of aborting.

---

# [Medium - 03] Cashback Vault Velocity Drain

## Summary
A medium-severity economic vulnerability exists in the cashback pool where funds can be drained rapidly. The protocol lacks "Velocity Limits" (caps on how much can be claimed per day/hour), allowing a surge of users to empty the treasury in a single burst.

---

## Description
Cashback is paid out from a central treasury resource. The current logic performs a simple transfer without assessing the treasury's health or rate of outflow.

---

## Root Cause
The root cause is the **lack of rate-limiting controls**. Specifically:
1.  **Infinite liquidity assumption**: The protocol trusts that the treasury will always be replenished faster than it is claimed.

---

## Technical Code Trace

1.  **Cashback Payout**: `GuaranteedYieldLocking.move:807`
    ```move
    if (pending.to_user > 0) {
        primary_fungible_store::transfer(admin, asset, user, amount);
    }
    ```
2.  **Missing Check**: There is no logic to check if `amount` exceeds a certain percentage of the pool per hour.

---

## Proof of Concept: Mathematical & Code Execution Trace

### Phase 1: Attacker Group Coordination
A Sybil attacker creates 1,000 accounts.

---

### Phase 2: Simultaneous Claims
All accounts deposit large amounts and immediately claim cashback.
*   Treasury Balance: $1,000,000$ USDT.
*   Total Claims in 1 block: $1,000,000$ USDT.

---

### Phase 3: Liquidity Exhaustion
The treasury is exhausted instantly.
*   **Impact**: Legitimate users who lock funds later receive 0 cashback because the vault is empty.

---

## Remediation
1.  **Daily Cap**: Implement a global daily limit on cashback distributions.
2.  **Circuit Breaker**: Auto-disable cashback if the treasury balance falls below a certain threshold.

---

# [Medium - 04] Decimal Inconsistency in Risk Thresholds 

## Summary
A medium-severity configuration risk exists where the protocol uses inconsistent decimal scales (6 vs 8) for critical safety thresholds. This leads to the `CashbackVaultLow` alert system being $100x$ too sensitive or $100x$ too delayed, potentially leading to a protocol halt or missed funding windows.

---

## Description
The protocol hardcodes numerical thresholds for risk monitoring. However, across different modules, these values assume different decimal precisions for the same underlying asset (USDT/USDC).

*   `CASHBACK_LOW_THRESHOLD`: $100\_00000000$ (Assumes 8 decimals)
*   `DEFAULT_MIN_DEPOSIT`: $1\_000000$ (Assumes 6 decimals)

---

## Root Cause
The root cause is the **hardcoding of magic numbers** without regard for the dynamic nature of fungible asset decimals on the Aptos chain.
1.  **Implicit Scale Assumptions**: Different modules (Bridge vs. G.Y.L.) use different constants for the same asset type.

---

## Technical Code Trace

1.  **Threshold Definition**: `GuaranteedYieldLocking.move:47`
    ```move
    const CASHBACK_LOW_THRESHOLD: u64 = 100_00000000;
    ```
2.  **Minimum Deposit**: `GuaranteedYieldLocking.move:51`
    ```move
    const DEFAULT_MIN_DEPOSIT: u64 = 1_000000;
    ```

---

## Proof of Concept: Mathematical Trace

### Scenario: Stablecoin with 6 Decimals (Standard USDC)
1.  **Min Deposit Check**: $1,000,000$ units = $1$ USDC. (Correct)
2.  **Alert Check**: $100,000,000,00$ units = $10,000$ USDC. (Incorrect)
**Impact**: The `CashbackVaultLow` event will fire whenever the vault balance drops below $10,000$ USDC. If the admin expects the trigger at $100$ USDC ($100,000,000$ units), they will receive false alarms prematurely, potentially causing unnecessary protocol interventions.

### Scenario: Stablecoin with 8 Decimals
1.  **Min Deposit Check**: $1,000,000$ units = $0.01$ USDC. (Incorrect)
**Impact**: The protocol allows deposits of effectively zero value, leading to state bloat and "dust" position spam.

---

## Remediation
1.  **Dynamic Metadata**: Query the decimals from the asset metadata object during initialization.
2.  **Unified Constant**: Use a single precision constant (e.g., `USD_DECIMAL_SCALE`) for all stablecoin-related thresholds.
