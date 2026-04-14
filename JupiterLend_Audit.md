## Title
### [High - 1] In the function `calculate_new_token_exchange_price` there is missing reward accounting

### Finding description and impact
In the function calculate_new_token_exchange_price there is missing reward accounting This is edge case when the curr_timestamp: u128 = Clock::get()?.unix_timestamp.cast()?; is more the next_end_time . In the update_rates function it update the lending.last_update_timestamp upto the Clock::get()?.unix_timestamp.cast()?; but in the calculate_new_token_exchange_price(...) function this only account upto the next_end_time.

This create the edge case of missing rewards of the time_diff of curr_timestamp - next_end_time.Because when we go in the next update rates call the last_update_timestamp is set to the lending.last_update_timestamp

```rust
// Only process if there's actually time to account for
        if current_period_end > last_update_timestamp.cast()? {
@>            let time_diff: u128 = current_period_end - last_update_timestamp.cast::<u128>()?;
            let current_rewards_return = current_rewards_rate
                .cast::<u128>()?
                .safe_mul(time_diff)?
                .safe_div(SECONDS_PER_YEAR)?;

            total_rewards_return = total_rewards_return.safe_add(current_rewards_return)?;

            // Update the tracking timestamp
            last_update_timestamp = current_period_end.cast()?;
        }
```
here the time_diff is current_period_end - last_update_timestamp(Clock::get()?.unix_timestamp.cast() or curr_timestamp of previuos call) but there is missing between the curr_timestamp - next_end_time this is never be counted

### Attack Path
This easy number assumption to understand this but this can be scale upto the large no because we donot when the next update_rate is called

1. taking the `curr_timestamp` = 1500 sec
2. `next_end_time` == 1200 sec
3. After the first call of the function `update_rates` finish
State update of the lending struct
```rust
pub fn update_rates(
    lending: &mut Account<Lending>,
    f_token_mint: &InterfaceAccount<Mint>,
    current_rate_model: &Account<LendingRewardsRateModel>,
    liquidity_exchange_price: u64,
) -> Result<u64> {
    let token_exchange_price = calculate_new_token_exchange_price(
        liquidity_exchange_price,
        lending,
        current_rate_model,
        f_token_mint.supply,
    )?;

    lending.token_exchange_price = token_exchange_price;
    lending.liquidity_exchange_price = liquidity_exchange_price;
@>    lending.last_update_timestamp = Clock::get()?.unix_timestamp.cast()?;

    emit!(LogUpdateRates {
        token_exchange_price,
        liquidity_exchange_price,
    });

    Ok(token_exchange_price)
}
```
means the `lending.last_update_timestamp` is set to the `curr_timestamp = 1500 sec`.

Next the `update_rates` calls internal function `calculate_new_token_exchange_price`

In this call variable `last_update_timestamp` is set to the `lending.last_update_timestamp == 1500 sec`
`curr_timestamp == 2000 sec`

This is satisfy the if condition:

```rust
    if current_start_time > 0
        && current_rewards_rate > 0
        && last_update_timestamp < current_end_time
    { // SKIP
        if last_update_timestamp < current_start_time {
            last_update_timestamp = current_start_time;
        }
Here the last_update_timestamp > current_start_time so there is no update on the last_update_timestamp

        if current_period_end > last_update_timestamp.cast()? {
            let time_diff: u128 = current_period_end - last_update_timestamp.cast::<u128>()?;
            let current_rewards_return = current_rewards_rate
                .cast::<u128>()?
                .safe_mul(time_diff)?
                .safe_div(SECONDS_PER_YEAR)?;

            total_rewards_return = total_rewards_return.safe_add(current_rewards_return)?;

            // Update the tracking timestamp
            last_update_timestamp = current_period_end.cast()?;
        }
```
Now the `time_diff` is `current_period_end - last_update_timestamp == 2000 - 1500` is `500` then we update the `total_rewards_return` and `last_update_timestamp`

As you see there is no accounting of the between this time `1500(last_update_timestamp) - current_start_time(or prev next_end_time)` That the clearly the missing reward between this time.

### Recommended mitigation steps:
I think we need to use more condition when updating the `lending.last_update_timestamp` If we use current there is loss for the users between that time.



### [High - 2] Missing Ownership Validation in `StakePool` oracle Reader

### Finding description and impact
The oracle reads the stake pool data from external accounts to derive exchange rates.When processing data StakePool source, The function `read_single_pool_source(...)` internal calls the function `get_single_pool_stake(...)` that deserializes the account data with `try_from_slice_unchecked::<StakeStateV2>` without verifying that the account owned by the original Stake Program or not.

The validation check that the account key matches the configured source address it does not verify the account owner.The oracle trusts the account data without verifying that the account is actually a legitimate stake pool.

### Root Cause
The verify(verify_source) Step:
programs/oracle/src/state/struct.rs

Does not check for the ownership:

```rust
    pub fn verify_source(&self, account: &AccountInfo) -> Result<()> {
        if account.key() != self.source {
            return err!(ErrorCodes::InvalidSource);
        }

        Ok(())
    }
```
Unchecked deserialization of external account data:

```rust
pub fn read_stake_pool_source(stake_pool: &AccountInfo) -> Result<Price> {
    #[allow(deprecated)]
    let stake_pool_data = try_from_slice_unchecked::<StakePool>(&stake_pool.data.borrow())?;
    // Skip
}
```
`try_from_slice_unchecked` help in interpret the raw bytes as a StakePool struct does not enforce ownership checks
The oracle assumes the provided account contains valid stake pool data.
If the oracle `config. points` to an incorrect account, the oracle reader will deserialize arbitrary account data and treat it as a valid stake pool state.
these field can easily configurable to manipulated price

```
total_lamports
pool_token_supply
```

Leads to :
1. collateral overvaluation
2. incorrect liquidation thresholds
3. potential bad debt if inflated collateral is used for borrowing

### Recommended mitigation steps
Add the stake pool owner check in the `verify_source` function

```rust
require!(
    stake_pool.owner == spl_stake_pool::id(),
    ErrorCodes::InvalidSource
);
Describe the best method(s) to mitigate the finding.

Proof of Concept
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, BorshSerialize, BorshDeserialize)]
struct Lockup {
    pub unix_timestamp: i64,
    pub epoch: u64,
    pub custodian: Pubkey,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, BorshSerialize, BorshDeserialize)]
struct Fee {
    pub denominator: u64,
    pub numerator: u64,
}

#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
enum AccountType {
    #[default]
    Uninitialized,
    StakePool,
    ValidatorList,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
enum FutureEpoch<T> {
    None,
    One(T),
    Two(T),
}

impl<T> Default for FutureEpoch<T> {
    fn default() -> Self {
        Self::None
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
struct StakePool {
    pub account_type: AccountType,
    pub manager: Pubkey,
    pub staker: Pubkey,
    pub stake_deposit_authority: Pubkey,
    pub stake_withdraw_bump_seed: u8,
    pub validator_list: Pubkey,
    pub reserve_stake: Pubkey,
    pub pool_mint: Pubkey,
    pub manager_fee_account: Pubkey,
    pub token_program_id: Pubkey,
    pub total_lamports: u64,
    pub pool_token_supply: u64,
    pub last_update_epoch: u64,
    pub lockup: Lockup,
    pub epoch_fee: Fee,
    pub next_epoch_fee: FutureEpoch<Fee>,
    pub preferred_deposit_validator_vote_address: Option<Pubkey>,
    pub preferred_withdraw_validator_vote_address: Option<Pubkey>,
    pub stake_deposit_fee: Fee,
    pub stake_withdrawal_fee: Fee,
    pub next_stake_withdrawal_fee: FutureEpoch<Fee>,
    pub stake_referral_fee: u8,
    pub sol_deposit_authority: Option<Pubkey>,
    pub sol_deposit_fee: Fee,
    pub sol_referral_fee: u8,
    pub sol_withdraw_authority: Option<Pubkey>,
    pub sol_withdrawal_fee: Fee,
    pub next_sol_withdrawal_fee: FutureEpoch<Fee>,
    pub last_epoch_pool_token_supply: u64,
    pub last_epoch_total_lamports: u64,
}

#[test]
fn test_oracle_stake_pool_attack() {

    // malicious pool
    let fake_pool = StakePool {
        account_type: AccountType::StakePool,
        manager: Pubkey::new_unique(),
        staker: Pubkey::new_unique(),
        stake_deposit_authority: Pubkey::new_unique(),
        stake_withdraw_bump_seed: 0,
        validator_list: Pubkey::new_unique(),
        reserve_stake: Pubkey::new_unique(),
        pool_mint: Pubkey::new_unique(),
        manager_fee_account: Pubkey::new_unique(),
        token_program_id: Pubkey::new_unique(),

        // manipulated values
        total_lamports: 1_000_000_000_000_000,
        pool_token_supply: 1,

        last_update_epoch: 0,
        lockup: Lockup::default(),
        epoch_fee: Fee { numerator: 1, denominator: 1000 },
        next_epoch_fee: FutureEpoch::None,

        preferred_deposit_validator_vote_address: None,
        preferred_withdraw_validator_vote_address: None,

        stake_deposit_fee: Fee { numerator: 1, denominator: 1000 },
        stake_withdrawal_fee: Fee { numerator: 1, denominator: 1000 },
        next_stake_withdrawal_fee: FutureEpoch::None,

        stake_referral_fee: 0,

        sol_deposit_authority: None,
        sol_deposit_fee: Fee { numerator: 1, denominator: 1000 },
        sol_referral_fee: 0,

        sol_withdraw_authority: None,
        sol_withdrawal_fee: Fee { numerator: 1, denominator: 1000 },
        next_sol_withdrawal_fee: FutureEpoch::None,

        last_epoch_pool_token_supply: 0,
        last_epoch_total_lamports: 0,
    };

    let mut serialized = Vec::new();
    fake_pool.serialize(&mut serialized).unwrap();

    let fake_key = Pubkey::new_unique();
    let fake_owner = Pubkey::new_unique();
    let mut lamports = 0;

    let account_info = AccountInfo::new(
        &fake_key,
        false,
        false,
        &mut lamports,
        serialized.as_mut_slice(),
        &fake_owner,
        false,
        0,
    );

    let source = Sources {
        source: fake_key,
        source_type: SourceType::StakePool,
        multiplier: 1,
        divisor: 1,
    };

    let sources = vec![source];

    let price = get_hops_exchange_rate(
        &sources,
        &[account_info],
        Some(false),
    )
    .unwrap();
    println!("Manipulated oracle price: {}", price);

    assert!(price > 1_000_000_000_000);
}
```
