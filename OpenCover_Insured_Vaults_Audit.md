## [High] In Contract `CoveredMetavault.sol` any user/attacker can DOS the `KEEPER_ROLE` functionality `settle(...)` by frontruning and User has to pay more premium sometime hits underflow

### Summary
In Contract `CoveredMetavault.sol` any user/attacker can DOS the `KEEPER_ROLE` functionality `settle(...)` Stop from settlement of the redeemRequest by frontruning the `KEEPER_ROLE` by depositing `$.minimumRequestAssets` that is set by the owner of the Contract by the functionality `requestDeposit(...)`

```solidity
function settle(uint256 expectedPendingAssets, uint256[] calldata redeemRequestIds)
        external
        override
        whenNotPaused
        nonReentrant
        onlyRole(KEEPER_ROLE)
    {
        VaultStorage storage $ = _getVaultStorage();

        // Verify expected pending asset to match actual pending assets to prevent manipulation.
        // Setting expectedPendingAssets to 0 settles all pending.
        uint256 pendingAssetsTotal = $.totalPendingAssets;
        if (expectedPendingAssets != 0) {
@>            require(
                pendingAssetsTotal == expectedPendingAssets,
                UnexpectedPendingAssets(expectedPendingAssets, pendingAssetsTotal)
            );
        }

        // Stream premium from settled assets of the previous epoch.
        _streamPremium();

       // .. SKIP
    }
```
The require statement assume that the parameters passed expectedPendingAssets by the KEEPER_ROLE needed to equal to the $.totalPendingAssets but It can be easily changed by any user / attacker by the function requestDeposit(...) increase it and then frontrun the KEEPER_ROLE with amount $.minimumRequestAssets and $.totalPendingAssets increasing this value
```solidity
function requestDeposit(uint256 assets, address controller, address owner)
        external
        override
        whenNotPaused
        nonReentrant
        returns (uint256 requestId)
    {
        require(assets != 0, ZeroAssets());
        require(controller == owner, InvalidController(controller)); // Intentional spec deviation for better security.
        require(owner == msg.sender, InvalidOwner(owner));

        _requireMinimumRequestAssets(assets);

        // .. skip

        // Check and disallow fee-on-transfer assets (rebasing assets are also not supported).
        uint256 received = assetToken.balanceOf(address(this)) - balanceBefore;
        require(received == assets, UnsupportedAsset());

        // Roll previous epoch's pending assets to claimable.
        _syncEpoch(controller);

        VaultStorage storage $ = _getVaultStorage();
        DepositStorage storage depositStorage = $.deposits[controller];
        // New requests are pending until settled by the vault.
        depositStorage.pendingAssets += assets;
@>        $.totalPendingAssets += assets;

        emit DepositRequest(controller, owner, DEPOSIT_REQUEST_ID, msg.sender, assets);

        return DEPOSIT_REQUEST_ID;
    }
```
After it checked in the `settle(...)` function it will revert and Then user can cancel the deposit Request with the function `cancelDepositRequest`

```solidity
function cancelDepositRequest(uint256 requestId, address controller, address receiver)
        external
        override
        whenNotPaused
        nonReentrant
        returns (uint256 assets)
    {
        require(controller == msg.sender, InvalidController(controller));
        require(receiver == controller, InvalidReceiver(receiver));

        assets = _cancelDepositRequest(requestId, controller, receiver);
    }
/// @dev Synchronously cancel a pending deposit request and refund assets.
    function _cancelDepositRequest(uint256 requestId, address controller, address receiver)
        internal
        returns (uint256 assets)
    {
        // ... SKIP 

        assets = depositStorage.pendingAssets;
        require(assets != 0, NoPendingDeposit(controller));

        uint256 currentTotalPendingAssets = $.totalPendingAssets;

        depositStorage.pendingAssets = 0;
@>        $.totalPendingAssets = currentTotalPendingAssets - assets;

        emit CancelDepositRequest(controller, requestId, msg.sender);

        // Push assets back to receiver and untrack them.
@>      _pushAssets(receiver, assets);

        emit CancelDepositClaim(controller, receiver, requestId, msg.sender, assets);
    }
```

With the almost nothing gasFee attacker can DOS the `KEEPER_ROLE` functionality make it useless.

In the function `settle()` there is premium is taken from the redeemer value if this continuously get DoS after some time it go through it by in the function `_streamPremium()` there premium taken form the user based on the time leads to DOS due to underflow if user donot have that much amount to pay or User has to pay more amount they are not willing to pay for.

```solidity
function _streamPremium() internal returns (uint256 assetsStreamed, uint64 duration) {
         // ...


        if (lastPremiumTimestamp != 0 && nowTimestamp > lastPremiumTimestamp) {
@>            duration = nowTimestamp - lastPremiumTimestamp;

            // .. SKIP

      @>              uint64 fullYears = duration / SECONDS_IN_YEAR;
                    // slither-disable-next-line weak-prng - Modulo used for time arithmetic not for randomness.
       @>             uint64 remainingSeconds = duration % SECONDS_IN_YEAR;

                    // Bound loop iterations to prevent gas DoS if vault is inactive for extended periods.
                    if (fullYears >= MAX_PREMIUM_YEARS) {
                        fullYears = MAX_PREMIUM_YEARS;
                        remainingSeconds = 0;
                    }

                    // Full years: compounding for each year elapsed.
                    for (uint64 i = 0; i < fullYears; ++i) {
                        uint256 premium = assetsAfter.bps(annualRateBps);
                        if (premium == 0) break; // Early exit if premium is zero.
                        assetsAfter -= premium;
                        if (assetsAfter == 0) break; // Early exit if assets are fully consumed.
                    }

                    // Partial year: pro-rata within the remaining year (no compounding within the partial).
                    if (remainingSeconds != 0 && assetsAfter != 0) {
       @>                 uint256 premium = assetsAfter.annualBpsProRata(annualRateBps, remainingSeconds);
      @>                  if (premium != 0) assetsAfter -= premium;
                    }

        // SKIP

        emit PremiumStreamed($.currentEpoch, assetsStreamed, duration);
    }
```

### Root Cause
```solidity
 require( 
        if (expectedPendingAssets != 0) {
            require(
@>                pendingAssetsTotal == expectedPendingAssets,
                UnexpectedPendingAssets(expectedPendingAssets, pendingAssetsTotal)
            );
        }

        // Stream premium from settled assets of the previous epoch.
@>        _streamPremium();
```

### Internal Pre-conditions
None

### External Pre-conditions
User/ Attacker frontrun the `KEEPER_ROLE` by paying slightly high fee and call the `requestDeposit(...)` with the asset amount `$.minimumRequestAssets` and cancel the Deposit Request after DoS the `KEEPER_ROLE` and increase the timestamp for the premium calculation taking more premium from user or some time Hit the underflow again we go the DoS problem. This problem never solved unless the we deposit more amount in the contract

### Attack Path
1. `KEEPER_ROLE` call the function `settle(...)` function -> take the parameter `expectedPendingAssets == A and $.totalPendingAssets  == A`
2. Any User or Attacker frontrun the `KEEPER_ROLE` and call the `requestDeposit(...)` with the assets amount `$.minimumRequestAssets` and take the `minimumRequestAssets == 5 `
3. Increasing the amount of the `$.totalPendingAssets` in `line::261` now the `$.totalPendingAssets == A + 5`
then the call form the `KEEPER_ROLE` comes and `revert at the line::742`
4. Now in the function require statement check `expectedPendingAssets == A == $.totalPendingAssets == A + 5` that is not it revert
5. User call the function `cancelDepositRequest(...)` take there amount back revert by paying small `gasFee` amount more than `KEEPER_ROLE` call
6. If the call pass through the large timestamp  has been passed `_streamPremium()` can take the more premium that you donot want to pay

### Impact
DoS for the Role based function and taking high premium from the user impact with the protocol and user - High loss of the User and Stopping Role based caller from doing there functionality

### PoC
None

### Mitigation
None


## [High] In the Contract `CoveredMetavault.sol` in the function `_streamPremium()` premium is not calculated correctly direct Loss to the Protocol

## Summary
In the Contract `CoveredMetavault.sol` in the function `_streamPremium()` that used for the Collector to collect the premium through this function does not check When the premium is zero  when there is more call `settleMaturedRedemption(...)` and `settle(...)`.

```solidity
 function _streamPremium() internal returns (uint256 assetsStreamed, uint64 duration) { 
Because missing of the small check in the function when the function reaches the ,

if (remainingSeconds != 0 && assetsAfter != 0) {
 @>    uint256 premium = assetsAfter.annualBpsProRata(annualRateBps, remainingSeconds);
     if (premium != 0) assetsAfter -= premium;
}
How this calculation happen the contract:

    function bpsProRata(uint256 value, uint16 rateBps, uint64 period, uint64 duration) internal pure returns (uint256) {
        return value.mulDiv(uint256(rateBps) * duration, BPS_DENOMINATOR * period, Math.Rounding.Floor);
    } 

    function annualBpsProRata(uint256 value, uint16 rateBps, uint64 duration) internal pure returns (uint256) {
        return bpsProRata(value, rateBps, SECONDS_IN_YEAR, duration); 
    }
```

- If the assetsAfter is not above the certain value the premium eventually reaches ==> 0
- If the assetsAfter < BPS_DENOMINATOR * period / uint256(rateBps) * duration the premium eventually reaches to the zero in the Contract. There is no after for the premium if it reaches to 0 

### Root Cause
```solidity
    function _streamPremium() internal returns (uint256 assetsStreamed, uint64 duration) {
        VaultStorage storage $ = _getVaultStorage();
        uint64 lastPremiumTimestamp = $.lastPremiumTimestamp;
        uint64 nowTimestamp = uint64(block.timestamp);

        // No premium is streamed 1) before the first epoch or 2) if current timestamp's same as last stream.
        if (lastPremiumTimestamp != 0 && nowTimestamp > lastPremiumTimestamp) {
            duration = nowTimestamp - lastPremiumTimestamp;

            uint16 annualRateBps = $.premiumRateBps;
            // No premium is streamed if the annual rate is zero.
            if (annualRateBps != 0) {
                address collector = $.premiumCollector;

                uint256 assetsBefore = totalAssets();
                // No premium is streamed if there are no settled assets.
                if (assetsBefore != 0) {
                    uint256 assetsAfter = assetsBefore;

                    uint64 fullYears = duration / SECONDS_IN_YEAR;
                    // slither-disable-next-line weak-prng - Modulo used for time arithmetic not for randomness.
                    uint64 remainingSeconds = duration % SECONDS_IN_YEAR;

                    // Bound loop iterations to prevent gas DoS if vault is inactive for extended periods.
                    if (fullYears >= MAX_PREMIUM_YEARS) {
                        fullYears = MAX_PREMIUM_YEARS;
                        remainingSeconds = 0;
                    }

                    // Full years: compounding for each year elapsed.
                    for (uint64 i = 0; i < fullYears; ++i) {
                        uint256 premium = assetsAfter.bps(annualRateBps);
                        if (premium == 0) break; // Early exit if premium is zero.
                        assetsAfter -= premium;
                        if (assetsAfter == 0) break; // Early exit if assets are fully consumed.
                    }

                    // Partial year: pro-rata within the remaining year (no compounding within the partial).
                    if (remainingSeconds != 0 && assetsAfter != 0) {
 @>                       uint256 premium = assetsAfter.annualBpsProRata(annualRateBps, remainingSeconds);
                        if (premium != 0) assetsAfter -= premium;
                    }

                    assetsStreamed = assetsBefore - assetsAfter;

                    // Invariant: streamed premium cannot exceed settled assets.
   @>                assert(assetsStreamed <= assetsBefore);

                    // Push premium to collector and untrack them.
   @>                 if (assetsStreamed != 0) _pushAssets(collector, assetsStreamed);
                }
            }
        }

        $.lastPremiumTimestamp = nowTimestamp;

        emit PremiumStreamed($.currentEpoch, assetsStreamed, duration);
    }
```
The user simply leave without giving the premium to the controller.

### Internal Pre-conditions
None

### External Pre-conditions
None

### Attack Path
1. vault storage here `lastPremiumTimeStamp !=  1769082520`

2. Taking `unixTimestamp =  1769082532`

3. `duration =  1769082532 - 1769082520 == 12` -> `duration = nowTimestamp - lastPremiumTimestamp`

4. Taking the `premiumRateBps == 1_000`

5. `assetBefore == A  != 0`

6. `uint256 assetAfter == assetsBefore == A line:: 973`

7. `duration < SECONDS_IN_YEAR`

8. `uint64 fullYears = duration / SECONDS_IN_YEAR;`
9. for Calculation:
`fullYears = 13 / 31,536,000 == 0`
So there is no full year passed, leaving the loop there.
```
uint64  remainingSeconds == 12 % 31,536,000 = 12 line::977
if (remainingSeconds != 0 && assetsAfter != 0) {
        uint256 premium = assetsAfter.annualBpsProRata(annualRateBps, remainingSeconds);
        if (premium != 0) assetsAfter -= premium;
}
```
`A * (1_000 * 12 )/ (10_000 *31,536,000)`
if the `A < 26280000` there is no premium is accumulated
So the user leave without paying the `premium`

### Impact
This is direct loss the `fee or premium` in the Contract , There is direct `loss of the Protocol`

### PoC
None

### Mitigation
None
