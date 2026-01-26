
## [Medium] In the contract Lender.sol there is loss of fee every time when fee update
### Summary
In the contract Lender.sol there is loss of fee every time when fee update through the Factory.sol contract with the function setCustomFeeBps. After the fee get updated by the factory contract then function accrueInterest() take the old fee that initialize in the constructor of the contract. This happen single very time when fee is changed.

```solidity
constructor(LenderParams memory params) {
        // .. skip
        // here first initialize
@>        cachedGlobalFeeBps = uint16(factory.getFeeOf(address(this)));
        if(psmVault != ERC4626(address(0)))
            psmAsset.approve(address(psmVault), type(uint).max);
        // .. skip
    }
function setCustomFeeBps(address _address, uint256 _feeBps) external onlyOperator {
        require(_feeBps <= MAX_FEE_BPS, "Feebps must be less than or equal to 1000");
        customFeeBps[_address] = _feeBps;
        emit CustomFeeBpsSet(_address, _feeBps);
    }

function getFeeOf(address _lender) external view returns (uint256) {
        uint customFee = customFeeBps[_lender];
        if (customFee > 0) return customFee;
        return feeBps;
    }
```

after the initializing the cachedGlobalFeeBps  then factory called the setCustomFeeBps function update it. but in the Lender.sol the contract still using the old one fee .

Then after accrueInterest() the loss occured first time and then the fee get updated in the accrueInterest() function

```solidity
    function accrueInterest() public {
        uint timeElapsed = block.timestamp - lastAccrue;
        if(timeElapsed == 0) return;

        uint256 gasBefore = gasleft();

        try interestModel.calculateInterest(
            totalPaidDebt,
            lastBorrowRateMantissa,
            timeElapsed,
            expRate,
            getFreeDebtRatio(),
            targetFreeDebtRatioStartBps,
            targetFreeDebtRatioEndBps
        ) returns (uint currBorrowRate, uint interest) {
            uint120 localReserveFee = uint120(interest * feeBps / 10000);

            // old fee is used 
@>            uint120 globalReserveFee = uint120(interest * cachedGlobalFeeBps / 10000);
            accruedLocalReserves += localReserveFee;
            accruedGlobalReserves += globalReserveFee;
            
            // ... skip 
              
            // Updated here after the old fee used  ...
 @>           cachedGlobalFeeBps = uint16(factory.getFeeOf(address(this)));
        } catch {
            // If the call failed, check if sufficient gas was provided
            // We need to ensure the caller provided enough gas for accrueInterest to execute
            require(gasBefore >= INTEREST_CALCULATION_GAS_REQUIREMENT, "Not enough gas for accrueInterest");
        }
    }
```
But this loss occured every time you use want to change the fee using function setCustomFeeBps Because in the accrueInterest first take out the fee with old fee and then updated to the new in the Lender.sol at line::233

The Protocol can loss fee by according to sherlock severity rule:

### Section Identify high issue:
https://docs.sherlock.xyz/audits/judging/guidelines 

The protocol loses more than 1% and more than $10 of the fees. That is easily possible

### Root Cause
2025-12-monolith-stablecoin-factory-772005himanshu/Monolith/src/Lender.sol

```solidity
function accrueInterest() public {
        uint timeElapsed = block.timestamp - lastAccrue;
        if(timeElapsed == 0) return;

        uint256 gasBefore = gasleft();

        try interestModel.calculateInterest(
            // ...
        ) returns (uint currBorrowRate, uint interest) {
            uint120 localReserveFee = uint120(interest * feeBps / 10000);
@>            uint120 globalReserveFee = uint120(interest * cachedGlobalFeeBps / 10000);
            accruedLocalReserves += localReserveFee;
            accruedGlobalReserves += globalReserveFee;

            /// ..skip

@>            cachedGlobalFeeBps = uint16(factory.getFeeOf(address(this)));
        } catch {
            // If the call failed, check if sufficient gas was provided
            // We need to ensure the caller provided enough gas for accrueInterest to execute
            require(gasBefore >= INTEREST_CALCULATION_GAS_REQUIREMENT, "Not enough gas for accrueInterest");
        }
    }
```

### Internal Pre-conditions
Every time the fee get updated by factory.sol contract by function setCustomFeeBps

### External Pre-conditions
None

### Attack Path
None

### Impact
loss fee every time fee get updated

### PoC
None

### Mitigation
Update the fee before fee calculation


## [Medium] In the Contract InterestModel.sol the Formula used for the interest Calculation is Wrong as Per Docs and Code

### Summary
In the Contract InterestModel.sol the Formula used for the interest Calculation . The function calculateInterest(...) is used to calculate the interest occured on the totalPaidDebt at that point of time.

The main concern of the issue is :


Link - 2025-12-monolith-stablecoin-factory-772005himanshu/Monolith/src/InterestModel.sol

The controller observes the system’s free‑debt ratio f and compares it to a target band [f_start, f_end]

For more info check docs:
https://inversefinance-wip.mintlify.app/protocol/interest-rate-controller

### Root Cause
```solidity
In formula used in the calculateInterest(...) as verified with the docs and in the code snippet in case 1 and case 2 are different.

    function calculateInterest(
        // ... parameters
    ) external pure returns (uint currBorrowRate, uint interest) {
        // ... Skip
        
        if (_lastFreeDebtRatioBps < _targetFreeDebtRatioStartBps) {
            currBorrowRate = _lastRate * 1e18 / growthDecay;

@> 1.            interest = _totalPaidDebt * (currBorrowRate - _lastRate) / _expRate / 365 days;

        } else if (_lastFreeDebtRatioBps > _targetFreeDebtRatioEndBps) {
                // ... 
@> 2.                    interest = _totalPaidDebt * MIN_RATE * _timeElapsed / 365 days / 1e18;
                    
                } else {
                    uint timeToMin = uint(-wadLn(int(MIN_RATE * 1e18 / _lastRate))) / _expRate;
                    // Decaying integral up to min rate, then add flat rate portion
@> 3.                    interest = _totalPaidDebt * ((_lastRate - MIN_RATE) / _expRate + 
                              MIN_RATE * (_timeElapsed - timeToMin)) / 365 days / 1e18;
                }
            } else {
                interest = _totalPaidDebt * (_lastRate - currBorrowRate) / _expRate / 365 days;
            }
        } else {
            currBorrowRate = _lastRate;
            interest = _totalPaidDebt * _lastRate * _timeElapsed / 365 days / 1e18;
        }
        
        // If interest would overflow uint120 (cast in Lender), skip accrual
        // Also check if currBorrowRate would overflow uint88 (cast in Lender)
        if (interest > type(uint120).max || currBorrowRate > type(uint88).max) {
            return (_lastRate, 0);
        }
    }
```
When we calculate the interest there are two main formula are used in the function for simplicity for easy understanding:


1. first when we have the rate, _expRate and totalPaidDebt we use this
```solidity
interest =  totalPaidDebt * ( difference in Rate(Rate)) / _expRate / 365 days
```
3. Second when we have rate, timeElapsed and totalPaidDebt we use this
```solidity
interest = _totalPaidDebt * _lastRate * _timeElapsed / 365 days / 1e18;
```
3. These are used in this function and different condition:
```solidity
else if (_lastFreeDebtRatioBps > _targetFreeDebtRatioEndBps) {
            // ... skip
                } else {
                    uint timeToMin = uint(-wadLn(int(MIN_RATE * 1e18 / _lastRate))) / _expRate;
                    // Decaying integral up to min rate, then add flat rate portion
@>                    interest = _totalPaidDebt * ((_lastRate - MIN_RATE) / _expRate + 
                              MIN_RATE * (_timeElapsed - timeToMin)) / 365 days / 1e18; // @audit
                }
           // ... skip
```
Convert to simple formula as we simplify above,
```solidity
interest = _totalPaidDebt * ((difference_in_rate) / _expRate + 
                              MIN_RATE * (time_elapsed)) / 365 days / 1e18; // @audit
```
This is incorrect and according to docs and the formula we assumed upper:

The correct formula is:
```solidity
interest = _totalPaidDebt * ((_lastRate - MIN_RATE) / _expRate / 365 days + 
                              MIN_RATE * (_timeElapsed - timeToMin) / 365 days / 1e18);
```
### Internal Pre-conditions
This happen every time because formula used are incorrect here

### External Pre-conditions
None

### Attack Path
None

### Impact
The protocol have loss the interest when calculateInterest when there is condition currBorrowRate < MIN_RATE and _lastRate > MIN_RATE Decaying integral up to min rate, then add flat rate portion . Here we loss the interest in this condition every time.

### PoC
In docs of Interest Rate Controller Case 2:

https://inversefinance-wip.mintlify.app/protocol/interest-rate-controller#under-the-hood:-math-from-interestmodel-sol

```
Case 2 — Above target (decay toward a floor):
- `r_new = max(r_old * g, r_min)`
If the decay crosses the floor during dt, interest integrates piece‑wise: an exponential segment down to r_min, then a flat segment at r_min:

- `t_min = -ln(r_min / r_old) / k`

In this formula there is mistake in the code 
- `I = D * ((r_old - r_min) / k + r_min * (dt - t_min)) / (365 days)`
```

### Mitigation
use correct formula for the interest calculation in function calculateInterest
