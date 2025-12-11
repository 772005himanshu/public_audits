
### Finding 1
In the EVM chain the Contract `HTLC.sol` and `ArbHTLC.sol` there is no access control `initialise` function

#### Finding description and impact
In the EVM chain the Contract `HTLC.sol` and `ArbHTLC.sol` there is no access control initialise function . Attacker can front run this contract take over the contract by defining their own token and token used in the Contract

Attacker submit this before the owner and and passes there token contract making unusable to other user and entity in the Contract that are present.

This no called because of isInitialized global variable , Protocol team have redeploy and take the migration of user to this new contract and this cost gas loss for the Protocol.

```solidity
    function initialise(address _token) public {
        require(isInitialized == 0, ArbHTLC__HTLCAlreadyInitialized());
        token = IERC20(_token);
        unchecked {
            isInitialized++;
        }
    }
```
#### Recommended mitigation steps
Add this functionality called from the Contract or Add the access control to be called by the owner only using Ownable Contract by openzeppelin

#### Proof of Concept
Attacker make there own ERC20 contract and make frontrun and initialize is as the token in the HTLC contract on EVM

```solidity
contract HTLCTest is Test, EIP712 {
    using ECDSA for bytes32;

    // ...

    SimpleMockERC20  attackerToken;


    MockSmartAccount mock;
    // ...

    function setUp() public {
        // ... 

        attackerToken = new SimpleMockERC20();
        (alice, keyAlice) = makeAddrAndKey("alice");
        (bob, keyBob) = makeAddrAndKey("bob");
        (david, keyDavid) = makeAddrAndKey("david");
        (attacker, keyAttacker) = makeAddrAndKey("attacker");
        // ...
    }

    function test_AttckertokeninitialisedByFrontRunning() public {
        vm.prank(attacker);
        htlc.initialise(address(attackerToken));

        vm.expectRevert(HTLC.HTLC__HTLCAlreadyInitialized.selector);
        htlc.initialise(address(token));
    }

}
```

#### Links to affected code
>> HTLC.sol#L106
>> ArbHTLC.sol#L112


### FInding 2
In the function `instant_refund` function there is no timelock check means we have to check signature if we call `instant_refund` before the `timelock`

#### Summary
In the HTLC contract the function instant_redeem is called before or after the timelock if the function called before the timelock then we have to check for the signature in the function is discussed with the sponsor in QA

https://code4rena.com/audits/2025-11-garden/inbox/38
```
Ques 4 In any there is no check in instant_refund function this only called before the timelock as written in doc

Ans

If someone wants to call instant_refund after timelock expiry, they can. Since it allows refunds before timelock expiry, we check for a signature. However, after timelock expiry, anyone can just call refund. We allow instant_refund after timelock expiry since it's just refund but with extra steps. No such requirement that it can only be called before timelock expiry.
there is always the need of the signature verification if called before the timelock by anyone(redeemer or any user)
```

Procol docs

```
https://docs.garden.finance/contracts/starknet#instant-refund
```

The instant refund function provides a way for the `redeemer` to consent to `canceling the swap before the timelock expires using SNIP-12 signatures`.
```solidity
/**
     * @notice  Redeemers can let initiator refund the locked assets before expiry block number
     * @dev     Signers cannot refund the same order multiple times.
     *          Funds will be SafeTransferred to the initiator.
     *
     * @param orderID       orderID of the htlc order
     * @param signature     EIP712 signature provided by redeemer for instant refund.
     */
    function instantRefund(bytes32 orderID, bytes calldata signature) external {
        Order storage order = orders[orderID];
        require(order.fulfilledAt == 0, HTLC__OrderFulfilled());

        address orderRedeemer = order.redeemer;
@>        if (msg.sender != orderRedeemer) {
            bytes32 instantRefundHash = instantRefundDigest(orderID);
            require(
                SignatureChecker.isValidSignatureNow(orderRedeemer, instantRefundHash, signature),
                HTLC__InvalidRedeemerSignature()
            );
        }

        order.fulfilledAt = block.number;

        emit Refunded(orderID);

        token.safeTransfer(order.initiator, order.amount);
    }

```


There is no loss but according to docs and QA this is not be done

#### Recommendation
Always check the signature if the (called before the timelock) caller is redeemer or not 


#### Proof of Concept

https://code4rena.com/audits/2025-11-garden/inbox/38

```
Ques 4 In any there is no check in instant_refund function this only called before the timelock as written in doc

Ans

If someone wants to call instant_refund after timelock expiry, they can. Since it allows refunds before timelock expiry, we check for a signature. However, after timelock expiry, anyone can just call refund. We allow instant_refund after timelock expiry since it's just refund but with extra steps. No such requirement that it can only be called before timelock expiry.
Links to affected code
```
>> HTLC.sol#L332

### Finding 3
In EVM Chain `HTLC` contract there is Denial of Service Attack via `frontrunning` the deterministic `orderID`

#### Finding description and impact
The orderID is calculated as sha256(abi.encode(block.chainid, secretHash_, initiator_, redeemer_, timelock_, amount_, address(this))) All input parameter are present in the pending tx , so they are visible to the attacker in the mempool and the EVM mempool is public to all.

Then attacker call the initiate_on_behalf by the passing all same parameter as the order is created with same amount as the order present in the memepool. if the attacker tx confirm first. Causing the user tx to revert later with the HTLC__DuplicateOrder().

```solidity
    function _initiate(
        address funder_,
        address initiator_,
        address redeemer_,
        uint256 timelock_,
        uint256 amount_,
        bytes32 secretHash_
    ) internal returns (bytes32 orderID) {
@>        orderID =
            sha256(abi.encode(block.chainid, secretHash_, initiator_, redeemer_, timelock_, amount_, address(this)));

        require(orders[orderID].timelock == 0, HTLC__DuplicateOrder());

        orders[orderID] = Order({
            initiator: initiator_,
            redeemer: redeemer_,
            initiatedAt: block.number,
            timelock: timelock_,
            amount: amount_,
            fulfilledAt: 0
        });

        emit Initiated(orderID, secretHash_, amount_);

        token.safeTransferFrom(funder_, address(this), amount_);
    }
```

#### Impact
During high-volatility windows or trading opportunities, the attacker can deny a competitor access to an arbitrage opportunity at negligible cost. A potential exploit scenario is as follows:
- Spot a lucrative cross-chain price gap; watch the mempool for victims opening HTLCs to execute the arb.
- Copy their four pre-image fields and front-run with initiate_on_behalf dust order, blocking their swap via HTLC__DuplicateOrder().

#### Recommended mitigation steps
Add the unique number(continously increase after every order create) or salt to the orderID preimage

#### Proof of Concept
Add these to test the function will revert with the [FAIL: HTLC__DuplicateOrder()]

```solidity
contract HTLCTest is Test, EIP712 {
    using ECDSA for bytes32;

    // ... skip

    uint256 keyDavid;
    address attacker;
    uint256 keyAttacker;
    // ...
       


function setUp() public {
        token = new SimpleMockERC20();
        mock = new MockSmartAccount();
        htlc = new HTLC();
        // ...
        (attacker, keyAttacker) = makeAddrAndKey("attacker");
        // ...

}

//// ... skip

function test_FrontRunDuplicateOrderBlocksInitiator() public {
        // Attacker funds identical order before the initiator's transaction is mined
        uint256 frontRunBlock = block.number;
        token.transfer(attacker, amount);
        vm.startPrank(attacker);
        token.approve(address(htlc), amount);
        htlc.initiateOnBehalf(alice, bob, timelock, amount, secretHash);
        vm.stopPrank();

        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));

        // The legitimate initiator's transaction now reverts as a duplicate
        vm.startPrank(alice);
        htlc.initiate(bob, timelock, amount, secretHash);
        vm.stopPrank();

        // Order is already locked by the attacker's front-run call
        (address orderInitiator, address orderRedeemer, uint256 initiatedAt, uint256 orderTimelock, uint256 lockedAmount, uint256 fulfilledAt) =
            htlc.orders(orderID);
        assertEq(orderInitiator, alice);
        assertEq(orderRedeemer, bob);
        assertEq(orderTimelock, timelock);
        assertEq(initiatedAt, frontRunBlock);
        assertEq(lockedAmount, amount);
        assertEq(fulfilledAt, 0);
    }
Failing tests:
Encountered 1 failing test in test/HTLC.t.sol:HTLCTest
[FAIL: HTLC__DuplicateOrder()] test_FrontRunDuplicateOrderBlocksInitiator() (gas: 230679)

Encountered a total of 1 failing tests, 123 tests succeeded
```
#### Links to affected code
>> HTLC.sol#L305


### Finding 4
Missing Check in the All Contract of `HTLC` , On redeem function check for the `Order or Atomic Swap` is Still redeemed after the `Timelock` has passed

#### Finding description and impact
In the Contract of the HTLC on every chain there is missing check that after the timelock has passed , the redeemer / or anyone (if know the secret hash) can still call the redeem function and redeem to the redeemer account.

There is no loss of token but after the timelock they can redeem effect the basic invariant of the Protocol that it is designed for HTLC with the timelock.

After the timelock has passed there initiator or (any one has to call the refund or instant_refund) function to give the fund back to the initiator account in the Contract and This is stopping from happening.

#### Recommended mitigation steps
Add a check that the redeem function only work when called before the timelock has passed. Add this check on every chain like , show on move chain.

```javascript
assert!(
        order.initiated_at + order.timelock > clock::timestamp_ms(clock) as u256,
        EOrderExpiredCallTheRefund,
    );
```

#### Proof of Concept
As per discussed with the Sponsor of the Contest:

https://code4rena.com/audits/2025-11-garden/inbox/38
```
In Ques 2 this issue is discussed

Ans

After timelock has expired, the order is not passed and is refunded.

```

#### Links to affected code
>> main.move#L173
>> htlc.cairo#L276
>> lib.rs#L83
>> lib.rs#L67
HTLC.sol#L234
