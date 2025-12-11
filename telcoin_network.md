### Summary
In Contract `ConsensusRegistry.sol` the break in Core Functionality of delegateStake function. The function is not able to delegate the Stake to the Delegator Because of wrong Implementation of mapping delagations , in the Struct Delegation

### Finding Description
In delegatorStake function is used to set delegator to Stake , but the functionality break in setting up the delegations mapping

https://github.com/Telcoin-Association/tn-contracts/blob/37c3ea99551ff7affa79b5591379ea66abe0041a/src/consensus/ConsensusRegistry.sol#L227

https://github.com/Telcoin-Association/tn-contracts/blob/37c3ea99551ff7affa79b5591379ea66abe0041a/src/consensus/ConsensusRegistry.sol#L260

```
mapping(address => Delegation) internal delegations;
Delegation Struct Looks like that

struct Delegation {
        bytes32 blsPubkeyHash;
@>        address validatorAddress;
@>       address delegator;
        uint8 validatorVersion;
        uint64 nonce;
    }
In setting the delegations mapping there is confusion between the validatorAddress and delegator address , Due to this Delegator never able to call claimStakeRewards and unstake functionality of the Contract , always revert with NotRecipient(recipient).

The Functionality breaks in the Contract

/// @inheritdoc StakeManager
    function delegateStake(
        bytes calldata blsPubkey,
        address validatorAddress,
        bytes calldata validatorSig
    )
        external
        payable
        override
        whenNotPaused
    {
        // ...
            bytes32 digest = _hashTypedData(structHash);
            if (!SignatureCheckerLib.isValidSignatureNowCalldata(validatorAddress, digest, validatorSig)) {
                revert NotValidator(validatorAddress);
            }
        }

@>        delegations[validatorAddress] =
            Delegation(blsPubkeyHash, msg.sender, validatorAddress, validatorVersion, nonce + 1);  // Here the Problem in Setting up delegations
        _recordStaked(blsPubkey, validatorAddress, true, validatorVersion, stakeAmt);
    }
```

It also lead to DOS/DDos of these functionality if the called many time by the delegator.

### Impact Explanation
Breaks Core Functionality: The delegateStake is core functionality for delegator to set , there is break in setting the delegator ,lead to locks funds until the validatorAddress call these functionalities
Temporary Disruption or DoS: DoS/DDos Problem Will also come when these function called many time by the Delegators

### Likelihood Explanation
This can be called by any user (Who use the DelegateStake Functionality ) to stake ( Issues that can be triggered by any user, without significant constraints)

### Proof of Concept
First We call with delegator and Vulnerable Code

Add this function to the `ConsensusRegistryTest.t.sol` Contract

```solidity
function test_delegateStakeAndUnstake() public {
        vm.prank(crOwner);
        uint256 validator5PrivateKey = 5;
        validator5 = vm.addr(validator5PrivateKey);  // users validator address we are using 
        address delegator = _addressFromSeed(42);
        vm.deal(delegator, stakeAmount_);

        consensusRegistry.mint(validator5);

        // validator signs delegation
        bytes32 structHash = consensusRegistry.delegationDigest(validator5BlsPubkey, validator5, delegator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator5PrivateKey, structHash);
        bytes memory validatorSig = abi.encodePacked(r, s, v);

        // Check event emission
        bool isDelegate = true;
        vm.expectEmit(true, true, true, true);
        emit ValidatorStaked(
            ValidatorInfo(
                validator5BlsPubkey,
                validator5,
                PENDING_EPOCH,
                uint32(0),
                ValidatorStatus.Staked,
                false,
                isDelegate,
                uint8(0)
            )
        );
        vm.prank(delegator);
        consensusRegistry.delegateStake{ value: stakeAmount_ }(validator5BlsPubkey, validator5, validatorSig);

        // Check validator information
        ValidatorInfo[] memory validators = consensusRegistry.getValidators(ValidatorStatus.Staked);
        assertEq(validators.length, 1);
        assertEq(validators[0].validatorAddress, validator5);
        assertEq(validators[0].blsPubkey, validator5BlsPubkey);
        assertEq(validators[0].activationEpoch, PENDING_EPOCH);
        assertEq(validators[0].exitEpoch, uint32(0));
        assertEq(validators[0].isRetired, false);
        assertEq(validators[0].isDelegated, true);  // is delagted true // Bu delegated to the validator address
        assertEq(validators[0].stakeVersion, uint8(0));
        assertEq(uint8(validators[0].currentStatus), uint8(ValidatorStatus.Staked));

        // claimStakeRewards functionality add here 

        vm.prank(delegator);
        consensusRegistry.claimStakeRewards(validator5);

        // unstake functionality add here 
        vm.prank(delegator);
        consensusRegistry.unstake(validator5);
    }
```
This Will revert at NotRecipient.

OUTPUT:
Screenshot 2025-06-17 at 12.05.45 PM.png

```
forge test --mt test_delegateStakeAndUnstake -vvvvv
[⠊] Compiling...
No files changed, compilation skipped

Ran 1 test for test/consensus/ConsensusRegistryTest.t.sol:ConsensusRegistryTest
[FAIL: NotRecipient(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)] test_delegateStakeAndUnstake() (gas: 490067)
Traces:
  [7062297] ConsensusRegistryTest::setUp()
    ├─ [6911607] → new ConsensusRegistry@0x2e234DAe75C793f67A35089C9d99245E1C58470b
    │   ├─ emit OwnershipTransferred(previousOwner: 0x0000000000000000000000000000000000000000, newOwner: 0x0000000000000000000000000000000000C0FFEE)
    │   ├─ [117228] → new Issuance@0xffD4505B3452Dc22f8473616d50503bA9E1710Ac
    │   │   └─ ← [Return] 584 bytes of code
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x717e6a320cf44b4aFAc2b0732D9fcBe2B7fa0Cf6, tokenId: 647935101931755020891358879668158668242001988854 [6.479e47])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6, validatorAddress: 0x717e6a320cf44b4aFAc2b0732D9fcBe2B7fa0Cf6, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0xC41B3BA8828b3321CA811111fA75Cd3Aa3BB5ACe, tokenId: 1119569508167662895942198234849060215188302289614 [1.119e48])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace, validatorAddress: 0xC41B3BA8828b3321CA811111fA75Cd3Aa3BB5ACe, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x2F12DB2869C3395A3b0502d05E2516446f71F85B, tokenId: 268743070984790341878037720322852862765112096859 [2.687e47])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85bc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85bc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b, validatorAddress: 0x2F12DB2869C3395A3b0502d05E2516446f71F85B, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x4Fd709f28e8600b4aa8c65c6B64bFe7fE36bd19b, tokenId: 455805797661119744593529678857535516768150999451 [4.558e47])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0x8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b, validatorAddress: 0x4Fd709f28e8600b4aa8c65c6B64bFe7fE36bd19b, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   └─ ← [Return] 23680 bytes of code
    ├─ [340] ConsensusRegistry::SYSTEM_ADDRESS() [staticcall]
    │   └─ ← [Return] 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE
    ├─ [0] VM::deal(0x2D0C79bB0604C104A5fB6F4eB0703F3154BB3db0, 1000000000000000000000000 [1e24])
    │   └─ ← [Return]
    ├─ [0] VM::deal(0x0000000000000000000000000000000000C0FFEE, 714285714285714285714285 [7.142e23])
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x0000000000000000000000000000000000C0FFEE)
    │   └─ ← [Return]
    ├─ [7493] ConsensusRegistry::allocateIssuance{value: 714285714285714285714285}()
    │   ├─ [95] Issuance::receive{value: 714285714285714285714285}()
    │   │   └─ ← [Stop]
    │   └─ ← [Stop]
    └─ ← [Stop]

  [490067] ConsensusRegistryTest::test_delegateStakeAndUnstake()
    ├─ [0] VM::prank(0x0000000000000000000000000000000000C0FFEE)
    │   └─ ← [Return]
    ├─ [0] VM::addr(<pk>) [staticcall]
    │   └─ ← [Return] 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276
    ├─ [0] VM::deal(0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2, 1000000000000000000000000 [1e24])
    │   └─ ← [Return]
    ├─ [126789] ConsensusRegistry::mint(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, tokenId: 1288347612158191397270705234830805381732297126518 [1.288e48])
    │   ├─  storage changes:
    │   │   @ 8: 4 → 5
    │   │   @ 0xb6ab34d48b92a46d2d66f69803287936d00badd23b67adb2ee9e6f43d652ceb0: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0x057298a0d8443d83b9d534e863d2d44e850beb210c7670d514d14d688d5dedd5: 0 → 1
    │   │   @ 0x7a87865e5e975ce453cc98afc0decc1e2a8fa9a472b807ed8ebc4e364f4510a0: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0x0e897f31ba79cd2048bb42f11d2fe978acb1d89c0836069d03e56e0df9c89dc6: 0 → 4
    │   │   @ 0xf3f7a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee7: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   └─ ← [Stop]
    ├─ [20690] ConsensusRegistry::delegationDigest(0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, 0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2) [staticcall]
    │   └─ ← [Return] 0xe65b95d7813495700ab195516a85e6176fde45d3e12a992e3efea7e85e6a58b6
    ├─ [0] VM::sign("<pk>", 0xe65b95d7813495700ab195516a85e6176fde45d3e12a992e3efea7e85e6a58b6) [staticcall]
    │   └─ ← [Return] 27, 0xc1dfd13a6e11c14729b26ad48c9de9954a010fdb97c84e982b5b0a5a6cfe643f, 0x6aa13ee4aa628743e397e82b408f3b46738018d90b55275d0a0d9116bdab7751
    ├─ [0] VM::expectEmit(true, true, true, true)
    │   └─ ← [Return]
    ├─ emit ValidatorStaked(validator: ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 1, isRetired: false, isDelegated: true, stakeVersion: 0 }))
    ├─ [0] VM::prank(0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2)
    │   └─ ← [Return]
    ├─ [236387] ConsensusRegistry::delegateStake{value: 1000000000000000000000000}(0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, 0xc1dfd13a6e11c14729b26ad48c9de9954a010fdb97c84e982b5b0a5a6cfe643f6aa13ee4aa628743e397e82b408f3b46738018d90b55275d0a0d9116bdab77511b)
    │   ├─ [3000] PRECOMPILES::ecrecover(0xe65b95d7813495700ab195516a85e6176fde45d3e12a992e3efea7e85e6a58b6, 27, 87691830712271034647766397131711249402786371118477288535332665831738256024639, 48230058400340519978027422133806233037041153827642305941616173166309317244753) [staticcall]
    │   │   └─ ← [Return] 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   ├─ emit ValidatorStaked(validator: ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 1, isRetired: false, isDelegated: true, stakeVersion: 0 }))
    │   ├─  storage changes:
    │   │   @ 0x1a3b2069de01bdc41e02d4ef7c70d6b90abaf0a764915870c17d19ac5388ad97: 0 → 0xa40d8abca484ed8b46a279da6ff29828fbc82987a7420aebd37742b6a9e2440e
    │   │   @ 0xc2ab6246022194ce8a45dcde88fc805f184739bd2207b6e07c051941cc5cc357: 0 → 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0
    │   │   @ 0xc2ab6246022194ce8a45dcde88fc805f184739bd2207b6e07c051941cc5cc356: 0 → 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0
    │   │   @ 0x8ffec16e2621d02df7b30ed4b6c48d053eccd6ce3414caac3b6c747235e6ecf3: 0 → 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
    │   │   @ 0xc2ab6246022194ce8a45dcde88fc805f184739bd2207b6e07c051941cc5cc358: 0 → 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0
    │   │   @ 0x29efb54678ef28eff0c2637a9e549b206de19d9b07b19fe45a58823ea3ea6b55: 0 → 1
    │   │   @ 0x291ddde4a67136704fbd8110d7e9d2f066c809e3485ce521c3c66ec463f3c095: 0 → 193
    │   │   @ 0x291ddde4a67136704fbd8110d7e9d2f066c809e3485ce521c3c66ec463f3c096: 0 → 0x0001000100000000ffffffffe1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0x1a3b2069de01bdc41e02d4ef7c70d6b90abaf0a764915870c17d19ac5388ad98: 0 → 0x0000000000000000000000007bcc1d1292cf3e4b2a6b63f48335cbde5f7545d2
    │   │   @ 0x1a3b2069de01bdc41e02d4ef7c70d6b90abaf0a764915870c17d19ac5388ad99: 0 → 0x000000000000000000000100e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   └─ ← [Stop]
    ├─ [26587] ConsensusRegistry::getValidators(1) [staticcall]
    │   └─ ← [Return] [ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 1, isRetired: false, isDelegated: true, stakeVersion: 0 })]
    ├─ [0] VM::assertEq(1, 1) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(4294967295 [4.294e9], 4294967295 [4.294e9]) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0, 0) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(false, false) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(true, true) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0, 0) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(1, 1) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2)
    │   └─ ← [Return]
    ├─ [24098] ConsensusRegistry::claimStakeRewards(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)
    │   ├─  storage changes:
    │   │   @ 0x0000000000000000000000000000000000000000000000929eee149b4bd21268: 0 → 0x0000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b
    │   └─ ← [Revert] NotRecipient(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)
    ├─  storage changes:
    │   @ 88: 0x0000000000000000000000002d0c79bb0604c104a5fb6f4eb0703f3154bb3db0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   @ 0x8ffec16e2621d02df7b30ed4b6c48d053eccd6ce3414caac3b6c747235e6ecf3: 0 → 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
    └─ ← [Revert] NotRecipient(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 4.16ms (2.70ms CPU time)

Ran 1 test suite in 101.17ms (4.16ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)
```

Failing tests:
```
Encountered 1 failing test in test/consensus/ConsensusRegistryTest.t.sol:ConsensusRegistryTest
[FAIL: NotRecipient(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)] test_delegateStakeAndUnstake() (gas: 490067)
```

Encountered a total of 1 failing tests, 0 tests succeeded
Now calling With Validator Address
```solidity
function test_delegateStakeAndUnstake() public {
        vm.prank(crOwner);
        uint256 validator5PrivateKey = 5;
        validator5 = vm.addr(validator5PrivateKey);  // users validator address we are using 
        address delegator = _addressFromSeed(42);
        vm.deal(delegator, stakeAmount_);

        consensusRegistry.mint(validator5);

        // validator signs delegation
        bytes32 structHash = consensusRegistry.delegationDigest(validator5BlsPubkey, validator5, delegator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator5PrivateKey, structHash);
        bytes memory validatorSig = abi.encodePacked(r, s, v);

        // Check event emission
        bool isDelegate = true;
        vm.expectEmit(true, true, true, true);
        emit ValidatorStaked(
            ValidatorInfo(
                validator5BlsPubkey,
                validator5,
                PENDING_EPOCH,
                uint32(0),
                ValidatorStatus.Staked,
                false,
                isDelegate,
                uint8(0)
            )
        );
        vm.prank(delegator);
        consensusRegistry.delegateStake{ value: stakeAmount_ }(validator5BlsPubkey, validator5, validatorSig);

        // Check validator information
        ValidatorInfo[] memory validators = consensusRegistry.getValidators(ValidatorStatus.Staked);
        assertEq(validators.length, 1);
        assertEq(validators[0].validatorAddress, validator5);
        assertEq(validators[0].blsPubkey, validator5BlsPubkey);
        assertEq(validators[0].activationEpoch, PENDING_EPOCH);
        assertEq(validators[0].exitEpoch, uint32(0));
        assertEq(validators[0].isRetired, false);
        assertEq(validators[0].isDelegated, true);  // is delagted true // Bu delegated to the validator address
        assertEq(validators[0].stakeVersion, uint8(0));
        assertEq(uint8(validators[0].currentStatus), uint8(ValidatorStatus.Staked));

        vm.prank(validator5); 
        consensusRegistry.unstake(validator5);
    }
```

OUTPUT
Screenshot 2025-06-17 at 12.15.30 PM.png

After Changing the Vulnerable Contract

Calling With Delegator

Screenshot 2025-06-17 at 12.24.54 PM.png

```
forge test --mt test_delegateStakeAndUnstake -vvvvv
[⠊] Compiling...
No files changed, compilation skipped

Ran 1 test for test/consensus/ConsensusRegistryTest.t.sol:ConsensusRegistryTest
[PASS] test_delegateStakeAndUnstake() (gas: 436558)
Traces:
  [7062297] ConsensusRegistryTest::setUp()
    ├─ [6911607] → new ConsensusRegistry@0x2e234DAe75C793f67A35089C9d99245E1C58470b
    │   ├─ emit OwnershipTransferred(previousOwner: 0x0000000000000000000000000000000000000000, newOwner: 0x0000000000000000000000000000000000C0FFEE)
    │   ├─ [117228] → new Issuance@0xffD4505B3452Dc22f8473616d50503bA9E1710Ac
    │   │   └─ ← [Return] 584 bytes of code
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x717e6a320cf44b4aFAc2b0732D9fcBe2B7fa0Cf6, tokenId: 647935101931755020891358879668158668242001988854 [6.479e47])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6, validatorAddress: 0x717e6a320cf44b4aFAc2b0732D9fcBe2B7fa0Cf6, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0xC41B3BA8828b3321CA811111fA75Cd3Aa3BB5ACe, tokenId: 1119569508167662895942198234849060215188302289614 [1.119e48])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace, validatorAddress: 0xC41B3BA8828b3321CA811111fA75Cd3Aa3BB5ACe, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x2F12DB2869C3395A3b0502d05E2516446f71F85B, tokenId: 268743070984790341878037720322852862765112096859 [2.687e47])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85bc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85bc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b, validatorAddress: 0x2F12DB2869C3395A3b0502d05E2516446f71F85B, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x4Fd709f28e8600b4aa8c65c6B64bFe7fE36bd19b, tokenId: 455805797661119744593529678857535516768150999451 [4.558e47])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0x8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b, validatorAddress: 0x4Fd709f28e8600b4aa8c65c6B64bFe7fE36bd19b, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   └─ ← [Return] 23680 bytes of code
    ├─ [340] ConsensusRegistry::SYSTEM_ADDRESS() [staticcall]
    │   └─ ← [Return] 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE
    ├─ [0] VM::deal(0x2D0C79bB0604C104A5fB6F4eB0703F3154BB3db0, 1000000000000000000000000 [1e24])
    │   └─ ← [Return]
    ├─ [0] VM::deal(0x0000000000000000000000000000000000C0FFEE, 714285714285714285714285 [7.142e23])
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x0000000000000000000000000000000000C0FFEE)
    │   └─ ← [Return]
    ├─ [7493] ConsensusRegistry::allocateIssuance{value: 714285714285714285714285}()
    │   ├─ [95] Issuance::receive{value: 714285714285714285714285}()
    │   │   └─ ← [Stop]
    │   └─ ← [Stop]
    └─ ← [Stop]

  [550963] ConsensusRegistryTest::test_delegateStakeAndUnstake()
    ├─ [0] VM::prank(0x0000000000000000000000000000000000C0FFEE)
    │   └─ ← [Return]
    ├─ [0] VM::addr(<pk>) [staticcall]
    │   └─ ← [Return] 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276
    ├─ [0] VM::deal(0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2, 1000000000000000000000000 [1e24])
    │   └─ ← [Return]
    ├─ [126789] ConsensusRegistry::mint(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, tokenId: 1288347612158191397270705234830805381732297126518 [1.288e48])
    │   ├─  storage changes:
    │   │   @ 0xb6ab34d48b92a46d2d66f69803287936d00badd23b67adb2ee9e6f43d652ceb0: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 8: 4 → 5
    │   │   @ 0x7a87865e5e975ce453cc98afc0decc1e2a8fa9a472b807ed8ebc4e364f4510a0: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0xf3f7a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee7: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0x0e897f31ba79cd2048bb42f11d2fe978acb1d89c0836069d03e56e0df9c89dc6: 0 → 4
    │   │   @ 0x057298a0d8443d83b9d534e863d2d44e850beb210c7670d514d14d688d5dedd5: 0 → 1
    │   └─ ← [Stop]
    ├─ [20690] ConsensusRegistry::delegationDigest(0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, 0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2) [staticcall]
    │   └─ ← [Return] 0xe65b95d7813495700ab195516a85e6176fde45d3e12a992e3efea7e85e6a58b6
    ├─ [0] VM::sign("<pk>", 0xe65b95d7813495700ab195516a85e6176fde45d3e12a992e3efea7e85e6a58b6) [staticcall]
    │   └─ ← [Return] 27, 0xc1dfd13a6e11c14729b26ad48c9de9954a010fdb97c84e982b5b0a5a6cfe643f, 0x6aa13ee4aa628743e397e82b408f3b46738018d90b55275d0a0d9116bdab7751
    ├─ [0] VM::expectEmit(true, true, true, true)
    │   └─ ← [Return]
    ├─ emit ValidatorStaked(validator: ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 1, isRetired: false, isDelegated: true, stakeVersion: 0 }))
    ├─ [0] VM::prank(0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2)
    │   └─ ← [Return]
    ├─ [236387] ConsensusRegistry::delegateStake{value: 1000000000000000000000000}(0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, 0xc1dfd13a6e11c14729b26ad48c9de9954a010fdb97c84e982b5b0a5a6cfe643f6aa13ee4aa628743e397e82b408f3b46738018d90b55275d0a0d9116bdab77511b)
    │   ├─ [3000] PRECOMPILES::ecrecover(0xe65b95d7813495700ab195516a85e6176fde45d3e12a992e3efea7e85e6a58b6, 27, 87691830712271034647766397131711249402786371118477288535332665831738256024639, 48230058400340519978027422133806233037041153827642305941616173166309317244753) [staticcall]
    │   │   └─ ← [Return] 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   ├─ emit ValidatorStaked(validator: ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 1, isRetired: false, isDelegated: true, stakeVersion: 0 }))
    │   ├─  storage changes:
    │   │   @ 0xc2ab6246022194ce8a45dcde88fc805f184739bd2207b6e07c051941cc5cc356: 0 → 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0
    │   │   @ 0x291ddde4a67136704fbd8110d7e9d2f066c809e3485ce521c3c66ec463f3c096: 0 → 0x0001000100000000ffffffffe1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0x8ffec16e2621d02df7b30ed4b6c48d053eccd6ce3414caac3b6c747235e6ecf3: 0 → 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
    │   │   @ 0x1a3b2069de01bdc41e02d4ef7c70d6b90abaf0a764915870c17d19ac5388ad97: 0 → 0xa40d8abca484ed8b46a279da6ff29828fbc82987a7420aebd37742b6a9e2440e
    │   │   @ 0x1a3b2069de01bdc41e02d4ef7c70d6b90abaf0a764915870c17d19ac5388ad99: 0 → 0x0000000000000000000001007bcc1d1292cf3e4b2a6b63f48335cbde5f7545d2
    │   │   @ 0xc2ab6246022194ce8a45dcde88fc805f184739bd2207b6e07c051941cc5cc358: 0 → 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0
    │   │   @ 0x1a3b2069de01bdc41e02d4ef7c70d6b90abaf0a764915870c17d19ac5388ad98: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0xc2ab6246022194ce8a45dcde88fc805f184739bd2207b6e07c051941cc5cc357: 0 → 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0
    │   │   @ 0x29efb54678ef28eff0c2637a9e549b206de19d9b07b19fe45a58823ea3ea6b55: 0 → 1
    │   │   @ 0x291ddde4a67136704fbd8110d7e9d2f066c809e3485ce521c3c66ec463f3c095: 0 → 193
    │   └─ ← [Stop]
    ├─ [26587] ConsensusRegistry::getValidators(1) [staticcall]
    │   └─ ← [Return] [ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 1, isRetired: false, isDelegated: true, stakeVersion: 0 })]
    ├─ [0] VM::assertEq(1, 1) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(4294967295 [4.294e9], 4294967295 [4.294e9]) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0, 0) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(false, false) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(true, true) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0, 0) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(1, 1) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2)
    │   └─ ← [Return]
    ├─ [84978] ConsensusRegistry::unstake(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)
    │   ├─ emit ValidatorRetired(validator: ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 6, isRetired: true, isDelegated: true, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, to: 0x0000000000000000000000000000000000000000, tokenId: 1288347612158191397270705234830805381732297126518 [1.288e48])
    │   ├─ [32321] Issuance::distributeStakeReward{value: 1000000000000000000000000}(0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2, 0)
    │   │   ├─ [0] 0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2::fallback{value: 1000000000000000000000000}()
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Stop]
    │   ├─ emit RewardsClaimed(claimant: 0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2, rewards: 1000000000000000000000000 [1e24])
    │   ├─  storage changes:
    │   │   @ 8: 5 → 4
    │   │   @ 0x7a87865e5e975ce453cc98afc0decc1e2a8fa9a472b807ed8ebc4e364f4510a0: 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276 → 0
    │   │   @ 0xb6ab34d48b92a46d2d66f69803287936d00badd23b67adb2ee9e6f43d652ceb0: 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276 → 0
    │   │   @ 0x0e897f31ba79cd2048bb42f11d2fe978acb1d89c0836069d03e56e0df9c89dc6: 4 → 0
    │   │   @ 0xf3f7a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee7: 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276 → 0
    │   │   @ 0x057298a0d8443d83b9d534e863d2d44e850beb210c7670d514d14d688d5dedd5: 1 → 0
    │   │   @ 0x8ffec16e2621d02df7b30ed4b6c48d053eccd6ce3414caac3b6c747235e6ecf3: 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000 → 0
    │   │   @ 0x0000000000000000000000000000000000000000000000929eee149b4bd21268: 0 → 23680
    │   │   @ 0x291ddde4a67136704fbd8110d7e9d2f066c809e3485ce521c3c66ec463f3c096: 0x0001000100000000ffffffffe1ab8145f7e55dc933d51a18c793f901a3a0b276 → 0x0001010600000000ffffffffe1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   └─ ← [Stop]
    ├─  storage changes:
    │   @ 88: 0x0000000000000000000000002d0c79bb0604c104a5fb6f4eb0703f3154bb3db0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   @ 0x8ffec16e2621d02df7b30ed4b6c48d053eccd6ce3414caac3b6c747235e6ecf3: 0 → 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.21ms (2.74ms CPU time)

Ran 1 test suite in 102.63ms (4.21ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

On Calling With validator Address
Screenshot 2025-06-17 at 12.30.59 PM.png Calling With the Validator

```
forge test --mt test_delegateStakeAndUnstake -vvvvv
[⠊] Compiling...
No files changed, compilation skipped

Ran 1 test for test/consensus/ConsensusRegistryTest.t.sol:ConsensusRegistryTest
[PASS] test_delegateStakeAndUnstake() (gas: 436618)
Traces:
  [7062297] ConsensusRegistryTest::setUp()
    ├─ [6911607] → new ConsensusRegistry@0x2e234DAe75C793f67A35089C9d99245E1C58470b
    │   ├─ emit OwnershipTransferred(previousOwner: 0x0000000000000000000000000000000000000000, newOwner: 0x0000000000000000000000000000000000C0FFEE)
    │   ├─ [117228] → new Issuance@0xffD4505B3452Dc22f8473616d50503bA9E1710Ac
    │   │   └─ ← [Return] 584 bytes of code
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x717e6a320cf44b4aFAc2b0732D9fcBe2B7fa0Cf6, tokenId: 647935101931755020891358879668158668242001988854 [6.479e47])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6, validatorAddress: 0x717e6a320cf44b4aFAc2b0732D9fcBe2B7fa0Cf6, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0xC41B3BA8828b3321CA811111fA75Cd3Aa3BB5ACe, tokenId: 1119569508167662895942198234849060215188302289614 [1.119e48])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace, validatorAddress: 0xC41B3BA8828b3321CA811111fA75Cd3Aa3BB5ACe, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x2F12DB2869C3395A3b0502d05E2516446f71F85B, tokenId: 268743070984790341878037720322852862765112096859 [2.687e47])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85bc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85bc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b, validatorAddress: 0x2F12DB2869C3395A3b0502d05E2516446f71F85B, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x4Fd709f28e8600b4aa8c65c6B64bFe7fE36bd19b, tokenId: 455805797661119744593529678857535516768150999451 [4.558e47])
    │   ├─ emit ValidatorActivated(validator: ValidatorInfo({ blsPubkey: 0x8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b, validatorAddress: 0x4Fd709f28e8600b4aa8c65c6B64bFe7fE36bd19b, activationEpoch: 0, exitEpoch: 0, currentStatus: 3, isRetired: false, isDelegated: false, stakeVersion: 0 }))
    │   └─ ← [Return] 23680 bytes of code
    ├─ [340] ConsensusRegistry::SYSTEM_ADDRESS() [staticcall]
    │   └─ ← [Return] 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE
    ├─ [0] VM::deal(0x2D0C79bB0604C104A5fB6F4eB0703F3154BB3db0, 1000000000000000000000000 [1e24])
    │   └─ ← [Return]
    ├─ [0] VM::deal(0x0000000000000000000000000000000000C0FFEE, 714285714285714285714285 [7.142e23])
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x0000000000000000000000000000000000C0FFEE)
    │   └─ ← [Return]
    ├─ [7493] ConsensusRegistry::allocateIssuance{value: 714285714285714285714285}()
    │   ├─ [95] Issuance::receive{value: 714285714285714285714285}()
    │   │   └─ ← [Stop]
    │   └─ ← [Stop]
    └─ ← [Stop]

  [551038] ConsensusRegistryTest::test_delegateStakeAndUnstake()
    ├─ [0] VM::prank(0x0000000000000000000000000000000000C0FFEE)
    │   └─ ← [Return]
    ├─ [0] VM::addr(<pk>) [staticcall]
    │   └─ ← [Return] 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276
    ├─ [0] VM::deal(0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2, 1000000000000000000000000 [1e24])
    │   └─ ← [Return]
    ├─ [126789] ConsensusRegistry::mint(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, tokenId: 1288347612158191397270705234830805381732297126518 [1.288e48])
    │   ├─  storage changes:
    │   │   @ 0xf3f7a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee7: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0xb6ab34d48b92a46d2d66f69803287936d00badd23b67adb2ee9e6f43d652ceb0: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 8: 4 → 5
    │   │   @ 0x7a87865e5e975ce453cc98afc0decc1e2a8fa9a472b807ed8ebc4e364f4510a0: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0x057298a0d8443d83b9d534e863d2d44e850beb210c7670d514d14d688d5dedd5: 0 → 1
    │   │   @ 0x0e897f31ba79cd2048bb42f11d2fe978acb1d89c0836069d03e56e0df9c89dc6: 0 → 4
    │   └─ ← [Stop]
    ├─ [20690] ConsensusRegistry::delegationDigest(0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, 0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2) [staticcall]
    │   └─ ← [Return] 0xe65b95d7813495700ab195516a85e6176fde45d3e12a992e3efea7e85e6a58b6
    ├─ [0] VM::sign("<pk>", 0xe65b95d7813495700ab195516a85e6176fde45d3e12a992e3efea7e85e6a58b6) [staticcall]
    │   └─ ← [Return] 27, 0xc1dfd13a6e11c14729b26ad48c9de9954a010fdb97c84e982b5b0a5a6cfe643f, 0x6aa13ee4aa628743e397e82b408f3b46738018d90b55275d0a0d9116bdab7751
    ├─ [0] VM::expectEmit(true, true, true, true)
    │   └─ ← [Return]
    ├─ emit ValidatorStaked(validator: ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 1, isRetired: false, isDelegated: true, stakeVersion: 0 }))
    ├─ [0] VM::prank(0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2)
    │   └─ ← [Return]
    ├─ [236387] ConsensusRegistry::delegateStake{value: 1000000000000000000000000}(0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, 0xc1dfd13a6e11c14729b26ad48c9de9954a010fdb97c84e982b5b0a5a6cfe643f6aa13ee4aa628743e397e82b408f3b46738018d90b55275d0a0d9116bdab77511b)
    │   ├─ [3000] PRECOMPILES::ecrecover(0xe65b95d7813495700ab195516a85e6176fde45d3e12a992e3efea7e85e6a58b6, 27, 87691830712271034647766397131711249402786371118477288535332665831738256024639, 48230058400340519978027422133806233037041153827642305941616173166309317244753) [staticcall]
    │   │   └─ ← [Return] 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   ├─ emit ValidatorStaked(validator: ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 1, isRetired: false, isDelegated: true, stakeVersion: 0 }))
    │   ├─  storage changes:
    │   │   @ 0xc2ab6246022194ce8a45dcde88fc805f184739bd2207b6e07c051941cc5cc358: 0 → 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0
    │   │   @ 0x1a3b2069de01bdc41e02d4ef7c70d6b90abaf0a764915870c17d19ac5388ad97: 0 → 0xa40d8abca484ed8b46a279da6ff29828fbc82987a7420aebd37742b6a9e2440e
    │   │   @ 0x1a3b2069de01bdc41e02d4ef7c70d6b90abaf0a764915870c17d19ac5388ad99: 0 → 0x0000000000000000000001007bcc1d1292cf3e4b2a6b63f48335cbde5f7545d2
    │   │   @ 0x29efb54678ef28eff0c2637a9e549b206de19d9b07b19fe45a58823ea3ea6b55: 0 → 1
    │   │   @ 0xc2ab6246022194ce8a45dcde88fc805f184739bd2207b6e07c051941cc5cc356: 0 → 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0
    │   │   @ 0x291ddde4a67136704fbd8110d7e9d2f066c809e3485ce521c3c66ec463f3c096: 0 → 0x0001000100000000ffffffffe1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0x1a3b2069de01bdc41e02d4ef7c70d6b90abaf0a764915870c17d19ac5388ad98: 0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0x291ddde4a67136704fbd8110d7e9d2f066c809e3485ce521c3c66ec463f3c095: 0 → 193
    │   │   @ 0x8ffec16e2621d02df7b30ed4b6c48d053eccd6ce3414caac3b6c747235e6ecf3: 0 → 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
    │   │   @ 0xc2ab6246022194ce8a45dcde88fc805f184739bd2207b6e07c051941cc5cc357: 0 → 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0
    │   └─ ← [Stop]
    ├─ [26587] ConsensusRegistry::getValidators(1) [staticcall]
    │   └─ ← [Return] [ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 1, isRetired: false, isDelegated: true, stakeVersion: 0 })]
    ├─ [0] VM::assertEq(1, 1) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(4294967295 [4.294e9], 4294967295 [4.294e9]) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0, 0) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(false, false) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(true, true) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(0, 0) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(1, 1) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::prank(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)
    │   └─ ← [Return]
    ├─ [84947] ConsensusRegistry::unstake(0xe1AB8145F7E55DC933d51a18c793F901A3A0b276)
    │   ├─ emit ValidatorRetired(validator: ValidatorInfo({ blsPubkey: 0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, validatorAddress: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, activationEpoch: 4294967295 [4.294e9], exitEpoch: 0, currentStatus: 6, isRetired: true, isDelegated: true, stakeVersion: 0 }))
    │   ├─ emit Transfer(from: 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, to: 0x0000000000000000000000000000000000000000, tokenId: 1288347612158191397270705234830805381732297126518 [1.288e48])
    │   ├─ [32321] Issuance::distributeStakeReward{value: 1000000000000000000000000}(0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2, 0)
    │   │   ├─ [0] 0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2::fallback{value: 1000000000000000000000000}()
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Stop]
    │   ├─ emit RewardsClaimed(claimant: 0x7bCc1D1292cf3e4b2a6B63F48335CbDE5f7545D2, rewards: 1000000000000000000000000 [1e24])
    │   ├─  storage changes:
    │   │   @ 0xb6ab34d48b92a46d2d66f69803287936d00badd23b67adb2ee9e6f43d652ceb0: 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276 → 0
    │   │   @ 0xf3f7a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee7: 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276 → 0
    │   │   @ 8: 5 → 4
    │   │   @ 0x8ffec16e2621d02df7b30ed4b6c48d053eccd6ce3414caac3b6c747235e6ecf3: 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000 → 0
    │   │   @ 0x291ddde4a67136704fbd8110d7e9d2f066c809e3485ce521c3c66ec463f3c096: 0x0001000100000000ffffffffe1ab8145f7e55dc933d51a18c793f901a3a0b276 → 0x0001010600000000ffffffffe1ab8145f7e55dc933d51a18c793f901a3a0b276
    │   │   @ 0x0000000000000000000000000000000000000000000000929eee149b4bd21268: 0 → 23680
    │   │   @ 0x057298a0d8443d83b9d534e863d2d44e850beb210c7670d514d14d688d5dedd5: 1 → 0
    │   │   @ 0x0e897f31ba79cd2048bb42f11d2fe978acb1d89c0836069d03e56e0df9c89dc6: 4 → 0
    │   │   @ 0x7a87865e5e975ce453cc98afc0decc1e2a8fa9a472b807ed8ebc4e364f4510a0: 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276 → 0
    │   └─ ← [Stop]
    ├─  storage changes:
    │   @ 0x8ffec16e2621d02df7b30ed4b6c48d053eccd6ce3414caac3b6c747235e6ecf3: 0 → 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
    │   @ 88: 0x0000000000000000000000002d0c79bb0604c104a5fb6f4eb0703f3154bb3db0 → 0x000000000000000000000000e1ab8145f7e55dc933d51a18c793f901a3a0b276
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.38ms (2.88ms CPU time)

Ran 1 test suite in 102.48ms (4.38ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Recommendation
Change Incorrect mapping and Struct in `ConsensusRegistry.sol` Contract in function `delegateStake`

```diff
function delegateStake(
        bytes calldata blsPubkey,
        address validatorAddress,
        bytes calldata validatorSig
    )
        external
        payable
        override
        whenNotPaused
    {
        if (blsPubkey.length != 96) revert InvalidBLSPubkey();
        // require caller is known & whitelisted, having been issued a ConsensusNFT by governance
        uint8 validatorVersion = getCurrentEpochInfo().stakeVersion;
        uint256 stakeAmt = _checkStakeValue(msg.value, validatorVersion);
        _checkConsensusNFTOwner(validatorAddress);
        // require validator status is `Undefined`
        _checkValidatorStatus(validatorAddress, ValidatorStatus.Undefined);
        uint64 nonce = delegations[validatorAddress].nonce;
        bytes32 blsPubkeyHash = keccak256(blsPubkey);
        // governance may utilize white-glove onboarding or offchain agreements
        if (msg.sender != owner()) {
            bytes32 structHash = keccak256(
                abi.encode(DELEGATION_TYPEHASH, blsPubkeyHash, validatorAddress, msg.sender, validatorVersion, nonce)
            );
            bytes32 digest = _hashTypedData(structHash);
            if (!SignatureCheckerLib.isValidSignatureNowCalldata(validatorAddress, digest, validatorSig)) {
                revert NotValidator(validatorAddress);
            }
        }
-        delegations[validatorAddress] =
-            Delegation(blsPubkeyHash, msg.sender, validatorAddress, validatorVersion, nonce + 1);
+        delegations[validatorAddress] =
+            Delegation(blsPubkeyHash, validatorAddress, msg.sender, validatorVersion, nonce + 1);
        _recordStaked(blsPubkey, validatorAddress, true, validatorVersion, stakeAmt);
    }
    /// @inheritdoc IConsensusRegistry
    function activate() external override whenNotPaused {
        // require caller is whitelisted, having been issued a ConsensusNFT by governance
        _checkConsensusNFTOwner(msg.sender);
        // require caller status is `Staked`
        _checkValidatorStatus(msg.sender, ValidatorStatus.Staked);
        ValidatorInfo storage validator = validators[msg.sender];
        // begin validator activation, completing automatically next epoch
        _beginActivation(validator, currentEpoch);
    }
```
I think this will fix the Problem delegator mapping and Struct . Properly work As you can see in the POC properly calling the unstake and claimStakeRewards functionality
