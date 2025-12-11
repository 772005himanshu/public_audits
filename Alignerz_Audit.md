## Title Of Finding 1:
[High - 🔴] In the Contract A26ZDividendDistributor.sol function getUnclaimedAmounts(..) continue leads to the infinite loop leads to DoS vulnerability and Freeze the DistributorDividends Contract

### Summary

In the Contract `A26ZDividendDistributor.sol` function `getUnclaimedAmounts(..)` `continue`  leads to the infinite loop. 

If one time `continue` hits lead to infinite loop because it skips increament of the `for loop` . It possible easily if the `nftId` is not claimed. So `claimedSeconds[i] == 0` easily zero first increase the `amount += amounts[i]` then hits the continue. This is where infinite loop start 

Because because the increament never be called after the `continue`

```solidity
unchecked {
                ++i;
            }
```
This is never be called in the function . Repeating the same `i` in the function.

In this Contract at many time :
```solidity
/// @notice Internal logic that allows the owner to set crucial amounts for dividends calculations
    function _setAmounts() internal {
        stablecoinAmountToDistribute = stablecoin.balanceOf(address(this));
@>        totalUnclaimedAmounts = getTotalUnclaimedAmounts();
        emit amountsSet(stablecoinAmountToDistribute, totalUnclaimedAmounts);
    }
```

```solidity
/// @notice USD value in 1e18 of all the unclaimed tokens of all the TVS
    function getTotalUnclaimedAmounts() public returns (uint256 _totalUnclaimedAmounts) {
        uint256 len = nft.getTotalMinted();
        for (uint i; i < len;) {
            (, bool isOwned) = safeOwnerOf(i);
@>            if (isOwned) _totalUnclaimedAmounts += getUnclaimedAmounts(i);
            unchecked {
                ++i;
            }
        }
    }
```

### Root Cause

The issue is the improper use of the `continue` in the function 
```solidity
 /// @notice USD value in 1e18 of all the unclaimed tokens of a TVS
    /// @param nftId NFT Id
    function getUnclaimedAmounts(uint256 nftId) public returns (uint256 amount) {
        if (address(token) == address(vesting.allocationOf(nftId).token)) return 0;
        uint256[] memory amounts = vesting.allocationOf(nftId).amounts;
        uint256[] memory claimedSeconds = vesting.allocationOf(nftId).claimedSeconds;
        uint256[] memory vestingPeriods = vesting.allocationOf(nftId).vestingPeriods;
        bool[] memory claimedFlows = vesting.allocationOf(nftId).claimedFlows;
        uint256 len = vesting.allocationOf(nftId).amounts.length;
        for (uint i; i < len;) {
@>            if (claimedFlows[i]) continue;
@>           if (claimedSeconds[i] == 0) {
                amount += amounts[i];
                continue;
            }
            uint256 claimedAmount = claimedSeconds[i] * amounts[i] / vestingPeriods[i];
            uint256 unclaimedAmount = amounts[i] - claimedAmount;
            amount += unclaimedAmount;
            unchecked {
                ++i;
            }
        }
        unclaimedAmountsIn[nftId] = amount;
    }
```

### Internal Pre-conditions

There is should be one condition where `claimedFlows[i] == true` or `claimedSeconds[i] == 0` this lead to infinite loop in the function 

### External Pre-conditions

None

### Attack Path

Attacker or User(Bidder) never claimSeconds in One of their Allocation so `claimedSeconds[i] == 0` or Completely claimed the flow `claimedFlows[i] == true`

### Impact

Due to this the protocol never recover `DoS` vulnerability becuase of `out of gas ` infinite Loop 

### PoC

PoC from User(Attacker/ Bidder):
1. Call the `claimRewardTVS(..)` function 
```solidity
function claimRewardTVS(uint256 rewardProjectId) external {
        RewardProject storage rewardProject = rewardProjects[rewardProjectId];
        require(block.timestamp < rewardProject.claimDeadline, Deadline_Has_Passed());
        address kol = msg.sender;
        _claimRewardTVS(rewardProjectId, kol);
    }
```

then the `_claimRewardTVS(rewardProjectId, kol)` is called in the  function 

```solidity
    /// @notice Internal logic of reward TVS claim
    /// @param rewardProjectId Id of the rewardProject
    /// @param kol address of the KOL who chose to be rewarded in TVS
    function _claimRewardTVS(uint256 rewardProjectId, address kol) internal {
        RewardProject storage rewardProject = rewardProjects[rewardProjectId];
        uint256 amount = rewardProject.kolTVSRewards[kol];
        require(amount > 0, Caller_Has_No_TVS_Allocation());
        rewardProject.kolTVSRewards[kol] = 0;
        uint256 nftId = nftContract.mint(kol);
        rewardProject.allocations[nftId].amounts.push(amount);
        // ..
@>        rewardProject.allocations[nftId].claimedSeconds.push(0);
        // ..
    }
```

2. Here the `claimedSeconds` is push as the zero then in the Distributor this `NftId` is called when `_setAmounts()` function 

```solidity
function _setAmounts() internal {
        stablecoinAmountToDistribute = stablecoin.balanceOf(address(this));
@>        totalUnclaimedAmounts = getTotalUnclaimedAmounts();
        emit amountsSet(stablecoinAmountToDistribute, totalUnclaimedAmounts);
    }

```

```solidity
/// @notice USD value in 1e18 of all the unclaimed tokens of all the TVS
    function getTotalUnclaimedAmounts() public returns (uint256 _totalUnclaimedAmounts) {
        uint256 len = nft.getTotalMinted(); // Here we goes to all nft minted in by the Protocol
        for (uint i; i < len;) {
            (, bool isOwned) = safeOwnerOf(i);
 @>           if (isOwned) _totalUnclaimedAmounts += getUnclaimedAmounts(i);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice USD value in 1e18 of all the unclaimed tokens of a TVS
    /// @param nftId NFT Id
@>    function getUnclaimedAmounts(uint256 nftId) public returns (uint256 amount) {
        /// .. 
        for (uint i; i < len;) {
            if (claimedFlows[i]) continue;
            if (claimedSeconds[i] == 0) {
                amount += amounts[i];
                continue;
            }
            // ..
            // If the Continue is hits the increament never increased lead to infinite loops
            unchecked {
                ++i;
            }
        }
        unclaimedAmountsIn[nftId] = amount;
    }
```

### Mitigation

_No response_


## Title of Finding 2
[High - 🔴]In Contract `AlignerzVesting.sol` function `mergeTVS(...)` double accounting of the `mergeFee`

### Summary

In Contract `AlignerzVesting.sol` function `mergeTVS(...)` double accounting of the `mergeFee` When we `User(msg.sender)` merging there TVS fee calculation we first calculate fee for first amount allocation . Then we collect fee for  other `nftIds[i]` that we are merging through the function `_merge(...)`

```solidity
function mergeTVS(uint256 projectId, uint256 mergedNftId, uint256[] calldata projectIds, uint256[] calldata nftIds) external returns(uint256) {
        // ...
        (uint256 feeAmount, uint256[] memory newAmounts) = calculateFeeAndNewAmountForOneTVS(mergeFeeRate, amounts, nbOfFlows);


        for (uint256 i; i < nbOfNFTs; i++) {
            feeAmount += _merge(mergedTVS, projectIds[i], nftIds[i], token); // @audit double account of merge fee 
        }
        token.safeTransfer(treasury, feeAmount); // fee transfer to treasury
        // ....
    }



function _merge(Allocation storage mergedTVS, uint256 projectId, uint256 nftId, IERC20 token) internal returns (uint256 feeAmount) {
        require(msg.sender == nftContract.extOwnerOf(nftId), Caller_Should_Own_The_NFT());
        
        bool isBiddingProjectTVSToMerge = NFTBelongsToBiddingProject[nftId];
        (Allocation storage TVSToMerge, IERC20 tokenToMerge) = isBiddingProjectTVSToMerge ?
        (biddingProjects[projectId].allocations[nftId], biddingProjects[projectId].token) :
        (rewardProjects[projectId].allocations[nftId], rewardProjects[projectId].token);
        require(address(token) == address(tokenToMerge), Different_Tokens());

        uint256 nbOfFlowsTVSToMerge = TVSToMerge.amounts.length;
        for (uint256 j = 0; j < nbOfFlowsTVSToMerge; j++) {
            uint256 fee = calculateFeeAmount(mergeFeeRate, TVSToMerge.amounts[j]);
            mergedTVS.amounts.push(TVSToMerge.amounts[j] - fee); // here we also decrease the fee 
            // ...
            feeAmount += fee; // @audit here 
        }
        nftContract.burn(nftId);
    }
```

```
Final fee Amount look like this:
feeAmount = feeAmount + (fee (For MergeNfts))


For MergeNfts fee:
for (uint256 j = 0; j < nbOfFlowsTVSToMerge; j++) {
      feeAmount  = feeAmount  + fee[i] (Fee for every merging Fee)
}

fee[i] = feeAmount + fee(1) + fee(2) + ....

Final Look of FeeAmount:

feeAmount  = feeAmount + (feeAmount + fee(1) + fee(2) + fee(3)+ ....)
```

Here we can see the `feeAmount ` is accounted two times in the `mergeTVS` function and we also reduce from the `mergedTVS.amounts`

```solidity
for (uint256 j = 0; j < nbOfFlowsTVSToMerge; j++) {
            uint256 fee = calculateFeeAmount(mergeFeeRate, TVSToMerge.amounts[j]);
@>            mergedTVS.amounts.push(TVSToMerge.amounts[j] - fee); // also decrease the fee from the amounts 
            mergedTVS.vestingPeriods.push(TVSToMerge.vestingPeriods[j]);
            mergedTVS.vestingStartTimes.push(TVSToMerge.vestingStartTimes[j]);
            mergedTVS.claimedSeconds.push(TVSToMerge.claimedSeconds[j]);
            mergedTVS.claimedFlows.push(TVSToMerge.claimedFlows[j]);
            feeAmount += fee;
        }
```

### Root Cause

 
```solidity
   function mergeTVS(uint256 projectId, uint256 mergedNftId, uint256[] calldata projectIds, uint256[] calldata nftIds) external returns(uint256) {
        address nftOwner = nftContract.extOwnerOf(mergedNftId);
        require(msg.sender == nftOwner, Caller_Should_Own_The_NFT());
        
        bool isBiddingProject = NFTBelongsToBiddingProject[mergedNftId];
        (Allocation storage mergedTVS, IERC20 token) = isBiddingProject ?
        (biddingProjects[projectId].allocations[mergedNftId], biddingProjects[projectId].token) :
        (rewardProjects[projectId].allocations[mergedNftId], rewardProjects[projectId].token);

        uint256[] memory amounts = mergedTVS.amounts;
        uint256 nbOfFlows = mergedTVS.amounts.length;
 @>       (uint256 feeAmount, uint256[] memory newAmounts) = calculateFeeAndNewAmountForOneTVS(mergeFeeRate, amounts, nbOfFlows);
        mergedTVS.amounts = newAmounts;

        uint256 nbOfNFTs = nftIds.length;
        require(nbOfNFTs > 0, Not_Enough_TVS_To_Merge());
        require(nbOfNFTs == projectIds.length, Array_Lengths_Must_Match());

        for (uint256 i; i < nbOfNFTs; i++) {
@>            feeAmount += _merge(mergedTVS, projectIds[i], nftIds[i], token);
        }
        token.safeTransfer(treasury, feeAmount);
        emit TVSsMerged(projectId, isBiddingProject, nftIds, mergedNftId, mergedTVS.amounts, mergedTVS.vestingPeriods, mergedTVS.vestingStartTimes, mergedTVS.claimedSeconds, mergedTVS.claimedFlows);
        return mergedNftId;
    }

    function _merge(Allocation storage mergedTVS, uint256 projectId, uint256 nftId, IERC20 token) internal returns (uint256 feeAmount) {
        require(msg.sender == nftContract.extOwnerOf(nftId), Caller_Should_Own_The_NFT());
        
        bool isBiddingProjectTVSToMerge = NFTBelongsToBiddingProject[nftId];
        (Allocation storage TVSToMerge, IERC20 tokenToMerge) = isBiddingProjectTVSToMerge ?
        (biddingProjects[projectId].allocations[nftId], biddingProjects[projectId].token) :
        (rewardProjects[projectId].allocations[nftId], rewardProjects[projectId].token);
        require(address(token) == address(tokenToMerge), Different_Tokens());

        uint256 nbOfFlowsTVSToMerge = TVSToMerge.amounts.length;
        for (uint256 j = 0; j < nbOfFlowsTVSToMerge; j++) {
            uint256 fee = calculateFeeAmount(mergeFeeRate, TVSToMerge.amounts[j]);
@>       mergedTVS.amounts.push(TVSToMerge.amounts[j] - fee);
            mergedTVS.vestingPeriods.push(TVSToMerge.vestingPeriods[j]);
            mergedTVS.vestingStartTimes.push(TVSToMerge.vestingStartTimes[j]);
            mergedTVS.claimedSeconds.push(TVSToMerge.claimedSeconds[j]);
            mergedTVS.claimedFlows.push(TVSToMerge.claimedFlows[j]);
@>        feeAmount += fee;
        }
        nftContract.burn(nftId);
    }

```

### Internal Pre-conditions

None 

### External Pre-conditions

None

### Attack Path

None

### Impact

High - Because there is no need of any condition . This happen every time when user(msg.sender) calls the `mergeTVS` functionality 

### PoC

```
Final fee Amount look like this:
feeAmount = feeAmount + (fee (For MergeNfts))


For MergeNfts fee:
for (uint256 j = 0; j < nbOfFlowsTVSToMerge; j++) {
      feeAmount  = feeAmount  + fee[i] (Fee for every merging Fee)
}

Final Look of FeeAmount:

feeAmount  = feeAmount + (feeAmount + fee(1) + fee(2) + fee(3)+ ....)
```

Here we acn see there double account of `feeAmount` that is first fee that is accounted 

### Mitigation

None


## Title of Finding 3
[Medium - 🟠]In Contract ERC721A.sol function `_transfer` missing check for burned `tokenId` Still in `circulation loss for Sender, Receiver , Protocol`

### Summary

In Contract `ERC721A.sol` function  `_transfer` missing check for burned `tokenId`. This can lead to transfer of the burned tokenId to other user and there also decrease in balance of the sender `_addressData[from].balance -= 1` and increase in receiver balance `_addressData[to].balance += 1` 

This could lead to many issue like locked  one TokenID in the Contract forever and imaginary ownership of the burned TokenId that is not good for the users of the Protocol . There is should be check that we cannot transfer the `tokenOwnership.burned = true`  cannot be transferred direct revert should be implemented and at  burning of tokenId there is no change in the owner.

```solidity
function _transfer(address from, address to, uint256 tokenId) private {
        TokenOwnership memory prevOwnership = _ownershipOf(tokenId);

        if (prevOwnership.addr != from) revert TransferFromIncorrectOwner();

        bool isApprovedOrOwner =
            (_msgSender() == from || isApprovedForAll(from, _msgSender()) || getApproved(tokenId) == _msgSender());


        // ... skip 


        unchecked {
 @>           _addressData[from].balance -= 1;
 @>          _addressData[to].balance += 1;

            TokenOwnership storage currSlot = _ownerships[tokenId];
  @>          currSlot.addr = to;
            currSlot.startTimestamp = uint64(block.timestamp);

            // If the ownership slot of tokenId+1 is not explicitly set, that means the transfer initiator owns it.
            // Set the slot of tokenId+1 explicitly in storage to maintain correctness for ownerOf(tokenId+1) calls.
            uint256 nextTokenId = tokenId + 1;
            TokenOwnership storage nextSlot = _ownerships[nextTokenId];
            if (nextSlot.addr == address(0)) {
                // This will suffice for checking _exists(nextTokenId),
                // as a burned slot cannot contain the zero address.
                if (nextTokenId != _currentIndex) {
                    nextSlot.addr = from;
                    nextSlot.startTimestamp = prevOwnership.startTimestamp;
                }
            }
        }

        emit Transfer(from, to, tokenId);
        _afterTokenTransfers(from, to, tokenId, 1);
    }
```


```solidity
function _burn(uint256 tokenId, bool approvalCheck) internal virtual {
        TokenOwnership memory prevOwnership = _ownershipOf(tokenId);

        address from = prevOwnership.addr;

        // ... Skip 

        unchecked {
            AddressData storage addressData = _addressData[from];
@>            addressData.balance -= 1;
            addressData.numberBurned += 1;

            // Keep track of who burned the token, and the timestamp of burning.
            TokenOwnership storage currSlot = _ownerships[tokenId];
@>            currSlot.addr = from;
            currSlot.startTimestamp = uint64(block.timestamp);
            currSlot.burned = true; // This correct 

           // .. SKIP 
        }
```

### Root Cause

Missing check in the `_transfer(...) ` for the burned 

```solidity
require(!prevOwnership.burned ,"tokenId is already burned");
```

### Internal Pre-conditions

None

### External Pre-conditions

None

### Attack Path

None

### Impact

Medium - Loss for the Sender , Receiver , and the Protocol because the burned `tokenId` is Still in circulation in the Protocol In Future owner can take profit from it 

### PoC

_No response_

### Mitigation

```diff
function _transfer(address from, address to, uint256 tokenId) private {
        TokenOwnership memory prevOwnership = _ownershipOf(tokenId);

        if (prevOwnership.addr != from) revert TransferFromIncorrectOwner();

+        require(!prevOwnership.burned ,"tokenId is already burned");

        bool isApprovedOrOwner =
            (_msgSender() == from || isApprovedForAll(from, _msgSender()) || getApproved(tokenId) == _msgSender());

        if (!isApprovedOrOwner) revert TransferCallerNotOwnerNorApproved();
        if (to == address(0)) revert TransferToZeroAddress();

        _beforeTokenTransfers(from, to, tokenId, 1);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId, from);

        // Underflow of the sender's balance is impossible because we check for
        // ownership above and the recipient's balance can't realistically overflow.
        // Counter overflow is incredibly unrealistic as tokenId would have to be 2**256.
        unchecked {
            _addressData[from].balance -= 1;
            _addressData[to].balance += 1;

            TokenOwnership storage currSlot = _ownerships[tokenId];
            currSlot.addr = to;
            currSlot.startTimestamp = uint64(block.timestamp);

            // If the ownership slot of tokenId+1 is not explicitly set, that means the transfer initiator owns it.
            // Set the slot of tokenId+1 explicitly in storage to maintain correctness for ownerOf(tokenId+1) calls.
            uint256 nextTokenId = tokenId + 1;
            TokenOwnership storage nextSlot = _ownerships[nextTokenId];
            if (nextSlot.addr == address(0)) {
                // This will suffice for checking _exists(nextTokenId),
                // as a burned slot cannot contain the zero address.
                if (nextTokenId != _currentIndex) {
                    nextSlot.addr = from;
                    nextSlot.startTimestamp = prevOwnership.startTimestamp;
                }
            }
        }

        emit Transfer(from, to, tokenId);
        _afterTokenTransfers(from, to, tokenId, 1);
    }

```
## Title of Finding 4 
[Low- 🟢] Missing __UUPSUpgradeable_init() call in AlignerzVesting.sol initialization

### Summary

The `AlignerzVesting.sol.initialize()` function inherits from UUPSUpgradeable but does not call `__UUPSUpgradeable_init()` during initialization:

```solidity
function initialize(address _nftContract) public initializer {
        __Ownable_init(msg.sender);
        __FeesManager_init();
        __WhitelistManager_init();
        require(_nftContract != address(0), Zero_Address());
        nftContract = IAlignerzNFT(_nftContract);
        vestingPeriodDivisor = 2_592_000; // Set default vesting period multiples to 1 month (2592000 seconds)
    }
```

While UUPSUpgradeable in recent versions may not require explicit initialization, the inconsistent pattern compared to other initializer calls in the other contracts of the protocol, creates potential confusion.

### Root Cause

Missing `__UUPSUpgradeable_init()`

### Internal Pre-conditions

None

### External Pre-conditions

None

### Attack Path

None

### Impact

Low or Medium

### PoC

https://solodit.cyfrin.io/issues/l-06-missing-__uupsupgradeable_init-call-in-algebravaultfactory-initialization-pashov-audit-group-none-kittenswap_2025-07-31-markdown

### Mitigation

```diff
function initialize(address _nftContract) public initializer {
        __Ownable_init(msg.sender);
        __FeesManager_init();
        __WhitelistManager_init();
+       __UUPSUpgradeable_init()`
        require(_nftContract != address(0), Zero_Address());
        nftContract = IAlignerzNFT(_nftContract);
        vestingPeriodDivisor = 2_592_000; // Set default vesting period multiples to 1 month (2592000 seconds)
    }
```
