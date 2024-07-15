## L-01 -  Discrepancies in the distribution of shares on match

When matching in `BidOrdersFacet::matchlowestSell`, `dittoShares` are increased based on the collateral used:

```solidity
File: BidOrdersFacet.sol
    function matchlowestSell(
        address asset,
        STypes.Order memory lowestSell,
        STypes.Order memory incomingBid,
        MTypes.Match memory matchTotal
    ) private {
        uint88 fillErc = incomingBid.ercAmount > lowestSell.ercAmount ? lowestSell.ercAmount : incomingBid.ercAmount;
        uint88 fillEth = lowestSell.price.mulU88(fillErc);

        if (lowestSell.orderType == O.LimitShort) {
            // Match short
>>>         uint88 colUsed = fillEth.mulU88(LibOrders.convertCR(lowestSell.shortOrderCR));
>>>         LibOrders.increaseSharesOnMatch(asset, lowestSell, matchTotal, colUsed);
...
...
    }
```

However, this is incorrect as it should use the order amount. The documentation describes:

> Users generate userShares (dittoMatchedShares) denominated in ETH-seconds, by the product of the Order amount (in ETH) and time until match (in seconds). Assets can be lost

It is recommended to change to the order amount.

```diff
    function matchlowestSell(
        address asset,
        STypes.Order memory lowestSell,
        STypes.Order memory incomingBid,
        MTypes.Match memory matchTotal
    ) private {
        uint88 fillErc = incomingBid.ercAmount > lowestSell.ercAmount ? lowestSell.ercAmount : incomingBid.ercAmount;
        uint88 fillEth = lowestSell.price.mulU88(fillErc);

        if (lowestSell.orderType == O.LimitShort) {
            // Match short
            uint88 colUsed = fillEth.mulU88(LibOrders.convertCR(lowestSell.shortOrderCR));
--          LibOrders.increaseSharesOnMatch(asset, lowestSell, matchTotal, colUsed);
++          LibOrders.increaseSharesOnMatch(asset, lowestSell, matchTotal, fillEth);
...
...
```