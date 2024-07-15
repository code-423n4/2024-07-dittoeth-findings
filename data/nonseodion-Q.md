## L1 Users can transfer balances around and use it to propose withdrawals in yDUSD

### Description
When a proposal to withdraw is made in yDUSD the user's balance is checked to ensure he has the amount he says he wants to withdraw. After the proposal, the user can keep transferring the balance to multiple accounts and proposing. This may allow the user to withdraw at any time including withdrawing recent deposits.

```
    function proposeWithdraw(uint104 amountProposed) public {
        if (amountProposed <= 1) revert Errors.ERC4626AmountProposedTooLow();
        WithdrawStruct storage withdrawal = withdrawals[msg.sender];

        if (withdrawal.timeProposed > 0) revert Errors.ERC4626ExistingWithdrawalProposal();

        if (amountProposed > maxWithdraw(msg.sender)) revert Errors.ERC4626WithdrawMoreThanMax();

        checkDiscountWindow();

        withdrawal.timeProposed = uint40(block.timestamp);
        withdrawal.amountProposed = amountProposed;
    }
```

With the expiry of 45 days and a wait time of 7 days, he will need to repeat this every 38 days (45-7) to ensure he may have instant withdrawals.

### Fix
The sponsor may consider locking transfers of proposed amounts.

## Users may not be able to empty their balances easily.

### Description
When a proposal is made, a user has to wait for 45+7 days before he can withdraw. Within that time if a discount fee is applied the user won't be able to withdraw the additional reward if he is making a full withdrawal since his `amountProposed` is fixed.

```
    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
        WithdrawStruct storage withdrawal = withdrawals[msg.sender];
❌      uint256 amountProposed = withdrawal.amountProposed;
        uint256 timeProposed = withdrawal.timeProposed;

```

### Fix
The sponsor may consider enabling withdrawals with shares also.

## A malicious user may prevent withdrawals by selling at a discount and buying them himself.

### Description

Before a user can withdraw `checkDiscountWindow()` checks if there has been any recent discount match for the past 5 minutes (C.DISCOUNT_WAIT_TIME). If there are any, withdrawal is reverted.

```
    function checkDiscountWindow() internal {
        //Note: Will upgrade contract to diamond in the future
❌      bool WithinDiscountWindow = IDiamond(payable(diamond)).getTimeSinceDiscounted(dusd) < C.DISCOUNT_WAIT_TIME;
        bool isDiscounted = IDiamond(payable(diamond)).getInitialDiscountTime(dusd) > 1 seconds;
❌      if (isDiscounted || WithinDiscountWindow) revert Errors.ERC4626CannotWithdrawBeforeDiscountWindowExpires();
    }
```

A malicious user can open discounted asks and fill them himself with bids or vice versa. If he keeps at it every 5 minutes, he can DOS users from withdrawing. But since Ditto will be deploying on mainnet this will be cost-prohibitive because of transaction fees. He may still be able to target the withdrawals of a specific set of users.

### Fix
It seems the check is added to prevent the pool from being empty when discounts occur to prevent loss of DUSD minted. The protocol can decide to commit a withdrawable amount of DUSD to the yDUSD pool and get rid of the check.