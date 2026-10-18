# Expected findings (ground truth for tests)

| Contract | Function | Pattern | Notes |
|---|---|---|---|
| VulnBank (v1) | withdraw | reentrancy | fixed in v2 |
| VulnBank (v1, v2) | withdrawAll | reentrancy | unchanged in v2, never re-scanned |
| VulnBank (v1, v2) | sweepFees | reentrancy | true pattern match but trusted callee: demo of human DISMISS |
| Wallet | setOwner | missing_access_control_direct | |
| Wallet | initialize -> _setAdmin | missing_access_control_path | changeAdmin -> _setAdmin is guarded: no finding |
| UncheckedSend | withdraw | unchecked_low_level_call | `.call` result discarded |
| UncheckedSend | payout | unchecked_low_level_call | `.send` result discarded |
| SafeBank | (none) | none | must be ZERO findings |

v2 diff: changed = withdraw, sweepFees; new = transfer; one-hop callers = rebalance (calls sweepFees).
Not re-checked: deposit, withdrawAll, getBalance.
