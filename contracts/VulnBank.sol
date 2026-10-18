// SPDX-License-Identifier: MIT
// Synthetic demo contract (written for AuditGraph). DO NOT DEPLOY.
pragma solidity 0.8.20;

contract VulnBank {
    mapping(address => uint256) public balances;
    address public immutable treasury;
    uint256 public fees;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _treasury) {
        treasury = _treasury;
        owner = msg.sender;
    }

    function deposit() external payable {
        uint256 fee = msg.value / 100;
        fees += fee;
        balances[msg.sender] += msg.value - fee;
    }

    // EXPECTED: reentrancy (external call before the balance write)
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    // EXPECTED: reentrancy (same bug, second function; NOT changed in v2)
    function withdrawAll() external {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    // EXPECTED: reentrancy candidate that a human should DISMISS:
    // the callee is an immutable, trusted treasury address.
    function sweepFees() public {
        uint256 amt = fees;
        (bool ok, ) = treasury.call{value: amt}("");
        require(ok, "sweep failed");
        fees = 0;
    }

    // Guarded caller of sweepFees: used to demo the one-hop "callers" impact set.
    function rebalance() external onlyOwner {
        sweepFees();
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
