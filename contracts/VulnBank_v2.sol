// SPDX-License-Identifier: MIT
// Synthetic demo contract: upgraded version of VulnBank. DO NOT DEPLOY.
// Changes vs v1:  withdraw FIXED (checks-effects-interactions)
//                 sweepFees CHANGED (emits an event; still has the dismissed pattern)
//                 transfer  NEW
// Unchanged:      deposit, withdrawAll (still vulnerable), rebalance, getBalance
pragma solidity 0.8.20;

contract VulnBank {
    mapping(address => uint256) public balances;
    address public immutable treasury;
    uint256 public fees;
    address public owner;

    event FeesSwept(uint256 amount);

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

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function withdrawAll() external {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    function sweepFees() public {
        uint256 amt = fees;
        (bool ok, ) = treasury.call{value: amt}("");
        require(ok, "sweep failed");
        fees = 0;
        emit FeesSwept(amt);
    }

    function rebalance() external onlyOwner {
        sweepFees();
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
