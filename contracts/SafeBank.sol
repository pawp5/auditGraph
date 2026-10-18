// SPDX-License-Identifier: MIT
// Synthetic demo contract: the correct version of the patterns above. MUST yield ZERO findings.
pragma solidity 0.8.20;

contract SafeBank {
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Checks-effects-interactions AND a reentrancy guard; return value checked.
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero");
        owner = newOwner;
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
