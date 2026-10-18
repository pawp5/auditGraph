// SPDX-License-Identifier: MIT
// Synthetic demo contract (written for AuditGraph). DO NOT DEPLOY.
pragma solidity 0.8.20;

contract UncheckedSend {
    address public owner;
    mapping(address => uint256) public credit;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        credit[msg.sender] += msg.value;
    }

    // EXPECTED: unchecked_low_level_call (state is zeroed first, so no reentrancy,
    // but if the call fails the user's credit is silently lost)
    function withdraw() external {
        uint256 amt = credit[msg.sender];
        credit[msg.sender] = 0;
        payable(msg.sender).call{value: amt}("");
    }

    // EXPECTED: unchecked_low_level_call (send() returns false instead of reverting)
    function payout(address payable to, uint256 amt) external onlyOwner {
        to.send(amt);
    }

    // NOT a finding: return value is checked.
    function safePayout(address payable to, uint256 amt) external onlyOwner {
        (bool ok, ) = to.call{value: amt}("");
        require(ok, "payout failed");
    }
}
