// SPDX-License-Identifier: MIT
// Synthetic demo contract (written for AuditGraph). DO NOT DEPLOY.
pragma solidity 0.8.20;

contract Wallet {
    address public owner;
    address public admin;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // EXPECTED: missing_access_control_direct (anyone can take ownership)
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    // EXPECTED: missing_access_control_path (initialize -> _setAdmin -> WRITES admin)
    function initialize() external {
        _setAdmin(msg.sender);
    }

    // NOT a finding: same internal write, but the entry point is guarded.
    function changeAdmin(address newAdmin) external onlyOwner {
        _setAdmin(newAdmin);
    }

    function _setAdmin(address a) internal {
        admin = a;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function emergencyWithdraw(address payable to) external onlyAdmin {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "failed");
    }
}
