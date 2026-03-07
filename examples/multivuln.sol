// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title MultiVuln
/// @notice Multiple vulnerability patterns for comprehensive testing.
contract MultiVuln {
    mapping(address => uint256) public deposits;
    mapping(address => bool) public authorized;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABILITY: Reentrancy via .call
    function withdrawAll() external {
        uint256 bal = deposits[msg.sender];
        require(bal > 0, "Nothing to withdraw");

        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "Failed");

        deposits[msg.sender] = 0;
    }

    // VULNERABILITY: Unchecked send
    function distribute(address payable[] calldata recipients, uint256 amount) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            recipients[i].send(amount);
        }
    }

    // VULNERABILITY: Reentrancy via .transfer is less risky (2300 gas)
    // but still flagged for awareness.
    function refund(address payable user) external {
        uint256 amt = deposits[user];
        user.transfer(amt);
        deposits[user] = 0;
    }
}
