// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableBank
/// @notice Intentionally vulnerable contract for testing OpenAudit AI.
/// Contains classic reentrancy and unchecked-call patterns.
contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // VULNERABILITY: Reentrancy — external call before state update.
    // The balance is zeroed out AFTER sending ETH, so a malicious
    // fallback can re-enter withdraw() and drain the contract.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, amount);
    }

    // VULNERABILITY: Unchecked call — return value is ignored.
    function unsafeSend(address payable to, uint256 amount) external {
        to.call{value: amount}("");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
