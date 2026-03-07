// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SafeBank
/// @notice Correctly implemented bank using checks-effects-interactions.
/// This contract should produce zero findings from OpenAudit AI.
contract SafeBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // SAFE: State is updated BEFORE the external call.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, amount);

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
