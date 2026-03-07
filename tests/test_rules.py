"""Tests for vulnerability detection rules."""

from openaudit.analyzer.parser import parse_source
from openaudit.rules.reentrancy import ReentrancyRule
from openaudit.rules.unchecked_call import UncheckedCallRule
from openaudit.utils.types import ContractSource, Severity

VULNERABLE_SOURCE = """\
pragma solidity ^0.8.0;

contract VulnBank {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function unsafeSend(address payable to, uint256 amount) external {
        to.call{value: amount}("");
    }
}
"""

SAFE_SOURCE = """\
pragma solidity ^0.8.0;

contract SafeBank {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
"""


def _make_source(content: str) -> ContractSource:
    from pathlib import Path

    return ContractSource(path=Path("test.sol"), content=content)


class TestReentrancyRule:
    def test_detects_reentrancy(self):
        source = _make_source(VULNERABLE_SOURCE)
        ast = parse_source(source.content)
        rule = ReentrancyRule()
        findings = rule.run(ast, source)
        assert len(findings) >= 1
        assert findings[0].rule_id == "reentrancy"
        assert findings[0].severity == Severity.HIGH

    def test_no_false_positive_on_safe_code(self):
        source = _make_source(SAFE_SOURCE)
        ast = parse_source(source.content)
        rule = ReentrancyRule()
        findings = rule.run(ast, source)
        assert len(findings) == 0

    def test_finding_has_metadata(self):
        source = _make_source(VULNERABLE_SOURCE)
        ast = parse_source(source.content)
        findings = ReentrancyRule().run(ast, source)
        assert findings[0].metadata["function"] == "withdraw"


class TestUncheckedCallRule:
    def test_detects_unchecked_call(self):
        source = _make_source(VULNERABLE_SOURCE)
        ast = parse_source(source.content)
        rule = UncheckedCallRule()
        findings = rule.run(ast, source)
        assert len(findings) >= 1
        assert findings[0].rule_id == "unchecked-call"
        assert findings[0].severity == Severity.MEDIUM

    def test_no_finding_when_checked(self):
        source = _make_source(SAFE_SOURCE)
        ast = parse_source(source.content)
        rule = UncheckedCallRule()
        findings = rule.run(ast, source)
        assert len(findings) == 0
