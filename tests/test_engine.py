"""Tests for the analysis engine end-to-end pipeline."""

from pathlib import Path

from openaudit.analyzer.engine import AnalysisEngine
from openaudit.utils.types import ContractSource

VULNERABLE_SOURCE = """\
pragma solidity ^0.8.0;

contract VulnBank {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
"""


def test_engine_returns_findings():
    source = ContractSource(path=Path("test.sol"), content=VULNERABLE_SOURCE)
    engine = AnalysisEngine()
    findings = engine.analyze(source)
    assert len(findings) >= 1
    rule_ids = {f.rule_id for f in findings}
    assert "reentrancy" in rule_ids


def test_engine_findings_sorted_by_line():
    source = ContractSource(path=Path("test.sol"), content=VULNERABLE_SOURCE)
    engine = AnalysisEngine()
    findings = engine.analyze(source)
    lines = [f.line for f in findings if f.line]
    assert lines == sorted(lines)
