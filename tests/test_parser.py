"""Tests for the Solidity parser."""

from openaudit.analyzer.parser import NodeKind, get_functions, parse_source


SAMPLE_CONTRACT = """\
pragma solidity ^0.8.0;

contract Example {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
"""


def test_parse_finds_contract():
    nodes = parse_source(SAMPLE_CONTRACT)
    contracts = [n for n in nodes if n.kind == NodeKind.CONTRACT]
    assert len(contracts) == 1
    assert contracts[0].name == "Example"


def test_parse_finds_functions():
    nodes = parse_source(SAMPLE_CONTRACT)
    funcs = get_functions(nodes)
    func_names = {f.name for f in funcs}
    assert "deposit" in func_names
    assert "withdraw" in func_names


def test_parse_finds_external_call():
    nodes = parse_source(SAMPLE_CONTRACT)
    funcs = get_functions(nodes)
    withdraw = next(f for f in funcs if f.name == "withdraw")
    calls = [c for c in withdraw.children if c.kind == NodeKind.EXTERNAL_CALL]
    assert len(calls) >= 1
    assert any(".call" in c.content for c in calls)


def test_parse_finds_state_write():
    nodes = parse_source(SAMPLE_CONTRACT)
    funcs = get_functions(nodes)
    withdraw = next(f for f in funcs if f.name == "withdraw")
    writes = [c for c in withdraw.children if c.kind == NodeKind.STATE_WRITE]
    assert len(writes) >= 1


def test_parse_empty_source():
    nodes = parse_source("")
    assert nodes == []
