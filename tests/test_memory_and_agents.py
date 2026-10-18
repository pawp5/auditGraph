"""Memory, re-audit and agent tests. All state lives in (and is read back from) FalkorDB."""
import json

import pytest

from src import diff
from src.agents import Reporter, Scanner, Verifier, finding_id, parse_verdict
from src.ingest import ingest_file
from src.queries import run_pattern


def audit(g, version):
    scope = diff.impact_set(g)
    Scanner(g).run(scope, version)
    Verifier(g, use_llm=False).run()
    diff.mark_audited(g, scope)
    return scope


def status(g, fid):
    return g.query("MATCH (fd:Finding {id:$id}) RETURN fd.status, fd.resolved_in, fd.triage_note",
                   {"id": fid}).result_set[0]


def test_reaudit_checks_only_changed_functions_and_callers(g):
    ingest_file(g, "contracts/VulnBank.sol", "v1")
    audit(g, "v1")
    ingest_file(g, "contracts/VulnBank_v2.sol", "v2")
    assert diff.impact_set(g) == [
        "VulnBank.rebalance()",                 # 1-hop caller of the changed sweepFees
        "VulnBank.sweepFees()",                 # changed
        "VulnBank.transfer(address,uint256)",   # new
        "VulnBank.withdraw(uint256)",           # changed (bug fixed)
    ]
    audit(g, "v2")
    assert diff.impact_set(g) == []             # nothing left to re-check
    # fixed bug is resolved; untouched vulnerable function keeps its confirmed verdict
    assert status(g, finding_id("reentrancy", "VulnBank.withdraw(uint256)"))[1] == "v2"
    assert status(g, finding_id("reentrancy", "VulnBank.withdrawAll()"))[:2] == ["confirmed", None]


def test_prev_hash_is_kept_on_upgrade(g):
    ingest_file(g, "contracts/VulnBank.sol", "v1")
    old = g.query("MATCH (f:Function {id:'VulnBank.withdraw(uint256)'}) RETURN f.body_hash").result_set[0][0]
    ingest_file(g, "contracts/VulnBank_v2.sol", "v2")
    prev, new, ver = g.query("MATCH (f:Function {id:'VulnBank.withdraw(uint256)'}) "
                             "RETURN f.prev_hash, f.body_hash, f.version").result_set[0]
    assert prev == old and new != old and ver == "v2"


def test_dismissed_survives_reaudit(g):
    ingest_file(g, "contracts/VulnBank.sol", "v1")
    audit(g, "v1")
    fid = finding_id("reentrancy", "VulnBank.sweepFees()")
    assert diff.triage(g, fid, "dismissed", "trusted treasury")
    ingest_file(g, "contracts/VulnBank_v2.sol", "v2")      # sweepFees changed -> re-scanned
    assert "VulnBank.sweepFees()" in diff.impact_set(g)
    audit(g, "v2")
    Scanner(g).run(None, "v2")                             # and a full re-scan for good measure
    assert status(g, fid) == ["dismissed", None, "trusted treasury"]
    assert "trusted treasury" in Reporter(g).render()


def test_graph_is_load_bearing(g):
    """Detection reads graph edges, not Python state: editing ONE edge property in
    FalkorDB flips the reentrancy verdict; deleting ONE CALLS edge kills the path finding."""
    ingest_file(g, "contracts/VulnBank.sol")
    ingest_file(g, "contracts/Wallet.sol")
    fn = "VulnBank.withdraw(uint256)"
    assert run_pattern(g, "reentrancy", [fn])
    g.query("MATCH (:Function {id:$f})-[w:WRITES]->(:StateVar {name:'balances'}) SET w.seq = 0", {"f": fn})
    assert run_pattern(g, "reentrancy", [fn]) == []        # write now 'before' the call
    assert run_pattern(g, "missing_access_control_path")
    g.query("MATCH (:Function {id:'Wallet.initialize()'})-[c:CALLS]->() DELETE c")
    assert run_pattern(g, "missing_access_control_path") == []


def test_parse_verdict_rejects_malformed():
    ok = parse_verdict('```json\n{"verdict":"real","status":"confirmed","reasoning":"r","severity":"high"}\n```')
    assert ok["severity"] == "High"
    for bad in ["not json", '{"verdict":"x","status":"maybe","reasoning":"r","severity":"High"}',
                '{"verdict":"x","status":"confirmed","reasoning":"","severity":"High"}',
                '{"verdict":"x","status":"confirmed","reasoning":"r","severity":"Huge"}']:
        with pytest.raises((ValueError, json.JSONDecodeError)):
            parse_verdict(bad)


def test_llm_verifier_retries_then_writes_valid_verdict(g, monkeypatch):
    """LLM path with a fake client: first reply malformed, second valid."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    ingest_file(g, "contracts/UncheckedSend.sol")
    Scanner(g).run()

    class Block:
        type = "text"
        def __init__(self, t): self.text = t

    replies = iter(['Sure! here it is', '{"verdict":"v","status":"dismissed","reasoning":"r","severity":"Low"}'] * 10)

    class FakeMessages:
        def create(self, **kw):
            return type("R", (), {"content": [Block(next(replies))]})

    v = Verifier.__new__(Verifier)
    v.g, v.use_llm, v.max_retries = g, True, 2
    v.client = type("C", (), {"messages": FakeMessages()})()
    assert v.run() == {"verified": 2, "errors": 0}
    rows = g.query("MATCH (fd:Finding) RETURN fd.status, fd.verified_by").result_set
    assert all(r == ["dismissed", "llm:test-model"] for r in rows)
