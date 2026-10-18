"""Detection is Cypher over FalkorDB: these tests run the real queries on real graphs."""
from src.ingest import ingest_file
from src.queries import PATTERNS, run_pattern


def all_findings(g):
    return {(name, r["fn"]) for name in PATTERNS for r in run_pattern(g, name)}


def test_vulnbank_reentrancy(g):
    ingest_file(g, "contracts/VulnBank.sol")
    assert all_findings(g) == {
        ("reentrancy", "VulnBank.withdraw(uint256)"),
        ("reentrancy", "VulnBank.withdrawAll()"),
        ("reentrancy", "VulnBank.sweepFees()"),
    }
    ev = run_pattern(g, "reentrancy", ["VulnBank.withdraw(uint256)"])[0]["evidence"][0]
    assert ev["call_seq"] < ev["write_seq"]  # the seq edges are the proof


def test_wallet_access_control_direct_and_path(g):
    ingest_file(g, "contracts/Wallet.sol")
    found = all_findings(g)
    assert ("missing_access_control_direct", "Wallet.setOwner(address)") in found
    assert ("missing_access_control_path", "Wallet.initialize()->Wallet._setAdmin(address)") in found
    # changeAdmin reaches the same write but is guarded: must NOT be reported
    assert not any("changeAdmin" in fn for _, fn in found)
    assert len(found) == 2


def test_unchecked_calls(g):
    ingest_file(g, "contracts/UncheckedSend.sol")
    assert all_findings(g) == {
        ("unchecked_low_level_call", "UncheckedSend.withdraw()"),
        ("unchecked_low_level_call", "UncheckedSend.payout(address,uint256)"),
    }


def test_safebank_has_zero_findings(g):
    ingest_file(g, "contracts/SafeBank.sol")
    assert all_findings(g) == set()
