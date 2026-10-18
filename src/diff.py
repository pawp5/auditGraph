"""Re-audit memory: what changed, what it impacts, and human triage.

Persistent agent memory lives on the graph itself:
  Function.prev_hash / body_hash  - previous vs current body (set at ingest)
  Function.audited_hash           - body hash at the last completed audit
  Finding.status / triage_note    - verdicts and human decisions, never reset by re-scans
"""
from datetime import datetime, timezone

# Changed since last audit (new, or body differs), plus every ONE-HOP caller, because a
# caller's behaviour depends on the callee it reaches through CALLS.
IMPACT_SET = """
MATCH (f:Function)
WHERE f.removed_in IS NULL
  AND (f.audited_hash IS NULL OR f.audited_hash <> f.body_hash)
OPTIONAL MATCH (caller:Function)-[:CALLS]->(f)
WITH collect(DISTINCT f.id) + collect(DISTINCT caller.id) AS ids
UNWIND ids AS id
RETURN DISTINCT id
"""

# What changed in the latest ingest of a contract (for display): prev vs current hash.
VERSION_DIFF = """
MATCH (c:Contract)-[:DECLARES]->(f:Function)
WHERE f.version = $v AND c.version = $v
RETURN c.id, f.id, CASE WHEN f.prev_hash IS NULL THEN 'new' ELSE 'changed' END AS change
ORDER BY f.id
"""

MARK_AUDITED = """
MATCH (f:Function) WHERE f.id IN $ids SET f.audited_hash = f.body_hash
"""

VALID_STATUSES = {"candidate", "confirmed", "dismissed"}


def impact_set(g) -> list[str]:
    return sorted(r[0] for r in g.query(IMPACT_SET).result_set)


def version_diff(g, version: str) -> list[tuple]:
    return [tuple(r) for r in g.query(VERSION_DIFF, {"v": version}).result_set]


def mark_audited(g, ids: list[str]) -> None:
    g.query(MARK_AUDITED, {"ids": ids})


def triage(g, finding_id: str, status: str, note: str = "") -> bool:
    """Human decision. `triaged_by = 'human'` lets the Verifier skip it and the Reporter cite it."""
    if status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {sorted(VALID_STATUSES)}")
    res = g.query("""MATCH (fd:Finding {id: $id})
                     SET fd.status = $s, fd.triage_note = $n, fd.triaged_by = 'human', fd.triaged_at = $t
                     RETURN fd.id""",
                  {"id": finding_id, "s": status, "n": note,
                   "t": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    return bool(res.result_set)
