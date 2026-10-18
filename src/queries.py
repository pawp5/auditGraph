"""Vulnerability patterns as Cypher. This file IS the detection engine.

Every query takes a `$scope` parameter: null = whole graph, or a list of Function ids
(the re-audit impact set computed by diff.py). Each returns one row per finding:
    fn       - anchor Function id (identity of the finding)
    path     - list of Function ids that make up the evidence (EVIDENCED_BY targets)
    evidence - list of maps describing the concrete edges that prove it
"""

ENTRY = "['public', 'external']"

PATTERNS = {
    "reentrancy": {
        "swc_id": "SWC-107",
        "severity": "High",
        "title": "Reentrancy: external call before state write",
        # Why a graph problem: execution order is stored as `seq` on edges, so
        # "call happens before write" is a comparison between two edges of the same node.
        "cypher": f"""
MATCH (f:Function)-[m:MAKES]->(e:ExternalCall), (f)-[w:WRITES]->(s:StateVar)
WHERE f.visibility IN {ENTRY}
  AND m.seq < w.seq                                   // call BEFORE write
  AND NOT e.method IN ['send', 'transfer']            // 2300-gas stipend cannot re-enter
  AND NOT (f)-[:HAS_MODIFIER]->(:Modifier {{is_reentrancy_guard: true}})
  AND ($scope IS NULL OR f.id IN $scope)
RETURN f.id AS fn, [f.id] AS path,
       collect(DISTINCT {{call: e.method, call_seq: m.seq, line: e.line,
                         write: s.name, write_seq: w.seq}}) AS evidence
""",
        "fix": "Apply checks-effects-interactions (update state before the external call) "
               "and/or add a nonReentrant guard (e.g. OpenZeppelin ReentrancyGuard).",
    },
    "missing_access_control_direct": {
        "swc_id": "SWC-105/SWC-106",
        "severity": "Critical",
        "title": "Unguarded entry point writes a privileged variable",
        "cypher": f"""
MATCH (f:Function)-[w:WRITES]->(s:StateVar {{privileged: true}})
WHERE f.visibility IN {ENTRY} AND NOT f.guarded
  AND ($scope IS NULL OR f.id IN $scope)
RETURN f.id AS fn, [f.id] AS path,
       collect(DISTINCT {{write: s.name, write_seq: w.seq}}) AS evidence
""",
        "fix": "Restrict the function with an access-control modifier (e.g. onlyOwner) "
               "or an explicit require(msg.sender == owner).",
    },
    "missing_access_control_path": {
        "swc_id": "SWC-105/SWC-106",
        "severity": "Critical",
        "title": "Unguarded call path reaches a privileged write",
        # Why a graph problem: reachability through an arbitrary-depth call chain, with
        # a predicate (no guard) that must hold on EVERY node of the path.
        "cypher": f"""
MATCH p = (entry:Function)-[:CALLS*1..6]->(writer:Function),
      (writer)-[w:WRITES]->(s:StateVar {{privileged: true}})
WHERE entry.visibility IN {ENTRY}
  AND none(n IN nodes(p) WHERE n.guarded)             // no guard anywhere on the path
  AND ($scope IS NULL OR any(n IN nodes(p) WHERE n.id IN $scope))
WITH entry, writer, s, w, p ORDER BY length(p)
WITH entry, writer, s, w, collect(p)[0] AS shortest
RETURN entry.id + '->' + writer.id AS fn, [n IN nodes(shortest) | n.id] AS path,
       [{{write: s.name, write_seq: w.seq, via: [n IN nodes(shortest) | n.name]}}] AS evidence
""",
        "fix": "Guard the public entry point, or move the access check into the internal "
               "function that performs the privileged write.",
    },
    "unchecked_low_level_call": {
        "swc_id": "SWC-104",
        "severity": "Medium",
        "title": "Return value of low-level call is not checked",
        "cypher": """
MATCH (f:Function)-[m:MAKES]->(e:ExternalCall {kind: 'low_level', checked: false})
WHERE ($scope IS NULL OR f.id IN $scope)
RETURN f.id AS fn, [f.id] AS path,
       collect(DISTINCT {call: e.method, call_seq: m.seq, line: e.line}) AS evidence
""",
        "fix": "Capture and check the success flag: (bool ok, ) = to.call{...}(\"\"); require(ok);",
    },
}

# Risk prioritisation: PageRank over the CALLS graph. Functions many paths flow into
# (shared internals like _setAdmin) rank higher and are verified first.
RISK_RANKING = """
CALL algo.pageRank('Function', 'CALLS') YIELD node, score
RETURN node.id AS fn, score ORDER BY score DESC
"""
# Fallback if the algo.* procedures are unavailable: degree centrality in plain Cypher.
RISK_RANKING_FALLBACK = """
MATCH (f:Function) OPTIONAL MATCH (f)-[r:CALLS]-()
RETURN f.id AS fn, toFloat(count(r)) AS score ORDER BY score DESC
"""


def run_pattern(g, name: str, scope: list[str] | None = None) -> list[dict]:
    res = g.query(PATTERNS[name]["cypher"], {"scope": scope})
    return [dict(zip(["fn", "path", "evidence"], row)) for row in res.result_set]


def risk_ranking(g) -> dict[str, float]:
    try:
        rows = g.query(RISK_RANKING).result_set
    except Exception:
        rows = g.query(RISK_RANKING_FALLBACK).result_set
    return {fn: score for fn, score in rows}
