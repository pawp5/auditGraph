# Explain it to the judges (cheat sheet)

## 1. The graph model in one breath
Contracts DECLARE Functions. Functions CALL Functions, READ/WRITE StateVars, MAKE ExternalCalls, and HAVE_MODIFIER Modifiers. Findings are nodes too: EVIDENCED_BY the functions that prove them, MATCHING a Pattern, which was SEEN_IN historical Exploits. Code, findings and history live in one graph, so a single traversal goes from a bug to the line of code to The DAO.

## 2. Why `seq` is on edges
Reentrancy is about *order*: an external call happens before the state update. A node property can't express order, because one state variable is read and written at different points in the same function. So each READS/WRITES/MAKES edge stores the index of the statement it came from (statements ranked by source offset). The bug then becomes a comparison of two edges: `m.seq < w.seq`.

## 3. Queries, line by line
**Reentrancy**
- `MATCH (f)-[m:MAKES]->(e:ExternalCall), (f)-[w:WRITES]->(s)`: the same function both calls out and writes state.
- `f.visibility IN ['public','external']`: an attacker can enter it.
- `m.seq < w.seq`: the call happens before the write (the core of the bug).
- `NOT e.method IN ['send','transfer']`: these forward only 2300 gas, which is not enough to re-enter.
- `NOT (f)-[:HAS_MODIFIER]->(:Modifier {is_reentrancy_guard:true})`: no nonReentrant lock.
- `$scope`: lets the re-audit restrict the scan to the impact set.
- `RETURN … evidence`: the seq numbers and line, stored on the Finding as proof.

**Direct access control.** Public/external, `NOT f.guarded`, WRITES a `privileged` var. That's it.

**Path access control**
- `p = (entry)-[:CALLS*1..6]->(writer)`: any call chain of 1–6 hops.
- `(writer)-[:WRITES]->(s {privileged:true})`: it ends in a privileged write.
- `none(n IN nodes(p) WHERE n.guarded)`: no function anywhere on the chain checks the caller.
- `ORDER BY length(p)` … `collect(p)[0]`: report the shortest proof path.

**Unchecked call.** `MAKES` an ExternalCall with `kind:'low_level', checked:false`. `checked` was computed at ingest by following the success bool through SlithIR.

**PageRank.** `CALL algo.pageRank('Function','CALLS')`: shared internals that many callers flow into rank higher, and the Verifier spends its LLM budget on them first.

**Impact set.** Functions whose `audited_hash <> body_hash` (or new), plus `OPTIONAL MATCH (caller)-[:CALLS]->(f)`.

## 4. How the agents coordinate via graph state
- The Scanner only writes `Finding {status:'candidate'}` (MERGE, ON CREATE SET).
- The Verifier only reads candidates and writes verdict/status/reasoning/severity.
- The Reporter only reads.
- The human writes status + triage_note.

They never call each other, so any one of them can run alone, later, or in another process. Re-running is safe because everything is MERGE-idempotent.

## 5. Likely questions
- **"Couldn't this be a Python dict?"** Detection relies on variable-length traversal with a per-node predicate, edge-ordered comparisons, reverse-neighbourhood impact analysis and PageRank. The load-bearing test edits one edge in FalkorDB and the finding flips.
- **"Why Slither, then?"** Slither parses and gives us SlithIR. We use it as a compiler front end only. None of Slither's detectors are used; all detection is our Cypher.
- **"How do you stop LLM hallucination?"** The LLM never finds bugs. It only judges graph-proven candidates. Its output is schema-validated and retried on error, and invalid output is never written. Evidence and query always come from the graph, not from the LLM.
- **"What about false positives?"** The Verifier and human triage. Dismissals are memory: they survive re-scans and upgrades (tested).
- **"Why does dismissed stay dismissed?"** Finding ids are deterministic (hash of pattern + function), and status is only set in `ON CREATE`.
- **"Why one-hop callers?"** A caller's behaviour changes when its callee changes. Deeper hops are a one-line change (`CALLS*1..k`).
- **"Weakest part?"** The heuristics for guarded/privileged/checked and source-order `seq`. See README Limitations.
- **"Does it scale?"** Writes are batched with UNWIND, `id` is indexed on every label, and re-audits touch only the impact set.
