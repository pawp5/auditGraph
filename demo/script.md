# AuditGraph demo video script (about 3:30)

Before recording: `docker compose up -d`, then `python -m src.main reset`. Open the FalkorDB Browser at http://localhost:3000 and select graph `auditgraph`. Use a terminal with a large font. Export `ANTHROPIC_API_KEY` and `LLM_MODEL` if you want live LLM verdicts; otherwise use `--no-llm` everywhere.

| Time | Say | Do / show on screen |
|---|---|---|
| 0:00–0:20 | "AuditGraph audits smart contracts by turning them into a graph in FalkorDB. Detection is Cypher, every finding carries its proof path, and three agents coordinate only through the graph." | README title + architecture diagram |
| 0:20–0:45 | "First we ingest four contracts. Slither parses them; we store functions, state, calls and modifiers. Execution order sits on the edges." | `for f in VulnBank Wallet UncheckedSend SafeBank; do python -m src.main ingest contracts/$f.sol; done` |
| 0:45–1:15 | "Here is VulnBank.withdraw in the graph. Note seq: the external call is seq 2, the balance write is seq 5." | Browser: `MATCH (f:Function {name:'withdraw', contract:'VulnBank'})-[r]->(x) RETURN f,r,x` and click the MAKES and WRITES edges to show `seq` |
| 1:15–1:40 | "That makes reentrancy one comparison: call seq less than write seq, no reentrancy guard." | Browser or editor: show the reentrancy query in `src/queries.py` and run it in the Browser (replace `$scope` with `null`) |
| 1:40–2:10 | "Now the agents. The Scanner writes candidate findings, and the Verifier pulls each one's subgraph and returns validated JSON. SafeBank, the correct version, produces zero findings." | `python -m src.main audit --no-llm` (or without the flag). Point at the 7 findings, none for SafeBank |
| 2:10–2:30 | "The Wallet bug is indirect: initialize calls an internal function that writes admin. A variable-length path query finds it and ignores the guarded changeAdmin path." | Browser: `MATCH p=(:Function {name:'initialize'})-[:CALLS*]->()-[:WRITES]->(s) RETURN p` |
| 2:30–2:45 | "sweepFees pays a trusted immutable treasury, so as a human I dismiss it. That decision is stored on the graph." | `python -m src.main triage AG-8d7038 dismissed --note "trusted immutable treasury"` |
| 2:45–3:15 | "Now v2: withdraw is fixed, sweepFees changed, transfer is new. Only those, plus rebalance, which calls sweepFees, get re-checked. withdraw is resolved, and sweepFees stays dismissed." | `python -m src.main ingest contracts/VulnBank_v2.sol --version v2` then `python -m src.main audit --no-llm`. Highlight `Scope: 4 functions`, `resolved=1`, and the dismissed row |
| 3:15–3:35 | "The report gives each finding the Cypher query that proves it, the seq-numbered evidence path, the verifier reasoning, and the historical exploit it resembles, like The DAO." | `python -m src.main report` and scroll `report.md` to the reentrancy section |
| 3:35–3:45 | "Remove FalkorDB and nothing works. Detection, coordination and memory are all graph operations. Thanks!" | README "Why the graph is essential" table |
