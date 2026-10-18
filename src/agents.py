"""Scanner, Verifier and Reporter.

The agents never call each other or pass objects. Each one reads from and writes to the
FalkorDB graph only:
  Scanner  : pattern queries -> MERGE (:Finding {status:'candidate'})
  Verifier : reads candidates  -> writes verdict/status/reasoning/severity
  Reporter : reads confirmed/dismissed findings + Pattern/Exploit KG -> report.md
So any agent can be re-run, crash, or run in another process/session and pick up from
graph state. That shared state is also the persistent memory across audits.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone

from . import exploits
from .queries import PATTERNS, risk_ranking, run_pattern

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


def finding_id(pattern: str, anchor: str) -> str:
    # Deterministic: the same bug in the same function always maps to the same node,
    # which is what makes MERGE-based memory (and "dismissed stays dismissed") work.
    return "AG-" + hashlib.sha1(f"{pattern}:{anchor}".encode()).hexdigest()[:6]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ======================================================================= Scanner
class Scanner:
    def __init__(self, g):
        self.g = g

    def run(self, scope: list[str] | None = None, version: str | None = None) -> dict:
        exploits.seed(self.g)
        rank = risk_ranking(self.g)
        matched, created = [], 0
        for name, meta in PATTERNS.items():
            for row in run_pattern(self.g, name, scope):
                fid = finding_id(name, row["fn"])
                matched.append(fid)
                res = self.g.query(
                    """MERGE (fd:Finding {id: $id})
                       // ON CREATE only: a re-scan must never reset confirmed/dismissed
                       ON CREATE SET fd.status = 'candidate', fd.created_at = $now,
                                     fd.severity = $sev, fd.pattern = $pattern
                       SET fd.key = $key, fd.anchor = $anchor, fd.query = $query,
                           fd.evidence = $evidence, fd.risk = $risk, fd.last_seen = $now,
                           fd.resolved_in = null
                       WITH fd
                       MATCH (p:Pattern {id: $pattern}) MERGE (fd)-[:MATCHES]->(p)
                       WITH fd
                       MATCH (f:Function) WHERE f.id IN $path MERGE (fd)-[:EVIDENCED_BY]->(f)
                       RETURN fd.created_at = $now""",
                    {"id": fid, "now": _now(), "sev": meta["severity"], "pattern": name,
                     "key": f"{name}:{row['fn']}", "anchor": row["path"][0],
                     "query": meta["cypher"].strip(), "evidence": json.dumps(row["evidence"], default=dict),
                     "risk": max(rank.get(f, 0.0) for f in row["path"]), "path": row["path"]})
                created += bool(res.result_set and res.result_set[0][0])
        # Findings in scope that no longer match were fixed by this version.
        resolved = self.g.query(
            """MATCH (fd:Finding)
               WHERE fd.resolved_in IS NULL AND NOT fd.id IN $matched
                 AND ($scope IS NULL OR fd.anchor IN $scope)
               SET fd.resolved_in = $v RETURN count(fd)""",
            {"matched": matched, "scope": scope, "v": version or "latest"}).result_set[0][0]
        return {"matched": len(matched), "new": created, "resolved": resolved}


# ======================================================================= Verifier
class VerifierError(RuntimeError):
    pass


SYSTEM_PROMPT = """You are a smart contract security verifier. A graph-based scanner flagged a
candidate vulnerability. Decide if it is a real, exploitable issue given the code and the
graph evidence. Respond with ONLY a JSON object, no prose, no markdown fences:
{"verdict": "<one short sentence>", "status": "confirmed" | "dismissed",
 "reasoning": "<2-4 sentences grounded in the code and evidence>",
 "severity": "Critical" | "High" | "Medium" | "Low" | "Info"}"""


def parse_verdict(text: str) -> dict:
    """Strictly validate LLM output. Raises ValueError on anything malformed."""
    cleaned = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end < start:
        raise ValueError("no JSON object found")
    data = json.loads(cleaned[start:end + 1])
    if not isinstance(data, dict):
        raise ValueError("JSON is not an object")
    out = {}
    for k in ("verdict", "reasoning"):
        if not isinstance(data.get(k), str) or not data[k].strip():
            raise ValueError(f"missing/empty '{k}'")
        out[k] = data[k].strip()
    if data.get("status") not in ("confirmed", "dismissed"):
        raise ValueError("status must be 'confirmed' or 'dismissed'")
    sev = str(data.get("severity", "")).capitalize()
    if sev not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    out["status"], out["severity"] = data["status"], sev
    return out


class Verifier:
    def __init__(self, g, use_llm: bool = True, max_retries: int = 2):
        self.g, self.use_llm, self.max_retries = g, use_llm, max_retries
        self.client = None
        if use_llm:
            if not os.getenv("ANTHROPIC_API_KEY"):
                raise VerifierError("ANTHROPIC_API_KEY is not set. Export it, or run with --no-llm.")
            if not os.getenv("LLM_MODEL"):
                raise VerifierError("LLM_MODEL is not set (e.g. export LLM_MODEL=<anthropic model id>), or use --no-llm.")
            import anthropic
            self.client = anthropic.Anthropic()

    def context(self, fid: str) -> dict:
        """Pull the finding's neighbourhood from the graph: evidence functions, their
        modifiers, ordered READS/WRITES/MAKES edges, callers, and source code."""
        fd = self.g.query("MATCH (fd:Finding {id: $id}) RETURN fd.pattern, fd.evidence, fd.query",
                          {"id": fid}).result_set[0]
        rows = self.g.query(
            """MATCH (:Finding {id: $id})-[:EVIDENCED_BY]->(f:Function)
               OPTIONAL MATCH (f)-[:HAS_MODIFIER]->(m:Modifier)
               OPTIONAL MATCH (caller:Function)-[:CALLS]->(f)
               OPTIONAL MATCH (f)-[r]->(x) WHERE type(r) IN ['READS', 'WRITES', 'MAKES']
               RETURN f.id, f.source, collect(DISTINCT m.name), collect(DISTINCT caller.id),
                      collect(DISTINCT [r.seq, type(r), coalesce(x.name, x.method)])""",
            {"id": fid}).result_set
        funcs = [{"id": r[0], "source": r[1], "modifiers": r[2], "callers": r[3],
                  "ordered_effects": sorted(e for e in r[4] if e[0] is not None)} for r in rows]
        return {"pattern": fd[0], "evidence": json.loads(fd[1]), "query": fd[2], "functions": funcs}

    def mock_verdict(self, ctx: dict) -> dict:
        """Deterministic, offline verdict derived only from graph evidence (for demos/tests)."""
        ev = ctx["evidence"][0]
        fn = ctx["functions"][0]["id"] if ctx["functions"] else "?"
        p = ctx["pattern"]
        if p == "reentrancy":
            why = (f"In {fn}, the external `{ev['call']}` (seq {ev['call_seq']}) executes before "
                   f"`{ev['write']}` is written (seq {ev['write_seq']}) and no reentrancy guard is attached.")
        elif p == "unchecked_low_level_call":
            why = f"In {fn}, the success flag of `{ev['call']}` (seq {ev['call_seq']}) is never read."
        elif p == "missing_access_control_path":
            why = (f"Call path {' -> '.join(ev['via'])} reaches a write of privileged `{ev['write']}` "
                   f"with no guarded function on the path.")
        else:
            why = f"Unguarded entry point {fn} writes privileged `{ev['write']}`."
        return {"verdict": f"Pattern {p} holds on the graph evidence.", "status": "confirmed",
                "reasoning": "[mock verifier] " + why, "severity": PATTERNS[p]["severity"]}

    def llm_verdict(self, ctx: dict) -> dict:
        prompt = ("Candidate finding:\n" + json.dumps(ctx, indent=2, default=str))
        messages = [{"role": "user", "content": prompt}]
        last_err = None
        for _ in range(self.max_retries + 1):
            resp = self.client.messages.create(model=os.environ["LLM_MODEL"], max_tokens=800,
                                               system=SYSTEM_PROMPT, messages=messages)
            text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
            try:
                return parse_verdict(text)
            except (ValueError, json.JSONDecodeError) as e:
                last_err = e
                # Retry with the validation error so the model can correct its format.
                messages += [{"role": "assistant", "content": text},
                             {"role": "user", "content": f"Invalid output ({e}). Reply with ONLY the JSON object."}]
        raise VerifierError(f"LLM output still invalid after retries: {last_err}")

    def run(self) -> dict:
        # Only untriaged candidates: human decisions and earlier verdicts are memory, not redone.
        ids = [r[0] for r in self.g.query(
            """MATCH (fd:Finding {status: 'candidate'}) WHERE fd.resolved_in IS NULL
               RETURN fd.id ORDER BY fd.risk DESC""").result_set]
        stats = {"verified": 0, "errors": 0}
        for fid in ids:
            ctx = self.context(fid)
            try:
                v = self.llm_verdict(ctx) if self.use_llm else self.mock_verdict(ctx)
            except VerifierError as e:
                self.g.query("MATCH (fd:Finding {id: $id}) SET fd.verifier_error = $e", {"id": fid, "e": str(e)})
                stats["errors"] += 1
                continue
            self.g.query("""MATCH (fd:Finding {id: $id})
                            SET fd.verdict = $verdict, fd.status = $status, fd.reasoning = $reasoning,
                                fd.severity = $severity, fd.verified_by = $by, fd.verifier_error = null""",
                         {"id": fid, **v, "by": "llm:" + os.getenv("LLM_MODEL", "") if self.use_llm else "mock"})
            stats["verified"] += 1
        return stats


# ======================================================================= Reporter
REPORT_QUERY = """
MATCH (fd:Finding)-[:MATCHES]->(p:Pattern)
WHERE fd.resolved_in IS NULL AND fd.status IN $statuses
OPTIONAL MATCH (p)-[:SEEN_IN]->(e:Exploit)
RETURN fd.id, fd.status, fd.severity, fd.key, p.swc_id, p.id, fd.query, fd.evidence,
       fd.verdict, fd.reasoning, fd.triage_note, fd.risk,
       collect(DISTINCT e.name + ' (' + toString(e.year) + '): ' + e.description)
"""


class Reporter:
    def __init__(self, g):
        self.g = g

    def _rows(self, statuses):
        rows = self.g.query(REPORT_QUERY, {"statuses": statuses}).result_set
        return sorted(rows, key=lambda r: (SEVERITIES.index(r[2]) if r[2] in SEVERITIES else 9, -(r[11] or 0)))

    @staticmethod
    def _evidence_lines(pattern: str, evidence: list) -> list[str]:
        out = []
        for e in evidence:
            if "via" in e:
                out.append(f"call path: `{' -> '.join(e['via'])}` -[:WRITES {{seq:{e['write_seq']}}}]-> `{e['write']}` (no guard on any node)")
            elif "call" in e and "write" in e:
                out.append(f"`-[:MAKES {{seq:{e['call_seq']}}}]-> {e['call']}` (line {e.get('line')}) happens before "
                           f"`-[:WRITES {{seq:{e['write_seq']}}}]-> {e['write']}`")
            elif "call" in e:
                out.append(f"`-[:MAKES {{seq:{e['call_seq']}}}]-> {e['call']}` (line {e.get('line')}), checked = false")
            else:
                out.append(f"`-[:WRITES {{seq:{e['write_seq']}}}]-> {e['write']}` (privileged) from an unguarded entry point")
        return out

    def render(self) -> str:
        confirmed = self._rows(["confirmed"])
        dismissed = self._rows(["dismissed"])
        candidates = self._rows(["candidate"])
        resolved = self.g.query("MATCH (fd:Finding) WHERE fd.resolved_in IS NOT NULL "
                                "RETURN fd.id, fd.key, fd.resolved_in ORDER BY fd.id").result_set
        L = ["# AuditGraph report", "", f"_Generated {_now()} from FalkorDB graph state._", "",
             f"**Confirmed:** {len(confirmed)}  |  **Dismissed:** {len(dismissed)}  |  "
             f"**Unverified candidates:** {len(candidates)}  |  **Resolved by upgrade:** {len(resolved)}", ""]
        L += ["## Confirmed findings", ""]
        if not confirmed:
            L.append("None.")
        for r in confirmed:
            fid, _, sev, key, swc, pattern, query, ev, verdict, reasoning, _, risk, expl = r
            fn = key.split(":", 1)[1]
            L += [f"### [{sev}] {PATTERNS[pattern]['title']} — `{fn}`", "",
                  f"- **Finding id:** `{fid}`  |  **SWC:** {swc}  |  **Risk (PageRank):** {risk:.4f}",
                  f"- **Verdict:** {verdict}", f"- **Verifier reasoning:** {reasoning}", "",
                  "**Graph evidence:**", ""]
            L += [f"- {x}" for x in self._evidence_lines(pattern, json.loads(ev))]
            L += ["", "**Cypher query that proves it:**", "", "```cypher", query, "```", ""]
            if expl:
                L += ["**Seen before in:**", ""] + [f"- {x}" for x in expl] + [""]
            L += [f"**Suggested fix:** {PATTERNS[pattern]['fix']}", ""]
        L += ["## Dismissed findings", ""]
        if not dismissed:
            L.append("None.")
        for r in dismissed:
            note = r[10] or r[9] or "(no note)"
            L.append(f"- `{r[0]}` {r[3]} — {note}")
        if candidates:
            L += ["", "## Unverified candidates", ""] + [f"- `{r[0]}` {r[3]}" for r in candidates]
        if resolved:
            L += ["", "## Resolved by upgrade", ""] + [f"- `{r[0]}` {r[1]} (no longer matches in {r[2]})" for r in resolved]
        return "\n".join(L) + "\n"

    def write(self, path: str = "report.md") -> str:
        text = self.render()
        with open(path, "w") as fh:
            fh.write(text)
        return path
