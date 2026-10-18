"""Slither -> FalkorDB ingestion: builds the code property graph.

Slither does the parsing (AST + SlithIR). We extract only the facts the detectors need
and write them as nodes/edges. All vulnerability reasoning happens later, in Cypher.

Key design decision: READS / WRITES / MAKES edges carry `seq`, the statement's position
inside its function (ranked by source offset). That ordering is what lets one Cypher
pattern say "the external call happens BEFORE the state write" (reentrancy).
"""
from __future__ import annotations

import hashlib
import logging
import re
import shutil
from pathlib import Path

# Slither/crytic-compile are chatty; keep CLI output readable.
logging.getLogger("CryticCompile").setLevel(logging.ERROR)
logging.getLogger("Slither").setLevel(logging.ERROR)

from slither import Slither  # noqa: E402
from slither.core.declarations import Modifier, SolidityVariableComposed  # noqa: E402
from slither.core.variables.state_variable import StateVariable  # noqa: E402
from slither.slithir.operations import (  # noqa: E402
    Binary, BinaryType, HighLevelCall, InternalCall, LowLevelCall, Send, Transfer, Unpack,
)

MSG_SENDER = SolidityVariableComposed("msg.sender")
# Name fallback for privileged variables that are not (yet) read by any guard in this contract.
PRIVILEGED_NAME = re.compile(
    r"^_?(owner|admin|governance|governor|authority|operator|guardian|implementation|pendingowner)$",
    re.I,
)
REENTRANCY_GUARD_NAME = re.compile(r"reentran|nonreentrant|lock|mutex", re.I)


class IngestError(RuntimeError):
    pass


# ---------------------------------------------------------------- Slither helpers
def _is_guard_node(node) -> bool:
    """Access-control check = a require/assert/if containing an ==/!= comparison on msg.sender.

    Requiring the equality matters: `require(balances[msg.sender] >= amt)` also reads
    msg.sender but is a balance check, not an authorisation check.
    """
    if not (node.contains_require_or_assert() or node.contains_if()):
        return False
    return any(
        isinstance(ir, Binary) and ir.type in (BinaryType.EQUAL, BinaryType.NOT_EQUAL)
        and MSG_SENDER in (ir.variable_left, ir.variable_right)
        for ir in node.irs
    )


def _is_auth_modifier(mod) -> bool:
    return any(_is_guard_node(n) for n in mod.nodes)


def _is_reentrancy_guard(mod) -> bool:
    """Name heuristic OR the classic lock shape: the modifier both checks and writes the same state var.

    onlyOwner reads `owner` but never writes it, so it is not mistaken for a lock.
    """
    if REENTRANCY_GUARD_NAME.search(mod.name):
        return True
    written = {v for n in mod.nodes for v in n.state_variables_written}
    checked = {v for n in mod.nodes if n.contains_require_or_assert() for v in n.state_variables_read}
    return bool(written & checked)


def _is_guarded(func) -> bool:
    """Guarded = an auth modifier OR an inline msg.sender check in the function's OWN body.

    Deliberately NOT transitive (unlike Slither's Function.is_protected, which also counts
    callees and msg.sender passed as an argument). Transitivity is the graph's job: the
    path query walks CALLS edges and checks `guarded` on every node of the path.
    """
    if any(_is_auth_modifier(m) for m in func.modifiers):
        return True
    return any(_is_guard_node(n) for n in func.nodes)


def _call_checked(func, call_ir) -> bool:
    """Is the success boolean of a low-level call / send actually used afterwards?

    Stricter than Slither's unchecked-lowlevel detector, which treats unpacking the result
    tuple as "use". Here: `(bool ok,) = x.call(...)` only counts as checked if `ok` is later
    read (require/if/return/assignment). Heuristic: no path sensitivity.
    """
    if isinstance(call_ir, Transfer):
        return True  # transfer() reverts on failure
    tracked = set()
    tuple_var = None
    if isinstance(call_ir, Send):
        tracked.add(call_ir.lvalue)
    elif call_ir.lvalue is not None:
        tuple_var = call_ir.lvalue
    seen_call = False
    for node in func.nodes:
        for ir in node.irs:
            if ir is call_ir:
                seen_call = True
                continue
            if not seen_call:
                continue
            if isinstance(ir, Unpack) and ir.tuple == tuple_var:
                if ir.index == 0:  # element 0 is the success bool
                    tracked.add(ir.lvalue)
                continue
            if any(r in tracked for r in ir.read):
                return True
    return False


def _body_hash(source: str) -> str:
    # Whitespace-normalised so reformatting alone does not count as a change.
    return hashlib.sha256(" ".join(source.split()).encode()).hexdigest()[:16]


def _external_call_info(ir):
    """(kind, method) for IR ops that leave the contract, else None."""
    if isinstance(ir, LowLevelCall):
        return "low_level", str(ir.function_name)  # call / delegatecall / staticcall
    if isinstance(ir, Send):
        return "low_level", "send"
    if isinstance(ir, Transfer):
        return "low_level", "transfer"
    if isinstance(ir, HighLevelCall):
        fn = ir.function
        return "high_level", str(getattr(fn, "full_name", ir.function_name))
    return None


# ---------------------------------------------------------------- extraction
def extract(path: str) -> dict:
    """Run Slither on one file and return plain dict rows ready for UNWIND."""
    if shutil.which("solc") is None:
        raise IngestError("solc not found. Run: solc-select install 0.8.20 && solc-select use 0.8.20")
    if not Path(path).exists():
        raise IngestError(f"No such file: {path}")
    try:
        sl = Slither(path, compile_force_framework="solc")
    except Exception as e:
        raise IngestError(f"Slither/solc failed on {path}: {e}") from e

    rows = {k: [] for k in ("contracts", "inherits", "functions", "modifiers", "statevars",
                            "reads", "writes", "calls", "extcalls", "has_mod")}
    for c in sl.contracts:
        if c.is_interface:
            continue
        rows["contracts"].append({"id": c.name, "name": c.name})
        for base in c.immediate_inheritance:
            rows["inherits"].append({"child": c.name, "parent": base.name})

        # Privileged state vars: read by an access-control guard anywhere in the contract
        # (auth modifier or inline check), or named like an authority role.
        guard_reads = set()
        for fn in list(c.functions) + list(c.modifiers):
            for n in fn.nodes:
                if _is_guard_node(n):
                    guard_reads.update(n.state_variables_read)
        for sv in c.state_variables_declared:
            rows["statevars"].append({
                "id": sv.canonical_name, "name": sv.name,
                "privileged": sv in guard_reads or bool(PRIVILEGED_NAME.match(sv.name)),
            })

        for m in c.modifiers_declared:
            rows["modifiers"].append({
                "id": m.canonical_name, "name": m.name,
                "is_auth": _is_auth_modifier(m), "is_reentrancy_guard": _is_reentrancy_guard(m),
            })

        for f in c.functions_declared:
            if isinstance(f, Modifier):
                continue
            fid = f.canonical_name
            src = f.source_mapping.content or ""
            rows["functions"].append({
                "id": fid, "name": f.name, "contract": c.name,
                # constructors only run at deployment, so they are never an attack entry point
                "visibility": "constructor" if f.is_constructor else f.visibility,
                "guarded": _is_guarded(f), "body_hash": _body_hash(src), "source": src,
            })
            for m in f.modifiers:
                rows["has_mod"].append({"f": fid, "m": m.canonical_name})

            # seq = rank of the statement's source offset inside the function.
            nodes = sorted(f.nodes, key=lambda n: (n.source_mapping.start, n.node_id))
            seq_of = {n: i for i, n in enumerate(nodes)}
            for n in nodes:
                s = seq_of[n]
                for v in n.state_variables_read:
                    rows["reads"].append({"f": fid, "v": v.canonical_name, "seq": s})
                for v in n.state_variables_written:
                    rows["writes"].append({"f": fid, "v": v.canonical_name, "seq": s})
                for ir in n.irs:
                    if isinstance(ir, InternalCall) and not ir.is_modifier_call \
                            and ir.function is not None and not isinstance(ir.function, Modifier):
                        rows["calls"].append({"src": fid, "dst": ir.function.canonical_name})
                        continue
                    info = _external_call_info(ir)
                    if info:
                        kind, method = info
                        rows["extcalls"].append({
                            "f": fid, "id": f"{fid}#ext{len(rows['extcalls'])}", "kind": kind,
                            "method": method, "seq": s, "checked": _call_checked(f, ir),
                            "line": n.source_mapping.lines[0] if n.source_mapping.lines else None,
                        })
    # Deduplicate edges that Slither reports once per IR (e.g. balances read twice in one statement).
    for k in ("reads", "writes", "calls"):
        rows[k] = [dict(t) for t in {tuple(sorted(r.items())) for r in rows[k]}]
    return rows


# ---------------------------------------------------------------- load into FalkorDB
def load(g, rows: dict, version: str) -> dict:
    """Write the extracted rows. Re-ingesting a contract rebuilds its edges but keeps
    Function nodes (by id), so findings and triage attached to them survive upgrades."""
    contract_ids = [c["id"] for c in rows["contracts"]]
    fn_ids = [f["id"] for f in rows["functions"]]

    # 1) Drop stale structural edges/call-sites of these contracts (memory nodes untouched).
    g.query("""MATCH (c:Contract)-[:DECLARES]->(f:Function)-[:MAKES]->(e:ExternalCall)
               WHERE c.id IN $cs DETACH DELETE e""", {"cs": contract_ids})
    g.query("""MATCH (c:Contract)-[:DECLARES]->(f:Function)-[r:READS|WRITES|CALLS|HAS_MODIFIER]->()
               WHERE c.id IN $cs DELETE r""", {"cs": contract_ids})
    # Functions that disappeared in this version: unlink them, remember when they went.
    g.query("""MATCH (c:Contract)-[d:DECLARES]->(f:Function)
               WHERE c.id IN $cs AND NOT f.id IN $fns
               SET f.removed_in = $v DELETE d""", {"cs": contract_ids, "fns": fn_ids, "v": version})

    g.query("""UNWIND $rows AS r MERGE (c:Contract {id: r.id})
               SET c.name = r.name, c.version = $v""", {"rows": rows["contracts"], "v": version})
    g.query("""UNWIND $rows AS r MATCH (a:Contract {id: r.child}), (b:Contract {id: r.parent})
               MERGE (a)-[:INHERITS]->(b)""", {"rows": rows["inherits"]})
    g.query("""UNWIND $rows AS r MERGE (s:StateVar {id: r.id})
               SET s.name = r.name, s.privileged = r.privileged""", {"rows": rows["statevars"]})
    g.query("""UNWIND $rows AS r MERGE (m:Modifier {id: r.id})
               SET m.name = r.name, m.is_auth = r.is_auth, m.is_reentrancy_guard = r.is_reentrancy_guard""",
            {"rows": rows["modifiers"]})

    # Versioning memory: before overwriting body_hash, keep the old one in prev_hash.
    # New functions get prev_hash = null. `version` only advances when the body changed.
    g.query("""UNWIND $rows AS r
               MERGE (f:Function {id: r.id})
               ON CREATE SET f.prev_hash = null, f.version = $v
               ON MATCH SET f.prev_hash = f.body_hash
               SET f.name = r.name, f.contract = r.contract, f.visibility = r.visibility,
                   f.guarded = r.guarded, f.body_hash = r.body_hash, f.source = r.source,
                   f.removed_in = null
               WITH f WHERE f.prev_hash IS NULL OR f.prev_hash <> f.body_hash
               SET f.version = $v""", {"rows": rows["functions"], "v": version})
    g.query("""UNWIND $rows AS r MATCH (c:Contract {id: r.contract}), (f:Function {id: r.id})
               MERGE (c)-[:DECLARES]->(f)""", {"rows": rows["functions"]})

    g.query("""UNWIND $rows AS r MATCH (f:Function {id: r.f}), (m:Modifier {id: r.m})
               MERGE (f)-[:HAS_MODIFIER]->(m)""", {"rows": rows["has_mod"]})
    g.query("""UNWIND $rows AS r MATCH (f:Function {id: r.f}), (s:StateVar {id: r.v})
               CREATE (f)-[:READS {seq: r.seq}]->(s)""", {"rows": rows["reads"]})
    g.query("""UNWIND $rows AS r MATCH (f:Function {id: r.f}), (s:StateVar {id: r.v})
               CREATE (f)-[:WRITES {seq: r.seq}]->(s)""", {"rows": rows["writes"]})
    g.query("""UNWIND $rows AS r MATCH (a:Function {id: r.src}), (b:Function {id: r.dst})
               MERGE (a)-[:CALLS]->(b)""", {"rows": rows["calls"]})
    g.query("""UNWIND $rows AS r MATCH (f:Function {id: r.f})
               CREATE (f)-[:MAKES {seq: r.seq}]->(:ExternalCall {id: r.id, kind: r.kind,
                      method: r.method, checked: r.checked, line: r.line})""",
            {"rows": rows["extcalls"]})
    return {k: len(v) for k, v in rows.items()}


def ingest_file(g, path: str, version: str = "v1") -> dict:
    return load(g, extract(path), version)
