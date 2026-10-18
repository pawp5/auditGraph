"""FalkorDB connection and schema (indexes).

Every agent gets its graph handle from here, so all state lives in ONE FalkorDB
graph. That shared graph is the only channel the agents use to coordinate.
"""
import os
import sys

from falkordb import FalkorDB

GRAPH_NAME = os.getenv("AUDITGRAPH_GRAPH", "auditgraph")

# Indexes on the `id` property of every label. Ingest and the agents MERGE/MATCH
# by id constantly, and without an index each lookup would be a label scan.
INDEXED_LABELS = [
    "Contract", "Function", "StateVar", "Modifier",
    "ExternalCall", "Finding", "Pattern", "Exploit",
]


class GraphUnavailable(RuntimeError):
    pass


def get_graph(name: str | None = None):
    """Return a FalkorDB graph handle, failing with an actionable message."""
    host = os.getenv("FALKORDB_HOST", "localhost")
    port = int(os.getenv("FALKORDB_PORT", "6380"))
    try:
        db = FalkorDB(host=host, port=port)
        g = db.select_graph(name or GRAPH_NAME)
        g.query("RETURN 1")  # forces a round trip so a dead server fails here, not mid-audit
        return g
    except Exception as e:  # redis ConnectionError and friends
        raise GraphUnavailable(
            f"Cannot reach FalkorDB at {host}:{port} ({e}).\n"
            "Start it with:  docker compose up -d   (then retry)"
        ) from e


def ensure_schema(g) -> list[str]:
    """Create indexes if missing. Idempotent: the error for an existing index is ignored."""
    created = []
    for label in INDEXED_LABELS:
        try:
            g.query(f"CREATE INDEX FOR (n:{label}) ON (n.id)")
            created.append(label)
        except Exception as e:
            if "already indexed" not in str(e).lower():
                raise
    return created


def reset(g) -> None:
    """Drop the whole graph (all contracts, findings and memory)."""
    try:
        g.delete()
    except Exception:
        pass  # graph did not exist yet


if __name__ == "__main__":
    try:
        graph = get_graph()
    except GraphUnavailable as e:
        print(e)
        sys.exit(1)
    print("Connected. Indexes created:", ensure_schema(graph) or "none (already present)")
    print(graph.query("CALL db.indexes() YIELD label, properties RETURN label, properties").result_set)
