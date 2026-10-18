import uuid

import pytest

from src.schema import GraphUnavailable, ensure_schema, get_graph


@pytest.fixture
def g():
    """A fresh, uniquely named FalkorDB graph per test; dropped afterwards."""
    try:
        graph = get_graph(f"ag_test_{uuid.uuid4().hex[:8]}")
    except GraphUnavailable as e:
        pytest.skip(str(e))
    ensure_schema(graph)
    yield graph
    graph.delete()
