"""Disposable transport fixtures for current-note search and protected subtrees."""
import json

import pytest

from ov_http.mutations import call_mutation
from ov_http.reader import Reader
from test_http_document_sidecars import tree, TARGET, SIDECAR
from test_http_document_write import invoke, A
from test_http_mutations import TypedBackend, direct, search_hit


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["memory_mv", "memory_rm", "dry_run"])
async def test_protected_subtree(operation):
    engine = tree()
    before = dict(engine.files)
    destination = A + "/moved.md"
    arguments = ({"from_uri": TARGET, "to_uri": destination} if operation == "memory_mv"
                 else {"uri": TARGET, "recursive": True, "dry_run": operation == "dry_run"})
    async with invoke(engine) as (_, _, backend):
        answer, failed = await call_mutation(backend, "memory_rm" if operation == "dry_run"
                                            else operation, arguments, {})
    assert not failed, answer
    assert SIDECAR not in json.dumps(answer)
    if operation == "memory_mv":
        for path, raw in before.items():
            if path.startswith(TARGET + "/"):
                assert engine.files[destination + path[len(TARGET):]] == raw
        assert not any(p.startswith(TARGET + "/") for p in engine.files)
    elif operation == "dry_run":
        assert engine.files == before and not engine.effects
    else:
        assert not any(p.startswith(TARGET + "/") for p in engine.files)


@pytest.mark.asyncio
@pytest.mark.parametrize("group", [True, False])
@pytest.mark.parametrize("include_archived", [True, False])
async def test_source_title_not_summary_prose_controls_supersession(group, include_archived):
    engine = TypedBackend()
    old, current, history = A + "/old.md", A + "/current.md", A + "/archive/old.md"
    engine.files.update({old: b"# Superseded: old\n\nRead instead: current.md",
                         current: b"# Current catalog\n\nSome tools are superseded."})
    engine.search_rows = []
    for uri in (old, current, history):
        row = search_hit(uri)
        row["abstract"] = "A superseded note or current catalog of superseded tools."
        engine.search_rows.append(row)
    async with invoke(engine) as (_, _, backend):
        answer = await Reader(backend).semantic("search", "services", None, 10,
                                                group, include_archived)
    assert [m["uri"] for m in answer["matches"]] == (
        [old, current, history] if include_archived else [current])
