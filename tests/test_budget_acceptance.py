"""Large immutable SDK fixtures distinguish safe scan truncation from denial."""
import json
import os
from pathlib import Path
import time

import pytest

from test_http_acceptance import A, B, f, call


def assert_caps(f, roots=(A,)):
    assert 0 < len(f.captured) <= 128
    assert sum(f.response_bytes) <= 1048576
    assert all(size <= 262144 for size in f.response_bytes)
    f.assert_capture(roots)
    home = Path(os.environ["HOME"]).resolve()
    assert home.name == "home" and home.parent.name == ".scratch"
    receipt = {"layout": f.layout, "requests": len(f.captured), "response_bytes": sum(f.response_bytes),
               "largest_response": max(f.response_bytes, default=0), "fault": f.scan_fault,
               "calls": [(m, p, args) for m, p, args, _ in f.captured]}
    with (home / "budget-http-captures.jsonl").open("a") as output:
        output.write(json.dumps(receipt) + "\n")


@pytest.mark.asyncio
@pytest.mark.parametrize("f", ["flat"], indirect=True)
@pytest.mark.parametrize("tool,args,key", [
    ("memory_ls", {"uri": A + "/bulk", "recursive": True, "limit": 100}, "entries"),
    ("memory_tree", {"uri": A + "/bulk", "level_limit": 12, "limit": 100}, "entries"),
    ("memory_glob", {"uri": A + "/bulk", "pattern": "*.md", "limit": 100}, "matches"),
    ("memory_grep", {"uri": A + "/bulk", "pattern": "needle", "limit": 100}, "matches"),
    ("memory_stat", {"uri": A + "/bulk"}, "parts"),
    ("memory_relations", {"uri": A + "/other.md"}, "backlinks"),
])
async def test_more_than_128_nodes_return_safe_partial_results(f, tool, args, key):
    assert sum(path.startswith(A + "/bulk/") for path in f.files) == 200
    f.poison = True
    async with f.session() as session:
        response, value = await call(session, tool, **args)
        assert not response.is_error, value
        assert value["truncated"] is True and value[key]
        assert B not in json.dumps(value) and A + "-neighbor" not in json.dumps(value)
        if tool == "memory_stat":
            assert value["parts"] < 200 and value["content_bytes"] > 0
        if tool == "memory_relations":
            # The unseen zzz/other.md makes short-name resolution unsafe.
            assert value["wikilinks"] == []
            assert all("/bulk/" in uri and int(uri.rsplit("_", 1)[1][:-3]) % 2 == 0
                       for uri in value["backlinks"])
    assert_caps(f)


@pytest.mark.asyncio
@pytest.mark.parametrize("f", ["chunks"], indirect=True)
@pytest.mark.parametrize("tool,args,key", [
    ("memory_grep", {"uri": A + "/library", "pattern": "needle", "limit": 100}, "matches"),
    ("memory_glob", {"uri": A + "/library", "pattern": "*.md", "limit": 100}, "matches"),
    ("memory_relations", {"uri": A + "/other.md"}, "backlinks"),
])
async def test_large_chunked_namespace_returns_observed_partial_records(f, tool, args, key):
    assert sum(path.startswith(A + "/library/") for path in f.files) == 90
    async with f.session() as session:
        response, value = await call(session, tool, **args)
        assert not response.is_error, value
        assert value["truncated"] and value[key]
        if tool == "memory_grep":
            assert all(1 <= m["matching_parts"] <= 3 for m in value["matches"])
            assert all("/part_" not in m["uri"] for m in value["matches"])
    assert_caps(f)


@pytest.mark.asyncio
@pytest.mark.parametrize("f", ["bytes"], indirect=True)
@pytest.mark.parametrize("tool,args,key", [
    ("memory_grep", {"uri": A + "/bytes", "pattern": "needle", "group": False, "limit": 100}, "matches"),
    ("memory_relations", {"uri": A + "/other.md"}, "backlinks"),
])
async def test_aggregate_bytes_stop_before_io_with_partial_records(f, tool, args, key):
    async with f.session() as session:
        response, value = await call(session, tool, **args)
        assert not response.is_error, value
        assert value["truncated"] and 0 < len(value[key]) < 8
    assert len(f.captured) < 128 and sum(f.response_bytes) > 700000
    assert_caps(f)


@pytest.mark.asyncio
@pytest.mark.parametrize("f", ["list-bytes"], indirect=True)
async def test_nonrecursive_multi_root_listing_obeys_aggregate_budget(f):
    async with f.session(f.token(f.large_roots)) as session:
        response, value = await call(session, "memory_ls", limit=10)
        assert not response.is_error, value
        assert value["truncated"] and len(value["entries"]) == 10
    assert 1 < len(f.captured) < len(f.large_roots)
    assert sum(f.response_bytes) <= 1048576
    assert all(size <= 262144 for size in f.response_bytes)
    assert_caps(f, tuple(f.large_roots))


@pytest.mark.asyncio
@pytest.mark.parametrize("f,uri", [("huge", A + "/huge.md"), ("byte-doc", A + "/big.md")], indirect=["f"])
async def test_incomplete_document_remains_atomic_and_next_call_has_fresh_budget(f, uri):
    async with f.session() as session:
        response, value = await call(session, "memory_read", uri=uri, parts=True)
        assert response.is_error and value == {"error": "Resource unavailable."}
        assert "text" not in value and "parts" not in value
        assert_caps(f)
        response, read = await call(session, "memory_read", uri=A + "/note.md", parts=True)
        assert not response.is_error and "Tail" in read["text"] and len(read["parts"]) == 2
    f.assert_capture()


@pytest.mark.asyncio
@pytest.mark.parametrize("f", ["flat"], indirect=True)
@pytest.mark.parametrize("tool,args,after", [
    ("memory_tree", {"uri": A + "/bulk", "level_limit": 12}, 10),
    ("memory_grep", {"uri": A + "/bulk", "pattern": "needle"}, 70),
])
@pytest.mark.parametrize("mode", ["error", "malformed", "expiry"])
async def test_partial_scan_never_hides_backend_or_expiry_failure(f, tool, args, after, mode):
    f.scan_fault = {"after": after, "mode": mode}
    if mode == "expiry":
        # Allow discovery to finish, then expire during the chosen backend call.
        # This uses real signed expiry, not a patched clock/principal/client.
        f.scan_fault["expires"] = int(time.time()) + 12
        token = f.token(exp=f.scan_fault["expires"])
    else:
        token = f.token()
    async with f.session(token) as session:
        response, value = await call(session, tool, **args)
        assert response.is_error and value == {"error": "Resource unavailable."}
        assert SECRET_MARKER not in json.dumps(value)
    assert len(f.captured) == after  # no continuation after the failure
    assert_caps(f)


SECRET_MARKER = "synthetic-backend-key"
