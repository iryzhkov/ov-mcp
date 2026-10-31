"""Read-only recovery observations; synthetic backend and official SDK only."""
import ast
import hashlib
import json
from pathlib import Path
import time

import httpx
import pytest

from ov_http.auth import Principal, Refused
from ov_http.config import RESOURCES_URI_POLICY
from ov_http.reader import Backend, BudgetExhausted, Reader
from ov_http.document_node import NODE_PATH
from test_http_document_write import Documents, sdk_documents
from test_http_mutations import A, DOC, ROOT, config, error
from test_http_acceptance import call


def test_actual_closed_image_input_pins():
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse((root / ".github/scripts/http_image_artifact.py").read_text())
    pins = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "INPUTS" for t in n.targets))
    runtime = {str(p.relative_to(root)) for p in (root / "ov_http").iterdir()
               if p.is_file()}
    assert runtime == {p for p in pins if p.startswith("ov_http/")}
    for name, expected in pins.items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name


@pytest.mark.asyncio
@pytest.mark.parametrize("uri", [DOC, A + "/parsed.md"])
async def test_sdk_revision_schema_roundtrip_and_two_observations(sdk_documents, uri):
    session, engine = sdk_documents
    engine.dirs.add(A + "/parsed.md")
    engine.files[A + "/parsed.md/part.md"] = b"held parsed note"
    before = (dict(engine.files), set(engine.dirs))
    async with session(enabled=False, roots=(uri,), ov_actions=["read"], scope="ov.read") as client:
        tools = await client.list_tools()
        spec = next(t for t in tools.tools if t.name == "memory_stat")
        assert spec.input_schema["properties"]["include_revision"] == {"type": "boolean"}
        assert "include_revision" not in spec.input_schema["required"]
        observations = []
        for _ in range(2):
            response, value = await call(client, "memory_stat", uri=uri, include_revision=True)
            assert not response.is_error, value
            observations.append(value)
        assert observations == [{"uri": uri, "node": engine.descriptor(uri)}] * 2
    assert engine.calls == [("GET", NODE_PATH, {"uri": uri}, None)] * 2
    assert not engine.effects and before == (engine.files, engine.dirs)


@pytest.mark.asyncio
async def test_sdk_default_and_false_unchanged_and_bad_types_no_io(sdk_documents):
    session, engine = sdk_documents
    engine.dirs.add(A + "/parsed.md")
    engine.files[A + "/parsed.md/part.md"] = b"abc"
    async with session(enabled=False, roots=(A,), ov_actions=["read"], scope="ov.read") as client:
        for uri, expected in [
            (DOC, {"uri": DOC, "isDir": False, "size": 4}),
            (A + "/parsed.md", {"uri": A + "/parsed.md", "isDir": True,
                               "content_bytes": 3, "parts": 1, "truncated": False}),
        ]:
            for args in ({}, {"include_revision": False}):
                response, value = await call(client, "memory_stat", uri=uri, **args)
                assert not response.is_error and value == expected
        engine.calls.clear()
        for flag in ("true", 1, None, [], {}):
            response, _ = await call(client, "memory_stat", uri=DOC, include_revision=flag)
            assert response.is_error
        for uri in (ROOT + "/other/foreign.md", "viking://user/private",
                    ROOT + "/.watch_tasks.json", A + "/.path.ovlock",
                    A + "/.exact.ovlock.private", A + "/.relations.json", A + "/../bad"):
            response, _ = await call(client, "memory_stat", uri=uri, include_revision=True)
            assert response.is_error
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [
    None, [], {}, {"uri": DOC, "node": {"kind": "absent"}},
    {"uri": ROOT + "/other/foreign.md", "node": {"kind": "directory", "tree_revision": "tree-sha256:" + "a"*64}},
    {"uri": DOC, "node": {"kind": "directory", "tree_revision": "tree-sha256:" + "a"*64}, "private": "SECRET"},
    {"uri": DOC, "node": {"kind": "directory", "tree_revision": "tree-sha256:" + "a"*64, "private": "SECRET"}},
    {"uri": DOC, "node": {"kind": "directory", "tree_revision": "a"*64}},
    {"uri": DOC, "node": {"kind": "file", "content_sha256": "A"*64,
                          "control_revision": "file-controls-v1-sha256:" + "c"*64}},
    {"uri": DOC, "node": {"kind": "file", "content_sha256": "a"*64}},
])
async def test_malformed_foreign_and_absent_refuse(bad):
    engine = Documents()
    engine.node_overrides[DOC] = bad
    principal = Principal("test", (DOC,), int(time.time()) + 60, "fixture",
                          ("read",), RESOURCES_URI_POLICY)
    async with httpx.AsyncClient(transport=httpx.MockTransport(engine.transport)) as client:
        with pytest.raises(Refused):
            await Reader(Backend(config(), principal, client)).stat(DOC, True)
    assert engine.calls == [("GET", NODE_PATH, {"uri": DOC}, None)]
    assert not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["expired_before", "expired_after", "grant_before", "grant_after",
                                    "action_before", "action_after", "budget", "notfound", "unknown"])
async def test_authority_expiry_budget_and_backend_failures(mode):
    engine = Documents()
    principal = Principal("test", (DOC,), int(time.time()) + 60, "fixture",
                          ("read",), RESOURCES_URI_POLICY)
    def revoke():
        if mode.startswith("expired"):
            object.__setattr__(principal, "expires", 0)
        elif mode.startswith("grant"):
            object.__setattr__(principal, "roots", (A + "/foreign.md",))
        elif mode.startswith("action"):
            object.__setattr__(principal, "actions", ())
    if mode.endswith("before"):
        revoke()
    async def transport(request):
        response = await engine.transport(request)
        if mode.endswith("after"):
            revoke()
        return response
    if mode in ("notfound", "unknown"):
        engine.node_fault = (404 if mode == "notfound" else 500, error("NOT_FOUND" if mode == "notfound" else "INTERNAL"))
    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        backend = Backend(config(), principal, client)
        if mode == "budget":
            backend.requests = 128
        with pytest.raises((Refused, BudgetExhausted)):
            await Reader(backend).stat(DOC, True)
    assert len(engine.calls) == (0 if mode.endswith("before") or mode == "budget" else 1)
    assert all(c[:2] == ("GET", NODE_PATH) for c in engine.calls)
    assert not engine.effects


@pytest.mark.asyncio
async def test_sdk_malformed_reply_is_safe_error(sdk_documents):
    session, engine = sdk_documents
    engine.node_overrides[DOC] = {"uri": DOC, "node": {"kind": "directory",
                                  "tree_revision": "tree-sha256:" + "a"*64, "private": "SECRET"}}
    async with session(enabled=False, ov_actions=["read"], scope="ov.read") as client:
        response, value = await call(client, "memory_stat", uri=DOC, include_revision=True)
        assert response.is_error and value == {"error": "Resource unavailable."}
        assert "SECRET" not in json.dumps(value)
    assert not engine.effects
