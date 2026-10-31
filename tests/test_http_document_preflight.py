"""Read-only WebMCP preflight, including dispatch and disclosure boundaries."""
import asyncio
import json
import time

import pytest

from test_http_document_write import (
    ACTIONS, A, Documents, args, invoke, sdk_documents,
)
from test_http_acceptance import SECRET, call
from ov_http.document_write import CONTRACT_PATH, NODE_PATH, WRITE_PATH, DocumentWriter



@pytest.mark.asyncio
@pytest.mark.parametrize("capability", [None, {"contract": "resources-document-write", "version": 1},
                                      {"contract": "resources-document-write", "version": True},
                                      {"contract": "resources-document-write", "version": 2, "extra": True}])
async def test_exact_directory_requires_closed_v2_before_post(capability):
    engine = Documents()
    target = A + "/new.md"
    engine.dirs.add(target)
    engine.files[target + "/old.md"] = b"old"
    engine.document_contract = capability
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(storage="exact-directory-v2", overwrite=True))
    assert failed and answer["outcome"] == "not_started"
    assert not engine.effects and all(c[0] == "GET" for c in engine.calls)


@pytest.mark.asyncio
async def test_exact_directory_roundtrip_original_uri_and_backup():
    from ov_http.reader import Reader

    engine = Documents()
    target = A + "/new.md"
    engine.dirs.add(target)
    engine.files[target + "/old.md"] = b"old exact\r\n "
    engine.files[target + "/.relations.json"] = b'{"relations":[]}'
    engine.document_contract = {"contract": "resources-document-write", "version": 2}
    body = "# Original Ω\n\n## Decisions 漢字\n\n" + ("  cobalt Ω  \t\n\n" * 650) + "\r\n "
    assert len(body.encode()) > len(body) > 6000
    async with invoke(engine) as (run, _, backend):
        answer, failed = await run(**args(text=body, storage="exact-directory-v2", overwrite=True))
        assert not failed, answer
        assert answer["uri"] == target and answer["verification"]["status"] == "exact"
        observed = await Reader(backend).read(target, limit=2000, storage="exact-directory-v2")
        assert observed["text"].encode() == body.encode() and not observed["truncated"]
    backup = answer["backup"]["uri"]
    assert engine.files[backup + "/old.md"] == b"old exact\r\n "
    assert engine.files[backup + "/.relations.json"] == b'{"relations":[]}'
    contract = next(c for c in engine.calls if c[1] == CONTRACT_PATH)
    assert str(contract[2]["version"]) == "2"
    payload = next(c[3] for c in engine.calls if c[1] == WRITE_PATH)
    assert payload["target_uri"] == target and payload["contract_version"] == 2
    assert payload["representation"] == "exact_directory"


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["remove", "sidecar_denied", "stale_sidecar", "verbatim", "file", "absent"])
async def test_exact_directory_denials_preserve_content(fault):
    engine = Documents()
    target = A + "/new.md"
    engine.dirs.add(target)
    engine.files[target + "/.relations.json"] = b"old private metadata"
    engine.document_contract = {"contract": "resources-document-write", "version": 2}
    options, arguments = {}, {}
    if fault == "remove":
        options["actions"] = ("read", "write", "maintain")
    elif fault == "sidecar_denied":
        engine.list_poison = {"uri": target + "/.relations.json", "isDir": False, "access": "denied"}
    elif fault == "stale_sidecar":
        engine.before_post = lambda uri: engine.files.update({uri + "/.relations.json": b"concurrent"})
    elif fault == "verbatim":
        arguments["verbatim"] = True
    elif fault in {"file", "absent"}:
        engine.dirs.remove(target)
        engine.files.clear()
        if fault == "file":
            engine.files[target] = b"old"
    async with invoke(engine, **options) as (run, _, _):
        answer, failed = await run(**args(storage="exact-directory-v2", overwrite=True, **arguments))
    assert failed and not engine.effects and not engine.backups
    assert answer["outcome"] in {"not_started", "target_unchanged"}
    assert all(c[0] == "GET" for c in engine.calls) or fault == "stale_sidecar"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["absent", "file", "directory"])
async def test_dry_run_prepares_without_any_mutation(kind):
    engine = Documents()
    target = A + "/new.md"
    if kind == "file":
        engine.files[target] = b"retained"
    if kind == "directory":
        engine.dirs.add(target)
        engine.files[target + "/chunk.md"] = b"retained"
    before = (dict(engine.files), set(engine.dirs))
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(dry_run=True, overwrite=True))
    assert not failed
    assert answer["outcome"] == "not_started"
    assert answer["preflight_passed"] and answer["dispatched"] is False
    assert answer["preflight"] == {"stage": "ready", "category": "passed"}
    assert all(c[0] == "GET" for c in engine.calls)
    assert not engine.effects and not engine.backups
    assert (engine.files, engine.dirs) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("message,category", [
    ("Document URI must be canonical resources content", "invalid_document_uri"),
    ("Directory fragment controls are unsupported", "directory_fragment_controls"),
    ("Resource document has residual index state", "residual_index_state"),
    ("Document context inventory incomplete", "context_inventory_incomplete"),
    ("Document context limit exceeded", "context_limit"),
    ("Document aliases are unsupported", "document_alias"),
    (SECRET, "unavailable"),
])
async def test_node_refusal_projects_only_closed_category(message, category):
    engine = Documents()
    engine.node_fault = (400, {"status": "error", "error": {
        "code": "INVALID_ARGUMENT", "message": message,
        "details": {"uri": SECRET, "owner": SECRET},
    }})
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(dry_run=True))
    assert failed and answer["outcome"] == "not_started"
    assert answer["preflight"] == {"stage": "target_node", "category": category}
    assert SECRET not in json.dumps(answer)
    assert all(c[0] == "GET" for c in engine.calls)
    assert not engine.effects


@pytest.mark.asyncio
async def test_inflight_expiry_suppresses_backend_category():
    class Expiring(Documents):
        def reply(self, method, path, params, body):
            if path == NODE_PATH:
                object.__setattr__(principal, "expires", int(time.time()) - 1)
                return 400, {"status": "error", "error": {
                    "code": "INVALID_ARGUMENT",
                    "message": "Document URI must be canonical resources content",
                    "details": {"uri": SECRET},
                }}
            return super().reply(method, path, params, body)
    engine = Expiring()
    async with invoke(engine) as (run, principal, _):
        answer, failed = await run(**args(dry_run=True))
    assert failed and answer["preflight"] == {
        "stage": "target_node", "category": "unavailable"}
    assert SECRET not in json.dumps(answer)
    assert not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["action", "expiry", "budget", "contract_expiry"])
async def test_dry_run_retains_authority_and_budget_guards(mode):
    engine = Documents()
    options = {}
    if mode == "action":
        options["actions"] = ("read", "write")
    elif mode == "expiry":
        options["expires"] = int(time.time()) - 1
    elif mode == "budget":
        options["requests"] = 1000
    async with invoke(engine, **options) as (run, principal, _):
        if mode == "contract_expiry":
            engine.document_contract_hook = lambda: object.__setattr__(
                principal, "expires", int(time.time()) - 1)
        answer, failed = await run(**args(dry_run=True))
    assert failed and answer["dispatched"] is False
    assert not engine.effects and all(c[0] == "GET" for c in engine.calls)


@pytest.mark.asyncio
async def test_dry_run_still_requires_remove_for_overwrite():
    engine = Documents()
    engine.files[A + "/new.md"] = b"retained"
    async with invoke(engine, actions=("read", "write", "maintain")) as (run, _, _):
        answer, failed = await run(**args(dry_run=True, overwrite=True))
    assert failed and answer["preflight"]["stage"] == "subtree"
    assert not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("effect", [False, True])
async def test_dry_run_dispatch_guard_survives_writer_regression(monkeypatch, effect):
    async def accidental_post(self, arguments):
        return await self.m.request("POST", WRITE_PATH, effect=effect, json={})
    monkeypatch.setattr(DocumentWriter, "write", accidental_post)
    engine = Documents()
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(dry_run=True))
    assert failed and not engine.calls and not engine.effects
    assert answer["dispatched"] is False


@pytest.mark.asyncio
async def test_cancelled_dry_run_never_dispatches():
    class Cancelled(Documents):
        def reply(self, method, path, params, body):
            if path == NODE_PATH:
                raise asyncio.CancelledError()
            return super().reply(method, path, params, body)
    engine = Cancelled()
    async with invoke(engine) as (run, _, _):
        with pytest.raises(asyncio.CancelledError):
            await run(**args(dry_run=True))
    assert not engine.effects and all(c[0] == "GET" for c in engine.calls)


@pytest.mark.asyncio
async def test_deferred_dry_run_is_explicitly_unsupported():
    engine = Documents()
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(dry_run=True, storage="file-deferred-v1"))
    assert failed and answer["supported"] is False
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
async def test_sdk_dry_run_schema_and_default_write_unchanged(sdk_documents):
    session, engine = sdk_documents
    claims = {"ov_actions": list(ACTIONS), "scope": "ov.read ov.write ov.maintain ov.remove"}
    async with session(**claims) as client:
        spec = next(t for t in (await client.list_tools()).tools if t.name == "memory_write")
        assert spec.input_schema["properties"]["dry_run"] == {"type": "boolean"}
        response, answer = await call(client, "memory_write", **args(dry_run=True))
        assert not response.is_error and answer["preflight_passed"]
        assert not engine.effects
        response, answer = await call(client, "memory_write", **args())
        assert not response.is_error and answer["content_state"] == "committed"
        assert "dry_run" not in answer and len(engine.effects) == 1
