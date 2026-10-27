"""Focused move/reindex SDK and typed transport fixtures, not native acceptance."""
import json

import pytest

from ov_http.app import SPECS
from test_http_acceptance import call
from test_http_mutations import ROOT, A, B, DOC, TypedBackend, direct, error, ok, sdk

FULL = {"ov_namespaces": [ROOT], "scope": "ov.read ov.write ov.remove ov.maintain",
        "ov_actions": ["read", "write", "remove", "maintain"]}
TARGET = B + "/moved.md"


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args", [
    ("memory_mv", {"from_uri": DOC, "to_uri": TARGET}),
    ("memory_reindex", {"uri": A}),
])
async def test_cancel_after_dispatch_does_not_imply_rollback_or_retry(name, args):
    import asyncio
    import time
    import httpx
    from ov_http.auth import Principal
    from ov_http.config import RESOURCES_URI_POLICY
    from ov_http.mutations import call_mutation
    from ov_http.reader import Backend
    from test_http_mutations import config
    engine = TypedBackend()
    principal = Principal("fixture", (ROOT,), int(time.time()) + 240, "fixture",
                          ("read", "write", "remove", "maintain"), RESOURCES_URI_POLICY)
    dispatched, hold = asyncio.Event(), asyncio.Event()
    async def transport(request):
        response = await engine.transport(request)
        if request.method == "POST":
            dispatched.set()
            await hold.wait()
        return response
    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        state = {}
        task = asyncio.create_task(call_mutation(Backend(config(), principal, client), name, args, state))
        await asyncio.wait_for(dispatched.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert state["dispatched"] is True and len(engine.effects) == 1
    assert len([row for row in engine.calls if row[0] == "POST"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", [{}, {"reindex": True}])
async def test_sdk_move_default_and_explicit_true_same_native_payload(sdk, arguments):
    sessions, engine = sdk
    async with sessions(**FULL) as session:
        response, answer = await call(session, "memory_mv", from_uri=DOC, to_uri=TARGET, **arguments)
        assert not response.is_error, answer
        assert answer["outcome"] == "committed" and answer["no_replace"] is True
        assert answer["index_repair"] == "native_transfer_and_parent_refresh"
        assert answer["indexing"] == "not_observed" and not answer["target_reingested"]
        assert not answer["searchable_completion"] and answer["retry_safe"] is False
    posts = [row for row in engine.calls if row[0] == "POST"]
    assert len(posts) == 1 and posts[0][1:] == (
        "/fs/mv", {}, {"from_uri": DOC, "to_uri": TARGET, "no_replace": True})
    assert engine.calls[-2][1] == "/fs/resources-only/mutation-contract"
    assert engine.files[TARGET] == b"old\n" and DOC not in engine.files
    assert "SECRET" not in json.dumps(answer)


@pytest.mark.asyncio
async def test_sdk_move_false_refuses_before_backend_io(sdk):
    sessions, engine = sdk
    async with sessions(**FULL) as session:
        response, answer = await call(session, "memory_mv", from_uri=DOC, to_uri=TARGET, reindex=False)
        assert response.is_error and answer["outcome"] == "not_started"
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args", [
    ("memory_mv", {"from_uri": DOC, "to_uri": TARGET}),
    ("memory_reindex", {"uri": A}),
])
@pytest.mark.parametrize("claims", [{}, {"scope": "ov.read ov.write ov.remove ov.maintain"},
    {"scope": "ov.read ov.write ov.remove", "ov_actions": ["read", "write", "remove"]}])
async def test_sdk_missing_signed_authority_cannot_mutate(sdk, name, args, claims):
    sessions, engine = sdk
    async with sessions(ov_namespaces=[ROOT], **claims) as session:
        response, _ = await call(session, name, **args)
        assert response.is_error
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("source,target", [
    (ROOT, TARGET), (DOC, ROOT), (DOC, "viking://user/private"), (DOC, B + "/space name"),
    (A + "/.path.ovlock", TARGET), (DOC, B + "/.relations.json"), (DOC, DOC + "/child"),
    (A + "/space name", TARGET),
])
async def test_sdk_move_canonical_root_control_and_overlap_denials(sdk, source, target):
    sessions, engine = sdk
    async with sessions(**FULL) as session:
        response, _ = await call(session, "memory_mv", from_uri=source, to_uri=target)
        assert response.is_error
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("source,target", [(DOC, TARGET), (B + "/source.md", A + "/dest"),
                                          (A, A + "-new")])
async def test_sdk_move_source_destination_grant_and_propagated_parent_denial(sdk, source, target):
    sessions, engine = sdk
    async with sessions(scope=FULL["scope"], ov_actions=FULL["ov_actions"]) as session:
        response, _ = await call(session, "memory_mv", from_uri=source, to_uri=target)
        assert response.is_error
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
async def test_move_exact_generated_ancestor_sidecar_bound_refuses_before_io():
    engine = TypedBackend()
    base = A + "/" + "/".join(["a" * 240] * 4)
    parent = base + "/" + "b" * (1018 - len(base) - 1)
    assert len(parent) == 1018
    async with direct(engine, roots=(ROOT,)) as invoke:
        _, failed = await invoke("memory_mv", from_uri=parent + "/x", to_uri=TARGET)
    assert failed and not engine.calls and not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("poison", [
    {"uri": B + "/foreign.md", "isDir": False},
    {"uri": A + "/folder/.relations.json", "isDir": False},
    {"uri": A + "/folder/.path.ovlock", "isDir": False},
    {"uri": A + "/folder/denied.md", "isDir": False, "access": "denied"},
])
async def test_move_descendant_denials_precede_effects(poison):
    engine = TypedBackend()
    engine.dirs.add(A + "/folder")
    engine.list_poison = poison
    async with direct(engine, roots=(ROOT,)) as invoke:
        _, failed = await invoke("memory_mv", from_uri=A + "/folder", to_uri=B + "/folder")
    assert failed and not engine.effects
    assert not any(row[0] == "POST" for row in engine.calls)


@pytest.mark.asyncio
async def test_move_directory_exact_generated_paths_and_metadata_are_transferred():
    engine = TypedBackend()
    folder = A + "/folder"
    engine.dirs.add(folder)
    engine.files[folder + "/.abstract.md"] = b"abstract"
    engine.files[folder + "/part_1.md"] = b"content"
    async with direct(engine, roots=(ROOT,)) as invoke:
        answer, failed = await invoke("memory_mv", from_uri=folder, to_uri=B + "/folder")
    assert not failed and answer["outcome"] == "committed"
    assert engine.files[B + "/folder/.abstract.md"] == b"abstract"
    assert engine.files[B + "/folder/part_1.md"] == b"content"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["file", "directory"])
async def test_sdk_move_existing_destination_never_posts(sdk, kind):
    sessions, engine = sdk
    if kind == "file":
        engine.files[TARGET] = b"original"
    else:
        engine.dirs.add(TARGET)
    before = (dict(engine.files), set(engine.dirs))
    async with sessions(**FULL) as session:
        response, answer = await call(session, "memory_mv", from_uri=DOC, to_uri=TARGET)
        assert response.is_error and answer["outcome"] == "not_started"
    assert (engine.files, engine.dirs) == before and not engine.effects
    assert not any(row[0] == "POST" for row in engine.calls)


@pytest.mark.asyncio
async def test_sdk_move_concurrent_destination_native_refusal_is_conservative_unknown(sdk):
    sessions, engine = sdk
    engine.on_contract = lambda: engine.files.update({TARGET: b"concurrent original"})
    async with sessions(**FULL) as session:
        response, answer = await call(session, "memory_mv", from_uri=DOC, to_uri=TARGET)
        assert response.is_error and answer["outcome"] == "unknown" and not answer["retry_safe"]
    assert not engine.effects and engine.files[DOC] == b"old\n"
    assert engine.files[TARGET] == b"concurrent original"


@pytest.mark.asyncio
@pytest.mark.parametrize("force,args", [(False, {}), (False, {"force": False}), (True, {"force": True})])
async def test_sdk_reindex_typed_call_fixed_scoped_projection(sdk, force, args):
    sessions, engine = sdk
    async with sessions(**FULL) as session:
        response, answer = await call(session, "memory_reindex", uri=A, **args)
        assert not response.is_error, answer
        assert answer["outcome"] == "completed" and answer["indexing"] == "completed"
        assert answer["content_revision_bound"] is False
        assert answer["counters"]["rebuilt_records"] == 1
        assert "SECRET" not in json.dumps(answer) and "task_id" not in answer
    assert engine.calls[-1][1:] == ("/content/reindex", {}, {
        "uri": A, "mode": "vectors_only", "wait": True, "recursive": True, "force": force})
    assert engine.calls[-2][1] == "/fs/resources-only/mutation-contract"


@pytest.mark.asyncio
async def test_reindex_file_requires_parent_overview_read_authority():
    engine = TypedBackend()
    async with direct(engine, roots=(DOC,)) as invoke:
        _, failed = await invoke("memory_reindex", uri=DOC)
    assert failed and not engine.effects and not any(row[0] == "POST" for row in engine.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", [
    {"unsupported_records": 1}, {"failed_records": 1}, {"warnings": ["SECRET source path"]},
])
async def test_sdk_reindex_partial_or_unsupported_is_explicit_error(sdk, changes):
    sessions, engine = sdk
    engine.reindex_changes = changes
    async with sessions(**FULL) as session:
        response, answer = await call(session, "memory_reindex", uri=A)
        assert response.is_error and answer["outcome"] == "completed_with_issues"
        assert answer["indexing"] == "partial" and not answer["retry_safe"]
        assert "SECRET" not in json.dumps(answer)


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", [
    {"uri": B}, {"mode": "semantic_and_vectors"}, {"status": "accepted"},
    {"object_type": "global_namespace"}, {"scanned_records": True}, {"rebuilt_records": -1},
    {"deleted_records": 2**31}, {"unsupported_records": "1"}, {"failed_records": .5},
    {"warnings": "SECRET"},
])
async def test_sdk_reindex_wrong_or_unsafe_result_is_unknown(sdk, changes):
    sessions, engine = sdk
    engine.reindex_changes = changes
    async with sessions(**FULL) as session:
        response, answer = await call(session, "memory_reindex", uri=A)
        assert response.is_error and answer["outcome"] == "unknown"
        assert "SECRET" not in json.dumps(answer)
    assert len([row for row in engine.calls if row[0] == "POST"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args", [
    ("memory_mv", {"from_uri": DOC, "to_uri": TARGET}),
    ("memory_reindex", {"uri": A}),
])
@pytest.mark.parametrize("fault", ["timeout", "malformed", "foreign", "failure_after", "conflict"])
async def test_sdk_postdispatch_error_is_unknown_without_retry(sdk, name, args, fault):
    sessions, engine = sdk
    engine.fault = fault
    async with sessions(**FULL) as session:
        response, answer = await call(session, name, **args)
        assert response.is_error and answer["outcome"] == "unknown" and not answer["retry_safe"]
        assert "SECRET" not in json.dumps(answer)
    assert len([row for row in engine.calls if row[0] == "POST"]) == 1
    if name == "memory_mv" and fault == "failure_after":
        assert DOC not in engine.files and engine.files[TARGET] == b"old\n"


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args", [
    ("memory_mv", {"from_uri": DOC, "to_uri": TARGET}),
    ("memory_reindex", {"uri": A}),
])
async def test_sdk_old_contract_refuses_both_before_effect(sdk, name, args):
    sessions, engine = sdk
    engine.contract = None
    async with sessions(**FULL) as session:
        response, answer = await call(session, name, **args)
        assert response.is_error and answer["outcome"] == "not_started"
    assert not engine.effects and not any(row[0] == "POST" for row in engine.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args,after", [
    ("memory_mv", {"from_uri": DOC, "to_uri": TARGET}, "committed"),
    ("memory_reindex", {"uri": A}, "completed"),
])
@pytest.mark.parametrize("fault", ["expire_on_contract", "expire_after_commit"])
async def test_expiry_before_dispatch_and_after_valid_ack_distinct(name, args, after, fault):
    engine = TypedBackend()
    engine.fault = fault
    async with direct(engine, roots=(ROOT,)) as invoke:
        answer, failed = await invoke(name, **args)
    assert failed
    assert answer["outcome"] == ("not_started" if fault == "expire_on_contract" else after)
    assert len(engine.effects) == (0 if fault == "expire_on_contract" else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args", [
    ("memory_mv", {"from_uri": DOC, "to_uri": TARGET}),
    ("memory_reindex", {"uri": A}),
])
async def test_sdk_off_catalog_never_exposes_or_dispatches_new_handlers(sdk, name, args):
    sessions, engine = sdk
    async with sessions(enabled=False, **FULL) as session:
        assert {tool.name for tool in (await session.list_tools()).tools} == set(SPECS)
        response, _ = await call(session, name, **args)
        assert response.is_error
    assert not engine.calls and not engine.effects
