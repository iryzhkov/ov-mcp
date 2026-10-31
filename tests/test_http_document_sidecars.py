"""Document-only physical metadata preservation; fixtures are not native proof."""
import json
import time

import pytest

from test_http_document_write import ACTIONS, A, Documents, args, invoke
from ov_http.auth import Principal
from ov_http.mutations import call_mutation

TARGET = A + "/new.md"
SIDECAR = "/.relations.json"


def tree():
    engine = Documents()
    engine.dirs.update({TARGET, TARGET + "/nested"})
    engine.files[TARGET + "/chunk.md"] = b"old body"
    engine.files[TARGET + SIDECAR] = b'{"private":"root metadata"}'
    engine.files[TARGET + "/nested" + SIDECAR] = b'{"private":"nested metadata"}'
    return engine


@pytest.mark.asyncio
@pytest.mark.parametrize("dry_run", [True, False])
async def test_document_sidecars_preserved_with_owner_authority_only(dry_run, monkeypatch):
    engine = tree()
    before = (dict(engine.files), set(engine.dirs))
    checked = []
    original = Principal.require_action

    def record(self, action, *uris):
        checked.extend((action, uri) for uri in uris)
        return original(self, action, *uris)

    monkeypatch.setattr(Principal, "require_action", record)
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(overwrite=True, verify=False, dry_run=dry_run))
    assert not failed
    assert all(SIDECAR not in uri for _, uri in checked)
    assert SIDECAR not in json.dumps(answer) and "metadata" not in json.dumps(answer)
    for owner in (TARGET, TARGET + "/nested"):
        assert all((action, owner) in checked for action in ACTIONS)
    if dry_run:
        assert answer["preflight"] == {"stage": "ready", "category": "passed"}
        assert answer["dispatched"] is False
        assert (engine.files, engine.dirs) == before
        assert not engine.effects and all(c[0] == "GET" for c in engine.calls)
    else:
        backup = answer["backup"]["uri"]
        for path, raw in before[0].items():
            if path.startswith(TARGET + "/"):
                assert engine.files[backup + path[len(TARGET):]] == raw
        for owner in (backup, backup + "/nested"):
            assert all((action, owner) in checked for action in ("read", "write", "maintain"))
        payload = next(c[3] for c in engine.calls if c[1] == "/resources/document-write")
        assert set(payload) == {"target_uri", "source_name", "text", "reason",
                                "representation", "expected", "backup_uri"}
        assert answer["content_state"] == "committed"


@pytest.mark.asyncio
@pytest.mark.parametrize("dry_run", [True, False])
@pytest.mark.parametrize("fault", [
    "directory", "denied", "duplicate", "misplaced", "foreign", "lookalike",
    "hidden", "lock", "watch", "malformed", "budget", "physical_length",
    "backup_length", "missing_remove", "uncovered_parent",
])
async def test_bad_inventory_or_authority_never_dispatches(fault, dry_run):
    engine = tree()
    options = {}
    if fault == "directory":
        engine.dirs.add(TARGET + SIDECAR)
    elif fault in {"denied", "duplicate", "malformed"}:
        engine.list_poison = {"uri": TARGET + SIDECAR, "isDir": False}
        if fault == "denied":
            engine.list_poison["access"] = "denied"
        if fault == "malformed":
            engine.list_poison["isDir"] = 0
    elif fault in {"misplaced", "foreign"}:
        engine.list_poison = {
            "uri": TARGET + "/nested" + SIDECAR if fault == "misplaced"
            else "viking://user/private" + SIDECAR, "isDir": False}
    elif fault in {"lookalike", "hidden", "lock", "watch"}:
        leaf = {"lookalike": ".relations.json.bak", "hidden": ".other.json",
                "lock": ".path.ovlock", "watch": ".watch_tasks.json"}[fault]
        engine.files[TARGET + "/" + leaf] = b"private"
    elif fault == "budget":
        # Root + nested + sidecars + chunks exceed the shared 128-node budget.
        engine.files.update({TARGET + f"/chunk-{i}.md": b"x" for i in range(125)})
    elif fault in {"physical_length", "backup_length"}:
        parent = TARGET
        for part in ["a" * 240] * 3 + ["β" * (127 if fault == "physical_length" else 115)]:
            parent += "/" + part
            engine.dirs.add(parent)
        engine.files[parent + SIDECAR] = b"private"
        physical = parent + SIDECAR
        if fault == "backup_length":
            assert len(physical.encode()) <= 1024
            assert len(physical.encode()) + len("/archive") + len(".backup-") + 16 > 1024
        else:
            assert len(physical.encode()) > 1024
    elif fault == "missing_remove":
        options["actions"] = ("read", "write", "maintain")
    elif fault == "uncovered_parent":
        options["roots"] = (TARGET,)
    before = (dict(engine.files), set(engine.dirs))
    async with invoke(engine, **options) as (run, _, _):
        answer, failed = await run(**args(overwrite=True, verify=False, dry_run=dry_run))
    assert failed and answer["outcome"] == "not_started"
    assert (engine.files, engine.dirs) == before
    assert not engine.effects and not engine.backups
    assert all(c[0] == "GET" for c in engine.calls)
    assert SIDECAR not in json.dumps(answer) and "private" not in json.dumps(answer)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation,arguments", [
    ("memory_mv", {"from_uri": TARGET, "to_uri": A + "/moved.md"}),
    ("memory_reindex", {"uri": TARGET}),
    ("memory_rm", {"uri": TARGET, "recursive": True}),
    ("memory_rm", {"uri": TARGET, "recursive": True, "dry_run": True}),
])
async def test_ordinary_mutations_still_refuse_sidecars(operation, arguments):
    engine = tree()
    before = (dict(engine.files), set(engine.dirs))
    async with invoke(engine) as (_, _, backend):
        answer, failed = await call_mutation(backend, operation, arguments, {})
    assert failed and answer["outcome"] == "not_started"
    assert SIDECAR not in json.dumps(answer)
    assert not engine.effects and (engine.files, engine.dirs) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("point", ["inventory", "contract"])
async def test_expiry_during_sidecar_preflight_never_dispatches_or_discloses(point):
    class Expiring(Documents):
        def reply(self, method, path, params, body):
            result = super().reply(method, path, params, body)
            if point == "inventory" and path == "/fs/ls":
                object.__setattr__(principal, "expires", int(time.time()) - 1)
            return result

    engine = Expiring()
    engine.dirs.add(TARGET)
    engine.files[TARGET + SIDECAR] = b"private"
    async with invoke(engine) as (run, principal, _):
        if point == "contract":
            engine.document_contract_hook = lambda: object.__setattr__(
                principal, "expires", int(time.time()) - 1)
        answer, failed = await run(**args(overwrite=True, dry_run=True))
    assert failed and answer["preflight"]["category"] == "unavailable"
    assert answer["dispatched"] is False and not engine.effects
    assert SIDECAR not in json.dumps(answer)
