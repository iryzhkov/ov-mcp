"""Typed backend transport and official SDK fixtures, not native acceptance."""
import asyncio
import base64
from contextlib import asynccontextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import ssl
import time

import httpx
import pytest
import pytest_asyncio
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from ov_http.app import SPECS, create_app, schema
from ov_http.auth import Principal
from ov_http.config import Config, RESOURCES_PROFILE, RESOURCES_REVISION, RESOURCES_URI_POLICY
from ov_http.mutations import CONTRACT, CONTRACT_PATH, MUTATION_SPECS, PROFILE, call_mutation
from ov_http.reader import Backend
from test_http_acceptance import Fixture, ISSUER, SECRET, call, serving

ROOT = "viking://resources"
A = ROOT + "/notes"
B = ROOT + "/other"
DOC = A + "/old.md"


def ok(value, **extra):
    return {"status": "ok", "result": value, **extra}


def error(code, **details):
    return {"status": "error", "error": {"code": code, "message": "SECRET source=/host/private",
                                        "details": details}}


class TypedBackend:
    """Only modeled endpoints; unknown routes fail the fixture."""
    def __init__(self):
        self.files = {DOC: b"old\n"}
        self.dirs = {ROOT, A, B}
        self.calls = []
        self.effects = []
        self.contract = CONTRACT
        self.fault = ""
        self.hits = []
        self.search_rows: list[dict] | None = None
        self.on_search = None
        self.stat_fault = {}
        self.list_poison = None
        self.on_contract = None
        self.read_fault = False
        self.on_effect = None
        self.reindex_changes = {}

    def reply(self, method, path, params, body):
        self.calls.append((method, path, params, body))
        if path == CONTRACT_PATH:
            if self.on_contract is not None:
                self.on_contract()
            if self.contract is None:
                return 404, error("NOT_FOUND")
            return 200, ok(self.contract)
        uri = params.get("uri")
        if path == "/fs/stat":
            if uri in self.stat_fault:
                return self.stat_fault[uri]
            if uri in self.dirs:
                return 200, ok({"uri": uri, "isDir": True, "size": 4096, "source": "SECRET"})
            if uri in self.files:
                return 200, ok({"uri": uri, "isDir": False, "size": len(self.files[uri]),
                                "source": "SECRET"})
            return 404, error("NOT_FOUND")
        if path == "/content/read":
            if self.read_fault:
                return 500, error("INTERNAL")
            if uri not in self.files:
                return 404, error("NOT_FOUND")
            return 200, ok(self.files[uri].decode())
        if path == "/fs/ls":
            assert params["simple"] == "false" and params["show_all_hidden"] == "true"
            rows = [{"uri": name, "isDir": name in self.dirs} for name in sorted(self.dirs | self.files.keys())
                    if name.startswith(uri + "/") and "/" not in name[len(uri) + 1:]]
            if self.list_poison is not None:
                rows.append(self.list_poison)
            return 200, ok(rows, has_more=False)
        if path == "/search/search":
            assert set(body["target_uri"]) <= self.dirs
            assert body["context_type"] == "resource" and body["read_content"] is False
            assert body["telemetry"] is False and body["limit"] == 100
            # Filter before score sorting and limit, as required of the actual backend.
            candidates = self.hits + [B + "/foreign.md", "viking://user/private.md"]
            hits = [name for name in candidates if any(name == root or name.startswith(root + "/")
                                                       for root in body["target_uri"])]
            rows = [search_hit(name) for name in hits] if self.search_rows is None else self.search_rows
            if self.on_search is not None:
                self.on_search()
            return 200, ok({"memories": [], "skills": [], "resources": rows})
        assert method == "POST", (method, path)
        if self.fault == "timeout":
            raise httpx.ReadTimeout("SECRET transport")
        if self.fault == "conflict":
            return 409, error("CONFLICT")
        if path == "/content/batch-write":
            assert set(body) == {"root_uri", "operations", "wait", "telemetry",
                                 "skip_conflicts", "defer_processing", "edit_source"}
            assert body["wait"] is True and body["defer_processing"] is True
            assert body["skip_conflicts"] is False and body["telemetry"] is False
            assert len(body["operations"]) == 1
            op = body["operations"][0]
            allowed = {"uri", "content_base64", "mode", "expected_absent", "expected_sha256"}
            assert not set(op) - allowed and "content" not in op
            uri = op["uri"]
            assert body["root_uri"] == uri.rsplit("/", 1)[0]
            assert body["root_uri"] in self.dirs
            exists = uri in self.files or uri in self.dirs
            if op.get("expected_absent") and exists:
                return 409, error("CONFLICT")
            if "expected_sha256" in op and (uri not in self.files or
                    hashlib.sha256(self.files[uri]).hexdigest() != op["expected_sha256"]):
                return 409, error("CONFLICT")
            data = base64.b64decode(op["content_base64"], validate=True)
            self.files[uri] = data
            self.effects.append((path, uri))
            value = {"root_uri": body["root_uri"], "created": [] if exists else [uri],
                     "updated": [uri] if exists else [], "unchanged": [], "queue_status": None,
                     "semantic_status": "deferred", "vector_status": "deferred", "source": "SECRET"}
        elif path == "/fs/mv":
            assert set(body) == {"from_uri", "to_uri", "no_replace"} and body["no_replace"] is True
            source, target = body["from_uri"], body["to_uri"]
            assert source.rsplit("/", 1)[0] in self.dirs and target.rsplit("/", 1)[0] in self.dirs
            if target in self.files or target in self.dirs:
                return 409, error("ALREADY_EXISTS")
            moved_files = {target + name[len(source):]: value for name, value in self.files.items()
                           if name == source or name.startswith(source + "/")}
            self.files = {name: value for name, value in self.files.items()
                          if not (name == source or name.startswith(source + "/"))}
            self.files.update(moved_files)
            self.dirs = {target + name[len(source):] if name == source or name.startswith(source + "/")
                         else name for name in self.dirs}
            self.effects.append((path, source))
            value = {"from": source, "to": target, "no_replace": True, "source": "SECRET"}
        elif path == "/content/reindex":
            assert set(body) == {"uri", "mode", "wait", "recursive", "force"}
            assert body["mode"] == "vectors_only" and body["wait"] is True and body["recursive"] is True
            assert type(body["force"]) is bool
            uri = body["uri"]
            self.effects.append((path, uri))
            value = {"uri": uri, "mode": "vectors_only", "object_type": "resource", "status": "completed",
                     "scanned_records": 1, "rebuilt_records": 1, "deleted_records": 0,
                     "unsupported_records": 0, "failed_records": 0, "duration_ms": 3,
                     "warnings": [], "task_id": "SECRET", "source": "/host/SECRET"}
            value.update(self.reindex_changes)
        elif path == "/fs/mkdir":
            assert set(body) <= {"uri", "description"} and "uri" in body
            uri = body["uri"]
            assert uri.rsplit("/", 1)[0] in self.dirs
            if uri in self.dirs or uri in self.files:
                return 409, error("ALREADY_EXISTS")
            self.dirs.add(uri)
            self.files[uri + "/.abstract.md"] = body.get("description", "# directory").encode("utf-8")
            self.effects.append((path, uri))
            value = {"uri": uri, "secret": "SECRET"}
        elif path in {"/fs/resources-only/remove", "/fs/resources-only/prune-index"}:
            assert set(body) == ({"uri", "recursive"} if path.endswith("/remove") else {"uri"})
            uri = body["uri"]
            exists = uri in self.dirs or uri in self.files
            if path.endswith("/prune-index"):
                if exists:
                    return 409, error("CONFLICT")
                outcome = "pruned"
            else:
                if not exists:
                    return 404, error("NOT_FOUND")
                self.files = {name: value for name, value in self.files.items()
                              if not (name == uri or name.startswith(uri + "/"))}
                self.dirs = {name for name in self.dirs
                             if not (name == uri or name.startswith(uri + "/"))}
                outcome = "removed"
            self.effects.append((path, uri))
            value = {"uri": uri, "outcome": outcome, "memory_cleanup": {"SECRET": True}}
        else:
            raise AssertionError("Unmodeled effectful endpoint " + path)
        if self.on_effect is not None:
            self.on_effect()
        if self.fault == "malformed":
            return 200, ok(["SECRET"])
        if self.fault == "foreign":
            return 200, ok({"uri": B + "/foreign.md", "source": "SECRET"})
        if self.fault == "failure_after":
            return 500, error("INTERNAL", outcome="unknown")
        return 200, ok(value)

    async def transport(self, request):
        body = json.loads(request.content) if request.content else None
        status, value = self.reply(request.method, request.url.path.removeprefix("/api/v1"),
                                   dict(request.url.params), body)
        return httpx.Response(status, json=value)


def config():
    return Config(resource="https://ov.example/mcp", issuer=ISSUER,
                  jwks_url="https://issuer.example/jwks", backend_url="http://backend/api/v1",
                  backend_secret_file="/unused", semantic_profile=RESOURCES_PROFILE,
                  semantic_backend_revision=RESOURCES_REVISION, namespace_roots=(ROOT,),
                  mutation_profile=PROFILE)


@asynccontextmanager
async def direct(engine, *, roots=(A,), actions=("read", "write", "remove", "maintain"), expires=None,
                 requests=0):
    principal = Principal("fixture", roots, int(time.time()) + 240 if expires is None else expires,
                          "fixture-grants", actions, RESOURCES_URI_POLICY)
    async with httpx.AsyncClient(transport=httpx.MockTransport(engine.transport)) as client:
        backend = Backend(config(), principal, client)
        backend.requests = requests
        engine.on_contract = lambda: None
        if engine.fault == "expire_on_contract":
            engine.on_contract = lambda: object.__setattr__(principal, "expires", int(time.time()) - 1)
        if engine.fault == "expire_after_search":
            engine.on_search = lambda: object.__setattr__(principal, "expires", int(time.time()) - 1)
        if engine.fault == "expire_after_commit":
            engine.on_effect = lambda: object.__setattr__(principal, "expires", int(time.time()) - 1)
        async def invoke(name, **arguments):
            return await call_mutation(backend, name, arguments, {})
        yield invoke


def write_args(**changes):
    return {"to": A, "filename": "new.md", "text": "  alpha\r\nβ\n\n",
            "storage": "file-deferred-v1", **changes}


@pytest.mark.asyncio
async def test_conditional_file_create_overwrite_exact_bytes_and_no_clobber():
    engine = TypedBackend()
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_write", **write_args())
        assert not failed and answer["indexing"] == "deferred"
        assert answer["verification"] == "exact" and answer["searchable_completion"] is False
        assert engine.files[A + "/new.md"] == write_args()["text"].encode()
        again, failed = await invoke("memory_write", **write_args())
        assert failed and again["conflict"] and len(engine.effects) == 1
    async with direct(engine) as invoke:
        stale, failed = await invoke("memory_write", **write_args(
            filename="old.md", overwrite=True, expected_sha256="0" * 64))
        assert failed and stale["outcome"] == "not_started" and engine.files[DOC] == b"old\n"
        answer, failed = await invoke("memory_write", **write_args(
            filename="old.md", overwrite=True, expected_sha256=hashlib.sha256(b"old\n").hexdigest()))
        assert not failed and answer["outcome"] == "committed"
    posts = [i for i, row in enumerate(engine.calls) if row[0] == "POST"]
    assert all(engine.calls[i - 1][1] == CONTRACT_PATH for i in posts)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    {"to": A + "/space name"}, {"filename": "space name.md"},
    {"filename": ".watch_tasks.json", "to": ROOT},
    {"filename": ".path.ovlock"}, {"filename": ".relations.json"},
    {"filename": "../escape"}, {"to": B}, {"filename": ".exact.ovlock.x"},
    {"filename": ".abstract.md"}, {"filename": ".overview.md"},
])
async def test_target_denials_precede_any_effect(change):
    engine = TypedBackend()
    async with direct(engine) as invoke:
        _, failed = await invoke("memory_write", **write_args(**change))
    assert failed and engine.effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize("actions", [("read",), ("read", "remove"), ("read", "maintain")])
async def test_signed_read_authority_cannot_write(actions):
    engine = TypedBackend()
    async with direct(engine, actions=actions) as invoke:
        _, failed = await invoke("memory_write", **write_args())
    assert failed and engine.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("contract", [None, {}, {"contract": "resources-document-mutations", "version": 0},
    {"contract": "resources-document-mutations", "version": True}, {**CONTRACT, "extra": True}])
async def test_old_or_malformed_contract_never_dispatches(contract):
    engine = TypedBackend()
    engine.contract = contract
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_write", **write_args())
    assert failed and answer["outcome"] == "not_started" and engine.effects == []
    assert not any(row[0] == "POST" for row in engine.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["timeout", "malformed", "foreign", "failure_after"])
async def test_uncertain_dispatch_never_retries_or_projects_upstream_details(fault):
    engine = TypedBackend()
    engine.fault = fault
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_write", **write_args())
    assert failed and answer["outcome"] == "unknown" and answer["retry_safe"] is False
    assert len([row for row in engine.calls if row[0] == "POST"]) == 1
    assert "SECRET" not in json.dumps(answer)


@pytest.mark.asyncio
async def test_mkdir_generated_path_and_resources_only_delete_dry_run_and_prune():
    engine = TypedBackend()
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_mkdir", uri=A + "/folder")
        assert not failed and answer["outcome"] == "committed"
        assert answer["indexing"] == "not_observed" and not answer["searchable_completion"]
        assert engine.effects == [("/fs/mkdir", A + "/folder")]
        before = len(engine.effects)
        answer, failed = await invoke("memory_rm", uri=A + "/folder", recursive=True, dry_run=True)
        assert not failed and A + "/folder/.abstract.md" in answer["paths"]
        assert len(engine.effects) == before
        answer, failed = await invoke("memory_rm", uri=A + "/folder", recursive=True)
        assert not failed and answer["memory_cleanup"] is False
        answer, failed = await invoke("memory_index_prune", uri=A + "/absent.md", dry_run=True)
        assert not failed and answer["outcome"] == "dry_run" and len(engine.effects) == before + 1
        answer, failed = await invoke("memory_index_prune", uri=A + "/absent.md")
        assert not failed and answer["scope"] == "exact_uri"
    assert all(path != "/fs" for path, _ in engine.effects)
    assert "SECRET" not in json.dumps(answer)


@pytest.mark.asyncio
@pytest.mark.parametrize("poison", [
    {"uri": B + "/foreign.md", "isDir": False},
    {"uri": A + "/folder/.relations.json", "isDir": False},
    {"uri": A + "/folder/.path.ovlock", "isDir": False},
    {"uri": A + "/folder/denied.md", "isDir": False, "access": "denied"},
    {"uri": A + "/folder/nested/x.md", "isDir": False},
])
async def test_recursive_denial_before_remove(poison):
    engine = TypedBackend()
    engine.dirs.add(A + "/folder")
    engine.list_poison = poison
    async with direct(engine) as invoke:
        _, failed = await invoke("memory_rm", uri=A + "/folder", recursive=True)
    assert failed and engine.effects == []


@pytest.mark.asyncio
async def test_audit_scope_before_rank_exact_absence_only_and_no_error_as_absence():
    engine = TypedBackend()
    missing = A + "/gone.md"
    engine.hits = [DOC, missing]
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_index_audit", query="note", scope=A, fix=True)
        assert not failed and answer["absent"] == [missing] and answer["pruned_count"] == 1
        assert answer["checked"] == 2 and answer["complete"] is False
    assert engine.effects == [("/fs/resources-only/prune-index", missing)]
    engine.effects.clear()
    engine.stat_fault[missing] = (403, error("PERMISSION_DENIED"))
    async with direct(engine) as invoke:
        _, failed = await invoke("memory_index_audit", query="note", scope=A, fix=True)
    assert failed and engine.effects == []

def search_hit(uri, level=2, **changes):
    """Injected typed rows, including source-supported L0/L1 sidecar shapes."""
    return {
        "uri": uri,
        "context_type": "resource",
        "level": level,
        "score": 0.8,
        "abstract": "ignored",
        "source": "SECRET",
        **changes,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("fix", [False, True])
@pytest.mark.parametrize("limit", [1, 2, 40])
async def test_sdk_audit_document_candidates_omit_only_validated_metadata(sdk, fix, limit):
    sessions, engine = sdk
    abstract, overview, missing = A + "/.abstract.md", DOC + "/.overview.md", A + "/gone.md"
    engine.search_rows = [
        search_hit(abstract, 0),
        search_hit(DOC),
        search_hit(abstract, 0),
        search_hit(DOC),
        search_hit(missing),
        search_hit(overview, 1),
    ]
    claims = {"scope": "ov.read ov.maintain", "ov_actions": ["read", "maintain"]} if fix else {}
    async with sessions(**claims) as session:
        response, answer = await call(
            session, "memory_index_audit", query="note", scope=A, limit=limit, fix=fix
        )
    assert not response.is_error, answer
    assert answer == {
        "checked": min(limit, 2),
        "present": [DOC],
        "absent": [] if limit == 1 else [missing],
        "pruned_count": int(fix and limit > 1),
        "metadata_omitted": 3,
        "candidate_kind": "document",
        "complete": False,
        "descendant_orphan_sweep": False,
    }
    stats = [row[2]["uri"] for row in engine.calls if row[1] == "/fs/stat"]
    assert abstract not in stats and overview not in stats
    assert engine.effects == ([("/fs/resources-only/prune-index", missing)] if fix and limit > 1 else [])
    assert "SECRET" not in json.dumps(answer)


@pytest.mark.asyncio
@pytest.mark.parametrize("fix", [False, True])
@pytest.mark.parametrize("count", [0, 100, 101])
async def test_audit_metadata_omission_count_is_bounded_validated_batch(fix, count):
    engine = TypedBackend()
    engine.search_rows = [
        search_hit(A + "/.abstract.md", 0) if i % 2 == 0 else search_hit(DOC + "/.overview.md", 1)
        for i in range(count)
    ]
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_index_audit", query="note", scope=A, fix=fix)
    assert failed == (count > 100)
    if not failed:
        assert answer["metadata_omitted"] == count
        assert answer["candidate_kind"] == "document" and answer["complete"] is False
        assert answer["checked"] == answer["pruned_count"] == 0
        assert answer["present"] == answer["absent"] == []
    assert not engine.effects
    assert [row[2]["uri"] for row in engine.calls if row[1] == "/fs/stat"] == [A]


@pytest.mark.asyncio
@pytest.mark.parametrize("fix", [False, True])
@pytest.mark.parametrize("beyond_limit", [False, True])
@pytest.mark.parametrize("roots", [(A,), (A, B)])
@pytest.mark.parametrize(
    "poison",
    [
        search_hit(A + "/bad/../.abstract.md", 0),
        search_hit(B + "/.abstract.md", 0),
        search_hit("viking://user/private/.overview.md", 1),
        search_hit(A + "/.abstract.md", 0, score="bad"),
        search_hit(A + "/.overview.md", 1, context_type="memory"),
        search_hit(A + "/.abstract.md", True),
    ],
)
async def test_audit_validates_entire_batch_before_metadata_omission(fix, beyond_limit, roots, poison):
    engine = TypedBackend()
    valid = [search_hit(A + "/gone.md"), search_hit(A + "/.overview.md", 1)]
    engine.search_rows = valid + [poison] if beyond_limit else [poison] + valid
    async with direct(engine, roots=roots) as invoke:
        answer, failed = await invoke("memory_index_audit", query="note", scope=A, limit=1, fix=fix)
    assert failed and answer["outcome"] == "not_started"
    assert not engine.effects
    assert [row[2]["uri"] for row in engine.calls if row[1] == "/fs/stat"] == [A]


@pytest.mark.asyncio
@pytest.mark.parametrize("fix", [False, True])
@pytest.mark.parametrize(
    "uri,level",
    [
        (A + "/.abstract.md", 1),
        (A + "/.abstract.md", 2),
        (A + "/.overview.md", 0),
        (A + "/.overview.md", 2),
        (A + "/.abstract.md/child.md", 0),
        (A + "/.overview.md/child.md", 1),
        (A + "/.abstract.md/.overview.md", 1),
    ],
)
async def test_audit_unexpected_metadata_shapes_still_refuse(fix, uri, level):
    engine = TypedBackend()
    engine.search_rows = [search_hit(A + "/gone.md"), search_hit(uri, level)]
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_index_audit", query="note", scope=A, fix=fix)
    assert failed and answer["outcome"] == "not_started" and not engine.effects
    assert uri not in [row[2]["uri"] for row in engine.calls if row[1] == "/fs/stat"]


@pytest.mark.asyncio
@pytest.mark.parametrize("fix", [False, True])
@pytest.mark.parametrize("status,code", [(403, "PERMISSION_DENIED"), (500, "INTERNAL"), (404, "UNKNOWN")])
async def test_audit_metadata_does_not_hide_later_stat_failure(fix, status, code):
    engine = TypedBackend()
    broken = A + "/broken.md"
    engine.search_rows = [search_hit(A + "/gone.md"), search_hit(A + "/.abstract.md", 0), search_hit(broken)]
    engine.stat_fault[broken] = (status, error(code))
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_index_audit", query="note", scope=A, fix=fix)
    assert failed and answer["outcome"] == "not_started" and not engine.effects
    assert broken in [row[2]["uri"] for row in engine.calls if row[1] == "/fs/stat"]


@pytest.mark.asyncio
@pytest.mark.parametrize("fix", [False, True])
@pytest.mark.parametrize("boundary", ["expired", "after_search", "budget", "read_only"])
async def test_audit_metadata_preserves_expiry_budget_and_actions(fix, boundary):
    engine = TypedBackend()
    engine.search_rows = [search_hit(A + "/.abstract.md", 0), search_hit(A + "/gone.md")]
    if boundary == "after_search":
        engine.fault = "expire_after_search"
    expires = int(time.time()) - 1 if boundary == "expired" else None
    actions = ("read",) if boundary == "read_only" else ("read", "maintain")
    async with direct(
        engine, expires=expires, actions=actions, requests=127 if boundary == "budget" else 0
    ) as invoke:
        answer, failed = await invoke("memory_index_audit", query="note", scope=A, fix=fix)
    assert failed == (boundary != "read_only" or fix)
    if failed:
        assert answer["outcome"] == "not_started"
    assert not engine.effects
    if boundary == "expired" or boundary == "read_only" and fix:
        assert not engine.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["memory_index_prune", "memory_rm"])
@pytest.mark.parametrize("leaf", [".abstract.md", ".overview.md"])
async def test_direct_metadata_prune_and_remove_still_refuse(tool, leaf):
    engine = TypedBackend()
    async with direct(engine) as invoke:
        answer, failed = await invoke(tool, uri=A + "/" + leaf)
    assert failed and answer["outcome"] == "not_started"
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
async def test_audit_metadata_preserves_partial_prune_unknown():
    engine = TypedBackend()
    first, second = A + "/gone1.md", A + "/gone2.md"
    engine.search_rows = [search_hit(first), search_hit(A + "/.abstract.md", 0), search_hit(second)]
    original = engine.reply

    def raced(method, path, params, body):
        if path == "/fs/resources-only/prune-index" and engine.effects:
            engine.files[body["uri"]] = b"concurrent writer"
        return original(method, path, params, body)

    engine.reply = raced
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_index_audit", query="note", scope=A, fix=True)
    assert failed and answer["outcome"] == "unknown" and answer["retry_safe"] is False
    assert engine.effects == [("/fs/resources-only/prune-index", first)]


@pytest.mark.asyncio
@pytest.mark.parametrize("status,code", [(403, "PERMISSION_DENIED"), (500, "INTERNAL"), (404, "UNKNOWN")])
async def test_prune_stat_failures_are_not_absence(status, code):
    engine = TypedBackend()
    uri = A + "/missing.md"
    engine.stat_fault[uri] = (status, error(code))
    async with direct(engine) as invoke:
        _, failed = await invoke("memory_index_prune", uri=uri)
    assert failed and not engine.effects


@pytest.mark.asyncio
async def test_unsupported_routes_and_legacy_write_preserve_defaults_and_old_chunks():
    engine = TypedBackend()
    engine.dirs.add(A + "/chunked.md")
    engine.files[A + "/chunked.md/part_1.md"] = b"original"
    async with direct(engine) as invoke:
        for name, args in [
            ("memory_write", {"to": A, "filename": "new.md", "text": "body"}),
            ("memory_write", write_args(filename="chunked.md", overwrite=True, expected_sha256="0" * 64)),
            ("memory_write", write_args(verbatim=True)),
            ("memory_mv", {"from_uri": DOC, "to_uri": A + "/dest.md", "reindex": False}),
            ("memory_reindex", {"uri": ROOT}),
        ]:
            answer, failed = await invoke(name, **args)
            assert failed and answer["outcome"] == "not_started"
    assert not engine.effects and engine.files[A + "/chunked.md/part_1.md"] == b"original"


@pytest.mark.asyncio
async def test_scoped_status_expiry_budget_and_file_only_parent_denial():
    engine = TypedBackend()
    async with direct(engine, roots=(DOC,)) as invoke:
        answer, failed = await invoke("memory_status")
        assert not failed and answer["resources"] == [{"uri": DOC, "availability": "present"}]
        assert "SECRET" not in json.dumps(answer) and "count" not in json.dumps(answer)
        _, failed = await invoke("memory_write", **write_args(filename="old.md", overwrite=True,
                                          expected_sha256=hashlib.sha256(b"old\n").hexdigest()))
        assert failed and not engine.effects
    before = len(engine.calls)
    async with direct(engine, expires=int(time.time()) - 1) as invoke:
        _, failed = await invoke("memory_write", **write_args())
    assert failed and len(engine.calls) == before


@pytest_asyncio.fixture
async def sdk(tmp_path):
    home = Path(os.environ["HOME"]).resolve()
    assert home.name == "home" and home.parent.name == ".scratch"
    assert tmp_path.resolve().is_relative_to(home)
    fixture, engine = Fixture(tmp_path), TypedBackend()

    async def route(request):
        if request.url.path == "/jwks":
            return await fixture.backend(request)
        assert request.headers["X-API-Key"] == SECRET
        body = await request.json() if request.method == "POST" else None
        before_reply = getattr(engine, "before_reply", None)
        if before_reply is not None:
            await before_reply(request)
        status, value = engine.reply(request.method, request.url.path.removeprefix("/api/v1"),
                                    dict(request.query_params), body)
        return JSONResponse(value, status_code=status)

    backend = Starlette(routes=[Route("/api/v1/{path:path}", route, methods=["GET", "POST"]),
                                Route("/jwks", route)])
    key = tmp_path / "backend.key"
    key.write_text(SECRET)
    key.chmod(0o600)
    async with serving(backend) as port, serving(backend, ssl_certfile=str(fixture.cert),
                                               ssl_keyfile=str(fixture.cert_key)) as jwks_port:
        cfg = replace(config(), backend_url=f"http://127.0.0.1:{port}/api/v1",
                      backend_secret_file=str(key), jwks_url=f"https://127.0.0.1:{jwks_port}/jwks")
        fixture.resource = cfg.resource
        tls = ssl.create_default_context(cafile=str(fixture.cert))
        @asynccontextmanager
        async def app_session(*, enabled=True, **claims):
            app = create_app(cfg if enabled else replace(cfg, mutation_profile="disabled"),
                             jwks_ssl_context=tls)
            async with serving(app) as app_port:
                fixture.url = f"http://127.0.0.1:{app_port}/mcp"
                async with fixture.session(fixture.token([A], **claims)) as session:
                    yield session
        yield app_session, engine


@pytest.mark.asyncio
async def test_sdk_off_catalog_old11_on_catalog19_signed_readonly_refusal(sdk):
    sessions, engine = sdk
    async with sessions(enabled=False) as session:
        assert {t.name for t in (await session.list_tools()).tools} == set(SPECS)
        response, _ = await call(session, "memory_write", **write_args())
        assert response.is_error
    async with sessions() as session:
        catalog = (await session.list_tools()).tools
        assert {t.name for t in catalog} == set(SPECS) | set(MUTATION_SPECS)
        assert all(not t.annotations.idempotent_hint for t in catalog if t.name == "memory_write")
        response, _ = await call(session, "memory_write", **write_args())
        assert response.is_error
    assert engine.calls == []


@pytest.mark.asyncio
async def test_sdk_explicit_action_scope_matching_and_success(sdk):
    sessions, engine = sdk
    async with sessions(scope="ov.read ov.write", ov_actions=["read", "write"]) as session:
        response, answer = await call(session, "memory_write", **write_args())
        assert not response.is_error and answer["outcome"] == "committed", answer
        response, answer = await call(session, "memory_rm", uri=DOC)
        assert response.is_error
        response, answer = await call(session, "memory_write", **write_args(filename="bad.md", to=B))
        assert response.is_error
    assert len(engine.effects) == 1
    before = len(engine.calls)
    with pytest.raises(Exception):
        async with sessions(scope="ov.read", ov_actions=["read", "write"]):
            pytest.fail("Action/scope mismatch authenticated")
    assert len(engine.calls) == before



@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["café.md", "cafe\u0301.md", "猫😀.md", "a1²2.md"])
async def test_exact_unicode_names_and_bytes_do_not_use_legacy_ingestion_or_sort(name):
    engine = TypedBackend()
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_write", **write_args(filename=name))
    assert not failed and answer["uri"] == A + "/" + name
    assert engine.files[A + "/" + name] == write_args()["text"].encode("utf-8")


@pytest.mark.asyncio
async def test_contract_is_not_cached_and_readback_failure_keeps_known_content_commit():
    engine = TypedBackend()
    engine.read_fault = True
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_write", **write_args())
        assert not failed and answer["outcome"] == "committed"
        assert answer["verification"] == "unavailable" and answer["indexing"] == "deferred"
        engine.contract = None
        answer, failed = await invoke("memory_write", **write_args(filename="second.md"))
        assert failed and answer["outcome"] == "not_started"
    assert len(engine.effects) == 1 and len([r for r in engine.calls if r[1] == CONTRACT_PATH]) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("fault,requests", [("expire_on_contract", 0), ("", 127)])
async def test_expiry_after_contract_and_request_budget_refuse_before_dispatch(fault, requests):
    engine = TypedBackend()
    engine.fault = fault
    async with direct(engine, requests=requests) as invoke:
        answer, failed = await invoke("memory_write", **write_args())
    assert failed and answer["outcome"] == "not_started"
    assert not engine.effects and not any(row[0] == "POST" for row in engine.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("row", [
    {"uri": B + "/foreign.md", "isDir": False, "size": 1},
    {"uri": DOC, "isDir": "false", "size": 1},
    {"uri": DOC, "isDir": False, "size": True},
    {"uri": DOC, "isDir": False, "size": -1},
])
async def test_malformed_or_foreign_metadata_cannot_become_status_or_absence(row):
    engine = TypedBackend()
    engine.stat_fault[DOC] = (200, ok(row))
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_index_prune", uri=DOC)
    assert failed and answer["outcome"] == "not_started" and not engine.effects


@pytest.mark.asyncio
async def test_prune_existing_uri_and_namespace_root_remove_never_dispatch():
    engine = TypedBackend()
    async with direct(engine, roots=(ROOT,)) as invoke:
        for name, args in [
            ("memory_index_prune", {"uri": DOC}),
            ("memory_rm", {"uri": ROOT, "recursive": True}),
            ("memory_mkdir", {"uri": ROOT + "/.watch_tasks.json"}),
            ("memory_mkdir", {"uri": A + "/.relations.json"}),
        ]:
            _, failed = await invoke(name, **args)
            assert failed
    assert not engine.effects


@pytest.mark.asyncio
async def test_sdk_extra_scopes_without_signed_actions_stay_readonly(sdk):
    sessions, engine = sdk
    async with sessions(scope="ov.read ov.write ov.remove ov.maintain") as session:
        response, _ = await call(session, "memory_write", **write_args())
        assert response.is_error
        response, _ = await call(session, "memory_index_prune", uri=A + "/gone.md")
        assert response.is_error
    assert not engine.effects and not engine.calls



@pytest.mark.asyncio
async def test_expiry_after_valid_commit_ack_keeps_committed_outcome():
    engine = TypedBackend()
    engine.fault = "expire_after_commit"
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_write", **write_args(verify=False))
    assert failed and answer["outcome"] == "committed" and answer["indexing"] == "deferred"
    assert answer["retry_safe"] is False and len(engine.effects) == 1


@pytest.mark.asyncio
async def test_http_task_cancellation_does_not_prove_backend_rollback():
    engine = TypedBackend()
    principal = Principal("fixture", (A,), int(time.time()) + 240, "grants",
                          ("read", "write"), RESOURCES_URI_POLICY)
    committed = asyncio.Event()
    blocked = asyncio.Event()
    async def delayed_response(request):
        response = await engine.transport(request)
        if request.method == "POST":
            committed.set()
            await blocked.wait()
        return response
    async with httpx.AsyncClient(transport=httpx.MockTransport(delayed_response)) as client:
        state = {}
        task = asyncio.create_task(call_mutation(Backend(config(), principal, client),
                                                 "memory_write", write_args(), state))
        await asyncio.wait_for(committed.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert state["dispatched"] is True and engine.files[A + "/new.md"] == write_args()["text"].encode()
    assert len(engine.effects) == 1


@pytest.mark.asyncio
async def test_audit_multi_prune_conflict_does_not_hide_prior_effects():
    engine = TypedBackend()
    engine.hits = [A + "/absent1.md", A + "/absent2.md"]
    original = engine.reply
    def raced(method, path, params, body):
        if path == "/fs/resources-only/prune-index" and engine.effects:
            engine.files[body["uri"]] = b"concurrent writer"
        return original(method, path, params, body)
    engine.reply = raced
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_index_audit", query="note", scope=A, fix=True)
    assert failed and answer["outcome"] == "unknown" and answer["retry_safe"] is False
    assert engine.effects == [("/fs/resources-only/prune-index", A + "/absent1.md")]



@pytest.mark.asyncio
async def test_sdk_mkdir_exact_uri_description_payload_and_sanitized_ack(sdk):
    sessions, engine = sdk
    uri = A + "/cafe\u0301猫"
    description = "  # Résumé\r\n\nExact payload β  "
    async with sessions(scope="ov.read ov.write", ov_actions=["read", "write"]) as session:
        response, answer = await call(session, "memory_mkdir", uri=uri, description=description)
        assert not response.is_error, answer
        assert answer == {"uri": uri, "outcome": "committed", "resource_type": "directory",
                          "indexing": "not_observed", "searchable_completion": False, "retry_safe": False}
    assert engine.effects == [("/fs/mkdir", uri)]
    posts = [row for row in engine.calls if row[0] == "POST"]
    assert len(posts) == 1 and posts[0][3] == {"uri": uri, "description": description}
    assert engine.calls[-2][1] == CONTRACT_PATH
    assert engine.files[uri + "/.abstract.md"] == description.encode("utf-8")
    assert "SECRET" not in json.dumps(answer)


@pytest.mark.asyncio
@pytest.mark.parametrize("claims", [{}, {"scope": "ov.read ov.write"},
    {"scope": "ov.read ov.remove", "ov_actions": ["read", "remove"]}])
async def test_sdk_mkdir_readonly_missing_write_action_refuses_before_io(sdk, claims):
    sessions, engine = sdk
    async with sessions(**claims) as session:
        response, _ = await call(session, "memory_mkdir", uri=A + "/folder")
        assert response.is_error
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
async def test_sdk_mkdir_scope_action_mismatch_fails_authentication(sdk):
    sessions, engine = sdk
    with pytest.raises(Exception):
        async with sessions(scope="ov.read", ov_actions=["read", "write"]):
            pytest.fail("Mismatched signed scope authenticated")
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("uri", [
    ROOT, A, B + "/folder", A + "/space name", A + "/../escape", A + "/x%20y",
    A + "/{namespace:key}", A + "/.path.ovlock", A + "/.exact.ovlock.a",
    A + "/.relations.json", A + "/.abstract.md", A + "/.overview.md",
    A + "/.sync_log.json", ROOT + "/.watch_tasks.json",
])
async def test_sdk_mkdir_path_root_and_parent_denial_before_io(sdk, uri):
    sessions, engine = sdk
    async with sessions(scope="ov.read ov.write", ov_actions=["read", "write"]) as session:
        response, _ = await call(session, "memory_mkdir", uri=uri)
        assert response.is_error
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
async def test_mkdir_generated_abstract_bound_and_narrow_parent_denial():
    engine = TypedBackend()
    base = A + "/" + "/".join(["a" * 240] * 4)
    uri = base + "/" + "b" * (1018 - len(base) - 1)
    assert len(uri.encode()) == 1018
    async with direct(engine) as invoke:
        _, failed = await invoke("memory_mkdir", uri=uri)
        assert failed
    assert not engine.calls
    async with direct(engine, roots=(A + "/folder/child",)) as invoke:
        _, failed = await invoke("memory_mkdir", uri=A + "/folder/child")
        assert failed
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("args", [
    {"acl": {"owner": "someone"}}, {"parents": True}, {"recursive": True},
    {"description": "x" * 4097}, {"description": "β" * 2049},
])
async def test_sdk_mkdir_unsupported_parameters_and_description_budget_refuse(sdk, args):
    sessions, engine = sdk
    async with sessions(scope="ov.read ov.write", ov_actions=["read", "write"]) as session:
        response, _ = await call(session, "memory_mkdir", uri=A + "/folder", **args)
        assert response.is_error
    assert not engine.calls and not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["file", "directory", "absent_parent", "file_parent"])
async def test_sdk_mkdir_preflight_existing_target_or_bad_parent_has_no_post(sdk, kind):
    sessions, engine = sdk
    uri = A + "/folder"
    if kind == "file":
        engine.files[uri] = b"original file"
    elif kind == "directory":
        engine.dirs.add(uri)
        engine.files[uri + "/.abstract.md"] = b"original abstract"
    elif kind == "absent_parent":
        uri = A + "/missing/child"
    else:
        uri = DOC + "/child"
    baseline = (dict(engine.files), set(engine.dirs))
    async with sessions(scope="ov.read ov.write", ov_actions=["read", "write"]) as session:
        response, _ = await call(session, "memory_mkdir", uri=uri)
        assert response.is_error
    assert not engine.effects and not any(row[0] == "POST" for row in engine.calls)
    assert (engine.files, engine.dirs) == baseline


@pytest.mark.asyncio
async def test_sdk_mkdir_concurrent_native_target_exists_does_not_clobber(sdk):
    sessions, engine = sdk
    uri = A + "/raced"
    def competing_create():
        engine.dirs.add(uri)
        engine.files[uri + "/.abstract.md"] = b"competing original"
    engine.on_contract = competing_create
    async with sessions(scope="ov.read ov.write", ov_actions=["read", "write"]) as session:
        response, answer = await call(session, "memory_mkdir", uri=uri)
        assert response.is_error and answer["outcome"] == "not_started" and answer["conflict"]
    assert not engine.effects and engine.files[uri + "/.abstract.md"] == b"competing original"
    assert len([row for row in engine.calls if row[0] == "POST"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("contract", [None, {"contract": "resources-document-mutations", "version": 0},
                                      {"contract": "resources-document-mutations", "version": True}])
async def test_sdk_mkdir_old_malformed_contract_never_dispatches(sdk, contract):
    sessions, engine = sdk
    engine.contract = contract
    async with sessions(scope="ov.read ov.write", ov_actions=["read", "write"]) as session:
        response, answer = await call(session, "memory_mkdir", uri=A + "/folder")
        assert response.is_error and answer["outcome"] == "not_started"
    assert not engine.effects and not any(row[0] == "POST" for row in engine.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["timeout", "malformed", "foreign", "failure_after"])
async def test_sdk_mkdir_postdispatch_uncertainty_no_retry(sdk, fault):
    sessions, engine = sdk
    engine.fault = fault
    async with sessions(scope="ov.read ov.write", ov_actions=["read", "write"]) as session:
        response, answer = await call(session, "memory_mkdir", uri=A + "/folder")
        assert response.is_error and answer["outcome"] == "unknown" and answer["retry_safe"] is False
        assert "SECRET" not in json.dumps(answer)
    assert len([row for row in engine.calls if row[0] == "POST"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status,code", [(403, "PERMISSION_DENIED"), (500, "INTERNAL"), (404, "UNKNOWN")])
async def test_sdk_mkdir_stat_failure_never_becomes_absent(sdk, status, code):
    sessions, engine = sdk
    uri = A + "/folder"
    engine.stat_fault[uri] = (status, error(code))
    async with sessions(scope="ov.read ov.write", ov_actions=["read", "write"]) as session:
        response, answer = await call(session, "memory_mkdir", uri=uri)
        assert response.is_error and answer["outcome"] == "not_started"
    assert not engine.effects and not any(row[0] == "POST" for row in engine.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault,expected", [("expire_on_contract", "not_started"),
                                          ("expire_after_commit", "committed")])
async def test_mkdir_expiry_before_dispatch_and_after_exact_ack_are_distinct(fault, expected):
    engine = TypedBackend()
    engine.fault = fault
    async with direct(engine) as invoke:
        answer, failed = await invoke("memory_mkdir", uri=A + "/folder")
    assert failed and answer["outcome"] == expected
    assert len(engine.effects) == (1 if expected == "committed" else 0)
    if expected == "committed":
        assert answer["resource_type"] == "directory" and answer["indexing"] == "not_observed"


@pytest.mark.asyncio
async def test_sdk_mkdir_off_profile_does_not_expose_or_enable(sdk):
    sessions, engine = sdk
    async with sessions(enabled=False, scope="ov.read ov.write", ov_actions=["read", "write"]) as session:
        assert {tool.name for tool in (await session.list_tools()).tools} == set(SPECS)
        response, _ = await call(session, "memory_mkdir", uri=A + "/folder")
        assert response.is_error
    assert not engine.calls and not engine.effects


def test_profile_requires_explicit_resources_config_and_mutation_schema_is_closed():
    with pytest.raises(ValueError):
        replace(config(), semantic_profile="disabled", semantic_backend_revision="", namespace_roots=())
    with pytest.raises(ValueError):
        replace(config(), mutation_profile="arbitrary")
    for name in MUTATION_SPECS:
        assert schema(name)["additionalProperties"] is False
