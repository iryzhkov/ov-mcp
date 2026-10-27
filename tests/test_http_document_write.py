"""Closed document-write SDK/ASGI fixtures; not native acceptance."""

import asyncio
import hashlib
import json
import os
import ssl
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from test_http_acceptance import SECRET, Fixture, call, serving
from test_http_mutations import DOC, ROOT, A, TypedBackend, config, error, ok

from ov_http.app import create_app
from ov_http.auth import Principal
from ov_http.document_write import CONTRACT, CONTRACT_PATH, NODE_PATH, WRITE_PATH, node
from ov_http.mutations import call_mutation
from ov_http.reader import Backend, BudgetExhausted, Reader

ACTIONS = ("read", "write", "remove", "maintain")
TREE = "tree-sha256:"
CONTROL = "file-controls-v1-sha256:"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Documents(TypedBackend):
    def __init__(self):
        super().__init__()
        self.dirs.add(A + "/archive")
        self.document_contract = CONTRACT
        self.document_contract_hook = None
        self.ack_changes = {}
        self.node_fault = None
        self.node_overrides = {}
        self.processing = "accepted"
        self.post_fault = None
        self.post_error = None
        self.before_post = None
        self.after_ack = False
        self.observations = []
        self.changed_after_ack = False
        self.backups = []
        self.control = "c"
        self.rendered_parts = None

    def descriptor(self, uri):
        if uri in self.files:
            return {
                "kind": "file",
                "content_sha256": sha(self.files[uri]),
                "control_revision": CONTROL + self.control * 64,
            }
        if uri in self.dirs:
            rows = {
                k: v.decode() for k, v in self.files.items() if k.startswith(uri + "/")
            }
            return {
                "kind": "directory",
                "tree_revision": TREE + sha(json.dumps(rows, sort_keys=True).encode()),
            }
        return {"kind": "absent"}

    def reply(self, method, path, params, body):
        if path == CONTRACT_PATH:
            self.calls.append((method, path, params, body))
            assert method == "GET"
            if self.document_contract_hook:
                self.document_contract_hook()
            if self.document_contract is None:
                return 404, error("NOT_FOUND")
            return 200, ok(self.document_contract)
        if path == NODE_PATH:
            self.calls.append((method, path, params, body))
            assert method == "GET" and set(params) == {"uri"}
            uri = params["uri"]
            self.observations.append(uri)
            if self.node_fault:
                return self.node_fault
            if uri in self.node_overrides:
                return 200, ok(self.node_overrides[uri])
            if self.after_ack and self.changed_after_ack and uri in self.files:
                self.files[uri] = b"concurrent writer"
            return 200, ok({"uri": uri, "node": self.descriptor(uri)})
        if path == WRITE_PATH:
            self.calls.append((method, path, params, body))
            assert method == "POST"
            assert set(body) <= {
                "target_uri",
                "source_name",
                "text",
                "reason",
                "representation",
                "expected",
                "backup_uri",
            }
            assert set(body) >= {
                "target_uri",
                "source_name",
                "text",
                "reason",
                "representation",
                "expected",
            }
            assert body["representation"] in {"raw_file", "ingest", "verbatim"}
            assert "/" not in body["source_name"] and not body["source_name"].endswith(
                ".verbatim"
            )
            target = body["target_uri"]
            if self.before_post:
                self.before_post(target)
            if self.post_error:
                return self.post_error
            expected = body["expected"]
            if self.descriptor(target) != expected:
                return 409, error(
                    "CONFLICT",
                    uri=target,
                    content_state="target_unchanged",
                    processing_state="unobserved",
                )
            backup = None
            if expected["kind"] != "absent":
                backup_uri = body["backup_uri"]
                assert backup_uri.rsplit("/", 1)[0] in self.dirs
                assert self.descriptor(backup_uri) == {"kind": "absent"}
                old_files = {
                    backup_uri + k[len(target) :]: v
                    for k, v in self.files.items()
                    if k == target or k.startswith(target + "/")
                }
                old_dirs = {
                    backup_uri + k[len(target) :]
                    for k in self.dirs
                    if k == target or k.startswith(target + "/")
                }
                self.files.update(old_files)
                self.dirs.update(old_dirs)
                old = self.descriptor(backup_uri)
                if old["kind"] == "file":
                    old["control_revision"] = CONTROL + "d" * 64
                backup = {"uri": backup_uri, "node": old}
                self.backups.append(backup)
            else:
                assert "backup_uri" not in body
            self.files = {
                k: v
                for k, v in self.files.items()
                if not (k == target or k.startswith(target + "/"))
            }
            self.dirs = {
                k for k in self.dirs if not (k == target or k.startswith(target + "/"))
            }
            if body["representation"] == "raw_file":
                assert expected["kind"] == "file"
                self.files[target] = body["text"].encode()
                representation = "raw_file"
            else:
                self.dirs.add(target)
                part = target + "/0000.md"
                if body["representation"] == "verbatim":
                    assert target.endswith(".verbatim")
                    self.dirs.add(target + "/0001")
                    part = target + "/0001/0000.md"
                self.files[part] = body["text"].encode()
                representation = (
                    "verbatim_directory"
                    if body["representation"] == "verbatim"
                    else "parsed_directory"
                )
            if self.rendered_parts is not None:
                self.files = {
                    k: v
                    for k, v in self.files.items()
                    if not (k == target or k.startswith(target + "/"))
                }
                if representation == "raw_file":
                    self.files[target] = next(
                        iter(self.rendered_parts.values())
                    ).encode()
                else:
                    for relative, text in self.rendered_parts.items():
                        member = target + "/" + relative
                        self.files[member] = text.encode()
                        parent = member.rsplit("/", 1)[0]
                        while parent != target:
                            self.dirs.add(parent)
                            parent = parent.rsplit("/", 1)[0]
            self.effects.append((path, target))
            result = {
                "uri": target,
                "node": self.descriptor(target),
                "input_sha256": sha(body["text"].encode()),
                "representation": representation,
                "content_state": "committed",
                "processing_state": self.processing,
                "backup": backup,
                "cleanup_state": "retained" if backup else "complete",
            }
            result.update(self.ack_changes)
            if self.on_effect:
                self.on_effect()
            self.after_ack = True
            if self.post_fault == "timeout":
                raise httpx.ReadTimeout("SECRET response lost")
            if self.post_fault == "cancel":
                raise asyncio.CancelledError()
            return 200, ok(result)
        if path == "/fs/ls" and params.get("simple") == "true":
            self.calls.append((method, path, params, body))
            uri = params["uri"]
            return 200, ok(
                sorted(
                    k
                    for k in self.dirs | self.files.keys()
                    if k.startswith(uri + "/") and "/" not in k[len(uri) + 1 :]
                )
            )
        return super().reply(method, path, params, body)


@asynccontextmanager
async def invoke(engine, *, roots=(ROOT,), actions=ACTIONS, expires=None, requests=0):
    principal = Principal(
        "fixture",
        roots,
        int(time.time()) + 240 if expires is None else expires,
        "fixture-grants",
        actions,
        config().uri_policy,
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(engine.transport)
    ) as client:
        backend = Backend(config(), principal, client)
        backend.requests = requests

        async def run(**arguments):
            return await call_mutation(backend, "memory_write", arguments, {})

        yield run, principal, backend


def args(**changes):
    return {"to": A, "filename": "new.md", "text": "  alpha\r\nβ\n\n", **changes}


@pytest.mark.asyncio
@pytest.mark.parametrize("verbatim", [False, True])
async def test_create_composition_literal_reason_and_actual_reader(
    verbatim, monkeypatch
):
    engine = Documents()
    assembled = []
    original = Reader.assemble

    async def record(self, uri):
        assembled.append(uri)
        return await original(self, uri)

    monkeypatch.setattr(Reader, "assemble", record)
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(
            **args(verbatim=verbatim, reason="Preserve [[literal]] hint")
        )
    assert not failed
    target = A + "/new.md" + (".verbatim" if verbatim else "")
    assert answer["outcome"] == "committed" and answer["uri"] == target
    assert answer["verification"]["status"] == (
        "exact" if verbatim else "equivalent_reshaped"
    )
    assert assembled == [target]
    post = [c[3] for c in engine.calls if c[1] == WRITE_PATH][0]
    assert post["source_name"] == "new.md" and post["text"] == args()["text"]
    assert post["reason"] == "Preserve [[literal]] hint"
    assert post["expected"] == {"kind": "absent"} and "backup_uri" not in post
    assert post["representation"] == ("verbatim" if verbatim else "ingest")
    assert all(c[1] not in {"/resources", "/content/reindex"} for c in engine.calls)


@pytest.mark.asyncio
async def test_existing_file_raw_exact_backup_and_destination_control_digest():
    engine = Documents()
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(filename="old.md", overwrite=True))
    assert not failed and answer["verification"]["status"] == "exact"
    assert (
        answer["representation"] == "raw_file"
        and engine.files[DOC] == args()["text"].encode()
    )
    backup = answer["backup"]
    assert backup["uri"].startswith(A + "/archive/old.md.backup-")
    assert backup["node"]["content_sha256"] == sha(b"old\n")
    assert backup["node"]["control_revision"] == CONTROL + "d" * 64
    assert engine.files[backup["uri"]] == b"old\n"


@pytest.mark.asyncio
async def test_directory_overwrite_and_archived_extension_composition():
    engine = Documents()
    old = A + "/archive/config.yaml"
    engine.dirs.add(old)
    engine.files[old + "/chunk.md"] = b"old tree"
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(
            **args(filename="config.yaml", archived=True, overwrite=True, verify=False)
        )
    assert (
        not failed
        and answer["uri"] == old
        and answer["representation"] == "parsed_directory"
    )
    assert answer["backup"]["node"]["kind"] == "directory"
    assert engine.files[answer["backup"]["uri"] + "/chunk.md"] == b"old tree"
    assert answer["verification"]["status"] == "not_requested"


@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "absent", "revision": "absent"},
        {
            "kind": "file",
            "content_sha256": "A" * 64,
            "control_revision": CONTROL + "a" * 64,
        },
        {"kind": "file", "content_sha256": "a" * 64, "control_revision": "opaque"},
        {"kind": "directory", "tree_revision": "a" * 64},
        {
            "kind": "directory",
            "tree_revision": TREE + "a" * 64,
            "SECRET": "raw controls",
        },
    ],
)
def test_closed_node_descriptors(bad):
    with pytest.raises(Exception):
        node(bad)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "filename",
    [
        "space name",
        "../bad",
        ".abstract.md",
        ".watch_tasks.json",
        "a%20b",
        "x/",
        "x" * 255,
    ],
)
async def test_names_denied_before_any_io(filename):
    engine = Documents()
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(filename=filename))
    assert failed and answer["outcome"] == "not_started" and not engine.calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "actions,roots",
    [
        (("read",), (ROOT,)),
        (("read", "write"), (ROOT,)),
        (ACTIONS, (A,)),
        (ACTIONS, (A + "/new.md",)),
    ],
)
async def test_missing_actions_ancestors_and_grant_root_refuse_without_io(
    actions, roots
):
    engine = Documents()
    async with invoke(engine, actions=actions, roots=roots) as (run, _, _):
        answer, failed = await run(**args())
    assert failed and not engine.calls and not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "contract",
    [
        None,
        {},
        {"contract": "resources-document-mutations", "version": 1},
        {"contract": "resources-document-write", "version": True},
    ],
)
async def test_old_or_malformed_dedicated_contract_no_dispatch(contract):
    engine = Documents()
    engine.document_contract = contract
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args())
    assert failed and answer["outcome"] == "not_started" and not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "stale_body",
        "stale_control",
        "stale_tree",
        "observe_failure",
        "residual",
        "missing_archive",
        "existing_no_overwrite",
    ],
)
async def test_observed_preconditions_and_archive_parent_no_clobber(fault):
    engine = Documents()
    options = args(filename="old.md", overwrite=True, verify=False)
    if fault == "stale_body":
        engine.before_post = lambda target: engine.files.update({target: b"raced"})
    elif fault == "stale_control":
        engine.before_post = lambda target: setattr(engine, "control", "e")
    elif fault == "stale_tree":
        del engine.files[DOC]
        engine.dirs.add(DOC)
        engine.files[DOC + "/part.md"] = b"before"
        engine.before_post = lambda target: engine.files.update(
            {target + "/part.md": b"raced"}
        )
    elif fault in {"observe_failure", "residual"}:
        engine.node_fault = (
            (403, error("FORBIDDEN"))
            if fault == "observe_failure"
            else (409, error("FAILED_PRECONDITION"))
        )
    elif fault == "missing_archive":
        engine.dirs.remove(A + "/archive")
    else:
        options["overwrite"] = False
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**options)
    assert failed and answer["outcome"] in {"not_started", "target_unchanged"}
    assert not engine.effects and not engine.backups


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"uri": ROOT + "/foreign"},
        {"input_sha256": "0" * 64},
        {"node": {"kind": "absent"}},
        {"processing_state": "complete"},
        {"representation": "raw_file"},
        {"backup": {"uri": ROOT + "/private", "node": {"kind": "absent"}}},
        {"node": {"kind": "directory", "tree_revision": "bad"}},
        {"SECRET": "source=/host"},
    ],
)
async def test_wrong_ack_is_unknown_not_committed_or_retried(changes):
    engine = Documents()
    engine.ack_changes = changes
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(verify=False))
    assert failed and answer["outcome"] == "unknown" and answer["retry_safe"] is False
    assert len(engine.effects) == 1 and "SECRET" not in json.dumps(answer)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage", ["contract_expiry", "ack_expiry", "timeout", "cancel"]
)
async def test_expiry_dispatch_unknown_and_known_ack_distinct(stage):
    engine = Documents()
    async with invoke(engine) as (run, principal, _):

        def expire():
            object.__setattr__(principal, "expires", int(time.time()) - 1)

        if stage == "contract_expiry":
            engine.document_contract_hook = expire
        elif stage == "ack_expiry":
            engine.on_effect = expire
        else:
            engine.post_fault = stage
        answer, failed = await run(**args(verify=False))
    assert failed
    expected = (
        "not_started"
        if stage == "contract_expiry"
        else "committed"
        if stage == "ack_expiry"
        else "unknown"
    )
    assert answer["outcome"] == expected and len(engine.effects) == (
        stage != "contract_expiry"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["read_fail", "budget", "concurrent", "cancel"])
async def test_known_commit_survives_reader_observation_failures(case, monkeypatch):
    engine = Documents()
    if case == "concurrent":
        engine.changed_after_ack = True
    elif case == "read_fail":
        engine.read_fault = True
    else:

        async def failure(self, uri):
            if case == "budget":
                raise BudgetExhausted()
            raise asyncio.CancelledError()

        monkeypatch.setattr(Reader, "assemble", failure)
    async with invoke(engine) as (run, _, _):
        answer, _ = await run(**args(filename="old.md", overwrite=True))
    assert answer["outcome"] == "committed" and len(engine.effects) == 1
    assert (
        answer["verification"]["status"]
        == {
            "concurrent": "concurrent_change",
            "read_fail": "unavailable",
            "budget": "unavailable_budget",
            "cancel": "unavailable_cancelled",
        }[case]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text", ["", " \n\t", "https://example.invalid/file", "/host/private", "猫😀\n"]
)
async def test_literal_text_and_exact_raw_bytes(text):
    engine = Documents()
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(filename="old.md", text=text, overwrite=True))
    assert not failed and answer["verification"]["status"] == "exact"
    assert engine.files[DOC] == text.encode()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        "target_unchanged",
        "rolled_back",
        "rollback_failed",
        "rollback_unavailable",
        "unknown",
        "committed",
    ],
)
async def test_typed_error_target_states_sanitized_and_no_automatic_retry(state):
    engine = Documents()
    target = A + "/new.md"
    engine.post_error = (
        409,
        error(
            "CONFLICT",
            uri=target,
            content_state=state,
            processing_state="failed",
            retained_copies=[{"uri": ROOT + "/SECRET"}],
        ),
    )
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(verify=False))
    assert failed and answer["content_state"] == state and answer["retry_safe"] is False
    assert (
        "SECRET" not in json.dumps(answer)
        and len([c for c in engine.calls if c[1] == WRITE_PATH]) == 1
    )


@pytest_asyncio.fixture
async def sdk_documents(tmp_path):
    home = Path(os.environ["HOME"]).resolve()
    assert home.name == "home" and home.parent.name == ".scratch"
    assert tmp_path.resolve().is_relative_to(home)
    fixture, engine = Fixture(tmp_path), Documents()

    async def route(request):
        if request.url.path == "/jwks":
            return await fixture.backend(request)
        assert request.headers["X-API-Key"] == SECRET
        body = await request.json() if request.method == "POST" else None
        status, value = engine.reply(
            request.method,
            request.url.path.removeprefix("/api/v1"),
            dict(request.query_params),
            body,
        )
        return JSONResponse(value, status_code=status)

    upstream = Starlette(
        routes=[
            Route("/api/v1/{path:path}", route, methods=["GET", "POST"]),
            Route("/jwks", route),
        ]
    )
    key = tmp_path / "backend.key"
    key.write_text(SECRET)
    key.chmod(0o600)
    async with (
        serving(upstream) as port,
        serving(
            upstream, ssl_certfile=str(fixture.cert), ssl_keyfile=str(fixture.cert_key)
        ) as jwks_port,
    ):
        cfg = replace(
            config(),
            backend_url=f"http://127.0.0.1:{port}/api/v1",
            backend_secret_file=str(key),
            jwks_url=f"https://127.0.0.1:{jwks_port}/jwks",
        )
        fixture.resource = cfg.resource
        tls = ssl.create_default_context(cafile=str(fixture.cert))

        @asynccontextmanager
        async def session(*, enabled=True, roots=(ROOT,), **claims):
            app = create_app(
                cfg if enabled else replace(cfg, mutation_profile="disabled"),
                jwks_ssl_context=tls,
            )
            async with serving(app) as app_port:
                fixture.url = f"http://127.0.0.1:{app_port}/mcp"
                async with fixture.session(
                    fixture.token(list(roots), **claims)
                ) as client:
                    yield client

        yield session, engine


@pytest.mark.asyncio
async def test_sdk_default_path_verbatim_and_old11_off_catalog(sdk_documents):
    session, engine = sdk_documents
    claims = {
        "ov_actions": list(ACTIONS),
        "scope": "ov.read ov.write ov.maintain ov.remove",
    }
    async with session(**claims) as client:
        response, answer = await call(client, "memory_write", **args(verbatim=True))
        assert not response.is_error and answer["verification"]["status"] == "exact"
    async with session(enabled=False, **claims) as client:
        assert len((await client.list_tools()).tools) == 11
        response, _ = await call(client, "memory_write", **args())
        assert response.is_error
    assert len(engine.effects) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"ov_actions": ["read"], "scope": "ov.read ov.write ov.maintain ov.remove"},
        {"ov_actions": ["read", "write"], "scope": "ov.read ov.write"},
    ],
)
async def test_sdk_signed_readonly_or_missing_maintain_no_backend_io(
    sdk_documents, claims
):
    session, engine = sdk_documents
    async with session(**claims) as client:
        response, _ = await call(client, "memory_write", **args())
        assert response.is_error
    assert not engine.calls


@pytest.mark.asyncio
async def test_sdk_file_canary_grant_and_deferred_path_stay_separate(sdk_documents):
    session, engine = sdk_documents
    async with session(roots=(DOC,)) as client:
        response, answer = await call(client, "memory_read", uri=DOC)
        assert not response.is_error and answer["text"] == "old\n"
    async with session(
        roots=(A,),
        ov_actions=list(ACTIONS),
        scope="ov.read ov.write ov.maintain ov.remove",
    ) as client:
        response, answer = await call(
            client, "memory_write", **args(storage="file-deferred-v1")
        )
        assert not response.is_error and answer["indexing"] == "deferred"
    assert all(c[1] != WRITE_PATH for c in engine.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ["typed", "unknown", "empty", "foreign", "extra", "absent", "many", "expired"],
)
async def test_closed_error_recovery_copy_observation(case):
    engine = Documents()
    async with invoke(engine) as (run, principal, _):

        def fail(target):
            backup_uri = engine.calls[-1][3]["backup_uri"]
            old = {
                "kind": "file",
                "content_sha256": sha(b"old\\n"),
                "control_revision": CONTROL + "d" * 64,
            }
            copy = {"uri": backup_uri, "node": old}
            copies = [copy]
            if case == "unknown":
                copy["node"] = None
            elif case == "empty":
                copies = []
            elif case == "foreign":
                copy["uri"] = ROOT + "/SECRET"
            elif case == "extra":
                copy["SECRET"] = "private stage"
            elif case == "absent":
                copy["node"] = {"kind": "absent"}
            elif case == "many":
                copies = [copy, copy]
            elif case == "expired":
                object.__setattr__(principal, "expires", int(time.time()) - 1)
            engine.post_error = (
                500,
                error(
                    "INTERNAL",
                    uri=target,
                    content_state="committed",
                    processing_state="failed",
                    retained_copies=copies,
                ),
            )

        engine.before_post = fail
        answer, failed = await run(
            **args(filename="old.md", overwrite=True, verify=False)
        )
    assert failed and answer["outcome"] == "committed" and answer["retry_safe"] is False
    assert answer["backup_state"] == ("retained" if case == "typed" else "unobserved")
    assert ("retained_copies" in answer) == (case in {"typed", "unknown"})
    assert "SECRET" not in json.dumps(answer)


@pytest.mark.asyncio
async def test_explicit_verbatim_can_replace_file_and_reuses_actual_reader():
    engine = Documents()
    target = A + "/new.md.verbatim"
    engine.files[target] = b"old raw"
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(verbatim=True, overwrite=True))
    assert not failed and answer["representation"] == "verbatim_directory"
    assert answer["verification"]["status"] == "exact"
    assert engine.files[target + "/0001/0000.md"] == args()["text"].encode()
    assert answer["backup"]["node"]["content_sha256"] == sha(b"old raw")


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["accepted", "failed", "unobserved"])
async def test_processing_acceptance_never_claims_revision_index_completion(state):
    engine = Documents()
    engine.processing = state
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(text="body", verify=False))
    assert failed == (state == "failed")
    assert answer["outcome"] == "committed" and answer["processing_state"] == state
    assert (
        answer["indexing"] == "not_revision_bound"
        and not answer["searchable_completion"]
    )


@pytest.mark.asyncio
async def test_contract_not_cached_and_input_limits_precede_io():
    engine = Documents()
    async with invoke(engine) as (run, _, _):
        for index in range(2):
            answer, failed = await run(**args(filename=f"new-{index}.md", verify=False))
            assert not failed and answer["outcome"] == "committed"
    assert len([c for c in engine.calls if c[1] == CONTRACT_PATH]) == 2
    for changes in ({"text": "a" * 1048577}, {"reason": "β" * 513}):
        denied = Documents()
        async with invoke(denied) as (run, _, _):
            _, failed = await run(**args(**changes))
        assert failed and not denied.calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        None,
        {
            "uri": ROOT + "/foreign",
            "node": {
                "kind": "file",
                "content_sha256": "a" * 64,
                "control_revision": CONTROL + "a" * 64,
            },
        },
        {"uri": "declared", "node": {"kind": "absent"}},
        {
            "uri": "declared",
            "node": {
                "kind": "file",
                "content_sha256": "f" * 64,
                "control_revision": CONTROL + "a" * 64,
            },
        },
    ],
)
async def test_replacement_backup_ack_must_match_declared_uri_old_kind_and_body(bad):
    engine = Documents()

    def change(target):
        value = None if bad is None else json.loads(json.dumps(bad))
        if isinstance(value, dict) and value["uri"] == "declared":
            value["uri"] = engine.calls[-1][3]["backup_uri"]
        engine.ack_changes["backup"] = value

    engine.before_post = change
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(
            **args(filename="old.md", overwrite=True, verify=False)
        )
    assert failed and answer["outcome"] == "unknown" and len(engine.effects) == 1


FULL_WRITE = {
    "ov_actions": list(ACTIONS),
    "scope": "ov.read ov.write ov.remove ov.maintain",
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,parts,reshape",
    [
        ("  Alpha\n\nBeta  \n", None, "boundary_line_whitespace"),
        ("Alpha  \n\nBeta\t\n", None, "boundary_line_whitespace"),
        (
            "Alpha\n\nBeta\n\nAlpha",
            {"0000.md": "Beta", "0001.md": "Alpha\n\nAlpha"},
            "line_order",
        ),
        (
            "# Title\n\nAlpha\nBeta\n",
            {"Title/0000.md": "Alpha\nBeta"},
            "title_directory_and_boundary_whitespace",
        ),
        (
            "# Title\n\nAlpha\nBeta\nAlpha",
            {"Title/a.md": "Beta", "Title/b.md": "Alpha\nAlpha"},
            "title_directory_and_line_order",
        ),
    ],
)
async def test_sdk_default_parsed_known_reshape_is_equivalent_not_error(
    sdk_documents, text, parts, reshape
):
    session, engine = sdk_documents
    engine.rendered_parts = parts
    async with session(**FULL_WRITE) as client:
        response, answer = await call(client, "memory_write", **args(text=text))
    assert not response.is_error, answer
    assert answer["content_state"] == "committed" and answer["verification"]["complete"]
    assert answer["verification"]["status"] == "equivalent_reshaped"
    assert answer["verification"]["reshape"] == reshape
    assert "duplicate count" in answer["verification"]["explanation"]
    assert answer["verification"]["observation"] == "post_commit_not_linearizable"
    assert len(engine.effects) == 1 and answer["retry_safe"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,parts",
    [
        ("Alpha\nBeta", {"0000.md": "Alpha"}),
        ("Alpha\nBeta", {"0000.md": "Alpha\nGamma"}),
        ("Alpha\nAlpha\nBeta", {"0000.md": "Alpha\nBeta"}),
        ("Alpha\nBeta", {"0000.md": "Alpha\nBeta\nBeta"}),
        ("key = 'a b'", {"0000.md": "key = 'ab'"}),
        ("alpha beta", {"0000.md": "alphabeta"}),
        ("Alpha\n    code\nBeta", {"0000.md": "Alpha\ncode\nBeta"}),
        ("# Title\n\nAlpha", {"0000.md": "Alpha"}),
    ],
)
async def test_sdk_parsed_loss_alteration_duplicates_and_unevidenced_title_are_errors(
    sdk_documents, text, parts
):
    session, engine = sdk_documents
    engine.rendered_parts = parts
    async with session(**FULL_WRITE) as client:
        response, answer = await call(client, "memory_write", **args(text=text))
    assert response.is_error, answer
    assert (
        answer["content_state"] == "committed"
        and answer["verification"]["status"] == "different"
    )
    assert len(engine.effects) == 1 and answer["retry_safe"] is False
    assert "Do not retry" in answer["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("representation", ["raw_file", "verbatim"])
async def test_sdk_raw_and_verbatim_known_reshape_still_requires_exact_bytes(
    sdk_documents, representation
):
    session, engine = sdk_documents
    original_reply = engine.reply

    def readback(method, path, params, body):
        status, value = original_reply(method, path, params, body)
        if path == "/content/read":
            return 200, ok("Alpha\nBeta")
        return status, value

    engine.reply = readback
    options = args(text="  Alpha\n\nBeta\n")
    if representation == "raw_file":
        options.update(filename="old.md", overwrite=True)
    else:
        options["verbatim"] = True
    async with session(**FULL_WRITE) as client:
        response, answer = await call(client, "memory_write", **options)
    assert response.is_error and answer["outcome"] == "committed"
    assert answer["verification"]["status"] == "different" and len(engine.effects) == 1


def test_parsed_equivalence_comparison_bound_is_finite():
    from ov_http.document_write import MAX_EQUIVALENCE_LINES, parsed_equivalence

    with pytest.raises(BudgetExhausted):
        parsed_equivalence(
            "line\n" * (MAX_EQUIVALENCE_LINES + 1), "line", [], A + "/new.md"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,parts",
    [
        (
            "# Homelab backup plan\n\n## Storage\nDisk\n## Restore\nSteps",
            {
                "Homelab_backup_plan/first.md": "## Storage\nDisk",
                "Homelab_backup_plan/second.md": "## Restore\nSteps",
            },
        ),
        ("# Backup: plan (v2)!\n\nAlpha", {"Backup_plan_v2/0000.md": "Alpha"}),
        ("# A B\n\nAlpha", {"A_B/0000.md": "Alpha"}),
        ("# Title\n\nAlpha", {"alien/0000.md": "Alpha"}),
        (
            "# A B\n\nAlpha\nBeta\nAlpha",
            {"alien/a.md": "Beta", "alien/b.md": "Alpha\nAlpha"},
        ),
    ],
)
async def test_sdk_missing_leading_h1_with_nested_sources_is_inconclusive_not_equivalent(
    sdk_documents, text, parts
):
    session, engine = sdk_documents
    engine.rendered_parts = parts
    async with session(**FULL_WRITE) as client:
        response, answer = await call(client, "memory_write", **args(text=text))
    assert not response.is_error, answer
    assert answer["outcome"] == answer["content_state"] == "committed"
    verification = answer["verification"]
    assert verification["status"] == "unavailable_transformation"
    assert verification["complete"] is False and "reshape" not in verification
    assert "title retention is not proven" in verification["explanation"]
    assert "inconclusive" in verification["explanation"]
    assert answer["retry_safe"] is False and len(engine.effects) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,parts",
    [
        ("# A B\n\nAlpha\nBeta", {"A_B/part.md": "Alpha"}),
        ("# A B\n\nAlpha\nAlpha", {"alien/part.md": "Alpha"}),
        ("# A B\n\nAlpha", {"A_B/part.md": "Altered"}),
        ("# A B\n\nAlpha", {"A_B/part.md": "Alpha\nAlpha"}),
        ("# A B\n\nkey = 'a b'", {"A_B/part.md": "key = 'ab'"}),
        ("# A B\n\nAlpha", {"part.md": "Alpha"}),
        ("# A B\n\n## Missing\nAlpha", {"A_B/part.md": "Alpha"}),
    ],
)
async def test_sdk_unproven_title_never_masks_body_loss_or_missing_nested_evidence(
    sdk_documents, text, parts
):
    session, engine = sdk_documents
    engine.rendered_parts = parts
    async with session(**FULL_WRITE) as client:
        response, answer = await call(client, "memory_write", **args(text=text))
    assert response.is_error, answer
    assert answer["outcome"] == "committed"
    assert answer["verification"]["status"] == "different"
    assert answer["retry_safe"] is False and len(engine.effects) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("verbatim", [False, True])
async def test_sdk_unproven_h1_category_never_applies_to_raw_or_verbatim(
    sdk_documents, verbatim
):
    session, engine = sdk_documents
    original_reply = engine.reply

    def readback(method, path, params, body):
        status, value = original_reply(method, path, params, body)
        return (200, ok("Alpha")) if path == "/content/read" else (status, value)

    engine.reply = readback
    options = args(text="# A B\n\nAlpha")
    if verbatim:
        options["verbatim"] = True
    else:
        options.update(filename="old.md", overwrite=True)
    async with session(**FULL_WRITE) as client:
        response, answer = await call(client, "memory_write", **options)
    assert response.is_error and answer["verification"]["status"] == "different"
    assert answer["outcome"] == "committed" and len(engine.effects) == 1
