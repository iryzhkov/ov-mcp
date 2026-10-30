"""Synthetic signed SDK/ASGI qualification; no live service or credential use."""
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
from ov_http.auth import Principal, Verifier, Refused
from ov_http.config import RESOURCES_PROFILE, RESOURCES_REVISION
from ov_http.mutations import MUTATION_SPECS
from ov_http.personal import PERSONAL_ACTIONS, PERSONAL_SPECS, call_personal
from ov_http.reader import Backend
from test_http_acceptance import Fixture, SECRET, call, serving
from test_http_mutations import config

ROOT = "viking://user/default/memories"
DOC = ROOT + "/preferences/note.md"
SESSIONS = "viking://user/default/sessions"
PIN = "7f3faf6982f81116d6626bc7091f87f786a309c7"


def cfg():
    return replace(config(), personal_profile="shared-owner-v1", personal_account="default",
                   personal_user="default", personal_subjects=("pc", "laptop"),
                   personal_backend_revision=PIN)


def claims(actions=PERSONAL_ACTIONS, **changes):
    return {"sub": "pc", "scope": "ov.read " + " ".join("ov.personal." + a for a in actions),
            "ov_personal": {"account": "default", "user": "default", "actions": list(actions)}, **changes}


class Engine:
    def __init__(self):
        self.calls = []
        self.files = {DOC: "old"}
        self.raw_files = {}
        self.poison = None
        self.fault = False
        self.append_ack = {}
        self.omit_ack = None
        self.append_refusal = None
        self.messages = []

    async def route(self, request):
        path = request.url.path.removeprefix("/api/v1")
        body = await request.json() if request.method == "POST" else None
        self.calls.append((request.method, path, dict(request.query_params), body))
        assert request.headers["x-api-key"] == SECRET
        assert "x-openviking-user" not in request.headers
        assert "x-openviking-account" not in request.headers
        uri = request.query_params.get("uri")
        if path.startswith("/sessions/") and path.endswith("/messages"):
            sid = path.split("/")[2]
            assert request.method == "POST" and not request.query_params
            assert set(body) == {"role", "content", "append_mode", "telemetry"}
            assert body["append_mode"] == "existing_only_no_auto_commit" and body["telemetry"] is False
            if sid != "sibling" or self.append_refusal:
                return JSONResponse({"status": "error", "error": {
                    "code": self.append_refusal or "NOT_FOUND", "message": "private diagnostic"}}, 404 if
                    sid != "sibling" else 412)
            self.messages.append(body["content"])
            result = {"session_id": sid, "message_count": len(self.messages), "pending_tokens": 2,
                      "append_mode": "existing_only_no_auto_commit", "auto_commit_scheduled": False}
            result.update(self.append_ack)
            if self.omit_ack is not None:
                result.pop(self.omit_ack)
            return JSONResponse({"status": "ok", "result": result})
        if path == "/fs/ls":
            result = [self.poison or DOC]
        elif path == "/content/read":
            result = (self.raw_files.get(uri, self.files[uri])
                      if request.query_params.get("raw") == "true" else self.files[uri])
        elif path == "/search/find":
            assert body["target_uri"] and all(t.startswith(ROOT) for t in body["target_uri"])
            result = {"memories": [{"uri": self.poison or DOC}], "resources": [], "skills": []}
        elif path == "/content/batch-write":
            op = body["operations"][0]
            assert body["root_uri"] == ROOT + "/preferences"
            old = self.files.get(op["uri"])
            if ((op.get("expected_absent") and old is not None)
                    or ("expected_sha256" in op and (old is None or
                        hashlib.sha256(old.encode()).hexdigest() != op["expected_sha256"]))):
                return JSONResponse({"status": "error", "error": {"code": "CONFLICT"}}, 409)
            self.files[op["uri"]] = op["content"]
            if self.fault == "malformed":
                return JSONResponse({"status": "ok", "result": None})
            if self.fault:
                return JSONResponse({"status": "error"}, 500)
            result = {"root_uri": body["root_uri"], "created": [], "updated": [op["uri"]], "unchanged": []}
        elif path == "/sessions" and request.method == "GET":
            result = [{"session_id": "sibling", "uri": self.poison or SESSIONS + "/sibling"}]
        elif path == "/sessions" and request.method == "POST":
            assert body == {"auto_commit_policy": None, "telemetry": False}
            result = {"session_id": "new", "uri": SESSIONS + "/new",
                      "user": {"account_id": "default", "user_id": "default"}, "auto_commit_policy": None}
        elif path == "/sessions/sibling":
            assert request.query_params["auto_create"] == "false"
            result = {"session_id": "sibling", "uri": self.poison or SESSIONS + "/sibling"}
        elif path == "/sessions/sibling/context":
            assert request.query_params["token_budget"] == "4096"
            result = {"messages": [{"role": "user", "content": "saved conversation"}]}
        else:
            raise AssertionError(path)
        return JSONResponse({"status": "ok", "result": result})


@pytest_asyncio.fixture
async def personal(tmp_path):
    home = Path(os.environ["HOME"]).resolve()
    assert home.name == "home" and home.parent.name == ".scratch"
    assert tmp_path.resolve().is_relative_to(home)
    f, engine = Fixture(tmp_path), Engine()

    async def route(request):
        return await f.backend(request) if request.url.path == "/jwks" else await engine.route(request)

    backend = Starlette(routes=[Route("/api/v1/{path:path}", route, methods=["GET", "POST"]),
                                Route("/jwks", route)])
    key = tmp_path / "key"
    key.write_text(SECRET)
    key.chmod(0o600)
    async with serving(backend) as bp, serving(backend, ssl_certfile=str(f.cert),
                                             ssl_keyfile=str(f.cert_key)) as jp:
        c = replace(cfg(), backend_url=f"http://127.0.0.1:{bp}/api/v1",
                    jwks_url=f"https://127.0.0.1:{jp}/jwks", backend_secret_file=str(key))
        f.resource = c.resource
        tls = ssl.create_default_context(cafile=str(f.cert))
        @asynccontextmanager
        async def session(enabled=True, **extra):
            app = create_app(c if enabled else replace(c, personal_profile="disabled", personal_account="",
                              personal_user="", personal_subjects=(), personal_backend_revision=""),
                             jwks_ssl_context=tls)
            async with serving(app) as ap:
                f.url = f"http://127.0.0.1:{ap}/mcp"
                async with f.session(f.token(["viking://resources"], **extra)) as s:
                    yield s
        yield session, engine, f, c


@pytest.mark.asyncio
async def test_sdk_positive_and_resources_catalog_preservation(personal):
    sessions, e, _, _ = personal
    async with sessions(enabled=False) as s:
        tools = (await s.list_tools()).tools
        assert len(tools) == 19 and {t.name for t in tools} == set(SPECS) | set(MUTATION_SPECS)
        old = {t.name: t.input_schema for t in tools}
    async with sessions(**claims()) as s:
        tools = (await s.list_tools()).tools
        assert len(tools) == 28
        assert all(t.input_schema == old[t.name] for t in tools if t.name in old)
        for name, args in [
            ("personal_memory_browse", {"uri": ROOT + "/preferences"}),
            ("personal_memory_read", {"uri": DOC}),
            ("personal_memory_find", {"query": "note"}),
            ("personal_session_list", {}),
            ("personal_session_read", {"session_id": "sibling"}),
            ("personal_session_create", {}),
            ("personal_memory_create", {"uri": ROOT + "/preferences/new.md", "content": "new"}),
            ("personal_memory_replace", {"uri": DOC, "content": "changed",
                                         "expected_sha256": hashlib.sha256(b"old").hexdigest()}),
        ]:
            r, value = await call(s, name, **args)
            assert not r.is_error, value
        before = len(e.calls)
        r, v = await call(s, "personal_session_append", session_id="sibling", role="user", content="x")
        assert not r.is_error and v["outcome"] == "committed" and len(e.calls) == before + 1
        assert v["auto_commit_scheduled"] is False and e.messages == ["x"]
    async with sessions(**claims(sub="laptop")) as s:
        r, v = await call(s, "personal_session_read", session_id="sibling")
        assert not r.is_error and v["session_id"] == "sibling"


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", ["old\n<!-- MEMORY_FIELDS: hidden metadata -->", "private unsanitized secret"])
async def test_visible_memory_does_not_offer_raw_replacement_hash(personal, raw):
    sessions, e, _, _ = personal
    e.raw_files[DOC] = raw
    async with sessions(**claims()) as s:
        before = len(e.calls)
        r, value = await call(s, "personal_memory_read", uri=DOC)
        assert not r.is_error
        assert value["content"] == "old"
        assert value["sha256"] is None and value["replaceable"] is False
        assert raw not in str(value)
        assert len(e.calls) == before + 2
        assert e.calls[-1][2] == {"uri": DOC, "raw": "true"}
        before = len(e.calls)
        r, _ = await call(s, "personal_memory_replace", uri=DOC, content="changed",
                          expected_sha256=value["sha256"])
        assert r.is_error and len(e.calls) == before
        assert e.files[DOC] == "old" and e.raw_files[DOC] == raw


@pytest.mark.asyncio
async def test_matching_memory_read_hash_replaces_stored_bytes(personal):
    sessions, e, _, _ = personal
    async with sessions(**claims()) as s:
        r, value = await call(s, "personal_memory_read", uri=DOC)
        assert not r.is_error and value["replaceable"] is True
        assert value["sha256"] == hashlib.sha256(b"old").hexdigest()
        r, result = await call(s, "personal_memory_replace", uri=DOC, content="changed",
                               expected_sha256=value["sha256"])
        assert not r.is_error and result["outcome"] == "committed"
        assert e.files[DOC] == "changed"


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["error", "malformed", "oversize", "expiry_on_raw",
                                  "budget_after_visible", "reduced_after_visible"])
async def test_raw_comparison_failures_never_project_raw(fault):
    c = cfg()
    p = Principal("pc", ("viking://resources",), int(time.time()) + 60, "test",
                  personal_account="default", personal_user="default", personal_actions=PERSONAL_ACTIONS)
    calls = []
    secret = "RAW_COMPARISON_ONLY_SECRET"
    async def handler(request):
        calls.append(request)
        assert request.method == "GET" and request.url.params["uri"] == DOC
        if len(calls) == 1:
            assert "raw" not in request.url.params
            if fault == "budget_after_visible":
                b.requests = 128
            if fault == "reduced_after_visible":
                object.__setattr__(p, "personal_actions", ())
            return httpx.Response(200, json={"status": "ok", "result": "visible"})
        assert request.url.params["raw"] == "true"
        if fault == "error":
            return httpx.Response(500, json={"status": "error", "error": {"message": secret}})
        if fault == "expiry_on_raw":
            object.__setattr__(p, "expires", int(time.time()) - 1)
        raw = {"content": secret} if fault == "malformed" else (
            secret + "x" * 32769 if fault == "oversize" else secret)
        return httpx.Response(200, json={"status": "ok", "result": raw})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        b = Backend(c, p, client)
        value, failed = await call_personal(b, "personal_memory_read", {"uri": DOC}, {})
        assert failed and value["outcome"] == "not_started"
        assert secret not in json.dumps(value) and "sha256" not in value
        assert len(calls) == (1 if fault in ("budget_after_visible", "reduced_after_visible") else 2)


@pytest.mark.asyncio
async def test_sdk_denials_bounds_unknown_and_no_retry(personal):
    sessions, e, _, _ = personal
    async with sessions(**claims()) as s:
        for uri in ["viking://user/foreign/memories/preferences/n.md", "viking://~/memories/a.md",
                    "viking://session/sibling", ROOT + "/../x.md", ROOT + "/a/%2e%2e/x.md",
                    ROOT + "/a/x%252f.md", ROOT + "/a//x.md", ROOT + "/a/\\x.md",
                    ROOT + "/a/.abstract.md", ROOT + "/a/x.md/", "viking://resources/a.md"]:
            before = len(e.calls)
            r, _ = await call(s, "personal_memory_read", uri=uri)
            assert r.is_error and len(e.calls) == before
        for name, args in [
            ("personal_memory_find", {"query": "x", "targets": [ROOT, "viking://resources"]}),
            ("personal_memory_find", {"query": "x", "targets": []}),
            ("personal_memory_browse", {"limit": 41}),
            ("personal_memory_create", {"uri": DOC, "content": "x" * 16385}),
            ("personal_session_read", {"session_id": "../sibling"}),
            ("personal_memory_read", {"uri": DOC, "account": "foreign"}),
        ]:
            before = len(e.calls)
            r, _ = await call(s, name, **args)
            assert r.is_error and len(e.calls) == before
        e.poison = "viking://user/foreign/memories/preferences/leak.md"
        for name, args in [("personal_memory_browse", {}), ("personal_memory_find", {"query": "x"}),
                           ("personal_session_list", {}), ("personal_session_read", {"session_id": "sibling"})]:
            r, v = await call(s, name, **args)
            assert r.is_error and "foreign" not in json.dumps(v)
        e.poison = None
        before = len(e.calls)
        r, v = await call(s, "personal_memory_replace", uri=DOC, content="x", expected_sha256="0" * 64)
        assert r.is_error and e.files[DOC] == "old" and len(e.calls) == before + 1
        e.fault = True
        before = len(e.calls)
        r, v = await call(s, "personal_memory_create", uri=ROOT + "/preferences/unknown.md", content="x")
        assert r.is_error and v["outcome"] == "unknown" and v["retry_safe"] is False
        assert len(e.calls) == before + 1 and e.files[ROOT + "/preferences/unknown.md"] == "x"
        e.fault = "malformed"
        before = len(e.calls)
        r, v = await call(s, "personal_memory_create", uri=ROOT + "/preferences/malformed.md", content="x")
        assert r.is_error and v["outcome"] == "unknown" and len(e.calls) == before + 1
    async with sessions() as s:
        before = len(e.calls)
        r, _ = await call(s, "personal_memory_read", uri=DOC)
        assert r.is_error and len(e.calls) == before
    async with sessions(**claims(actions=("memory.read",))) as s:
        before = len(e.calls)
        r, _ = await call(s, "personal_memory_create", uri=DOC, content="x")
        assert r.is_error and len(e.calls) == before


@pytest.mark.asyncio
async def test_signed_foreign_and_expiry_vectors(personal):
    _, e, f, c = personal
    async with httpx.AsyncClient(verify=ssl.create_default_context(cafile=str(f.cert))) as client:
        verifier = Verifier(c, client)
        good = await verifier.verify(f.token(["viking://resources"], **claims()))
        reduced = await verifier.verify(f.token(["viking://resources"], **claims(actions=("memory.read",))))
        assert good.grant_digest != reduced.grant_digest
        for extra in [
            claims(sub="unapproved"), claims(ov_personal={"account": "foreign", "user": "default", "actions": ["memory.read"]}),
            claims(ov_personal={"account": "default", "user": "foreign", "actions": ["memory.read"]}),
            claims(scope="ov.read"), claims(exp=int(time.time()) - 1),
            claims(ov_personal={"account": "default", "user": "default", "actions": ["memory.read"] * 2}),
        ]:
            with pytest.raises(Refused):
                await verifier.verify(f.token(["viking://resources"], **extra))
        await verifier.close()
    p = replace(good, expires=int(time.time()) - 1)
    async with httpx.AsyncClient() as client:
        b = Backend(c, p, client)
        before = len(e.calls)
        _, failed = await call_personal(b, "personal_memory_read", {"uri": DOC}, {})
        assert failed and len(e.calls) == before


@pytest.mark.asyncio
async def test_asgi_auth_denials_and_request_body_bound(personal):
    _, e, f, c = personal
    app = create_app(c, jwks_ssl_context=ssl.create_default_context(cafile=str(f.cert)))
    async with app.app.router.lifespan_context(app.app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=c.origin) as client:
            before = len(e.calls)
            for token in [
                f.token(["viking://resources"], **claims(sub="foreign")),
                f.token(["viking://resources"], **claims(exp=int(time.time()) - 1)),
                f.token(["viking://resources"], **claims(ov_personal={
                    "account": "foreign", "user": "default", "actions": ["memory.read"]})),
            ]:
                r = await client.post("/mcp", headers={"Authorization": "Bearer " + token},
                                      json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                assert r.status_code == 401
            # Owner headers are never an authority source.
            r = await client.post("/mcp", headers={"X-OpenViking-User": "default",
                                                   "X-OpenViking-Account": "default"}, json={})
            assert r.status_code == 401
            r = await client.post("/mcp", headers={"Authorization": "Bearer " + f.token(
                ["viking://resources"], **claims()), "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"}, content=b" " * 32769)
            assert r.status_code == 413
            assert len(e.calls) == before


@pytest.mark.asyncio
async def test_returned_identity_depth_expiry_and_dispatch_unknown():
    c = cfg()
    p = Principal("pc", ("viking://resources",), int(time.time()) + 60, "test",
                  personal_account="default", personal_user="default", personal_actions=PERSONAL_ACTIONS)
    from ov_http.personal import Personal
    calls = []
    payload = {"account_id": "foreign"}
    async def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"status": "ok", "result": payload})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        b = Backend(c, p, client)
        op = Personal(b, {})
        for value in [
            {"user_id": "foreign"}, {"account_id": "foreign"}, {"uris": ["viking://resources/a"]},
            {"nested": {"unexpected": "viking://user/foreign/memories/a"}},
            {"uri": SESSIONS + "/../bad"}, {"uri": "viking://session/x"},
        ]:
            with pytest.raises(Refused):
                op.returned(value)
        deep = {}
        for _ in range(18):
            deep = {"nested": deep}
        with pytest.raises(Refused):
            op.returned(deep)
        # Successful backend status never makes a foreign identity safe.
        value, failed = await call_personal(b, "personal_session_create", {}, {})
        assert failed and value["outcome"] == "unknown" and len(calls) == 1
        async def expired(request):
            calls.append(request)
            object.__setattr__(p, "expires", int(time.time()) - 1)
            return httpx.Response(200, json={"status": "ok", "result": "owned"})
        client._transport = httpx.MockTransport(expired)
        value, failed = await call_personal(b, "personal_memory_read", {"uri": DOC}, {})
        assert failed and value["outcome"] == "not_started" and len(calls) == 2


@pytest.mark.parametrize("change", [
    {"personal_profile": "enabled"}, {"personal_account": "other/account"},
    {"personal_user": "../default"}, {"personal_subjects": ()},
    {"personal_subjects": ("pc", "pc")}, {"personal_backend_revision": "wrong"},
    {"personal_profile": "disabled"},
])
def test_config_fails_closed(change):
    with pytest.raises((ValueError, TypeError)):
        replace(cfg(), **change)


@pytest.mark.asyncio
@pytest.mark.parametrize("ack", [
    {"append_mode": None}, {"append_mode": "legacy"}, {"auto_commit_scheduled": True},
    {"auto_commit_scheduled": 0}, {"session_id": "foreign"}, {"message_count": True},
    {"message_count": 0}, {"message_count": 2**31}, {"pending_tokens": -1},
    {"pending_tokens": True}, {"pending_tokens": 2**53},
])
async def test_sdk_append_malformed_ack_unknown_no_retry(personal, ack):
    sessions, e, _, _ = personal
    e.append_ack = ack
    async with sessions(**claims()) as s:
        r, value = await call(s, "personal_session_append", session_id="sibling", role="user", content="x")
        assert r.is_error and value["outcome"] == "unknown" and value["retry_safe"] is False
    assert len(e.calls) == 1 and e.messages == ["x"]
    assert e.calls[0][1] == "/sessions/sibling/messages"


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["append_mode", "auto_commit_scheduled", "session_id",
                                  "message_count", "pending_tokens"])
async def test_sdk_append_missing_ack_unknown(personal, field):
    sessions, e, _, _ = personal
    e.omit_ack = field
    async with sessions(**claims()) as s:
        r, value = await call(s, "personal_session_append", session_id="sibling", role="user", content="x")
        assert r.is_error and value["outcome"] == "unknown"
    assert len(e.calls) == 1 and e.messages == ["x"]


@pytest.mark.asyncio
async def test_sdk_append_missing_policy_foreign_and_grant_denials(personal):
    sessions, e, _, _ = personal
    async with sessions(**claims()) as s:
        for sid, refusal in [("missing", None), ("foreign-id", None), ("sibling", "FAILED_PRECONDITION")]:
            e.append_refusal = refusal
            before = len(e.calls)
            r, value = await call(s, "personal_session_append", session_id=sid, role="user", content="x")
            assert r.is_error and value["outcome"] == "unknown" and value["retry_safe"] is False
            assert len(e.calls) == before + 1 and e.messages == []
        for sid in ["viking://user/foreign/sessions/x", "../foreign", "sibling%2f..", "sibling/child"]:
            before = len(e.calls)
            r, _ = await call(s, "personal_session_append", session_id=sid, role="user", content="x")
            assert r.is_error and len(e.calls) == before
    for grant in [claims(actions=("session.read",)), {}]:
        async with sessions(**grant) as s:
            before = len(e.calls)
            r, value = await call(s, "personal_session_append", session_id="sibling", role="user", content="x")
            assert r.is_error and value["outcome"] == "not_started" and len(e.calls) == before
    async with sessions(enabled=False) as s:
        before = len(e.calls)
        r, _ = await call(s, "personal_session_append", session_id="sibling", role="user", content="x")
        assert r.is_error and len(e.calls) == before


@pytest.mark.asyncio
async def test_asgi_append_positive_expired_and_foreign_owner(personal):
    _, e, f, c = personal
    app = create_app(c, jwks_ssl_context=ssl.create_default_context(cafile=str(f.cert)))
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "personal_session_append",
                       "arguments": {"session_id": "sibling", "role": "assistant", "content": "explicit"}}}
    async with app.app.router.lifespan_context(app.app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=c.origin) as client:
            for claim in [claims(exp=int(time.time()) - 1), claims(ov_personal={
                    "account": "default", "user": "foreign", "actions": ["session.append"]})]:
                response = await client.post("/mcp", json=body, headers={
                    "Authorization": "Bearer " + f.token(["viking://resources"], **claim),
                    "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
                assert response.status_code == 401 and e.calls == []
            response = await client.post("/mcp", json=body, headers={
                "Authorization": "Bearer " + f.token(["viking://resources"], **claims()),
                "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
            assert response.status_code == 200, response.text
            value = json.loads(response.json()["result"]["content"][0]["text"])
            assert value["append_mode"] == "existing_only_no_auto_commit"
            assert value["auto_commit_scheduled"] is False and e.messages == ["explicit"]
            assert len(e.calls) == 1


@pytest.mark.asyncio
async def test_append_expiry_before_dispatch_and_after_ack():
    c = cfg()
    p = Principal("pc", ("viking://resources",), int(time.time()) - 1, "test",
                  personal_account="default", personal_user="default", personal_actions=PERSONAL_ACTIONS)
    calls = []
    async def handler(request):
        calls.append(request)
        object.__setattr__(p, "expires", int(time.time()) - 1)
        return httpx.Response(200, json={"status": "ok", "result": {
            "session_id": "sibling", "append_mode": "existing_only_no_auto_commit",
            "auto_commit_scheduled": False, "message_count": 1, "pending_tokens": 1}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        a = {"session_id": "sibling", "role": "user", "content": "x"}
        value, failed = await call_personal(Backend(c, p, client), "personal_session_append", a, {})
        assert failed and value["outcome"] == "not_started" and calls == []
        object.__setattr__(p, "expires", int(time.time()) + 60)
        value, failed = await call_personal(Backend(c, p, client), "personal_session_append", a, {})
        assert failed and value["outcome"] == "unknown" and value["retry_safe"] is False and len(calls) == 1
