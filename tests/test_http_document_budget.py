"""Finite document observation budgets against synthetic backends, not native acceptance."""
import asyncio
import time
from dataclasses import replace

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from ov_http.app import SecurityGate
from ov_http.auth import Principal
from ov_http.mutations import Mutations, call_mutation
from ov_http.reader import Backend
from test_http_acceptance import serving
from test_http_document_write import ACTIONS, Documents, args, invoke
from test_http_mutations import ROOT, A, DOC, config
from ov_http.document_write import WRITE_PATH


@pytest.mark.asyncio
async def test_real_document_response_crosses_both_short_deadlines():
    engine = Documents()
    seen = []

    async def endpoint(request):
        path = request.url.path.removeprefix("/api/v1")
        seen.append((request.method, path))
        if path == WRITE_PATH:
            await asyncio.sleep(21)
        body = await request.json() if request.method == "POST" else None
        status, value = engine.reply(request.method, path, dict(request.query_params), body)
        return JSONResponse(value, status_code=status)

    app = Starlette(routes=[Route("/{path:path}", endpoint, methods=["GET", "POST"])])
    async with serving(app) as port, httpx.AsyncClient(timeout=10, trust_env=False) as client:
        cfg = replace(config(), backend_url=f"http://127.0.0.1:{port}/api/v1")
        principal = Principal("fixture", (ROOT,), int(time.time()) + 120,
                              "fixture-grants", ACTIONS, cfg.uri_policy)
        backend = Backend(cfg, principal, client)
        start = time.monotonic()
        async with asyncio.timeout(65):
            answer, failed = await call_mutation(backend, "memory_write", args(verify=False), {})
        elapsed = time.monotonic() - start
    assert not failed and answer["outcome"] == "committed"
    assert 20 < elapsed < 65
    assert seen.count(("POST", WRITE_PATH)) == 1
    assert len(engine.effects) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint,effect,long", [
    (WRITE_PATH, True, True),
    (WRITE_PATH, False, False),
    (WRITE_PATH + "/other", True, False),
    ("/fs/mv", True, True),
    ("/content/reindex", True, True),
    ("/content/write", True, False),
    ("/content/read", False, False),
])
async def test_actual_httpx_timeout_extensions(endpoint, effect, long):
    observed = []

    async def transport(request):
        observed.append(request.extensions["timeout"])
        return httpx.Response(200, json={"status": "ok", "result": {}})

    async with invoke(Documents()) as (_, _, backend):
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport), timeout=10) as client:
            backend.client = client
            await Mutations(backend).request("POST" if effect else "GET", endpoint, effect=effect)
            assert client.timeout == httpx.Timeout(10)
    assert observed == [dict(connect=5, pool=5, read=60, write=60) if long
                        else dict(connect=10, pool=10, read=10, write=10)]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,changes,cap", [
    ("memory_write", {}, 70),
    ("memory_write", {"storage": "legacy-chunked"}, 70),
    ("memory_write", {"dry_run": False}, 70),
    ("memory_write", {"dry_run": True}, 20),
    ("memory_write", {"storage": "file-deferred-v1"}, 20),
    ("memory_write", {"storage": "file-deferred-v1", "dry_run": True}, 20),
    ("memory_write", {"storage": "invalid"}, 20),
    ("memory_mv", {}, 70),
    ("memory_reindex", {}, 70),
    ("memory_mkdir", {}, 20),
])
@pytest.mark.parametrize("lifetime", [12, 200])
async def test_cap_selection_still_minimized_by_expiry(monkeypatch, name, changes, cap, lifetime):
    selected = []
    original_timeout = asyncio.timeout

    def record(seconds):
        selected.append(seconds)
        return original_timeout(seconds)

    # Hold wall time fixed, leaving the real event-loop timeout implementation intact.
    now = time.time()
    monkeypatch.setattr("ov_http.mutations.time.time", lambda: now)
    monkeypatch.setattr("ov_http.mutations.asyncio.timeout", record)
    async with invoke(Documents(), expires=now + lifetime) as (_, _, backend):
        arguments = args(**changes) if name == "memory_write" else {
            "uri": DOC if name == "memory_reindex" else A + "/new",
            "from_uri": DOC, "to_uri": A + "/moved.md",
        }
        await call_mutation(backend, name, arguments, {})
    assert selected == [min(cap, lifetime)]


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", [
    {"storage": "invalid"}, {"dry_run": 1}, {"dry_run": "true"},
])
async def test_invalid_classification_arguments_still_refuse_without_effects(changes):
    engine = Documents()
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(**changes))
    assert failed and answer["outcome"] == "not_started" and not engine.effects


@pytest.mark.asyncio
async def test_expired_before_call_has_zero_requests():
    engine = Documents()
    async with invoke(engine, expires=int(time.time()) - 1) as (run, _, backend):
        answer, failed = await run(**args())
    assert failed and answer["outcome"] == "not_started"
    assert not engine.calls and not engine.effects and backend.requests == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("budget", ["requests", "bytes"])
async def test_document_long_allowance_keeps_shared_budgets(budget):
    engine = Documents()
    async with invoke(engine) as (run, _, backend):
        if budget == "requests":
            backend.requests = 128
        else:
            backend.bytes = 1048576 - 262144 + 1
        answer, failed = await run(**args())
    assert failed and answer["outcome"] == "not_started" and not engine.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("committed", [False, True])
async def test_real_task_cancellation_after_post_never_retries(monkeypatch, committed):
    engine = Documents()
    reached = asyncio.Event()

    async with invoke(engine) as (run, principal, backend):
        original = backend.client.send
        posts = []

        async def send(request, **kwargs):
            if request.url.path.endswith(WRITE_PATH):
                posts.append(request)
                if not committed:
                    reached.set()
                    await asyncio.Future()
            return await original(request, **kwargs)

        async def observe(self, uri):
            reached.set()
            await asyncio.Future()

        if committed:
            monkeypatch.setattr("ov_http.reader.Reader.assemble", observe)
        monkeypatch.setattr(backend.client, "send", send)
        results = []

        class Verifier:
            async def verify(self, token):
                return principal

        async def app(scope, receive, send):
            results.append(await call_mutation(backend, "memory_write", args(), scope["ov.operation"]))

        async def receive():
            await reached.wait()
            return {"type": "http.disconnect"}

        async def send_response(message):
            pytest.fail("Disconnected request must not emit a response")

        cfg = config()
        scope = {"type": "http", "path": "/mcp", "query_string": b"",
                 "headers": [(b"host", cfg.authority.encode()),
                             (b"authorization", b"Bearer fixture")]}
        await asyncio.wait_for(SecurityGate(app, cfg, Verifier())(scope, receive, send_response), 5)
        [(answer, failed)] = results
    assert answer["outcome"] == ("committed" if committed else "unknown")
    if committed:
        assert answer["verification"]["status"] == "unavailable_cancelled"
    else:
        assert failed
    assert answer.get("retry_safe") is False
    assert len(engine.effects) == int(committed)
    assert len(posts) == 1
