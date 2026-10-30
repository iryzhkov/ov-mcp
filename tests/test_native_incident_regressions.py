"""Native incident regressions at typed transport and official SDK/HTTP seams."""

import asyncio
import time

import pytest

from test_http_acceptance import call
from test_http_document_write import Documents, args, invoke
import test_http_mutations as mutation_fixtures
from test_http_mutations import A, B, DOC, ROOT, TypedBackend, direct, error

sdk = mutation_fixtures.sdk

FULL = {
    "ov_namespaces": [ROOT],
    "scope": "ov.read ov.write ov.remove ov.maintain",
    "ov_actions": ["read", "write", "remove", "maintain"],
}


@pytest.mark.asyncio
async def test_sdk_move_observes_measured_slow_parent_refresh(sdk, monkeypatch):
    import httpx2

    original_init = httpx2.AsyncClient.__init__

    def long_client(self, *args, **kwargs):
        # This fixture normally caps the SDK client at 30 seconds; the test
        # deliberately observes a measured 36.5-second backend response.
        if kwargs.get("timeout") == 30:
            kwargs["timeout"] = 90
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx2.AsyncClient, "__init__", long_client)
    sessions, engine = sdk
    reply = engine.reply

    def delayed(method, path, params, body):
        if method == "POST" and path == "/fs/mv":
            # Real backend HTTP latency, matching the 36.5-second incident.
            time.sleep(36.5)
        return reply(method, path, params, body)

    engine.reply = delayed
    async with sessions(**FULL) as session:
        response, answer = await call(
            session,
            "memory_mv",
            from_uri=DOC,
            to_uri=B + "/slow.md",
        )
    assert not response.is_error, answer
    assert answer["outcome"] == "committed"
    assert len([row for row in engine.calls if row[0] == "POST"]) == 1


@pytest.mark.asyncio
async def test_long_move_still_cancels_at_authority_expiry():
    engine = TypedBackend()
    transport = engine.transport

    async def delayed(request):
        response = await transport(request)
        if request.method == "POST" and request.url.path.endswith("/fs/mv"):
            await asyncio.sleep(0.2)
        return response

    engine.transport = delayed
    async with direct(engine, roots=(ROOT,), expires=time.time() + 0.08) as run:
        answer, failed = await run("memory_mv", from_uri=DOC, to_uri=B + "/expiry.md")
    assert failed and answer["outcome"] == "unknown", answer
    assert answer["retry_safe"] is False
    assert len([row for row in engine.calls if row[0] == "POST"]) == 1


@pytest.mark.asyncio
async def test_observation_lock_busy_is_explicit_without_effect_or_upstream_details():
    engine = TypedBackend()
    reply = engine.reply

    def busy(method, path, params, body):
        if method == "GET" and path == "/fs/stat":
            return 409, error("CONFLICT", conflict_type="path_busy", uri="SECRET-owner")
        return reply(method, path, params, body)

    engine.reply = busy
    async with direct(engine, roots=(ROOT,)) as run:
        answer, failed = await run("memory_mkdir", uri=A + "/new")
    assert failed and answer["outcome"] == "not_started" and answer["busy"]
    assert "SECRET" not in str(answer)
    assert not engine.effects


@pytest.mark.asyncio
async def test_default_hash_input_explains_representation_contract_before_io():
    engine = Documents()
    async with invoke(engine) as (run, _, _):
        answer, failed = await run(**args(expected_sha256="0" * 64))
    assert failed and answer["outcome"] == "not_started"
    assert answer["supported"] is False
    assert "observed node CAS" in answer["error"]
    assert "file-deferred-v1" in answer["error"]
    assert not engine.calls
