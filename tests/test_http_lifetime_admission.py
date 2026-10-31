"""Signed lifetime admission fixtures; installed client refresh remains unproven."""
import asyncio
import time
from dataclasses import replace

import pytest
from starlette.responses import JSONResponse

from ov_http.app import SecurityGate
from ov_http.auth import Principal, Refused
from test_http_mutations import ROOT, config


async def gate(principal, *, method="POST", disabled=False, after_start=None):
    called, received, sent = [], [], []
    cfg = config()
    if disabled:
        cfg = replace(cfg, mutation_profile="disabled")

    class Verifier:
        async def verify(self, token):
            if principal is None:
                raise Refused()
            return principal

    async def app(scope, receive, send):
        called.append(True)
        if after_start:
            after_start(scope)
        await JSONResponse({"ok": True})(scope, receive, send)

    async def receive():
        received.append(True)
        await asyncio.Future()

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": method, "path": "/mcp", "query_string": b"",
             "headers": [(b"host", cfg.authority.encode()),
                         (b"authorization", b"Bearer synthetic")]}
    await SecurityGate(app, cfg, Verifier())(scope, receive, send)
    return called, received, sent


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["write", "remove", "maintain"])
async def test_gate_refusal_is_identical_and_before_body_app_or_backend(monkeypatch, caplog, action):
    monkeypatch.setattr("ov_http.app.time.time", lambda: 1000)
    principal = Principal("fixture", (ROOT,), 1144, "fixture", ("read", action), issued=844)
    called, received, sent = await gate(principal)
    _, _, invalid = await gate(None)
    assert sent == invalid
    assert sent[0]["status"] == 401
    assert not called and not received
    assert [r.getMessage() for r in caplog.records] == ["ov-http admission lifetime-refused"]


@pytest.mark.asyncio
@pytest.mark.parametrize("remaining,total,actions,personal,method,disabled,admitted", [
    (145, 300, ("read", "write"), (), "POST", False, True),
    (144, 300, ("read", "write"), (), "POST", False, False),
    (10, 159, ("read", "write"), (), "POST", False, True),
    (10, 160, ("read", "write"), (), "POST", False, False),
    (10, 300, ("read",), (), "POST", False, True),
    (10, 300, ("read",), ("memory.create",), "POST", False, True),
    (10, 300, ("read", "write"), (), "GET", False, True),
    (10, 300, ("read", "write"), (), "POST", True, True),
])
async def test_gate_boundaries_and_exemptions(
        monkeypatch, remaining, total, actions, personal, method, disabled, admitted):
    monkeypatch.setattr("ov_http.app.time.time", lambda: 1000)
    p = Principal("fixture", (ROOT,), 1000 + remaining, "fixture", actions,
                  personal_actions=personal, issued=1000 + remaining - total)
    called, _, sent = await gate(p, method=method, disabled=disabled)
    assert bool(called) == admitted
    assert sent[0]["status"] == (200 if admitted else 401)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", [{}, {"dispatched": True},
                                  {"dispatched": True, "document_committed": {"outcome": "committed"}}])
async def test_admitted_app_crossing_expiry_never_returns_401(monkeypatch, state):
    clock = [1000]
    monkeypatch.setattr("ov_http.app.time.time", lambda: clock[0])
    p = Principal("fixture", (ROOT,), 1200, "fixture", ("read", "write"), issued=900)

    def expire(scope):
        scope["ov.operation"].update(state)
        clock[0] = 1201

    called, _, sent = await gate(p, after_start=expire)
    assert called and sent[0]["status"] == 200
