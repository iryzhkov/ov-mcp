"""SDK-to-fixed-HTTP semantic contract checks. Native vector execution is not simulated proof."""
import asyncio
from dataclasses import replace
import json
import ssl

import httpx
import httpx2
import pytest
import pytest_asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from ov_http.app import create_app
from ov_http.config import Config, SEMANTIC_PROFILE, SEMANTIC_REVISION
from test_http_acceptance import A, B, ISSUER, SECRET, f, call, serving


@pytest_asyncio.fixture
async def semantic_f(f):
    config = replace(f.config, semantic_profile=SEMANTIC_PROFILE,
                     semantic_backend_revision=SEMANTIC_REVISION, namespace_roots=[A, B])
    tls = ssl.create_default_context(cafile=str(f.cert))
    app = create_app(config, jwks_ssl_context=tls)
    async with serving(app) as port:
        f.url, f.app, f.config = f"http://127.0.0.1:{port}/mcp", app, config
        yield f


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["search", "find"])
async def test_semantic_sdk_fixed_targets_group_archive_hidden_chunk_and_links(semantic_f, kind):
    f = semantic_f
    async with f.session() as session:
        catalog = await session.list_tools()
        assert "memory_" + kind in {t.name for t in catalog.tools}
        response, value = await call(session, "memory_" + kind, query="needle")
        assert not response.is_error, value
        assert value["complete"] is False and value["returned"] == len(value["matches"])
        assert "total" not in value and "cursor" not in value
        note = next(m for m in value["matches"] if m["uri"] == A + "/note.md")
        assert note["matching_parts"] == 4
        assert all("/archive/" not in m["uri"] for m in value["matches"])
        assert SECRET not in json.dumps(value) and '"relations"' not in json.dumps(value)
        response, raw = await call(session, "memory_" + kind, query="needle", group=False)
        assert not response.is_error
        uris = {m["uri"] for m in raw["matches"]}
        assert {A + "/note.md/part_1.md", A + "/note.md/part_2.md",
                A + "/note.md/.abstract.md", A + "/note.md/.overview.md",
                A + "/.abstract.md", A + "/.overview.md"} <= uris
        _, archives = await call(session, "memory_" + kind, query="needle", include_archived=True)
        assert A + "/archive/old.md" in {m["uri"] for m in archives["matches"]}
        _, limited = await call(session, "memory_" + kind, query="needle", limit=1)
        assert limited["truncated"] and limited["returned"] == 1
        _, read = await call(session, "memory_read", uri=note["uri"], parts=True, offset=1, limit=1)
        assert read["text"] == "[[other]]" and len(read["parts"]) == 2
        for summary in ("abstract", "overview"):
            _, hidden = await call(session, "memory_" + summary, uri=note["uri"])
            assert hidden["text"].startswith("Allowed")
        _, links = await call(session, "memory_relations", uri=note["uri"])
        assert links["wikilinks"] == [A + "/other.md"] and B not in json.dumps(links)
    assert f.semantic_trace
    for trace in f.semantic_trace:
        assert trace["targets"] == [A]
        assert all(uri.startswith(A + "/") for uri in trace["record_reads"])
        assert trace["scoped_count_before_limit"] == 8
        assert trace["summary_reads"] == ([A + "/.abstract.md"] if kind == "search" else [])
        assert not any(uri.startswith(B) or uri.startswith(A + "-") for uri in trace["record_reads"])
    f.assert_capture()


@pytest.mark.asyncio
@pytest.mark.parametrize("summary_mode", ["missing", "empty"])
async def test_semantic_missing_empty_namespace_summary_stays_local(semantic_f, summary_mode):
    f = semantic_f
    f.summary_mode = summary_mode
    async with f.session() as session:
        response, value = await call(session, "memory_search", query="needle")
        assert not response.is_error, value
    assert f.semantic_trace[-1]["summary_reads"] == [A + "/.abstract.md"]
    assert f.semantic_trace[-1]["summary_mode"] == summary_mode
    f.assert_capture()


@pytest.mark.asyncio
async def test_semantic_scope_is_grant_assertion_no_file_target_or_caller_authority(semantic_f):
    f = semantic_f
    async with f.session() as session:
        before = len(f.captured)
        for args in ({"scope": A + "/note.md"}, {"scope": B}, {"scope": A + "/*"},
                     {"scope": A + "/../namespaceB"}, {"target_uri": B},
                     {"filter": {"uri": B}}, {"cursor": "x"}, {"session_id": "x"}):
            response, _ = await call(session, "memory_search", query="needle", **args)
            assert response.is_error
        assert len(f.captured) == before
    async with f.session(f.token([A, B])) as session:
        response, value = await call(session, "memory_search", query="needle", scope=A)
        assert not response.is_error, value
    assert f.semantic_trace[-1]["targets"] == [A, B]
    f.assert_capture((A, B))


@pytest.mark.asyncio
async def test_semantic_admission_rejects_file_unknown_and_mixed_grants_before_backend(semantic_f):
    f = semantic_f
    async with httpx.AsyncClient(headers={"Host": "ov.example"}, trust_env=False) as client:
        for roots in ([A + "/note.md"], [A + "-neighbor"], [A, A + "/note.md"],
                      ["viking://resources/missing"], ["viking://resources/*"]):
            before = len(f.captured)
            response = await client.post(f.url, headers={"Authorization": "Bearer " + f.token(roots)},
                                         json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert response.status_code == 401 and len(f.captured) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("root_kind", ["file", "missing"])
async def test_semantic_preflight_denies_non_directory_before_any_semantic_post(semantic_f, root_kind):
    f = semantic_f
    f.root_kind[A] = root_kind
    async with f.session() as session:
        response, value = await call(session, "memory_search", query="needle")
        assert response.is_error and value == {"error": "Resource unavailable."}
    assert len(f.captured) == 1 and f.captured[0][1] == "/api/v1/fs/stat"
    assert not f.semantic_trace


@pytest.mark.asyncio
@pytest.mark.parametrize("poison", [B + "/secret.md", A + "-neighbor/leak.md",
                                   A + "/../namespaceB", A + "/%2e%2e/x"])
async def test_semantic_out_of_scope_or_ambiguous_response_fails_whole_call(semantic_f, poison):
    f = semantic_f
    f.semantic_bad = poison
    async with f.session() as session:
        response, value = await call(session, "memory_find", query="needle")
        assert response.is_error and value == {"error": "Resource unavailable."}
    # Poison is a response-validation test, not evidence that output filtering
    # protects retrieval. Actual fixture retrieval was A-only before the poison.
    f.assert_capture()


@pytest.mark.asyncio
async def test_semantic_same_subject_concurrent_and_one_client_changes_grants(semantic_f):
    f = semantic_f

    async def one(roots, query):
        async with f.session(f.token(roots)) as session:
            response, value = await call(session, "memory_find", query=query, group=False)
            assert not response.is_error, value
            assert all(any(m["uri"].startswith(r + "/") for r in roots) for m in value["matches"])

    await asyncio.gather(one([A], "A concurrent"), one([B], "B concurrent"))
    traces = {t["query"]: t for t in f.semantic_trace}
    assert traces["A concurrent"]["targets"] == [A]
    assert traces["B concurrent"]["targets"] == [B]
    async with httpx2.AsyncClient(headers={"Host": "ov.example",
                                         "Authorization": "Bearer " + f.token()},
                                 trust_env=False, timeout=30) as client:
        async with streamable_http_client(f.url, http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                await call(session, "memory_search", query="first A")
                client.headers["Authorization"] = "Bearer " + f.token([B])
                response, value = await call(session, "memory_search", query="then B")
                assert not response.is_error, value
                assert all(m["uri"].startswith(B + "/") for m in value["matches"])
    assert f.semantic_trace[-1]["targets"] == [B]
    f.assert_capture((A, B))


@pytest.mark.asyncio
async def test_semantic_explicit_batch_cutoff_and_backend_failure(semantic_f):
    f = semantic_f
    f.semantic_many = True
    async with f.session() as session:
        response, value = await call(session, "memory_search", query="many", limit=100)
        assert not response.is_error and value["truncated"] and value["complete"] is False
        assert value["returned"] == 100 and "total" not in value
        before = len(f.semantic_trace)
        f.bad_backend = "error"
        response, value = await call(session, "memory_search", query="failure")
        assert response.is_error and value == {"error": "Resource unavailable."}
        assert len(f.semantic_trace) == before  # preflight failure
    f.assert_capture()



@pytest.mark.asyncio
async def test_semantic_all_granted_roots_preflight_before_query(semantic_f):
    f = semantic_f
    f.root_kind[B] = "file"
    async with f.session(f.token([A, B])) as session:
        response, value = await call(session, "memory_find", query="needle")
        assert response.is_error and value == {"error": "Resource unavailable."}
    assert [args["uri"] for _, _, args, _ in f.captured] == [A, B]
    assert all(method == "GET" for method, _, _, _ in f.captured)
    assert not f.semantic_trace


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["redirect", "large", "error"])
async def test_semantic_post_network_limits_refuse_without_redirect_or_secret_leak(semantic_f, mode):
    f = semantic_f
    f.semantic_response_mode = mode
    async with f.session() as session:
        response, value = await call(session, "memory_search", query="needle")
        assert response.is_error and value == {"error": "Resource unavailable."}
    assert len(f.captured) == 2 and f.captured[-1][0] == "POST"
    f.assert_capture()


def test_semantic_operator_profile_refuses_unknown_or_incomplete_config():
    base = dict(resource="https://ov.example/mcp", issuer=ISSUER,
                jwks_url="https://issuer.example/jwks", backend_url="http://backend.example/api/v1",
                backend_secret_file="/synthetic/backend.key")
    valid = dict(semantic_profile=SEMANTIC_PROFILE, semantic_backend_revision=SEMANTIC_REVISION,
                 namespace_roots=[A])
    assert Config(**base, **valid).namespace_roots == (A,)
    for change in ({"semantic_profile": "auto"}, {"semantic_backend_revision": "0.2.6"},
                   {"namespace_roots": []}, {"namespace_roots": [A, A]},
                   {"namespace_roots": [A + "/note.md"]}, {"namespace_roots": [A + "/*"]},
                   {"semantic_profile": "disabled"}, {"unknown_setting": True}):
        with pytest.raises((ValueError, TypeError)):
            Config(**(base | valid | change))
