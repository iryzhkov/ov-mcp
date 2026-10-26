"""Native SDK fixtures for the opt-in resources search profile."""
from dataclasses import replace
import json
import ssl

import pytest
import pytest_asyncio

from ov_http.app import create_app
from ov_http.config import RESOURCES_PROFILE, RESOURCES_REVISION
from test_http_acceptance import A, B, f, call, serving

ROOT = "viking://resources"


@pytest_asyncio.fixture
async def resources_f(f):
    config = replace(f.config, semantic_profile=RESOURCES_PROFILE,
                     semantic_backend_revision=RESOURCES_REVISION,
                     namespace_roots=[ROOT])
    f.semantic_allowed_roots = (ROOT, A, B)
    tls = ssl.create_default_context(cafile=str(f.cert))
    app = create_app(config, jwks_ssl_context=tls)
    async with serving(app) as port:
        f.url, f.app, f.config = f"http://127.0.0.1:{port}/mcp", app, config
        yield f


def full_token(f):
    return f.token([ROOT], scope="ov.read ov.write ov.remove ov.maintain",
                   ov_actions=["read", "write", "remove", "maintain"])


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["search", "find"])
async def test_resources_search_filters_foreign_stores_before_limit_and_keeps_archives(resources_f, kind):
    f = resources_f
    async with f.session(full_token(f)) as session:
        response, value = await call(session, "memory_" + kind, query="needle", group=False,
                                     include_archived=True, limit=100)
        assert not response.is_error, value
        uris = {hit["uri"] for hit in value["matches"]}
        assert A + "/archive/old.md" in uris
        assert B + "/secret.md" in uris  # The full resources grant includes B.
        assert all(uri.startswith(ROOT + "/") for uri in uris)
        assert "viking://user/" not in json.dumps(value)
        assert value["complete"] is False and value["returned"] == 12
        assert f.semantic_trace[-1]["scoped_count_before_limit"] == 12
        assert f.semantic_trace[-1]["targets"] == [ROOT]
        assert all(uri.startswith(ROOT + "/") for uri in f.semantic_trace[-1]["record_reads"])
        response, visible = await call(session, "memory_" + kind, query="needle", group=False)
        assert not response.is_error
        assert all("/archive/" not in hit["uri"] for hit in visible["matches"])


@pytest.mark.asyncio
async def test_full_grant_can_narrow_search_before_backend_retrieval(resources_f):
    f = resources_f
    async with f.session(full_token(f)) as session:
        response, value = await call(session, "memory_search", query="needle", scope=A)
        assert not response.is_error, value
        assert f.semantic_trace[-1]["targets"] == [A]
        assert all(uri.startswith(A + "/") for uri in f.semantic_trace[-1]["record_reads"])
        before = len(f.captured)
        response, _ = await call(session, "memory_search", query="needle",
                                 scope="viking://user/default/memories")
        assert response.is_error and len(f.captured) == before


@pytest.mark.asyncio
async def test_narrowed_search_rejects_in_grant_but_out_of_query_response(resources_f):
    f = resources_f
    f.semantic_bad = B + "/secret.md"
    async with f.session(full_token(f)) as session:
        response, value = await call(session, "memory_find", query="needle", scope=A)
        assert response.is_error and value == {"error": "Resource unavailable."}
    assert f.semantic_trace[-1]["targets"] == [A]


@pytest.mark.asyncio
async def test_narrow_file_token_still_reads_metadata_without_wider_traversal(resources_f):
    f = resources_f
    uri = A + "/other.md"
    async with f.session(f.token([uri])) as session:
        tools = await session.list_tools()
        assert len(tools.tools) == 11
        response, value = await call(session, "memory_stat", uri=uri)
        assert not response.is_error and value["uri"] == uri
        response, _ = await call(session, "memory_find", query="needle")
        assert response.is_error
    assert not f.semantic_trace
    assert all(capture[2].get("uri") == uri for capture in f.captured)


@pytest.mark.asyncio
async def test_foreign_store_in_backend_response_refuses_entire_call(resources_f):
    f = resources_f
    f.semantic_bad = "viking://agent/default/memories/poison.md"
    async with f.session(full_token(f)) as session:
        response, value = await call(session, "memory_find", query="needle")
        assert response.is_error and value == {"error": "Resource unavailable."}


@pytest.mark.parametrize("changes", [
    {"semantic_backend_revision": "unqualified"},
    {"namespace_roots": [A]},
    {"namespace_roots": [ROOT, A]},
    {"namespace_roots": ["viking://user"]},
])
def test_resources_profile_requires_exact_search_source_and_single_ceiling(f, changes):
    with pytest.raises(ValueError):
        replace(f.config, **({"semantic_profile": RESOURCES_PROFILE,
                             "semantic_backend_revision": RESOURCES_REVISION,
                             "namespace_roots": [ROOT]} | changes))
