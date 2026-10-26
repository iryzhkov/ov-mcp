"""Exact UTF-8 read identities in the opt-in profile. Fixtures are not backend proof."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import ssl

import httpx
import pytest
import pytest_asyncio
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Route

from ov_http.app import create_app, result
from ov_http.auth import Principal, Refused, canonical, resources_canonical
from ov_http.config import (LEGACY_URI_POLICY, RESOURCES_URI_POLICY, RESOURCES_PROFILE,
                            RESOURCES_REVISION, SEMANTIC_PROFILE, SEMANTIC_REVISION)
from ov_http.reader import Backend, Reader
from test_browse_pagination import Pages, config, principal, reader, ROOT
from test_http_acceptance import A, B, f, call, serving
from test_http_actions import signed, verify

UTF_ROOT = ROOT + "/文档/会议 记录"
DOT_ROOT = UTF_ROOT + "/.笔记"
FILE = DOT_ROOT + "/café.md"

VALID = [
    ROOT, ROOT + "/café.md", ROOT + "/cafe\u0301.md", ROOT + "/资料/会议 记录.md",
    ROOT + "/📚/日本語.md", ROOT + "/.notes/普通 文档.md", ROOT + "/a  b.md",
    ROOT + "/ASCII_@+.,=-/file.md",
]
INVALID = [
    "", None, b"viking://resources/a", "https://attacker/a", "VIKING://resources/a",
    ROOT + "-neighbor/a", "viking://user/a", "viking://agent/a", "viking://session/a",
    ROOT + "/", ROOT + "//a", ROOT + "/a//b", ROOT + "/a/", ROOT + "/./a",
    ROOT + "/a/../b", ROOT + "/a?x", ROOT + "/a#b", ROOT + "/a\\b",
    ROOT + "/C:drive", ROOT + "/{calendar:today}", ROOT + "/%20",
    ROOT + "/%2e%2e/a", ROOT + "/%252e%252e/a", ROOT + "/%2F", ROOT + "/%zz",
    ROOT + "/ leading.md", ROOT + "/trailing /a", ROOT + "/trailing.md ",
    ROOT + "/a\x00b", ROOT + "/a\nb", ROOT + "/a\rb", ROOT + "/a\tb",
    ROOT + "/a\x7fb", ROOT + "/a\u0085b", ROOT + "/a\u2028b", ROOT + "/a\u2029b",
    ROOT + "/a\u202eb", ROOT + "/a\u200db", ROOT + "/a\ufeffb", ROOT + "/a\u00a0b",
    ROOT + "/\ud800.md", ROOT + "/\udfff.md", ROOT + "/\ud83d\udcda.md",
    ROOT + "/.path.ovlock", ROOT + "/.redirect.json", ROOT + "/.sync_log.json",
    ROOT + "/.exact.ovlock.name", ROOT + "/.relations.json", ROOT + "/.path.ovlock/child.md",
]


@pytest.mark.parametrize("uri", VALID)
def test_resources_read_policy_preserves_exact_identity(uri):
    assert resources_canonical(uri) == uri
    p = principal()
    assert p.require(uri) == uri
    # No Unicode normalization or name folding grants equivalent-looking paths.
    nfc, nfd = ROOT + "/café.md", ROOT + "/cafe\u0301.md"
    assert nfc != nfd
    with pytest.raises(Refused):
        principal((nfc,)).require(nfd)


@pytest.mark.parametrize("uri", INVALID)
def test_resources_rejects_aliases_controls_surrogates_internal_names(uri):
    with pytest.raises(Refused):
        resources_canonical(uri)


def test_utf8_byte_bounds_prevent_backend_component_shortening():
    segment = "é" * 127 + "a"
    assert len(segment.encode()) == 255
    assert resources_canonical(ROOT + "/" + segment)
    for bad in ("é" * 128, "a" * 256):
        with pytest.raises(Refused):
            resources_canonical(ROOT + "/" + bad)
    prefix = ROOT + "/" + "/".join(["é" * 125] * 3) + "/"
    exact = prefix + "a" * (1024 - len(prefix.encode()))
    assert len(exact.encode()) == 1024 and len(exact) < 1024
    assert resources_canonical(exact) == exact
    with pytest.raises(Refused):
        resources_canonical(exact + "a")
    # The older ASCII contract, including its component rules, is unchanged.
    legacy_long = ROOT + "/" + "a" * 256
    assert canonical(legacy_long) == legacy_long
    assert principal(uri_policy=LEGACY_URI_POLICY).require(legacy_long) == legacy_long


@pytest.mark.parametrize("uri", [ROOT + "/café.md", ROOT + "/meeting notes.md", ROOT + "/📚"])
def test_default_principal_and_legacy_helper_still_refuse_utf8_or_spaces(uri):
    with pytest.raises(Refused):
        canonical(uri)
    p = Principal("subject", (ROOT,), 2**40, "digest")
    assert p.uri_policy == LEGACY_URI_POLICY
    with pytest.raises(Refused):
        p.require(uri)
    with pytest.raises(Refused):
        replace(p, uri_policy="token-selected-unknown").require(ROOT)


@pytest.mark.asyncio
async def test_verifier_derives_policy_and_binds_effective_capability(signed):
    key, legacy_cfg, token = signed
    resources_cfg = replace(legacy_cfg, semantic_profile=RESOURCES_PROFILE,
                            semantic_backend_revision=RESOURCES_REVISION, namespace_roots=(ROOT,))
    namespace_cfg = replace(legacy_cfg, semantic_profile=SEMANTIC_PROFILE,
                            semantic_backend_revision=SEMANTIC_REVISION, namespace_roots=(A,))
    legacy = await verify(signed, ov_namespaces=[A], uri_policy=RESOURCES_URI_POLICY)
    namespace = await verify((key, namespace_cfg, token), ov_namespaces=[A])
    resources = await verify((key, resources_cfg, token), ov_namespaces=[A])
    assert legacy.uri_policy == namespace.uri_policy == LEGACY_URI_POLICY
    assert resources.uri_policy == RESOURCES_URI_POLICY
    expected_legacy = hashlib.sha256(json.dumps([(A,), ("read",)],
                                               separators=(",", ":")).encode()).hexdigest()
    assert legacy.grant_digest == namespace.grant_digest == expected_legacy
    assert resources.grant_digest != legacy.grant_digest
    same = await verify((key, resources_cfg, token), ov_namespaces=[A],
                        scope="ov.read ov.write", uri_policy=LEGACY_URI_POLICY)
    write = await verify((key, resources_cfg, token), ov_namespaces=[A],
                         scope="ov.read ov.write", ov_actions=["read", "write"])
    assert same.grant_digest == resources.grant_digest != write.grant_digest
    narrow = await verify((key, resources_cfg, token), ov_namespaces=[FILE])
    assert narrow.roots == (FILE,) and narrow.require(FILE) == FILE
    with pytest.raises(Refused):
        narrow.require(DOT_ROOT)
    for cfg in (legacy_cfg, namespace_cfg):
        with pytest.raises(Refused):
            await verify((key, cfg, token), ov_namespaces=[FILE], uri_policy=RESOURCES_URI_POLICY)
    for malformed in (ROOT + "/\ud800", ROOT + "/a\x00", ROOT + "/%20"):
        with pytest.raises(Refused):
            await verify((key, resources_cfg, token), ov_namespaces=[malformed])


def unicode_pages():
    pages = Pages()
    pages.files = {UTF_ROOT + f"/文档 {i:03}.md" for i in range(310)}
    pages.files |= {DOT_ROOT + f"/资料 é {i:03}.md" for i in range(310)}
    pages.files |= {FILE, UTF_ROOT + "/archive/旧 文档.md",
                    UTF_ROOT + "/café.md", UTF_ROOT + "/cafe\u0301.md"}
    return pages


@pytest.mark.asyncio
@pytest.mark.parametrize("root", [UTF_ROOT, DOT_ROOT])
@pytest.mark.parametrize("recursive", [False, True])
async def test_static_unicode_space_dot_directory_pages_are_exact_and_complete_within_fixture(root, recursive):
    pages = unicode_pages()
    observed, offset = [], 0
    while True:
        async with reader(pages, (root,)) as read:
            before = len(pages.calls)
            page = await read.paged_listing(root, recursive, 100, 12, offset)
            assert len(pages.calls) - before == 2
            assert read.backend.requests == 2 and read.backend.bytes <= 1048576
            assert not result(page).is_error and len(json.dumps(page, ensure_ascii=False).encode()) < 49152
            assert all(params["uri"] == root for _, params in pages.calls[before:])
        observed.extend(page["entries"])
        if page["next_offset"] is None:
            break
        offset = page["next_offset"]
    assert len(observed) > 256 and len(observed) == len(set(observed))
    assert observed == pages.paths(root, recursive, 12)
    if root == UTF_ROOT:
        assert DOT_ROOT in observed
        assert UTF_ROOT + "/café.md" in observed and UTF_ROOT + "/cafe\u0301.md" in observed


@pytest.mark.asyncio
@pytest.mark.parametrize("name", [".path.ovlock", ".redirect.json", ".sync_log.json",
                                  ".exact.ovlock.x", ".abstract.md", ".overview.md",
                                  ".relations.json", ".ordinary-file"])
@pytest.mark.parametrize("is_dir", [False, True])
async def test_dot_directory_type_does_not_turn_reserved_metadata_into_content(name, is_dir):
    pages = Pages()
    def unexpected(body, tree, uri):
        body.update(result=[{"uri": uri + "/" + name, "isDir": is_dir}], has_more=False)
    pages.fault = unexpected
    async with reader(pages) as read:
        if name == ".ordinary-file" and is_dir:
            value = await read.paged_listing(A, False, 1)
            assert value["entries"] == [A + "/" + name]
        else:
            with pytest.raises(Refused):
                await read.paged_listing(A, False, 1)


@pytest.mark.asyncio
async def test_stat_echo_and_unexpected_raw_listing_uris_fail_closed():
    pages = unicode_pages()
    async def changed_stat(request):
        body = pages.respond(request.url.path, dict(request.url.params))
        body["result"]["uri"] = UTF_ROOT.replace("会议 记录", "会议_记录")
        return httpx.Response(200, json=body)
    async with httpx.AsyncClient(transport=httpx.MockTransport(changed_stat)) as client:
        with pytest.raises(Refused):
            await Reader(Backend(config(), principal(), client)).paged_listing(UTF_ROOT, False, 1)
    assert len(pages.calls) == 1
    for unexpected in (UTF_ROOT + "/", UTF_ROOT + "/%20", UTF_ROOT + "/a\ud800",
                       UTF_ROOT + "/a/../b", B + "/foreign.md", "viking://agent/private"):
        # Encode surrogate test values as escaped JSON, before adapter validation.
        async def raw_list(request):
            body = json.dumps({"status": "ok", "result": [unexpected]}).encode()
            return httpx.Response(200, content=body)
        async with httpx.AsyncClient(transport=httpx.MockTransport(raw_list)) as client:
            with pytest.raises(Refused):
                await Backend(config(), principal((UTF_ROOT,)), client).children(UTF_ROOT)
    async def legacy_list(request):
        return httpx.Response(200, json={"status": "ok", "result": [B + "/foreign.md", A + "/ok.md"]})
    legacy_cfg = replace(config(), semantic_profile="disabled", semantic_backend_revision="", namespace_roots=())
    async with httpx.AsyncClient(transport=httpx.MockTransport(legacy_list)) as client:
        assert await Backend(legacy_cfg, principal((A,), uri_policy=LEGACY_URI_POLICY), client).children(A) == [A + "/ok.md"]


@pytest_asyncio.fixture
async def uri_sdk(f):
    pages = unicode_pages()
    pages.raw_fault = None
    async def endpoint(request):
        uri = request.query_params["uri"]
        if pages.raw_fault and request.url.path.endswith("/ls"):
            pages.calls.append((request.url.path, dict(request.query_params)))
            return Response(pages.raw_fault, media_type="application/json")
        if request.url.path.endswith("/read"):
            body = {"status": "ok", "result": "Exact UTF-8 content"}
            pages.calls.append((request.url.path, dict(request.query_params)))
        elif request.url.path.endswith("/ls") and request.query_params.get("simple") == "true":
            pages.calls.append((request.url.path, dict(request.query_params)))
            body = {"status": "ok", "result": pages.paths(uri, False, 1)}
        else:
            body = pages.respond(request.url.path, dict(request.query_params))
        return Response(json.dumps(body, ensure_ascii=True).encode(), media_type="application/json")
    backend = Starlette(routes=[Route("/api/v1/{path:path}", endpoint)])
    async with serving(backend) as backend_port:
        cfg = replace(f.config, backend_url=f"http://127.0.0.1:{backend_port}/api/v1",
                      semantic_profile=RESOURCES_PROFILE, semantic_backend_revision=RESOURCES_REVISION,
                      namespace_roots=(ROOT,))
        app = create_app(cfg, jwks_ssl_context=ssl.create_default_context(cafile=str(f.cert)))
        async with serving(app) as port:
            f.url = f"http://127.0.0.1:{port}/mcp"
            yield f, pages
    home = Path(os.environ["HOME"]).resolve()
    assert home.name == "home" and home.parent.name == ".scratch"
    with (home / "utf8-http-captures.jsonl").open("a") as output:
        output.write(json.dumps({"calls": pages.calls}) + "\n")


@pytest.mark.asyncio
async def test_sdk_signed_unicode_narrow_file_and_ordinary_dot_folder_paging(uri_sdk):
    fixture, pages = uri_sdk
    async with fixture.session(fixture.token([DOT_ROOT])) as session:
        found, offset = [], 0
        while True:
            response, page = await call(session, "memory_tree", uri=DOT_ROOT, offset=offset, limit=100)
            assert not response.is_error, page
            found.extend(page["entries"])
            if page["next_offset"] is None:
                break
            offset = page["next_offset"]
        assert found == pages.paths(DOT_ROOT, True, 2) and len(found) > 256
        for tool in ("memory_abstract", "memory_overview"):
            response, value = await call(session, tool, uri=DOT_ROOT)
            assert not response.is_error and value["text"] == "Exact UTF-8 content"
    before = len(pages.calls)
    async with fixture.session(fixture.token([FILE])) as session:
        response, value = await call(session, "memory_read", uri=FILE)
        assert not response.is_error and value["text"] == "Exact UTF-8 content"
        assert [p["uri"] for _, p in pages.calls[before:]] == [FILE, FILE]
        before = len(pages.calls)
        for tool in ("memory_ls", "memory_tree"):
            response, _ = await call(session, tool, uri=DOT_ROOT)
            assert response.is_error and len(pages.calls) == before
            response, _ = await call(session, tool, uri=FILE)
            assert response.is_error and pages.calls[-1][1]["uri"] == FILE
            before = len(pages.calls)


@pytest.mark.asyncio
async def test_sdk_malformed_unicode_and_backend_bytes_never_become_500(uri_sdk):
    fixture, pages = uri_sdk
    headers = {"Host": "ov.example", "Authorization": "Bearer " + fixture.token([ROOT]),
               "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    async with httpx.AsyncClient(headers=headers, trust_env=False) as client:
        for uri in (ROOT + "/\ud800", ROOT + "/a\x00", ROOT + "/%20", ROOT + "/" + "é" * 128):
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "memory_ls", "arguments": {"uri": uri}}}
            response = await client.post(fixture.url, content=json.dumps(request).encode())
            if "\ud800" in uri:
                # The SDK's strict JSON parser rejects this before call_tool.
                assert response.status_code == 400, response.text
                assert response.json()["error"]["code"] == -32700
            else:
                assert response.status_code == 200, response.text
                assert response.json()["result"]["isError"] is True
        assert not pages.calls
        response = await client.post(fixture.url, content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","bad":"\xff"}')
        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32700
    for raw in (b'{"status":"ok","result":["\xff"],"has_more":false}',
                json.dumps({"status": "ok", "result": [{"uri": ROOT + "/\ud800", "isDir": False}],
                            "has_more": False}).encode()):
        pages.raw_fault = raw
        async with fixture.session(fixture.token([ROOT])) as session:
            response, value = await call(session, "memory_ls", uri=ROOT)
            assert response.is_error and value == {"error": "Resource unavailable."}
