"""Scoped offset paging contracts. Synthetic fixtures are not native backend proof."""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import ssl
import time

import httpx
import jsonschema
import pytest
import pytest_asyncio
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from ov_http.app import create_app, result, schema, SPECS
from ov_http.auth import Principal, Refused
from ov_http.config import (Config, RESOURCES_PROFILE, RESOURCES_REVISION,
                            LEGACY_URI_POLICY, RESOURCES_URI_POLICY)
from ov_http import reader as reader_module
from ov_http.reader import Backend, Reader, BROWSE_OFFSET_LIMIT, BROWSE_PAGE_LIMIT
from test_http_acceptance import A, B, f, call, serving

ROOT = "viking://resources"


class Pages:
    def __init__(self):
        self.files = {ROOT + f"/doc_{i:03}.md" for i in range(315)}
        self.files |= {A + f"/sub/doc_{i:03}.md" for i in range(305)}
        self.files |= {A + "/archive/old.md", A + "/archived/older.md",
                       A + "/_archive/oldest.md", B + "/other.md"}
        self.hidden = {A + "/.abstract.md", A + "/.overview.md", A + "/.relations.json",
                       A + "/.path.ovlock", A + "/.exact.ovlock.123", A + "/.redirect.json"}
        self.calls = []
        self.sizes = []
        self.fault = None
        self.long_names = False
        self.texts = {}
        self.delay = 0

    def paths(self, root, recursive, depth):
        files = self.files
        if self.long_names:
            files = {root + "/" + "n" * 240 + f"{i:03}.md" for i in range(110)}
        paths = set()
        for path in files:
            if path.startswith(root + "/"):
                parts = path[len(root) + 1:].split("/")
                for i in range(1, min(len(parts), depth if recursive else 1) + 1):
                    paths.add(root + "/" + "/".join(parts[:i]))
        # Deterministic DFS fixture; native tree ordering is separately source qualified.
        return sorted(paths)

    def respond(self, path, params):
        self.calls.append((path, params))
        uri = params["uri"]
        assert uri == ROOT or uri.startswith(ROOT + "/")
        if path.endswith("/content/read"):
            assert uri in self.files and set(params) == {"uri"}
            body = {"status": "ok", "result": self.texts.get(uri, "plain text " + uri)}
        elif path.endswith("/stat"):
            body = {"status": "ok", "result": {
                "uri": uri, "isDir": any(f.startswith(uri + "/") for f in self.files)
                or self.long_names, "size": 0, "count": 999999,
                "parent_uri": "viking://user/private", "abstract": "private summary"}}
        else:
            recursive = path.endswith("/tree")
            limit, offset = int(params["node_limit"]), int(params["offset"])
            assert 1 <= limit <= BROWSE_PAGE_LIMIT and 0 <= offset <= BROWSE_OFFSET_LIMIT
            assert params["output"] == "original"
            for name in ("include_abstract", "include_overview", "include_tags", "show_all_hidden"):
                assert params[name] == "false"
            assert "extra_fields" not in params and "tags" not in params
            if recursive:
                assert params["directories_only"] == "false"
                depth = int(params["level_limit"])
            else:
                assert params["simple"] == "false" and params["recursive"] == "false"
                assert params["sort_by"] == "name" and params["sort_order"] == "asc"
                depth = 1
            paths = self.paths(uri, recursive, depth)
            selected = paths[offset:offset + limit]
            entries = [{"uri": p, "isDir": p not in self.files,
                        "count": 999999, "abstract": "unrequested private summary",
                        "parent_uri": "viking://user/private"} for p in selected]
            body = {"status": "ok", "result": entries, "has_more": offset + limit < len(paths),
                    "total": 999999, "abstract": "unrequested private summary"}
            if self.fault:
                self.fault(body, recursive, uri)
        self.sizes.append(len(json.dumps(body).encode()))
        return body

    async def mock(self, request):
        assert str(request.url).startswith("http://fixture/api/v1/")
        return httpx.Response(200, json=self.respond(request.url.path, dict(request.url.params)))

    async def http(self, request):
        if self.delay and request.url.path.endswith("/content/read"):
            await asyncio.sleep(self.delay)
        return JSONResponse(self.respond(request.url.path, dict(request.query_params)))


def config():
    return Config("https://ov.example/mcp", "https://issuer.example/",
                  "https://issuer.example/jwks", "http://fixture/api/v1", "/synthetic/key",
                  semantic_profile=RESOURCES_PROFILE, semantic_backend_revision=RESOURCES_REVISION,
                  namespace_roots=(ROOT,))


def principal(roots=(ROOT,), **kwargs):
    kwargs.setdefault("uri_policy", RESOURCES_URI_POLICY)
    return Principal("subject", roots, int(time.time()) + 240, "digest", **kwargs)


@asynccontextmanager
async def reader(pages, roots=(ROOT,), **kwargs):
    async with httpx.AsyncClient(transport=httpx.MockTransport(pages.mock)) as client:
        backend = Backend(config(), principal(roots, **kwargs), client)
        yield Reader(backend)


@pytest.mark.asyncio
@pytest.mark.parametrize("root", [ROOT, A, A + "/sub"])
@pytest.mark.parametrize("recursive", [False, True])
async def test_static_more_than_256_paths_across_every_page(root, recursive):
    pages = Pages()
    async with reader(pages) as read:
        entries, offset = [], 0
        while True:
            before = len(pages.calls)
            value = await read.paged_listing(root, recursive, 100, 12, offset)
            assert len(pages.calls) - before == 2
            assert len(value["entries"]) <= 40 and len(json.dumps(value).encode()) < 49152
            assert "private" not in json.dumps(value) and "999999" not in json.dumps(value)
            entries.extend(value["entries"])
            if value["next_offset"] is None:
                assert not value["has_more"] and not value["truncated"]
                break
            assert value["next_offset"] == offset + len(value["entries"])
            offset = value["next_offset"]
        expected = pages.paths(root, recursive, 12)
        if root != A or recursive:
            assert len(expected) > 256
        else:
            assert expected
        assert entries == expected and len(entries) == len(set(entries))
        assert all(path not in pages.hidden for path in entries)
        if recursive and root in (ROOT, A):
            assert A + "/archive/old.md" in entries
            assert A + "/archived/older.md" in entries
            assert A + "/_archive/oldest.md" in entries
    assert max(pages.sizes) <= 262144


@pytest.mark.asyncio
async def test_depth_exact_subdirectory_and_no_parent_discovery():
    pages = Pages()
    async with reader(pages, (A + "/sub",)) as read:
        value = await read.paged_listing(None, True, 7, 1)
        assert len(value["entries"]) == 7
        assert all(p.startswith(A + "/sub/") for p in value["entries"])
        assert all(params["uri"] == A + "/sub" for _, params in pages.calls)
        with pytest.raises(Refused):
            await read.paged_listing(A, True, 7, 1, value["next_offset"])
    assert len(pages.calls) == 2


@pytest.mark.asyncio
async def test_file_token_refuses_without_ancestor_read_and_offsets_never_grant_access():
    pages = Pages()
    file = B + "/other.md"
    async with reader(pages, (file,)) as read:
        with pytest.raises(Refused):
            await read.paged_listing(None, False, 40, offset=40)
        assert [params["uri"] for _, params in pages.calls] == [file]
        before = len(pages.calls)
        for target in (B, ROOT, A, "http://attacker/"):
            with pytest.raises(Refused):
                await read.paged_listing(target, True, 40, offset=40)
        assert len(pages.calls) == before


@pytest.mark.asyncio
async def test_grants_actions_and_expiry_rechecked_for_each_page():
    pages = Pages()
    async with reader(pages, (ROOT,)) as read:
        first = await read.paged_listing(A + "/sub", False, 3)
    async with reader(pages, (B,)) as read:
        with pytest.raises(Refused):
            await read.paged_listing(A + "/sub", False, 3, offset=first["next_offset"])
    async with reader(pages, (ROOT,), actions=("write",)) as read:
        with pytest.raises(Refused):
            await read.paged_listing(A, False, 3)
    assert len(pages.calls) == 2
    async with reader(pages) as read:
        read.principal = read.backend.principal = replace(read.principal, expires=0)
        with pytest.raises(Refused):
            await read.paged_listing(A, False, 3)
    assert len(pages.calls) == 2


@pytest.mark.asyncio
async def test_multiple_roots_require_explicit_authorized_directory():
    pages = Pages()
    async with reader(pages, (A, B)) as read:
        with pytest.raises(Refused):
            await read.paged_listing(None, False, 5)
        assert not pages.calls
        assert (await read.paged_listing(A, False, 5))["entries"]


@pytest.mark.asyncio
@pytest.mark.parametrize("offset", [-1, True, 1.5, "40", 100001, 2**53])
async def test_invalid_offsets_refused_before_network(offset):
    pages = Pages()
    async with reader(pages) as read:
        with pytest.raises(Refused):
            await read.paged_listing(ROOT, False, 5, offset=offset)
    assert not pages.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, 101, True, 1.1, "5"])
async def test_limit_bounds_refused_before_network(limit):
    pages = Pages()
    async with reader(pages) as read:
        with pytest.raises(Refused):
            await read.paged_listing(ROOT, False, limit)
    assert not pages.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["missing", "string", "integer", "short-more", "oversized",
                                  "foreign", "neighbor", "wrong-root", "self", "nested",
                                  "duplicate", "hidden", "unicode", "space", "shape", "denied", "large"])
@pytest.mark.parametrize("recursive", [False, True])
async def test_malformed_or_foreign_pages_refuse_entire_call(fault, recursive):
    pages = Pages()

    def corrupt(body, tree, uri):
        entries = body["result"]
        if fault == "missing":
            del body["has_more"]
        elif fault in ("string", "integer"):
            body["has_more"] = "true" if fault == "string" else 1
        elif fault == "short-more":
            body.update(result=[], has_more=True)
        elif fault == "large":
            body["padding"] = "x" * 270000
        elif fault == "oversized":
            entries.append(entries[0])
        elif fault == "duplicate":
            entries[1] = entries[0]
        elif fault == "shape":
            entries[0] = {"uri": entries[0]["uri"], "isDir": 1}
        elif fault == "denied":
            entries[0]["access"] = "denied"
        else:
            paths = {"foreign": "viking://user/private", "neighbor": A + "-neighbor/leak.md",
                     "wrong-root": B + "/other.md", "self": uri, "nested": uri + "/x/y",
                     "hidden": uri + "/.path.ovlock", "unicode": uri + "/café.md",
                     "space": uri + "/meeting notes.md"}
            target = paths[fault]
            entries[0]["uri"] = target

    pages.fault = corrupt
    # Retain these exact legacy denials. Resources-policy acceptance is tested separately.
    policy = LEGACY_URI_POLICY if fault in ("unicode", "space") else RESOURCES_URI_POLICY
    async with reader(pages, (ROOT,), uri_policy=policy) as read:
        with pytest.raises(Refused):
            await read.paged_listing(A, recursive, 3, depth=1)
    assert len(pages.calls) == 2


@pytest.mark.asyncio
async def test_output_request_and_offset_ceiling_limits():
    pages = Pages()
    pages.long_names = True
    long_root = ROOT + ("/" + "d" * 240) * 3
    async with reader(pages) as read:
        value = await read.paged_listing(long_root, False, 100)
        assert len(value["entries"]) == 40 and not result(value).is_error
        assert read.backend.requests == 2 and read.backend.bytes <= 1048576
        assert max(pages.sizes) <= 262144
    pages.long_names = False
    async with reader(pages) as read:
        empty = await read.paged_listing(ROOT, False, 100, offset=100000)
        assert empty["entries"] == [] and empty["next_offset"] is None
        assert pages.calls[-1][1]["node_limit"] == "1"

    def at_ceiling(body, tree, uri):
        body.update(result=[{"uri": uri + "/edge.md", "isDir": False}], has_more=True)

    pages.fault = at_ceiling
    async with reader(pages) as read:
        value = await read.paged_listing(ROOT, False, 100, offset=100000)
        assert value["has_more"] and value["truncated"] and value["continuation_limited"]
        assert value["next_offset"] is None and value["complete"] is False


def test_profile_specific_schema_preserves_legacy_catalog():
    for name in SPECS:
        assert ("offset" in schema(name, RESOURCES_PROFILE)["properties"]) == (
            name in ("memory_ls", "memory_tree", "memory_read", "memory_grep"))
    for name in ("memory_ls", "memory_tree", "memory_grep"):
        for profile in ("disabled", "namespace-directories-v1"):
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate({"offset": 0}, schema(name, profile))
        for offset in (-1, True, 100001, "0"):
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate({"offset": offset}, schema(name, RESOURCES_PROFILE))


def curator_layout(pages, archives=150):
    """Mirror the 2026-11 openviking namespace that defeated the per-node walk.

    A large archive sorts between the first live notes and the exact-directory
    notes that contain the literal, so a stat-per-node walk spent its discovery
    allowance inside archive/ and reported matches=[] with truncated=true.
    """
    ns = A + "/openviking"
    pages.files = {ns + "/agent-access-on-normandy.md/agent-access-on-normandy.md",
                   ns + "/agent-access.md/agent-access.md",
                   ns + "/memory-curation-job.md/0001/0000.md",
                   ns + "/memory-curation-status.md/0001/0000.md",
                   ns + "/zz-unrelated.md/0001/0000.md"}
    pages.files |= {ns + f"/archive/backup-{i:03}.md/0001/0000.md" for i in range(archives)}
    pages.texts = {
        ns + "/agent-access-on-normandy.md/agent-access-on-normandy.md": "# agent-access-on-normandy",
        ns + "/agent-access.md/agent-access.md": "See [[agent-access-on-normandy]].",
        ns + "/memory-curation-job.md/0001/0000.md": "Related: [[agent-access-on-normandy]].",
        ns + "/memory-curation-status.md/0001/0000.md":
            "[[upkeeper-publication]] and viking://resources/homelab/upkeeper-publication.md",
    }
    pages.texts |= {p: "[[upkeeper-publication]] [[agent-access-on-normandy]]"
                    for p in pages.files if "/archive/" in p}
    return ns


@pytest.mark.asyncio
@pytest.mark.parametrize("pattern,expected", [
    ("upkeeper-publication", ["memory-curation-status.md"]),
    ("agent-access-on-normandy", ["agent-access-on-normandy.md", "agent-access.md",
                                  "memory-curation-job.md"]),
])
async def test_grep_reaches_exact_directory_notes_behind_a_large_archive(pattern, expected):
    pages = Pages()
    ns = curator_layout(pages)
    async with reader(pages) as read:
        value = await read.grep(pattern, ns, False, 20, True, False)
        assert value["scan_complete"] is True and value["truncated"] is False
        assert value["next_offset"] is None and value["scanned_files"] == 5
        assert [m["uri"] for m in value["matches"]] == [ns + "/" + name for name in expected]
        assert read.backend.requests <= 128
    reads = [params["uri"] for path, params in pages.calls if path.endswith("/content/read")]
    assert reads and not any("/archive/" in uri for uri in reads)
    assert not any(path.endswith("/fs/ls") for path, _ in pages.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [3, 100])
async def test_grep_resumes_at_next_offset_until_the_scan_is_complete(limit):
    pages = Pages()
    ns = curator_layout(pages)
    async with reader(pages) as read:
        archived = await read.grep("upkeeper-publication", ns, False, 100, True, True)
    # Reading every archive file exceeds one call's 128-request budget.
    assert archived["scan_complete"] is False and archived["truncated"] is True
    assert archived["next_offset"] and not archived["continuation_limited"]
    found, offset, calls = set(), 0, 0
    while True:
        async with reader(pages) as read:
            value = await read.grep("upkeeper-publication", ns, False, limit, True, True, offset)
            assert read.backend.requests <= 128 and value["returned"] <= limit
        calls += 1
        found |= {m["uri"] for m in value["matches"]}
        if value["scan_complete"]:
            assert value["next_offset"] is None and not value["truncated"]
            break
        assert value["truncated"] and value["next_offset"] > offset
        offset = value["next_offset"]
    assert calls > 1
    expected = {ns + f"/archive/backup-{i:03}.md" for i in range(150)}
    assert found == expected | {ns + "/memory-curation-status.md"}


async def grep_sequence(pages, root, pattern, *, limit=100, group=True, include_archived=False):
    """Follow next_offset from zero; return every call's result."""
    values, offset = [], 0
    while True:
        async with reader(pages) as read:
            value = await read.grep(pattern, root, False, limit, group, include_archived, offset)
            assert read.backend.requests <= 128
        assert not result(value).is_error
        values.append(value)
        if value["next_offset"] is None:
            return values
        assert value["next_offset"] > offset and not value["scan_complete"]
        offset = value["next_offset"]


def deep(root, levels):
    return root + "".join(f"/d{i:02}" for i in range(levels))


@pytest.mark.asyncio
async def test_grep_depth_limit_is_never_completed_by_resuming():
    pages = Pages()
    ns = A + "/deep"
    # Many early files exhaust the first call before the depth boundary.
    pages.files = {ns + f"/a/early_{i:03}.md" for i in range(150)}
    hidden = deep(ns + "/b", 12) + "/note.md"
    pages.files |= {hidden, ns + "/c/late.md"}
    pages.texts = {hidden: "needle"}
    values = await grep_sequence(pages, ns, "needle")
    assert len(values) > 1
    last = values[-1]
    assert last["depth_limited"] and not last["scan_complete"] and last["truncated"]
    assert last["next_offset"] is None and last["continuation_limited"]
    assert not any(v["scan_complete"] for v in values)
    assert all(v["matches"] == [] for v in values)


@pytest.mark.asyncio
async def test_grep_excluded_archive_depth_does_not_block_completion():
    pages = Pages()
    ns = A + "/live"
    pages.files = {deep(ns + "/archive", 12) + "/old.md", ns + "/note.md"}
    pages.texts = {ns + "/note.md": "needle"}
    [value] = await grep_sequence(pages, ns, "needle")
    assert value["scan_complete"] and not value["depth_limited"] and not value["truncated"]
    assert value["matches"] == [{"uri": ns + "/note.md", "matching_parts": 1}]
    [archived] = await grep_sequence(pages, ns, "needle", include_archived=True)
    assert archived["depth_limited"] and not archived["scan_complete"]


@pytest.mark.asyncio
async def test_grep_offset_ceiling_matches_listing():
    pages = Pages()

    def at_ceiling(body, tree, uri):
        body.update(result=[{"uri": uri + "/edge.md", "isDir": False}], has_more=True)

    pages.files = {A + "/edge.md"}
    pages.fault = at_ceiling
    async with reader(pages) as read:
        value = await read.grep("needle", A, False, 5, True, False, BROWSE_OFFSET_LIMIT)
    assert [p["node_limit"] for path, p in pages.calls if path.endswith("/tree")] == ["1"]
    assert not value["scan_complete"] and value["next_offset"] is None
    assert value["continuation_limited"] and value["scanned_files"] == 1


@pytest.mark.asyncio
async def test_grep_output_budget_returns_a_resumable_batch():
    pages = Pages()
    ns = A + "/long"
    stem = ns + ("/" + "n" * 200) * 4
    pages.files = {stem + f"/f{i:03}.md" for i in range(60)}
    pages.texts = {p: "needle" for p in pages.files}
    values = await grep_sequence(pages, ns, "needle", group=False)
    assert len(values) > 1 and values[-1]["scan_complete"]
    found = [m["uri"] for v in values for m in v["matches"]]
    assert sorted(found) == sorted(pages.files) and len(found) == len(set(found))
    assert all(m["matching_parts"] == 1 for v in values for m in v["matches"])
    assert all(len(json.dumps(v).encode()) <= 49152 for v in values)


@pytest.mark.asyncio
async def test_grep_offsets_need_one_directory_and_file_grants_scan_once():
    pages = Pages()
    ns = curator_layout(pages, archives=2)
    async with reader(pages, (A, B)) as read:
        with pytest.raises(Refused):
            await read.grep("needle", None, False, 5, True, False, 40)
    assert not pages.calls
    for offset in (-1, True, 100001):
        async with reader(pages) as read:
            with pytest.raises(Refused):
                await read.grep("needle", ns, False, 5, True, False, offset)
    assert not pages.calls
    status = ns + "/memory-curation-status.md/0001/0000.md"
    async with reader(pages, (status,)) as read:
        value = await read.grep("UPKEEPER", None, True, 5, True, False)
        assert value["scan_complete"] and value["matches"] == [{"uri": status, "matching_parts": 1}]
        with pytest.raises(Refused):
            await read.grep("UPKEEPER", None, True, 5, True, False, 1)
    async with reader(pages, (B,)) as read:
        with pytest.raises(Refused):
            await read.grep("needle", ns, False, 5, True, False)


@pytest_asyncio.fixture
async def sdk_pages(f):
    pages = Pages()
    backend = Starlette(routes=[Route("/api/v1/fs/{path:path}", pages.http),
                                Route("/api/v1/content/{path:path}", pages.http)])
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
    with (home / "paging-http-captures.jsonl").open("a") as output:
        output.write(json.dumps({"calls": pages.calls, "response_bytes": pages.sizes}) + "\n")


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,args", [("memory_ls", {}), ("memory_ls", {"recursive": True}),
                                       ("memory_tree", {"level_limit": 12})])
async def test_sdk_pages_static_resources_and_reauthorizes_changed_tokens(sdk_pages, tool, args):
    fixture, pages = sdk_pages
    all_entries, offset = [], 0
    async with fixture.session(fixture.token([ROOT])) as session:
        tools = await session.list_tools()
        assert {tool.name for tool in tools.tools} == set(SPECS)
        while True:
            before = len(pages.calls)
            response, value = await call(session, tool, uri=A + "/sub", offset=offset, limit=100, **args)
            assert not response.is_error, value
            assert len(pages.calls) - before == 2
            all_entries.extend(value["entries"])
            if value["next_offset"] is None:
                break
            offset = value["next_offset"]
        assert len(all_entries) == len(set(all_entries)) == 305
        assert all_entries == pages.paths(A + "/sub", True, 12)
        before = len(pages.calls)
        response, _ = await call(session, tool, uri=A, offset=-1, **args)
        assert response.is_error and len(pages.calls) == before
    async with fixture.session(fixture.token([B])) as session:
        response, value = await call(session, tool, uri=A + "/sub", offset=40, **args)
        assert response.is_error and value == {"error": "Resource unavailable."}
        assert len(pages.calls) == before
    file = B + "/other.md"
    async with fixture.session(fixture.token([file])) as session:
        response, _ = await call(session, tool, uri=file, **args)
        assert response.is_error and pages.calls[-1][1]["uri"] == file
        assert len(pages.calls) == before + 1


@pytest.mark.asyncio
async def test_sdk_grep_time_budget_yields_resumable_partial_results(sdk_pages, monkeypatch):
    # Slow content reads must return progress and an offset, never a tool error.
    fixture, pages = sdk_pages
    ns = curator_layout(pages, archives=2)
    pages.delay = 0.2
    monkeypatch.setattr(reader_module, "GREP_TIME_BUDGET", 0.3)
    found, offset, calls = [], 0, 0
    async with fixture.session(fixture.token([ROOT])) as session:
        assert "offset" in next(t for t in (await session.list_tools()).tools
                                 if t.name == "memory_grep").input_schema["properties"]
        while True:
            response, value = await call(session, "memory_grep", uri=ns, offset=offset,
                                         pattern="agent-access-on-normandy", limit=20)
            assert not response.is_error, value
            calls += 1
            found += [m["uri"] for m in value["matches"]]
            if value["next_offset"] is None:
                break
            assert not value["scan_complete"] and value["next_offset"] > offset
            offset = value["next_offset"]
    assert calls > 1 and value["scan_complete"] and not value["truncated"]
    assert found == [ns + "/agent-access-on-normandy.md", ns + "/agent-access.md",
                     ns + "/memory-curation-job.md"]
