"""Black-box MCP/HTTP acceptance with a captured synthetic OV backend and local TLS JWKS."""
import asyncio
import base64
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import time

import httpx
import httpx2
import jwt
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

from ov_http.app import create_app
from ov_http.config import Config

A = "viking://resources/namespaceA"
B = "viking://resources/namespaceB"
ISSUER = "https://issuer.example/application/o/ov/"
SECRET = "synthetic-backend-key"


@asynccontextmanager
async def serving(app, **options):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False,
                                         proxy_headers=False, **options))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        yield port
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


def encode_json(value):
    return base64.urlsafe_b64encode(value if isinstance(value, bytes) else
                                   json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()


class Fixture:
    def __init__(self, root, layout="small"):
        self.root = root
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "one"
        self.keys = [self.jwk(self.key, "one")]
        self.jwks_status = 200
        self.jwks_mode = ""
        self.captured = []
        self.jwks_calls = 0
        self.jwks_delay = 0
        self.poison = False
        self.slow = False
        self.bad_backend = ""
        self.semantic_trace = []
        self.semantic_bad = ""
        self.semantic_response_mode = ""
        self.semantic_many = False
        self.summary_mode = "normal"
        self.root_kind = {}
        self.scan_fault = None
        self.response_bytes = []
        self.layout = layout
        self.large_roots = []
        self.files = {
            A + "/note.md/part_1.md": "Alpha needle\n[[other]]\n[[secret]]\n[[" + B + "/secret.md]]",
            A + "/note.md/part_2.md": "Tail\nsecond needle",
            A + "/note.md/.abstract.md": "Allowed abstract",
            A + "/note.md/.overview.md": "Allowed overview",
            A + "/other.md": "Allowed other [[note]]",
            A + "/broken.md": "[[" + "x" * 100000,
            A + "/archive/old.md": "needle archived",
            A + "/raw.verbatim/part_1.md/chunk.md": "verbatim \n",
            A + "/raw.verbatim/part_2.md/chunk.md": " tail",
            B + "/secret.md": "DENIED needle [[note]]",
            A + "-neighbor/leak.md": "PREFIX DENIED needle",
            "viking://resources/outside.md/private/chunk.md": "CHUNK-ONLY needle",
        }
        if layout == "flat":
            self.files.update({A + f"/bulk/file_{i:03}.md": "needle [[" +
                               (A + "/other.md" if i % 2 == 0 else "other") + "]]"
                               for i in range(200)})
            self.files[A + "/zzz/other.md"] = "unseen duplicate short name"
        elif layout == "chunks":
            self.files.update({A + f"/library/note_{i:03}.md/part_{j}.md":
                               "needle [[" + A + "/other.md]]" for i in range(30) for j in range(3)})
        elif layout == "huge":
            self.files.update({A + f"/huge.md/part_{i:03}.md": "needle chunk" for i in range(180)})
        elif layout in ("bytes", "byte-doc"):
            prefix = "/bytes/file_" if layout == "bytes" else "/big.md/part_"
            self.files.update({A + prefix + str(i) + ".md": "needle " + "x" * 180000 +
                               " [[" + A + "/other.md]]" for i in range(8)})
        elif layout == "list-bytes":
            self.large_roots = [A + "/" + "r" * 760 + str(i) for i in range(8)]
            self.files.update({root + f"/file_{i:03}.md": "needle"
                               for root in self.large_roots for i in range(200)})
        else:
            assert layout == "small"
        self.initial = hashlib.sha256(json.dumps(self.files, sort_keys=True).encode()).hexdigest()
        self.cert, self.cert_key = self.certificate()
        cert_der = x509.load_pem_x509_certificate(self.cert.read_bytes()).public_bytes(serialization.Encoding.DER)
        self.keys[0].update({"x5c": [base64.b64encode(cert_der).decode()],
                             "x5t": "synthetic-thumbprint", "x5t#S256": "synthetic-sha256"})

    def jwk(self, key, kid):
        value = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        return {**value, "kid": kid, "alg": "RS256", "use": "sig"}

    def certificate(self):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                               critical=False).sign(self.key, hashes.SHA256()))
        cert_path, key_path = self.root / "cert.pem", self.root / "tls.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
                                                  serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
        key_path.chmod(0o600)
        return cert_path, key_path

    def token(self, roots=None, **claims):
        now = int(time.time())
        body = {"iss": ISSUER, "aud": self.resource, "sub": "same-subject",
                "iat": now, "exp": now + 240, "scope": "ov.read",
                "ov_namespaces": [A] if roots is None else roots}
        body.update(claims)
        return jwt.encode(body, self.key, algorithm="RS256", headers={"kid": self.kid})

    async def backend(self, request):
        if request.url.path == "/jwks":
            self.jwks_calls += 1
            await asyncio.sleep(self.jwks_delay)
            if self.jwks_mode == "redirect":
                return JSONResponse({}, 302, headers={"Location": self.redirect_url})
            if self.jwks_mode == "large":
                return JSONResponse({"keys": [], "padding": "x" * 70000})
            return JSONResponse({"keys": self.keys}, self.jwks_status)
        if request.method == "POST":
            return await self.semantic_backend(request)
        uri = request.query_params.get("uri")
        self.captured.append((request.method, request.url.path, dict(request.query_params),
                              request.headers.get("x-api-key")))
        if self.slow:
            await asyncio.sleep(1)
        if self.bad_backend == "redirect":
            return JSONResponse({}, 302, headers={"Location": self.redirect_url})
        if self.bad_backend == "large":
            return JSONResponse({"status": "ok", "result": "x" * 270000})
        if self.bad_backend == "error":
            return JSONResponse({"error": SECRET + " private backend diagnostic"}, 500)
        if request.headers.get("x-api-key") != SECRET:
            return JSONResponse({}, 401)
        if self.scan_fault and len(self.captured) == self.scan_fault["after"]:
            if self.scan_fault["mode"] == "expiry":
                await asyncio.sleep(max(0, self.scan_fault["expires"] - time.time() + 0.15))
            elif self.scan_fault["mode"] == "error":
                return JSONResponse({"error": SECRET}, 500)
            else:
                assert self.scan_fault["mode"] == "malformed"
                return JSONResponse({"status": "ok", "result": {"isDir": "invalid"}})
        if self.root_kind.get(uri) == "missing":
            return JSONResponse({}, 404)
        is_dir = (self.root_kind.get(uri) != "file"
                  and any(p.startswith(str(uri) + "/") for p in self.files))
        exists = uri in self.files or is_dir or self.root_kind.get(uri) == "file"
        if not exists:
            return JSONResponse({"error": "different missing details"}, 404)
        if request.url.path.endswith("/stat"):
            value = {"uri": uri, "isDir": is_dir, "size": len(self.files.get(uri, "").encode()),
                     "backend_secret": SECRET, "parent_uri": B}
        elif request.url.path.endswith("/ls"):
            children = set()
            for path in self.files:
                if path.startswith(uri + "/"):
                    leaf = path[len(uri) + 1:].split("/")[0]
                    if not leaf.startswith("."):
                        children.add(uri + "/" + leaf)
            if self.poison:
                children.update({B + "/secret.md", A + "-neighbor/leak.md", uri + "/../bad",
                                 uri + "/%2e%2e/bad", uri + "/fake?uri=" + B, uri})
            value = sorted(children)
        elif request.url.path.endswith("/read"):
            value = self.files.get(uri, "")
        else:
            return JSONResponse({}, 500)
        response = JSONResponse({"status": "ok", "result": value})
        self.response_bytes.append(len(response.body))
        return response

    async def semantic_backend(self, request):
        payload = await request.json()
        self.captured.append((request.method, request.url.path, payload,
                              request.headers.get("x-api-key")))
        kind = request.url.path.rsplit("/", 1)[-1]
        roots = payload.get("target_uri")
        assert isinstance(roots, list) and roots and roots == sorted(set(roots))
        assert all(root in getattr(self, "semantic_allowed_roots", (A, B)) for root in roots)
        expected = {"query": payload["query"], "target_uri": roots, "context_type": "resource",
                    "limit": 100, "read_content": False, "include_provenance": False, "telemetry": False}
        if kind == "search":
            expected.update(mode="list", search_type="semantic")
        assert payload == expected and kind in ("search", "find")
        assert request.headers.get("x-api-key") == SECRET
        if self.semantic_response_mode == "redirect":
            return JSONResponse({}, 302, headers={"Location": self.redirect_url})
        if self.semantic_response_mode == "large":
            return JSONResponse({"padding": "x" * 270000})
        if self.semantic_response_mode == "error":
            return JSONResponse({"error": SECRET}, 500)
        trace = {"query": payload["query"], "targets": roots, "summary_reads": [], "record_reads": []}
        self.semantic_trace.append(trace)
        if self.slow:
            await asyncio.sleep(1)
        # The synthetic engine receives explicit scope before summaries, record
        # content, ranking, counts or links. It is not a native vector proof.
        if kind == "search":
            trace["summary_reads"].append(roots[0] + "/.abstract.md")
            summary = "" if self.summary_mode in ("missing", "empty") else "Allowed summary"
            trace["summary_mode"] = self.summary_mode
            assert isinstance(summary, str)
        indexed = [(B + "/secret.md", 999, 2), (B + "/.abstract.md", 998, 0),
                   (B + "/.overview.md", 997, 1), (A + "-neighbor/leak.md", 996, 2),
                   (A + "/archive/old.md", 95, 2), (A + "/note.md/part_1.md", 90, 2),
                   (A + "/note.md/part_2.md", 89, 2), (A + "/note.md/.abstract.md", 88, 0),
                   (A + "/note.md/.overview.md", 87, 1), (A + "/.abstract.md", 85, 0),
                   (A + "/.overview.md", 84, 1), (A + "/other.md", 80, 2)]
        # Higher-ranked foreign stores must be excluded before the batch limit.
        indexed.extend((f"viking://user/default/memories/foreign_{i}.md", 10000 + i, 2)
                       for i in range(120))
        if self.semantic_many:
            indexed.extend((A + "/extra_" + str(i) + ".md", 500 + i, 2) for i in range(150))
        scoped = [(uri, score, level) for uri, score, level in indexed
                  if any(uri == root or uri.startswith(root + "/") for root in roots)]
        resources = []
        for uri, score, level in scoped:
            trace["record_reads"].append(uri)
            resources.append({"uri": uri, "context_type": "resource", "level": level, "score": score,
                              "abstract": "permitted prose [[" + B + "/secret.md]]" if uri.startswith(A + "/")
                              else "B preview", "relations": [B + "/secret.md"]})
        resources.sort(key=lambda hit: hit["score"], reverse=True)
        trace["scoped_count_before_limit"] = len(resources)
        resources = resources[:payload["limit"]]
        if self.semantic_bad:
            resources.append({"uri": self.semantic_bad, "context_type": "resource", "level": 2,
                              "score": 1, "abstract": "poison"})
        trace["returned_uris"] = [r["uri"] for r in resources]
        return JSONResponse({"status": "ok", "result": {"resources": resources, "memories": [],
                              "skills": [], "total": len(resources),
                              "query_plan": {"private": SECRET, "uri": B}}})

    def assert_capture(self, roots=(A,)):
        for method, path, params, secret in self.captured:
            if method == "POST":
                assert path in ("/api/v1/search/find", "/api/v1/search/search")
                assert params["target_uri"] and all(r in roots for r in params["target_uri"])
                assert secret == SECRET
                continue
            assert method == "GET"
            assert path in ("/api/v1/fs/stat", "/api/v1/fs/ls", "/api/v1/content/read")
            uri = params["uri"]
            assert any(uri == r or uri.startswith(r + "/") for r in roots), uri
            assert "%" not in uri and "?" not in uri and "#" not in uri and "/../" not in uri
            assert secret == SECRET

    @asynccontextmanager
    async def session(self, token=None):
        headers = {"Authorization": "Bearer " + (self.token() if token is None else token),
                   "Host": "ov.example"}
        async with httpx2.AsyncClient(headers=headers, trust_env=False, timeout=30) as client:
            async with streamable_http_client(self.url, http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    yield session


@pytest_asyncio.fixture
async def f(tmp_path, request):
    # A test may create files only under Chaldea's asserted scratch HOME.
    home = Path(os.environ["HOME"]).resolve()
    assert home.name == "home" and home.parent.name == ".scratch"
    assert tmp_path.resolve().is_relative_to(home)
    fixture = Fixture(tmp_path, getattr(request, "param", "small"))
    backend = Starlette(routes=[Route("/api/v1/{path:path}", fixture.backend, methods=["GET", "POST"]),
                                Route("/jwks", fixture.backend)])
    key_file = tmp_path / "backend.key"
    key_file.write_text(SECRET)
    key_file.chmod(0o600)
    async with serving(backend) as backend_port, serving(
            backend, ssl_certfile=str(fixture.cert), ssl_keyfile=str(fixture.cert_key)) as jwks_port:
        fixture.resource = "https://ov.example/mcp"
        fixture.redirect_url = f"http://127.0.0.1:{backend_port}/api/v1/content/read?uri={B}/secret.md"
        config = Config(fixture.resource, ISSUER, f"https://127.0.0.1:{jwks_port}/jwks",
                        f"http://127.0.0.1:{backend_port}/api/v1", str(key_file))
        tls = ssl.create_default_context(cafile=str(fixture.cert))
        app = create_app(config, jwks_ssl_context=tls)
        async with serving(app) as port:
            fixture.url = f"http://127.0.0.1:{port}/mcp"
            fixture.app = app
            fixture.config = config
            yield fixture
    assert fixture.initial == hashlib.sha256(json.dumps(fixture.files, sort_keys=True).encode()).hexdigest()
    if any(method == "POST" for method, _, _, _ in fixture.captured):
        capture = {"test": tmp_path.name, "backend_calls": [(m, p, args) for m, p, args, _ in fixture.captured],
                   "semantic_trace": fixture.semantic_trace, "fixture_unchanged": True,
                   "response_poison": fixture.semantic_bad}
        with (home / "semantic-http-captures.jsonl").open("a") as output:
            output.write(json.dumps(capture) + "\n")


async def call(session, name, **arguments):
    response = await session.call_tool(name, arguments)
    return response, json.loads(response.content[0].text)


@pytest.mark.asyncio
async def test_official_sdk_catalog_chunking_hidden_offsets_and_navigation(f):
    async with f.session() as session:
        catalog = await session.list_tools()
        names = {t.name for t in catalog.tools}
        assert names == {"memory_" + n for n in
                         ("search", "find", "grep", "glob", "ls", "tree", "stat", "read",
                          "abstract", "overview", "relations")}
        response, read = await call(session, "memory_read", uri=A + "/note.md", parts=True)
        assert not response.is_error
        assert read["text"].startswith("Alpha needle") and "Tail" in read["text"]
        assert read["parts"] == [A + "/note.md/part_1.md", A + "/note.md/part_2.md"]
        _, offset = await call(session, "memory_read", uri=A + "/note.md", offset=1, limit=1)
        assert offset["text"] == "[[other]]"
        _, verbatim = await call(session, "memory_read", uri=A + "/raw.verbatim")
        assert verbatim["text"] == "verbatim \n\n tail"
        for name, expected in (("abstract", "Allowed abstract"), ("overview", "Allowed overview")):
            response, summary = await call(session, "memory_" + name, uri=A + "/note.md")
            assert not response.is_error and summary["text"] == expected
        for tool, args in (("memory_ls", {}), ("memory_tree", {"level_limit": 2}),
                           ("memory_stat", {"uri": A + "/note.md"}),
                           ("memory_glob", {"pattern": "*.md"})):
            response, value = await call(session, tool, **args)
            assert not response.is_error, value
            assert "DENIED" not in json.dumps(value)
        response, limited = await call(session, "memory_ls", limit=1)
        assert not response.is_error and limited["truncated"]
        response, _ = await call(session, "memory_write", uri=A + "/evil.md", content="oops")
        assert response.is_error
    f.assert_capture()


@pytest.mark.asyncio
async def test_search_refusal_scoped_grep_group_archive_and_links(f):
    async with f.session() as session:
        before = len(f.captured)
        for name in ("memory_search", "memory_find"):
            response, value = await call(session, name, query="needle")
            assert response.is_error and "Scoped semantic search unavailable" in value["error"]
        assert len(f.captured) == before
        _, grouped = await call(session, "memory_grep", pattern="needle")
        assert grouped["matches"] == [{"uri": A + "/note.md", "matching_parts": 2}]
        _, raw = await call(session, "memory_grep", pattern="NEEDLE", case_insensitive=True, group=False)
        assert len(raw["matches"]) == 2
        _, globbed = await call(session, "memory_glob", pattern="**/*.md")
        assert A + "/other.md" in globbed["matches"] and A + "/note.md/part_1.md" in globbed["matches"]
        _, archives = await call(session, "memory_grep", pattern="needle", include_archived=True)
        assert len(archives["matches"]) == 2
        _, links = await call(session, "memory_relations", uri=A + "/note.md")
        assert links["wikilinks"] == [A + "/other.md"]
        assert links["backlinks"] == [A + "/other.md"]
        assert B not in json.dumps(links)
        response, broken = await call(session, "memory_relations", uri=A + "/broken.md")
        assert not response.is_error and broken["wikilinks"] == []
    f.assert_capture()


@pytest.mark.asyncio
async def test_scope_precedes_retrieval_traversal_neighbors_and_response_equivalence(f):
    f.poison = True
    async with f.session() as session:
        _, missing = await call(session, "memory_read", uri=A + "/absent.md")
        for bad in (B + "/secret.md", A + "-neighbor/leak.md", "viking://resources",
                    A + "/../namespaceB/secret.md", A + "/%2e%2e/secret.md",
                    A + "/x?uri=" + B, A + "/x#part", A + "//note.md", A + "/note.md/",
                    A + "/x\\secret", "VIKING://resources/namespaceA/note.md"):
            for tool in ("memory_read", "memory_abstract", "memory_ls", "memory_relations"):
                before = len(f.captured)
                response, denied = await call(session, tool, uri=bad)
                assert response.is_error and denied == missing
                assert len(f.captured) == before
        response, _ = await call(session, "memory_ls", recursive=True)
        assert not response.is_error
        _, matches = await call(session, "memory_grep", pattern="needle")
        assert all(m["uri"].startswith(A + "/") for m in matches["matches"])
    f.assert_capture()


@pytest.mark.asyncio
async def test_same_subject_different_grants_and_concurrent_sessions(f):
    async def exercise(root):
        async with f.session(f.token([root])) as session:
            _, data = await call(session, "memory_glob", pattern="*.md")
            assert all(p.startswith(root + "/") for p in data["matches"])
            response, _ = await call(session, "memory_read", uri=(B + "/secret.md" if root == A else A + "/other.md"))
            assert response.is_error
            return data
    a, b = await asyncio.gather(exercise(A), exercise(B))
    assert a != b
    f.assert_capture((A, B))


@pytest.mark.asyncio
async def test_chunk_only_grant_cannot_expose_parent_group_or_summary(f):
    root = "viking://resources/outside.md/private"
    async with f.session(f.token([root])) as session:
        _, value = await call(session, "memory_grep", pattern="needle")
        assert value["matches"] == [{"uri": root + "/chunk.md", "matching_parts": 1}]
        before = len(f.captured)
        response, _ = await call(session, "memory_abstract", uri="viking://resources/outside.md")
        assert response.is_error and len(f.captured) == before
    f.assert_capture((root,))


@pytest.mark.asyncio
async def test_http_discovery_host_origin_body_limit_and_safe_health(f):
    async with httpx.AsyncClient(trust_env=False, headers={"Host": "ov.example"}) as client:
        r = await client.get(f.url)
        assert r.status_code == 401
        assert f.config.metadata_url in r.headers["www-authenticate"]
        r = await client.get(f.url.replace("/mcp", "/.well-known/oauth-protected-resource/mcp"))
        assert r.status_code == 200 and r.json()["authorization_servers"] == [ISSUER]
        r = await client.get(f.url.replace("/mcp", "/health"))
        assert r.json() == {"ok": True}
        for headers in ({"Host": "evil.example"}, {"Origin": "https://evil.example"}):
            r = await client.get(f.url, headers=headers)
            assert r.status_code in (400, 403)
        r = await client.post(f.url, headers={"Authorization": "Bearer " + f.token(),
                                              "Content-Type": "application/json",
                                              "Accept": "application/json, text/event-stream"},
                              content=" " * 33000)
        assert r.status_code == 413
    assert not f.captured


@pytest.mark.asyncio
async def test_bad_signed_claims_and_trust_inputs_never_reach_backend(f):
    now = int(time.time())
    tokens = [
        f.token(iss=ISSUER.rstrip("/")), f.token(aud="https://other.example/mcp"),
        f.token(scope="other"), f.token(scope="ov.read ov.read"), f.token(ov_namespaces=[]),
        f.token(ov_namespaces=[A, A]), f.token(ov_namespaces=[A, A + "/note.md"]),
        f.token(ov_namespaces=[A + "/../namespaceB"]), f.token(ov_namespaces=[A + "/"]),
        f.token(iat=now + 60, exp=now + 100), f.token(iat=now, exp=now + 301),
        f.token(exp=now - 1), f.token(iat=True), f.token(exp=str(now + 50)),
        f.token(sub=""), f.token(aud=[f.resource]), f.token(nbf=now + 60),
        f.token(ov_namespaces="namespaceA"), f.token(scope=["ov.read"]),
        f.token(sub=None), f.token(scope="ov.read\tother"),
    ]
    valid = jwt.decode(f.token(), options={"verify_signature": False})
    for field in ("iss", "aud", "scope", "iat", "exp", "sub", "ov_namespaces"):
        missing = dict(valid)
        missing.pop(field)
        tokens.append(jwt.encode(missing, f.key, algorithm="RS256", headers={"kid": "one"}))
    for headers in ({"kid": "one", "jku": f.config.jwks_url},
                    {"kid": "one", "x5u": f.config.jwks_url},
                    {"kid": "one", "jwk": f.keys[0]}, {"kid": "one", "crit": ["anything"]}):
        tokens.append(jwt.encode(valid, f.key, algorithm="RS256", headers=headers))
    tokens.extend([jwt.encode(valid, f.other_key, algorithm="RS256", headers={"kid": "one"}),
                   jwt.encode(valid, "different-secret-" * 3, algorithm="HS256", headers={"kid": "one"}),
                   jwt.encode(valid, None, algorithm="none", headers={"kid": "one"}),
                   "x" * 13000, "abc.def.ghi"])
    # Signed duplicate claims and headers, not merely a damaged signature.
    signer = jwt.algorithms.RSAAlgorithm(jwt.algorithms.RSAAlgorithm.SHA256)
    for header, claims in (
        (b'{"alg":"RS256","kid":"one"}',
         json.dumps(valid).encode()[:-1] + b',"ov_namespaces":["' + B.encode() + b'"]}'),
        (b'{"alg":"RS256","alg":"RS256","kid":"one"}', json.dumps(valid).encode()),
    ):
        signing = (encode_json(header) + "." + encode_json(claims)).encode()
        signature = signer.sign(signing, f.key)
        tokens.append(signing.decode() + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode())
    async with httpx.AsyncClient(headers={"Host": "ov.example"}, trust_env=False) as client:
        for token in tokens:
            r = await client.post(f.url, headers={"Authorization": "Bearer " + token},
                                  json={"jsonrpc": "2.0", "method": "ping", "id": 1})
            assert r.status_code == 401, r.text
    assert not f.captured


@pytest.mark.asyncio
async def test_jwks_rotation_failure_and_no_redirect_or_unbounded_body(f):
    async with f.session() as session:
        response, _ = await call(session, "memory_read", uri=A + "/other.md")
        assert not response.is_error
    assert f.jwks_calls == 1
    # A second key can rotate in after the bounded unknown-kid refresh cooldown.
    await asyncio.sleep(5.1)
    f.keys = [f.jwk(f.other_key, "two")]
    f.key, f.kid = f.other_key, "two"
    async with f.session() as session:
        response, _ = await call(session, "memory_read", uri=A + "/other.md")
        assert not response.is_error
    assert f.jwks_calls == 2
    await asyncio.sleep(5.1)
    f.kid = "unavailable"
    f.jwks_status = 503
    before = len(f.captured)
    async with httpx.AsyncClient(headers={"Host": "ov.example"}, trust_env=False) as client:
        for _ in range(3):
            r = await client.get(f.url, headers={"Authorization": "Bearer " + f.token()})
            assert r.status_code == 401
        assert f.jwks_calls == 3
        for mode in ("redirect", "large"):
            await asyncio.sleep(5.1)
            f.jwks_status, f.jwks_mode = 200, mode
            r = await client.get(f.url, headers={"Authorization": "Bearer " + f.token()})
            assert r.status_code == 401
    assert len(f.captured) == before
    f.assert_capture()


@pytest.mark.asyncio
async def test_concurrent_failed_jwks_authentication_is_bounded_including_lock_wait(f):
    f.jwks_delay = 6
    async with httpx.AsyncClient(headers={"Host": "ov.example"}, trust_env=False, timeout=10) as client:
        started = time.monotonic()
        replies = await asyncio.gather(*(
            client.post(f.url, headers={"Authorization": "Bearer " + f.token()},
                        json={"jsonrpc": "2.0", "id": i, "method": "tools/list"})
            for i in range(4)))
        assert all(r.status_code == 401 for r in replies)
        assert time.monotonic() - started < 8
    assert not f.captured


@pytest.mark.asyncio
async def test_backend_safe_failure_redirect_limits_and_cancellation(f):
    async with f.session() as session:
        for mode in ("error", "redirect", "large"):
            f.bad_backend = mode
            response, value = await call(session, "memory_read", uri=A + "/other.md")
            assert response.is_error and value == {"error": "Resource unavailable."}
            assert SECRET not in json.dumps(value)
    f.bad_backend = ""
    f.slow = True
    before = len(f.captured)
    # Cancelling ClientSession.call_tool sends a separate notification, which a
    # stateless SDK transport cannot route to the first POST. Test the HTTP
    # disconnect that actually bounds the lifetime of a stateless request.
    async with httpx.AsyncClient(headers={"Host": "ov.example"}, trust_env=False) as client:
        task = asyncio.create_task(client.post(
            f.url, headers={"Authorization": "Bearer " + f.token(),
                            "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 99, "method": "tools/call",
                  "params": {"name": "memory_ls", "arguments": {"recursive": True}}}))
        async with asyncio.timeout(5):
            while len(f.captured) == before:
                await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(1.2)
        assert len(f.captured) == before + 1
    f.assert_capture()


@pytest.mark.asyncio
async def test_one_client_changes_grants_each_request_and_expiry_stops_work(f):
    async with httpx2.AsyncClient(headers={"Host": "ov.example", "Authorization": "Bearer " + f.token()},
                                 trust_env=False, timeout=30) as client:
        async with streamable_http_client(f.url, http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                client.headers["Authorization"] = "Bearer " + f.token([B])
                response, value = await call(session, "memory_read", uri=B + "/secret.md")
                assert not response.is_error and "DENIED" in value["text"]
                before = len(f.captured)
                response, _ = await call(session, "memory_read", uri=A + "/other.md")
                assert response.is_error and len(f.captured) == before
                client.headers["Authorization"] = "Bearer " + f.token(exp=int(time.time()) + 1)
                f.slow = True
                before = len(f.captured)
                response, value = await call(session, "memory_read", uri=A + "/other.md")
                assert response.is_error and value == {"error": "Resource unavailable."}
                assert len(f.captured) <= before + 1
    f.assert_capture((A, B))


@pytest.mark.asyncio
@pytest.mark.parametrize("refresh_status", [200, 503])
async def test_expired_jwks_refresh_survives_cancelled_authentication(f, refresh_status):
    async with f.session() as session:
        response, _ = await call(session, "memory_read", uri=A + "/other.md")
        assert not response.is_error
    before = len(f.captured)
    # Exercise real expiry, then cancel the authentication task while its HTTPS
    # JWKS fetch is in flight. No clock, cache or process-global state patching.
    await asyncio.sleep(60.1)
    f.jwks_status, f.jwks_delay = refresh_status, 0.5
    triggering_auth = asyncio.create_task(f.app.verifier.verify(f.token()))
    async with asyncio.timeout(3):
        while f.jwks_calls < 2:
            await asyncio.sleep(0.01)
    triggering_auth.cancel()
    with pytest.raises(asyncio.CancelledError):
        await triggering_auth
    async with httpx.AsyncClient(headers={"Host": "ov.example"}, trust_env=False) as client:
        started = time.monotonic()
        r = await client.post(f.url, headers={"Authorization": "Bearer " + f.token(),
                                              "Accept": "application/json, text/event-stream"},
                              json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == (200 if refresh_status == 200 else 401)
        assert time.monotonic() - started < 3
        if refresh_status == 200:
            assert "memory_read" in r.text
    assert f.jwks_calls == 2 and len(f.captured) == before


def test_protected_config_and_secret_no_ambient_fallback(tmp_path, monkeypatch):
    home = Path(os.environ["HOME"]).resolve()
    assert tmp_path.resolve().is_relative_to(home)
    monkeypatch.setenv("OV_API_KEY", "ambient-must-not-be-used")
    missing = tmp_path / "missing.key"
    config = Config("https://ov.example/mcp", ISSUER, "https://issuer.example/jwks",
                    "http://backend.example/api/v1", str(missing))
    with pytest.raises(OSError):
        create_app(config)
    missing.write_text("synthetic")
    missing.chmod(0o644)
    with pytest.raises(ValueError):
        create_app(config)
    missing.chmod(0o600)
    link = tmp_path / "linked"
    link.symlink_to(missing)
    with pytest.raises(OSError):
        create_app(Config(config.resource, config.issuer, config.jwks_url, config.backend_url, str(link)))
    for field, value in (("issuer", ISSUER.rstrip("/")), ("jwks_url", "http://issuer.example/jwks"),
                         ("resource", "https://ov.example/mcp/"),
                         ("backend_url", "http://user:password@backend.example/api/v1")):
        values = vars(config) | {field: value}
        with pytest.raises(ValueError):
            Config(**values)
