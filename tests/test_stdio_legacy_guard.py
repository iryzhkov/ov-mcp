"""The stdio server refuses delete-then-reingest operations on a backend that
cannot take its ingest request, before it changes anything.

OpenViking 0.5.2 answers temp_upload with temp_file_id and rejects temp_path
and timeout on POST /resources. Against it, overwrite, reindex and the default
mv used to delete the note and then fail to write it back. These tests run
server.py against an in-memory fake of both backend shapes, through httpx's
mock transport, so no network, store, key or model is touched.
"""
import importlib
import json
import os
from urllib.parse import parse_qs

import httpx
import pytest

os.environ["OV_BASE_URL"] = "http://ov.invalid"
os.environ["OV_API_KEY"] = "synthetic-key-only"
os.environ["OV_CONFIG"] = os.devnull

server = importlib.import_module("server")

NOTE = "viking://resources/ns/note.md"
CHUNK = NOTE + "/note.md"
OLD_TEXT = "the only copy of this note"


def schema(shape: str) -> dict:
    """An OpenAPI document shaped like the backend's add-resource model."""
    if shape == "v0.5.2":
        model = {"type": "object", "additionalProperties": False, "properties": {
            name: {} for name in ("path", "temp_file_id", "to", "parent", "reason",
                                  "instruction", "wait", "strict")}}
    else:
        model = {"type": "object", "properties": {
            name: {} for name in ("path", "temp_path", "to", "parent", "reason",
                                  "wait", "timeout")}}
    return {"openapi": "3.1.0", "paths": {"/api/v1/resources": {"post": {"requestBody": {
        "content": {"application/json": {"schema": {
            "$ref": "#/components/schemas/AddResourceRequest"}}}}}}},
        "components": {"schemas": {"AddResourceRequest": model}}}


class FakeBackend:
    """A tiny OpenViking: a dict of file URIs to text, directories implied."""

    READS = {("GET", "/openapi.json"), ("GET", "/api/v1/fs/stat"),
             ("GET", "/api/v1/fs/ls"), ("GET", "/api/v1/content/read")}

    def __init__(self, shape: str, openapi_status: int = 200):
        self.shape = shape
        self.openapi_status = openapi_status
        self.files = {CHUNK: OLD_TEXT, "viking://resources/ns/other.md/other.md": "x"}
        self.empty_dirs: set[str] = set()
        self.spec: dict | None = None  # overrides the shape's schema when set
        self.upload_key: str | None = None  # overrides the shape's upload answer
        self.upload_value: object = "upload_1"
        self.calls: list[tuple[str, str]] = []

    @property
    def mutations(self) -> list[tuple[str, str]]:
        return [c for c in self.calls if c not in self.READS]

    def _dirs(self) -> set[str]:
        dirs = set(self.empty_dirs)
        for uri in self.files:
            parts = uri.split("/")
            for i in range(4, len(parts)):
                dirs.add("/".join(parts[:i]))
        return dirs

    @staticmethod
    def ok(result) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok", "result": result})

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        query = {k: v[0] for k, v in parse_qs(request.url.query.decode()).items()}
        uri = query.get("uri", "").rstrip("/")
        if path == "/openapi.json":
            if self.openapi_status != 200:
                return httpx.Response(self.openapi_status, text="not here")
            return httpx.Response(200, json=self.spec or schema(self.shape))
        if path == "/api/v1/fs/stat":
            if uri in self.files:
                return self.ok({"isDir": False, "size": len(self.files[uri])})
            if uri in self._dirs():
                return self.ok({"isDir": True, "size": 0})
            return httpx.Response(404, json={"status": "error"})
        if path == "/api/v1/fs/ls":
            children = sorted({u[: len(uri) + 1] + u[len(uri) + 1:].split("/")[0]
                               for u in list(self.files) + list(self._dirs())
                               if u.startswith(uri + "/")})
            if query.get("simple") == "true":
                return self.ok(children)
            return self.ok([{"uri": c, "isDir": c not in self.files} for c in children])
        if path == "/api/v1/content/read":
            return self.ok(self.files.get(uri, ""))
        if path == "/api/v1/fs" and request.method == "DELETE":
            self.empty_dirs = {d for d in self.empty_dirs
                               if d != uri and not d.startswith(uri + "/")}
            for key in [k for k in self.files if k == uri or k.startswith(uri + "/")]:
                del self.files[key]
            return self.ok({})
        if path == "/api/v1/fs/mv":
            body = json.loads(request.content)
            src, dst = body["from_uri"], body["to_uri"]
            for key in [k for k in self.files if k == src or k.startswith(src + "/")]:
                self.files[dst + key[len(src):]] = self.files.pop(key)
            return self.ok({})
        if path == "/api/v1/resources/temp_upload":
            key = self.upload_key or ("temp_file_id" if self.shape == "v0.5.2" else "temp_path")
            return self.ok({key: self.upload_value})
        if path == "/api/v1/resources":
            body = json.loads(request.content)
            if self.shape == "v0.5.2" and ("temp_path" in body or "timeout" in body):
                return httpx.Response(400, json={"status": "error", "error": {
                    "code": "INVALID_ARGUMENT", "message": "Extra inputs are not permitted"}})
            to = body["to"]
            self.files[to + "/" + to.rsplit("/", 1)[-1]] = "rewritten"
            return self.ok({"root_uri": to})
        return self.ok({})


@pytest.fixture
def backend(request, monkeypatch):
    fake = FakeBackend(*getattr(request, "param", ("v0.5.2",)))
    real_client = httpx.Client

    def client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(fake.handle)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(server.httpx, "Client", client)
    monkeypatch.setattr(server, "_legacy_ingest_cache", None)
    monkeypatch.setattr(server.time, "sleep", lambda _s: None)
    return fake


def assert_refused_untouched(reply: str, fake: FakeBackend) -> None:
    assert reply.startswith("Refused, nothing changed"), reply
    assert "unsupported on this backend" in reply
    assert fake.mutations == []
    assert fake.files[CHUNK] == OLD_TEXT


def test_overwrite_is_refused_before_any_change(backend):
    reply = server.memory_write("new text", "viking://resources/ns", "note.md", overwrite=True)
    assert_refused_untouched(reply, backend)
    assert "temp_path" in reply and "temp_file_id" in reply


def test_verbatim_overwrite_is_refused_before_any_change(backend):
    backend.files = {NOTE + ".verbatim/part-0001-note.md/p.md": OLD_TEXT}
    reply = server.memory_write("new", "viking://resources/ns", "note.md", overwrite=True,
                                verbatim=True)
    assert reply.startswith("Refused, nothing changed"), reply
    assert backend.mutations == []


def test_reindex_is_refused_before_any_change(backend):
    assert_refused_untouched(server.memory_reindex(NOTE), backend)


def test_namespace_reindex_is_refused_before_any_change(backend):
    assert_refused_untouched(server.memory_reindex("viking://resources/ns"), backend)


def test_default_mv_is_refused_before_the_move(backend):
    reply = server.memory_mv(NOTE, "viking://resources/ns/moved.md")
    assert_refused_untouched(reply, backend)
    assert "reindex=False" in reply
    assert "viking://resources/ns/moved.md/note.md" not in backend.files


def test_mv_without_reindex_still_moves(backend):
    reply = server.memory_mv(NOTE, "viking://resources/ns/moved.md", reindex=False)
    assert reply.startswith("Moved "), reply
    assert backend.files["viking://resources/ns/moved.md/note.md"] == OLD_TEXT
    assert ("GET", "/openapi.json") not in backend.calls


def test_reads_and_new_writes_do_not_consult_the_schema(backend):
    assert OLD_TEXT in server.memory_read(NOTE)
    assert "note.md" in server.memory_ls("viking://resources/ns")
    assert backend.mutations == []
    # A plain new write keeps its old behaviour, which on this backend is a
    # failed upload that deletes nothing.
    reply = server.memory_write("fresh", "viking://resources/ns", "fresh.md")
    assert "UPLOAD_FAILED" in reply
    assert backend.files[CHUNK] == OLD_TEXT
    assert ("GET", "/openapi.json") not in backend.calls


@pytest.mark.parametrize("backend", [("classic", 404), ("classic", 500)], indirect=True)
def test_unreadable_schema_fails_closed_and_is_not_cached(backend):
    assert_refused_untouched(server.memory_reindex(NOTE), backend)
    assert server._legacy_ingest_cache is None


def test_overwrite_of_an_empty_directory_is_refused_without_clearing_it(backend):
    empty = "viking://resources/ns/empty.md"
    backend.empty_dirs = {empty}
    reply = server.memory_write("new", "viking://resources/ns", "empty.md", overwrite=True)
    assert reply.startswith("Refused, nothing changed"), reply
    assert backend.mutations == []
    assert backend.empty_dirs == {empty}


def test_plain_write_over_an_empty_directory_keeps_its_old_behaviour(backend):
    backend.empty_dirs = {"viking://resources/ns/empty.md"}
    reply = server.memory_write("new", "viking://resources/ns", "empty.md")
    assert "UPLOAD_FAILED" in reply
    assert ("DELETE", "/api/v1/fs") in backend.mutations
    assert ("GET", "/openapi.json") not in backend.calls


def cyclic_spec() -> dict:
    spec = schema("classic")
    spec["components"]["schemas"] = {
        "A": {"$ref": "#/components/schemas/B"}, "B": {"$ref": "#/components/schemas/A"}}
    spec["paths"]["/api/v1/resources"]["post"]["requestBody"]["content"][
        "application/json"]["schema"] = {"$ref": "#/components/schemas/A"}
    return spec


def model_of(spec: dict) -> dict:
    return spec["components"]["schemas"]["AddResourceRequest"]


def bad_spec(edit) -> dict:
    spec = schema("classic")
    edit(spec)
    return spec


@pytest.mark.parametrize("spec", [
    cyclic_spec(),
    bad_spec(lambda s: s["components"]["schemas"].update(
        AddResourceRequest={"$ref": "#/components/schemas/AddResourceRequest"})),
    bad_spec(lambda s: s["components"]["schemas"]["AddResourceRequest"].update(
        properties=["temp_path", "to", "reason", "wait", "timeout"])),
    bad_spec(lambda s: s["paths"]["/api/v1/resources"]["post"]["requestBody"]["content"][
        "application/json"].update(schema={"$ref": "other.json#/AddResourceRequest"})),
    bad_spec(lambda s: s.update(components=[])),
    bad_spec(lambda s: s.update(paths={})),
    bad_spec(lambda s: model_of(s).update(required="path")),
    bad_spec(lambda s: model_of(s).update(required=["to", 1])),
    bad_spec(lambda s: model_of(s).update(allOf=[{"required": ["path"]}])),
    bad_spec(lambda s: model_of(s)["properties"].update(temp_path=False)),
    bad_spec(lambda s: model_of(s).update(minProperties=1)),
    bad_spec(lambda s: model_of(s).update(additionalProperties={"type": "string"})),
    bad_spec(lambda s: model_of(s).update(type="array")),
    bad_spec(lambda s: model_of(s)["properties"].update(
        temp_path={"type": "string", "pattern": "^/"})),
    bad_spec(lambda s: model_of(s)["properties"].update(to={"enum": ["viking://x"]})),
    bad_spec(lambda s: model_of(s)["properties"].update(
        wait={"$ref": "#/components/schemas/AddResourceRequest"})),
    bad_spec(lambda s: model_of(s)["properties"].update(
        reason={"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]})),
    bad_spec(lambda s: model_of(s)["properties"].update(timeout={"type": 5})),
])
def test_malformed_or_cyclic_schema_fails_closed_and_is_not_cached(backend, spec):
    backend.spec = spec
    assert_refused_untouched(server.memory_reindex(NOTE), backend)
    assert "does not describe" in server.memory_reindex(NOTE)
    assert server._legacy_ingest_cache is None


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
def test_a_required_field_the_legacy_body_omits_is_refused(backend):
    spec = schema("classic")
    model_of(spec).update(required=["path"])
    backend.spec = spec
    for reply in (server.memory_reindex(NOTE),
                  server.memory_mv(NOTE, "viking://resources/ns/moved.md"),
                  server.memory_write("new", "viking://resources/ns", "note.md",
                                      overwrite=True)):
        assert reply.startswith("Refused, nothing changed"), reply
        assert "requires path" in reply
    assert backend.mutations == []
    assert backend.files[CHUNK] == OLD_TEXT


REF = "#/components/schemas/AddResourceRequest"


def body_schema(spec: dict, value: dict) -> dict:
    spec["paths"]["/api/v1/resources"]["post"]["requestBody"]["content"][
        "application/json"]["schema"] = value
    return spec


def component_ref_sibling(spec: dict) -> None:
    spec["components"]["schemas"]["Wrapper"] = {"$ref": REF, "required": ["path"]}
    body_schema(spec, {"$ref": "#/components/schemas/Wrapper"})


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
@pytest.mark.parametrize("spec", [
    bad_spec(lambda s: body_schema(s, {"$ref": REF, "allOf": [{"required": ["path"]}]})),
    bad_spec(lambda s: body_schema(s, {"$ref": REF, "required": ["path"]})),
    bad_spec(component_ref_sibling),
])
def test_ref_with_sibling_constraints_is_refused_before_any_change(backend, spec):
    backend.spec = spec
    for reply in (server.memory_reindex(NOTE),
                  server.memory_mv(NOTE, "viking://resources/ns/moved.md"),
                  server.memory_write("new", "viking://resources/ns", "note.md",
                                      overwrite=True)):
        assert reply.startswith("Refused, nothing changed"), reply
        assert "does not describe" in reply
    assert backend.mutations == []
    assert backend.files[CHUNK] == OLD_TEXT
    assert server._legacy_ingest_cache is None


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
@pytest.mark.parametrize("field, value", [
    ("wait", {"type": "string"}),
    ("temp_path", {"anyOf": [{"type": "integer"}, {"type": "null"}]}),
    ("timeout", {"type": "string", "title": "Timeout"}),
    ("to", {"type": ["array", "null"]}),
])
def test_a_legacy_field_typed_against_the_sent_value_is_refused(backend, field, value):
    spec = schema("classic")
    model_of(spec)["properties"][field] = value
    backend.spec = spec
    reply = server.memory_reindex(NOTE)
    assert_refused_untouched(reply, backend)
    assert f"types {field} differently" in reply


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
def test_a_typed_compatible_schema_still_passes(backend):
    spec = schema("classic")
    model_of(spec).update(title="AddResourceRequest", description="Legacy body.",
                          additionalProperties=False, required=["to"])
    model_of(spec)["properties"].update(
        temp_path={"anyOf": [{"type": "string"}, {"type": "null"}], "title": "Temp Path"},
        to={"type": "string", "title": "To"},
        reason={"type": "string", "default": "", "title": "Reason"},
        wait={"type": "boolean", "default": False},
        timeout={"anyOf": [{"type": "number"}, {"type": "null"}], "default": None},
        path={"pattern": "ignored because the legacy body never sends path"})
    backend.spec = spec
    assert server._legacy_ingest_problem() is None
    assert server.memory_reindex(NOTE) == "Reindexed 1 document(s)."


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
def test_required_fields_the_legacy_body_sends_still_pass(backend):
    spec = schema("classic")
    model_of(spec).update(required=["temp_path", "to"], additionalProperties=False)
    backend.spec = spec
    assert server.memory_reindex(NOTE) == "Reindexed 1 document(s)."


BAD_UPLOADS = [None, "", "   ", 7, ["upload_1"], {"path": "upload_1"}]


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
@pytest.mark.parametrize("value", BAD_UPLOADS)
def test_unusable_temp_path_stops_overwrite_before_the_delete(backend, value):
    backend.upload_value = value
    reply = server.memory_write("new", "viking://resources/ns", "note.md", overwrite=True)
    assert reply.startswith("Overwrite aborted, nothing changed"), reply
    assert backend.mutations == [("POST", "/api/v1/resources/temp_upload")]
    assert backend.files[CHUNK] == OLD_TEXT


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
@pytest.mark.parametrize("value", BAD_UPLOADS)
def test_unusable_temp_path_stops_reindex_before_the_delete(backend, value):
    backend.upload_value = value
    assert server.memory_reindex(NOTE).startswith("Reindexed 0")
    assert backend.mutations == [("POST", "/api/v1/resources/temp_upload")]
    assert backend.files[CHUNK] == OLD_TEXT
    # The move itself still happens; its re-ingest must not delete the moved note.
    reply = server.memory_mv(NOTE, "viking://resources/ns/moved.md")
    assert reply.count("Could not re-ingest") == 1, reply
    assert ("POST", "/api/v1/resources") not in backend.mutations
    assert backend.files["viking://resources/ns/moved.md/note.md"] == OLD_TEXT


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
@pytest.mark.parametrize("value", BAD_UPLOADS)
def test_unusable_temp_path_never_reaches_ingest_on_a_new_write(backend, value):
    backend.upload_value = value
    reply = server.memory_write("new", "viking://resources/ns", "fresh.md")
    assert "UPLOAD_FAILED" in reply
    assert ("POST", "/api/v1/resources") not in backend.mutations


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
def test_a_pass_is_rechecked_by_every_destructive_call(backend):
    server.memory_reindex(NOTE)
    server.memory_reindex(NOTE)
    assert backend.calls.count(("GET", "/openapi.json")) == 2
    assert server._legacy_ingest_cache is None


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
def test_namespace_reindex_checks_once_for_the_whole_call(backend):
    reply = server.memory_reindex("viking://resources/ns")
    assert reply == "Reindexed 2 document(s).", reply
    assert backend.calls.count(("GET", "/openapi.json")) == 1


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
def test_backend_swapped_to_incompatible_in_the_same_process_is_refused(backend):
    assert server.memory_reindex(NOTE) == "Reindexed 1 document(s)."
    backend.shape = "v0.5.2"
    backend.files[CHUNK] = OLD_TEXT
    before = list(backend.mutations)
    for reply in (server.memory_reindex(NOTE),
                  server.memory_mv(NOTE, "viking://resources/ns/moved.md"),
                  server.memory_write("new", "viking://resources/ns", "note.md",
                                      overwrite=True)):
        assert reply.startswith("Refused, nothing changed"), reply
    assert backend.mutations == before
    assert backend.files[CHUNK] == OLD_TEXT


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
def test_overwrite_stages_the_new_text_before_it_deletes(backend):
    # A schema that accepts the legacy body does not prove the upload answers
    # with temp_path; when it does not, the old note must stay.
    backend.upload_key = "temp_file_id"
    reply = server.memory_write("new", "viking://resources/ns", "note.md", overwrite=True)
    assert reply.startswith("Overwrite aborted, nothing changed"), reply
    assert backend.mutations == [("POST", "/api/v1/resources/temp_upload")]
    assert backend.files[CHUNK] == OLD_TEXT


def test_incompatibility_is_cached_for_a_bounded_time(backend, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(server.time, "monotonic", lambda: clock[0])
    server.memory_reindex(NOTE)
    server.memory_reindex(NOTE)
    assert backend.calls.count(("GET", "/openapi.json")) == 1
    clock[0] += server.LEGACY_INGEST_TTL + 1
    server.memory_reindex(NOTE)
    assert backend.calls.count(("GET", "/openapi.json")) == 2


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
def test_classic_backend_still_reindexes(backend):
    assert server._legacy_ingest_problem() is None
    reply = server.memory_reindex(NOTE)
    assert reply == "Reindexed 1 document(s).", reply
    assert ("POST", "/api/v1/resources") in backend.mutations
    assert backend.files[CHUNK] == "rewritten"


@pytest.mark.parametrize("backend", [("classic",)], indirect=True)
def test_classic_backend_still_overwrites(backend):
    reply = server.memory_write("new text", "viking://resources/ns", "note.md",
                                overwrite=True, verify=False)
    assert reply.startswith("Stored "), reply


def test_reingest_uploads_before_it_deletes(backend, monkeypatch):
    # Even if the schema check were wrong, an upload answer without temp_path
    # now stops the reingest before the purge.
    monkeypatch.setattr(server, "_legacy_ingest_problem", lambda: None)
    assert server.memory_reindex(NOTE).startswith("Reindexed 0")
    assert backend.mutations == [("POST", "/api/v1/resources/temp_upload")]
    assert backend.files[CHUNK] == OLD_TEXT
