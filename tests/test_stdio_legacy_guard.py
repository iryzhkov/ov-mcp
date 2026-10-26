"""Overwrite, reindex and a move with reindex=True are temporarily disabled.

Each deleted a note and then re-ingested it, and the OpenViking 0.5.2 backend
rejects the ingest request server.py sends, so each lost the note. They now
refuse before any backend call. These tests run server.py against an
in-memory fake through httpx's mock transport, so no network, store, key or
model is touched, and check that the blocked calls send no request at all and
that reads, plain writes and moves without reindex still work.
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

NS = "viking://resources/ns"
NOTE = NS + "/note.md"
CHUNK = NOTE + "/note.md"
OLD_TEXT = "the only copy of this note"
MOVED = NS + "/moved.md"


class FakeBackend:
    """A tiny OpenViking: a dict of file URIs to text, directories implied."""

    READS = {"/api/v1/fs/stat", "/api/v1/fs/ls", "/api/v1/content/read"}

    def __init__(self):
        self.files = {CHUNK: OLD_TEXT}
        self.calls: list[tuple[str, str]] = []

    @property
    def mutations(self) -> list[tuple[str, str]]:
        return [c for c in self.calls if c[1] not in self.READS]

    def _dirs(self) -> set[str]:
        return {"/".join(uri.split("/")[:i]) for uri in self.files
                for i in range(4, len(uri.split("/")))}

    @staticmethod
    def ok(result) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok", "result": result})

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        query = {k: v[0] for k, v in parse_qs(request.url.query.decode()).items()}
        uri = query.get("uri", "").rstrip("/")
        if path == "/api/v1/fs/stat":
            if uri in self.files:
                return self.ok({"isDir": False, "size": len(self.files[uri])})
            if uri in self._dirs():
                return self.ok({"isDir": True, "size": 0})
            return httpx.Response(404, json={"status": "error"})
        if path == "/api/v1/fs/ls":
            children = sorted({uri + "/" + u[len(uri) + 1:].split("/")[0]
                               for u in list(self.files) + list(self._dirs())
                               if u.startswith(uri + "/")})
            if query.get("simple") == "true":
                return self.ok(children)
            return self.ok([{"uri": c, "isDir": c not in self.files} for c in children])
        if path == "/api/v1/content/read":
            return self.ok(self.files.get(uri, ""))
        if path == "/api/v1/fs" and request.method == "DELETE":
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
            return self.ok({"temp_path": "upload_1"})
        if path == "/api/v1/resources":
            to = json.loads(request.content)["to"]
            self.files[to + "/" + to.rsplit("/", 1)[-1]] = "stored"
            return self.ok({"root_uri": to})
        return self.ok({})


@pytest.fixture
def backend(monkeypatch):
    fake = FakeBackend()
    real_client = httpx.Client

    def client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(fake.handle)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(server.httpx, "Client", client)
    monkeypatch.setattr(server.time, "sleep", lambda _s: None)
    return fake


BLOCKED = {
    "overwrite": lambda: server.memory_write("new", NS, "note.md", overwrite=True),
    "verbatim overwrite": lambda: server.memory_write("new", NS, "note.md", overwrite=True,
                                                      verbatim=True),
    "overwrite, invalid scope": lambda: server.memory_write("new", "viking://user/x", "n.md",
                                                            overwrite=True),
    "overwrite, empty target": lambda: server.memory_write("", "", "", overwrite=True),
    "reindex note": lambda: server.memory_reindex(NOTE),
    "reindex namespace, force": lambda: server.memory_reindex(NS, force=True),
    "reindex, invalid scope": lambda: server.memory_reindex("viking://agent/x"),
    "reindex, empty target": lambda: server.memory_reindex(""),
    "default mv": lambda: server.memory_mv(NOTE, MOVED),
    "mv reindex=True": lambda: server.memory_mv(NOTE, MOVED, reindex=True),
    "mv, invalid scope": lambda: server.memory_mv("viking://user/a", "viking://user/b"),
    "mv, empty target": lambda: server.memory_mv("", ""),
}


@pytest.mark.parametrize("name", BLOCKED)
def test_blocked_operations_send_no_backend_request(backend, name):
    reply = BLOCKED[name]()
    assert "temporarily disabled; nothing changed" in reply, reply
    assert "not yet available" in reply
    assert backend.calls == []
    assert backend.files == {CHUNK: OLD_TEXT}


def test_the_delete_then_reingest_helper_is_gone():
    assert not hasattr(server, "_reingest")


def test_read_is_unaffected(backend):
    assert OLD_TEXT in server.memory_read(NOTE)
    assert "note.md" in server.memory_ls(NS)
    assert backend.mutations == []


def test_move_without_reindex_still_moves(backend):
    reply = server.memory_mv(NOTE, MOVED, reindex=False)
    assert reply.startswith(f"Moved {NOTE} -> {MOVED}."), reply
    assert "Not re-ingested" in reply
    assert backend.files[MOVED + "/note.md"] == OLD_TEXT
    assert CHUNK not in backend.files
    assert ("POST", "/api/v1/resources") not in backend.mutations


def test_plain_new_write_still_writes(backend):
    reply = server.memory_write("fresh", NS, "fresh.md", verify=False)
    assert reply == f"Stored {NS}/fresh.md.", reply
    assert ("POST", "/api/v1/resources") in backend.mutations
    assert backend.files[CHUNK] == OLD_TEXT


def test_plain_write_onto_an_existing_note_refuses_without_change(backend):
    reply = server.memory_write("new", NS, "note.md")
    assert reply.startswith(f"Refused: {NOTE} already exists."), reply
    assert backend.mutations == []
    assert backend.files[CHUNK] == OLD_TEXT


def test_mkdir_is_unaffected(backend):
    server.memory_mkdir(NS + "/sub")
    assert backend.calls == [("POST", "/api/v1/fs/mkdir")]
