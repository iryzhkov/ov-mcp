"""Explicit shared-owner personal tools. No resource-policy or ingestion reuse."""
import asyncio
import hashlib
import re
import time

import httpx

from .auth import Refused, contains
from .mutations import Mutations, OperationError, UNKNOWN
from .reader import BudgetExhausted

APPEND_MODE = "existing_only_no_auto_commit"
PERSONAL_BACKEND_REVISION = "7f3faf6982f81116d6626bc7091f87f786a309c7"
PERSONAL_ACTIONS = ("memory.read", "memory.write", "session.read", "session.create", "session.append")
ID = {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"}
URI = {"type": "string", "minLength": 1, "maxLength": 1024}
TEXT = {"type": "string", "maxLength": 16384}
LIMIT = {"type": "integer", "minimum": 1, "maximum": 40}
HASH = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
PERSONAL_SPECS = {
    "personal_memory_browse": ("List direct children of an owned memory directory; bounded incomplete batch.",
                               {"uri": URI, "limit": LIMIT}, []),
    "personal_memory_read": ("Read explicit owned memory content and its byte hash.",
                             {"uri": URI}, ["uri"]),
    "personal_memory_find": ("Find only within explicit owned memory targets; bounded incomplete batch.",
                             {"query": {**TEXT, "minLength": 1, "maxLength": 1024},
                              "targets": {"type": "array", "minItems": 1, "maxItems": 8,
                                          "uniqueItems": True, "items": URI}, "limit": LIMIT}, ["query"]),
    "personal_memory_create": ("Explicit native content create, conditional on absence; no extraction.",
                               {"uri": URI, "content": TEXT}, ["uri", "content"]),
    "personal_memory_replace": ("Explicit native content replace, conditional on byte hash; no extraction.",
                                {"uri": URI, "content": TEXT, "expected_sha256": HASH},
                                ["uri", "content", "expected_sha256"]),
    "personal_session_list": ("List this owner's shared session collection, bounded incomplete batch.",
                              {"limit": LIMIT}, []),
    "personal_session_read": ("Read owned session metadata and bounded context; same-user siblings allowed.",
                              {"session_id": ID}, ["session_id"]),
    "personal_session_create": ("Create a shared owned session with automatic commit explicitly disabled.",
                                {}, []),
    "personal_session_append": ("Append one explicit message to an existing owned session with native locked disabled-policy checks; no automatic commit.",
                                {"session_id": ID, "role": {"enum": ["user", "assistant"]}, "content": TEXT},
                                ["session_id", "role", "content"]),
}
PERSONAL_READ_ONLY = {"personal_memory_browse", "personal_memory_read", "personal_memory_find",
                      "personal_session_list", "personal_session_read"}


def personal_grant(config, claims, subject, scope):
    grant = claims.get("ov_personal")
    if grant is None:
        return None
    if (config.personal_profile != "shared-owner-v1" or subject not in config.personal_subjects
            or not isinstance(grant, dict) or set(grant) != {"account", "user", "actions"}
            or grant["account"] != config.personal_account or grant["user"] != config.personal_user):
        raise Refused()
    actions = grant["actions"]
    if (not isinstance(actions, list) or not actions
            or any(not isinstance(a, str) or a not in PERSONAL_ACTIONS for a in actions)
            or actions != [a for a in PERSONAL_ACTIONS if a in actions]
            or any("ov.personal." + a not in scope.split() for a in actions)):
        raise Refused()
    return (grant["account"], grant["user"], tuple(actions))


class Personal:
    def __init__(self, backend, state):
        self.b = backend
        self.p = backend.principal
        self.m = Mutations(backend, state)
        self.memory_root = f"viking://user/{self.p.personal_user}/memories"
        self.session_root = f"viking://user/{self.p.personal_user}/sessions"

    def authorize(self, action):
        c, p = self.b.config, self.p
        if (c.personal_profile != "shared-owner-v1"
                or c.personal_backend_revision != PERSONAL_BACKEND_REVISION or time.time() >= p.expires
                or p.subject not in c.personal_subjects or not p.personal_user
                or p.personal_account != c.personal_account or p.personal_user != c.personal_user
                or action not in p.personal_actions):
            raise Refused()

    def uri(self, uri, root=None):
        root = self.memory_root if root is None else root
        if (not isinstance(uri, str) or len(uri.encode("utf-8")) > 1024
                or not contains(root, uri)):
            raise Refused()
        tail = uri[len(root):]
        if tail:
            for part in tail[1:].split("/"):
                if (not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}", part)
                        or part.endswith(".") or part in (".", "..")):
                    raise Refused()
        return uri

    def file(self, uri):
        self.uri(uri)
        tail = uri[len(self.memory_root) + 1:].split("/")
        if len(tail) != 2 or not tail[-1].endswith((".md", ".txt")):
            raise Refused()
        return uri

    def sid(self, sid):
        if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", sid):
            raise Refused()
        return sid

    def returned(self, value, depth=0):
        # Check structured references recursively; never reinterpret ordinary prose.
        if depth > 16:
            raise Refused()
        if isinstance(value, dict):
            for k, v in value.items():
                if k in ("account_id", "account") and v != self.p.personal_account:
                    raise Refused()
                if k in ("user_id", "owner") and v != self.p.personal_user:
                    raise Refused()
                if k == "uris" or k.endswith("uri") or k.endswith("_uris"):
                    refs = v if isinstance(v, list) else [v]
                    for ref in refs:
                        if ref:
                            if not isinstance(ref, str):
                                raise Refused()
                            root = self.session_root if contains(self.session_root, ref) else self.memory_root
                            self.uri(ref, root)
                self.returned(v, depth + 1)
        elif isinstance(value, list):
            if len(value) > 256:
                raise Refused()
            for v in value:
                self.returned(v, depth + 1)
        elif isinstance(value, str) and value.startswith("viking://"):
            root = self.session_root if contains(self.session_root, value) else self.memory_root
            self.uri(value, root)

    async def request(self, action, method, endpoint, *, effect=False, **kwargs):
        self.authorize(action)
        value = await self.m.request(method, endpoint, effect=effect,
                                     precondition_conflicts=False, **kwargs)
        self.authorize(action)
        if value is None:
            raise Refused()
        value = value.get("result")
        self.returned(value)
        return value

    def session(self, value, sid=None):
        if not isinstance(value, dict):
            raise Refused()
        ident = self.sid(value.get("session_id"))
        if sid is not None and ident != sid:
            raise Refused()
        if value.get("uri") != self.session_root + "/" + ident:
            raise Refused()
        user = value.get("user")
        if user is not None and (not isinstance(user, dict)
                                 or user.get("user_id") != self.p.personal_user
                                 or user.get("account_id") != self.p.personal_account):
            raise Refused()
        return {"session_id": ident, "uri": value["uri"]}

    async def call(self, name, a):
        if name == "personal_session_append":
            self.authorize("session.append")
            sid = self.sid(a["session_id"])
            if a["role"] not in ("user", "assistant") or len(a["content"].encode()) > 16384:
                raise Refused()
            # No preflight: the native mode checks existence and authoritative
            # disabled policy under the same lock as the message append.
            row = await self.request("session.append", "POST", "/sessions/" + sid + "/messages",
                                     effect=True, json={"role": a["role"], "content": a["content"],
                                                        "append_mode": APPEND_MODE, "telemetry": False})
            if (not isinstance(row, dict) or row.get("session_id") != sid
                    or row.get("append_mode") != APPEND_MODE
                    or row.get("auto_commit_scheduled") is not False
                    or type(row.get("message_count")) is not int
                    or not 1 <= row["message_count"] <= 2**31 - 1
                    or type(row.get("pending_tokens")) is not int
                    or not 0 <= row["pending_tokens"] <= 2**53 - 1):
                raise Refused()
            return {"session_id": sid, "uri": self.session_root + "/" + sid,
                    "outcome": "committed", "append_mode": APPEND_MODE,
                    "auto_commit_scheduled": False, "message_count": row["message_count"],
                    "pending_tokens": row["pending_tokens"]}
        if name == "personal_session_list":
            rows = await self.request("session.read", "GET", "/sessions")
            if not isinstance(rows, list) or len(rows) > 256:
                raise Refused()
            return {"sessions": [self.session(r) for r in rows][:a.get("limit", 40)], "complete": False}
        if name == "personal_session_create":
            # Backend generates ID; caller cannot accidentally overwrite an existing session.
            row = await self.request("session.create", "POST", "/sessions", effect=True,
                                     json={"auto_commit_policy": None, "telemetry": False})
            out = self.session(row)
            if "auto_commit_policy" not in row or row["auto_commit_policy"] is not None:
                raise Refused()
            return {**out, "outcome": "committed", "auto_commit_policy": None}
        if name == "personal_session_read":
            sid = self.sid(a["session_id"])
            row = await self.request("session.read", "GET", "/sessions/" + sid,
                                     params={"auto_create": "false"})
            out = self.session(row, sid)
            context = await self.request("session.read", "GET", "/sessions/" + sid + "/context",
                                         params={"token_budget": 4096})
            return {**out, "context": context}
        uri = self.uri(a.get("uri", self.memory_root))
        limit = a.get("limit", 40)
        if name == "personal_memory_browse":
            rows = await self.request("memory.read", "GET", "/fs/ls",
                                      params={"uri": uri, "simple": "true"})
            if not isinstance(rows, list) or len(rows) > 256:
                raise Refused()
            for child in rows:
                self.uri(child)
                if not child.startswith(uri + "/") or "/" in child[len(uri) + 1:]:
                    raise Refused()
            return {"uris": rows[:limit], "complete": False}
        if name == "personal_memory_read":
            self.file(uri)
            text = await self.request("memory.read", "GET", "/content/read", params={"uri": uri})
            if not isinstance(text, str) or len(text.encode()) > 32768:
                raise Refused()
            return {"uri": uri, "content": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}
        if name == "personal_memory_find":
            targets = a.get("targets", [self.memory_root])
            for target in targets:
                self.uri(target)
            value = await self.request("memory.read", "POST", "/search/find",
                                       json={"query": a["query"], "target_uri": targets,
                                             "context_type": "memory", "limit": limit,
                                             "read_content": False, "include_provenance": False,
                                             "telemetry": False})
            if (not isinstance(value, dict) or value.get("resources") != [] or value.get("skills") != []
                    or not isinstance(value.get("memories"), list) or len(value["memories"]) > limit):
                raise Refused()
            hits = []
            for row in value["memories"]:
                hit = self.uri(row.get("uri"))
                if not any(contains(t, hit) for t in targets):
                    raise Refused()
                hits.append({"uri": hit})
            return {"hits": hits, "complete": False}
        self.file(uri)
        content = a["content"]
        if len(content.encode()) > 16384:
            raise Refused()
        op = {"uri": uri, "content": content}
        if name == "personal_memory_create":
            op.update(mode="create", expected_absent=True)
        elif name == "personal_memory_replace":
            op.update(mode="replace", expected_sha256=a["expected_sha256"])
        else:
            raise Refused()
        result = await self.request("memory.write", "POST", "/content/batch-write", effect=True,
                           json={"root_uri": uri.rsplit("/", 1)[0], "operations": [op],
                                 "wait": False, "skip_conflicts": False, "telemetry": False})
        if not isinstance(result, dict) or result.get("root_uri") != uri.rsplit("/", 1)[0]:
            raise Refused()
        observed = []
        for field in ("created", "updated", "unchanged"):
            rows = result.get(field)
            if not isinstance(rows, list) or len(rows) > 1 or any(row != uri for row in rows):
                raise Refused()
            observed.extend(rows)
        if observed != [uri]:
            raise Refused()
        return {"uri": uri, "outcome": "committed", "indexing": "not_observed"}


async def call_personal(backend, name, arguments, state):
    try:
        async with asyncio.timeout(20):
            return await Personal(backend, state).call(name, arguments), False
    except OperationError as exc:
        return exc.value, True
    except (Refused, BudgetExhausted, httpx.HTTPError, TimeoutError, ValueError, TypeError,
            KeyError, RecursionError):
        return (UNKNOWN if state.get("dispatched") else
                {"error": "Personal operation refused.", "outcome": "not_started"}), True
