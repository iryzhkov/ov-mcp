"""Default-off, closed resources document maintenance operations.

This module never imports stdio ingestion or exposes arbitrary REST forwarding.
"""
import asyncio
import base64
import hashlib
import re
import time

import httpx

from .auth import Refused, contains, strict_json
from .reader import Backend, BudgetExhausted, DOC_EXTS

PROFILE = "resources-document-mutations-v1"
CONTRACT_PATH = "/fs/resources-only/mutation-contract"
CONTRACT = {"contract": "resources-document-mutations", "version": 1}
DOCUMENT_WRITE_SECONDS = 130
LONG_MUTATION_SECONDS = 70
LONG_MUTATION_NAMES = frozenset({"memory_mv", "memory_reindex"})
LONG_MUTATION_ENDPOINTS = frozenset({"/fs/mv", "/content/reindex"})
UNKNOWN = {"error": "Outcome unknown after dispatch. Do not retry automatically.",
           "outcome": "unknown", "retry_safe": False}
URI = {"type": "string", "minLength": 1, "maxLength": 1024}
BOOL = {"type": "boolean"}
MUTATION_SPECS = {
    "memory_write": (
        "Conditional document publication with observed typed revisions and retained protected backups. "
        "Processing acceptance is not revision-bound indexing. Explicit file-deferred-v1 stays deferred. "
        "dry_run=true checks preflight without dispatch; it never reserves a revision. "
        "storage=exact-directory-v2 replaces an existing directory at its original URI byte for byte.",
        {"text": {"type": "string", "maxLength": 1048576}, "to": URI, "filename": URI,
         "reason": {"type": "string", "maxLength": 1024}, "overwrite": BOOL, "archived": BOOL,
         "verbatim": BOOL, "verify": BOOL, "dry_run": BOOL,
         "storage": {"type": "string", "enum": ["legacy-chunked", "file-deferred-v1", "exact-directory-v2"]},
         "expected_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}},
        ["text", "to", "filename"]),
    "memory_mkdir": ("Create one exact directory and its authorized abstract beneath an existing parent. "
                     "Completion of indexing is not observed.",
                     {"uri": URI, "description": {"type": "string", "maxLength": 4096}}, ["uri"]),
    "memory_mv": ("No-clobber native move. Default reindex=true means vector transfer and tracked parent repair, "
                  "not target re-ingestion. Explicit false is unsupported. Ancestor authority is required.",
                  {"from_uri": URI, "to_uri": URI, "reindex": BOOL}, ["from_uri", "to_uri"]),
    "memory_rm": ("Remove resources only. No extracted-memory cleanup. Dry run is a bounded current plan.",
                  {"uri": URI, "recursive": BOOL, "dry_run": BOOL}, ["uri"]),
    "memory_reindex": ("Fresh vectors-only native reindex; mixed semantic/parent plans refuse. "
                       "Completion is not bound to a requested content revision.",
                       {"uri": URI, "force": BOOL}, ["uri"]),
    "memory_index_prune": ("Prune only the exact authorized absent URI. No descendant-orphan sweep.",
                           {"uri": URI, "dry_run": BOOL}, ["uri"]),
    "memory_index_audit": ("Bounded scoped document candidates and exact existence validation. "
                           "Reports omitted L0/L1 metadata hits. fix prunes proven absent documents only.",
                           {"query": {"type": "string", "minLength": 1, "maxLength": 1024},
                            "scope": URI, "limit": {"type": "integer", "minimum": 1, "maximum": 40},
                            "fix": BOOL}, ["query"]),
    "memory_status": ("Scoped document-service status. No native Task records, global counts or backend identity.",
                      {"uri": URI}, []),
}
READ_ONLY = {"memory_status"}


class OperationError(Exception):
    def __init__(self, value):
        self.value = value


def unsupported(detail):
    raise OperationError({"error": detail, "outcome": "not_started", "supported": False})


class Mutations:
    """One per call, sharing Reader's Backend, principal, transport and budgets."""
    def __init__(self, backend: Backend, state=None):
        self.backend = backend
        self.p = backend.principal
        self.state = {} if state is None else state
        self.kinds = {}
        self.metadata_owner = {}

    def authorize(self, action, *uris, strict=False):
        self.p.require_action(action, *uris)
        for uri in uris:
            # The read policy permits spaces; write normalization changes them.
            # Refuse rather than reproducing native sanitization.
            if uri == "viking://resources":
                raise Refused()
            if any(part in {".abstract.md", ".overview.md"} for part in uri.split("/")):
                raise Refused()
            if strict and any(c.isspace() for c in uri):
                raise Refused()

    async def request(self, method, endpoint, *, effect=False, precondition_conflicts=True,
                      error_projection=None, **kwargs):
        b = self.backend
        if self.state.get("document_dry_run") and (effect or method != "GET"):
            raise Refused()
        b.check_budget()
        b.requests += 1
        if effect:
            self.state["dispatched"] = True
            if method == "POST" and endpoint == "/resources/document-write":
                # Measured native preparation exceeded 60s; finite headroom only.
                kwargs["timeout"] = httpx.Timeout(120, connect=5, pool=5, write=5)
            elif endpoint in LONG_MUTATION_ENDPOINTS:
                # Allow bounded observation of slow native commits, below the
                # authority-bound outer cap. This is no completion guarantee.
                kwargs["timeout"] = httpx.Timeout(60, connect=5, pool=5)
        async with b.client.stream(method, b.config.backend_url + endpoint, **kwargs) as response:
            if response.headers.get("content-encoding", "identity") != "identity":
                raise Refused()
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw) > 262144:
                    raise Refused()
            status = response.status_code
        b.bytes += len(raw)
        value = strict_json(bytes(raw))
        if not isinstance(value, dict):
            raise Refused()
        if status == 200 and value.get("status") == "ok":
            return value
        error = value.get("error")
        if not isinstance(error, dict) or value.get("status") != "error":
            raise Refused()
        code = error.get("code")
        details = error.get("details")
        if (not effect and not self.state.get("dispatched")
                and not self.state.get("effects_confirmed")
                and not self.state.get("document_committed")
                and status == 409 and code == "CONFLICT"
                and isinstance(details, dict) and details.get("conflict_type") == "path_busy"):
            # This observation did not dispatch a mutation. Never expose the
            # upstream message, path or lock owner, and never retry here.
            raise OperationError({"error": "Resource is busy; no mutation dispatched.",
                                  "outcome": "not_started", "busy": True, "retry_safe": False})
        if error_projection is not None and (effect or self.state.get("document_dry_run")):
            error_projection(status, error)
        if not effect and status == 404 and code == "NOT_FOUND":
            return None
        if (effect and precondition_conflicts and status == 409
                and code in {"CONFLICT", "ALREADY_EXISTS", "WRITE_CONFLICT"}):
            # These conditional endpoints reject preconditions before commit.
            details = error.get("details")
            if isinstance(details, dict) and details.get("outcome") == "unknown":
                raise Refused()
            self.state["dispatched"] = False
            raise OperationError({"error": "Precondition conflict; no change committed.",
                                  "outcome": "not_started", "conflict": True})
        raise Refused()

    async def contract(self):
        self.p.require_action("read")
        value = await self.request("GET", CONTRACT_PATH)
        if (not isinstance(value, dict) or value.get("result") != CONTRACT
                or type(value["result"].get("version")) is not int):
            unsupported("Required document mutation contract unavailable.")
        self.p.require_action("read")

    async def dispatch(self, endpoint, payload, checks, *, precondition_conflicts=True):
        # No shared capability cache and no blind retries, even after a timeout.
        await self.contract()
        for action, uri in checks:
            self.p.require_action(action, uri)
        value = await self.request("POST", endpoint, effect=True,
                                   precondition_conflicts=precondition_conflicts, json=payload)
        if not isinstance(value, dict):
            raise Refused()
        self.state["effects_confirmed"] = True
        return value.get("result")

    async def stat(self, uri):
        self.p.require_action("read", uri)
        value = await self.request("GET", "/fs/stat", params={"uri": uri})
        self.p.require_action("read", uri)
        if value is None:
            return None
        row = value.get("result")
        if (not isinstance(row, dict) or row.get("uri") != uri
                or type(row.get("isDir")) is not bool
                or type(row.get("size", 0)) is not int or not 0 <= row.get("size", 0) <= 2**53):
            raise Refused()
        self.kinds[uri] = row["isDir"]
        return {"uri": uri, "isDir": row["isDir"], "size": row.get("size", 0)}

    async def existing_parent(self, uri, action):
        parent = uri.rsplit("/", 1)[0]
        self.p.require_action(action, parent)
        row = await self.stat(parent)
        if row is None or not row["isDir"]:
            unsupported("An existing authorized parent directory is required.")
        return parent

    async def subtree(self, uri, action, *, relations_sidecar=False):
        """Validate every original row, including hidden names and denied placeholders."""
        nodes, pending = [uri], [(uri, 0)]
        while pending:
            parent, depth = pending.pop()
            self.p.require_action(action, parent)
            page = await self.request("GET", "/fs/ls", params={
                "uri": parent, "simple": "false", "recursive": "false", "output": "original",
                "show_all_hidden": "true", "include_abstract": "false", "include_overview": "false",
                "include_tags": "false", "node_limit": 129, "offset": 0})
            if not isinstance(page, dict):
                raise Refused()
            rows = page.get("result")
            if (not isinstance(rows, list) or len(rows) > 128 or page.get("has_more") is not False):
                raise BudgetExhausted()
            for row in rows:
                if (not isinstance(row, dict) or type(row.get("isDir")) is not bool
                        or row.get("access") == "denied"):
                    raise Refused()
                child = row.get("uri")
                if not isinstance(child, str):
                    raise Refused()
                if relations_sidecar and child == parent + "/.relations.json":
                    # Private physical metadata is preserved only by document writes.
                    # The traversed parent is already canonical and authorized.
                    if row["isDir"] is not False or len(child.encode("utf-8")) > 1024 or child in nodes:
                        raise Refused()
                    nodes.append(child)
                    self.kinds[child] = False
                    self.metadata_owner[child] = parent
                    if len(nodes) > 128:
                        raise BudgetExhausted()
                    continue
                if (relations_sidecar and child.rsplit("/", 1)[-1].startswith(".")
                        and child.rsplit("/", 1)[-1] not in {".abstract.md", ".overview.md"}):
                    raise Refused()
                self.p.require_action(action, child)
                if (not contains(parent, child) or child == parent
                        or "/" in child[len(parent) + 1:] or child in nodes):
                    raise Refused()
                nodes.append(child)
                self.kinds[child] = row["isDir"]
                if len(nodes) > 128:
                    raise BudgetExhausted()
                if row["isDir"]:
                    if depth >= 11:
                        raise BudgetExhausted()
                    pending.append((child, depth + 1))
        return nodes

    async def write(self, a):
        if type(a.get("dry_run", False)) is not bool:
            raise Refused()
        if a.get("dry_run") and a.get("storage", "legacy-chunked") not in {"legacy-chunked", "exact-directory-v2"}:
            unsupported("Dry run supports default document writes only; no mutation dispatched.")
        if a.get("storage", "legacy-chunked") in {"legacy-chunked", "exact-directory-v2"}:
            from .document_write import DocumentWriter
            return await DocumentWriter(self).write(a)
        if a.get("storage") != "file-deferred-v1":
            raise Refused()
        to = a["to"]
        self.authorize("write", to, strict=True)
        filename = a["filename"]
        if "/" in filename:
            raise Refused()
        # Validate the supplied leaf before extension composition too. Reserved
        # control names must never be turned into ordinary document spellings.
        self.authorize("write", to + "/" + filename, strict=True)
        if not filename.endswith(DOC_EXTS):
            filename += ".md"
        if a.get("archived", False) and not set(to.split("/")) & {"archive", "archived", "_archive"}:
            to += "/archive"
        target = to + "/" + filename
        self.authorize("write", to, target, strict=True)
        if (a.get("storage", "legacy-chunked") != "file-deferred-v1"
                or a.get("verbatim", False) or a.get("reason", "")):
            unsupported("Legacy ingestion, verbatim storage and reason metadata are unqualified. "
                        "Explicit file-deferred-v1 supports plain file content only.")
        overwrite = a.get("overwrite", False)
        expected = a.get("expected_sha256")
        if overwrite != (expected is not None):
            unsupported("overwrite=true requires expected_sha256; create must omit it.")
        raw = a["text"].encode("utf-8")
        if len(raw) > 16384:
            raise Refused()
        parent = await self.existing_parent(target, "write")
        current = await self.stat(target)
        if current is not None and current["isDir"]:
            unsupported("Legacy directory or chunked-document replacement is unqualified.")
        operation = {"uri": target, "content_base64": base64.b64encode(raw).decode(),
                     "mode": "replace" if overwrite else "create"}
        operation.update({"expected_sha256": expected} if overwrite else {"expected_absent": True})
        value = await self.dispatch("/content/batch-write", {
            "root_uri": parent, "operations": [operation], "wait": True, "telemetry": False,
            "skip_conflicts": False, "defer_processing": True, "edit_source": "agent"},
            [("write", parent), ("write", target)])
        key = "updated" if overwrite else "created"
        if (not isinstance(value, dict) or value.get("root_uri") != parent
                or value.get(key) != [target] or value.get("created" if overwrite else "updated") != []
                or value.get("unchanged") != [] or value.get("semantic_status") != "deferred"
                or value.get("vector_status") != "deferred"):
            raise Refused()
        self.state["committed"] = True
        answer = {"uri": target, "outcome": "committed", "indexing": "deferred",
                  "searchable_completion": False, "sha256": hashlib.sha256(raw).hexdigest(),
                  "verification": "not_requested", "retry_safe": False}
        if a.get("verify", True):
            # Exactly one read. A verification failure cannot undo a known content commit.
            try:
                self.p.require_action("read", target)
                text = await self.backend.text(target)
                answer["verification"] = "exact" if text.encode("utf-8") == raw else "mismatch"
            except (Refused, BudgetExhausted, httpx.HTTPError, ValueError, TypeError):
                answer["verification"] = "unavailable"
        return answer

    async def mkdir(self, a):
        uri = a["uri"]
        self.authorize("write", uri, strict=True)
        if uri in self.p.roots or set(a) - {"uri", "description"}:
            raise Refused()
        abstract = uri + "/.abstract.md"
        self.p.require_action("write", uri.rsplit("/", 1)[0], abstract)
        payload = {"uri": uri}
        if "description" in a:
            description = a["description"]
            if not isinstance(description, str) or len(description.encode("utf-8")) > 4096:
                raise Refused()
            payload["description"] = description
        parent = await self.existing_parent(uri, "write")
        if await self.stat(uri) is not None:
            raise OperationError({"error": "Target exists; no change dispatched.", "outcome": "not_started",
                                  "conflict": True})
        value = await self.dispatch("/fs/mkdir", payload,
                                    [("write", parent), ("write", uri), ("write", abstract)])
        if not isinstance(value, dict) or value.get("uri") != uri:
            raise Refused()
        self.state["mkdir_committed"] = True
        return {"uri": uri, "outcome": "committed", "resource_type": "directory",
                "indexing": "not_observed", "searchable_completion": False, "retry_safe": False}

    def ancestor_checks(self, uri):
        checks, parent = [], uri.rsplit("/", 1)[0]
        while True:
            if len(checks) >= 108:
                raise BudgetExhausted()
            for action in ("read", "write", "maintain"):
                for path in (parent, parent + "/.abstract.md", parent + "/.overview.md"):
                    self.p.require_action(action, path)
                    checks.append((action, path))
            if parent == "viking://resources":
                return checks
            parent = parent.rsplit("/", 1)[0]

    async def move(self, a):
        source, target = a["from_uri"], a["to_uri"]
        self.authorize("read", source, strict=True)
        self.authorize("write", source, target, strict=True)
        self.authorize("remove", source, strict=True)
        if (source in self.p.roots or target in self.p.roots
                or contains(source, target) or contains(target, source)):
            raise Refused()
        if a.get("reindex", True) is not True:
            unsupported("reindex=false cannot suppress native parent repair; no move dispatched.")
        # Parent refresh can propagate upward in the original tracked Work.
        # Refuse narrow grants before even observing a resource.
        checks = self.ancestor_checks(source) + self.ancestor_checks(target)
        checks += [("read", source), ("write", source), ("remove", source),
                   ("maintain", source), ("write", target), ("maintain", target)]
        for action, path in checks:
            self.p.require_action(action, path)
        await self.existing_parent(source, "write")
        await self.existing_parent(target, "write")
        row = await self.stat(source)
        if row is None:
            raise OperationError({"error": "Source not found.", "outcome": "not_started"})
        if await self.stat(target) is not None:
            raise OperationError({"error": "Destination exists; no move dispatched.",
                                  "outcome": "not_started", "conflict": True})
        nodes = await self.subtree(source, "read") if row["isDir"] else [source]
        for path in nodes:
            destination = target + path[len(source):]
            if any(c.isspace() for c in path):
                raise Refused()
            for action in ("read", "write", "remove", "maintain"):
                self.p.require_action(action, path)
                checks.append((action, path))
            for action in ("write", "maintain"):
                self.p.require_action(action, destination)
                checks.append((action, destination))
        value = await self.dispatch("/fs/mv",
            {"from_uri": source, "to_uri": target, "no_replace": True},
            checks, precondition_conflicts=False)
        if (not isinstance(value, dict) or value.get("from") != source or value.get("to") != target
                or value.get("no_replace") is not True):
            raise Refused()
        self.state["move_committed"] = True
        return {"from_uri": source, "to_uri": target, "outcome": "committed",
                "no_replace": True, "index_repair": "native_transfer_and_parent_refresh",
                "indexing": "not_observed", "target_reingested": False,
                "searchable_completion": False, "retry_safe": False}

    async def reindex(self, a):
        uri = a["uri"]
        self.authorize("maintain", uri, strict=True)
        self.p.require_action("read", uri)
        row = await self.stat(uri)
        if row is None:
            raise OperationError({"error": "Resource not found.", "outcome": "not_started"})
        nodes = await self.subtree(uri, "maintain") if row["isDir"] else [uri]
        checks = []
        for path in nodes:
            for action in ("read", "maintain"):
                self.p.require_action(action, path)
                checks.append((action, path))
        # File RFV planning reads its parent's overview for L2 summary reuse.
        # Directory plans may read each directory's own metadata.
        for path in nodes:
            if self.kinds.get(path):
                for sidecar in (path + "/.abstract.md", path + "/.overview.md"):
                    for action in ("read", "maintain"):
                        self.p.require_action(action, sidecar)
                        checks.append((action, sidecar))
        if not row["isDir"]:
            parent = uri.rsplit("/", 1)[0]
            for path in (parent, parent + "/.overview.md"):
                self.p.require_action("read", path)
                checks.append(("read", path))
        value = await self.dispatch("/content/reindex",
            {"uri": uri, "mode": "vectors_only", "wait": True, "recursive": True,
             "force": a.get("force", False)}, checks, precondition_conflicts=False)
        if (not isinstance(value, dict) or value.get("uri") != uri
                or value.get("mode") != "vectors_only" or value.get("status") != "completed"
                or value.get("object_type") != "resource"):
            raise Refused()
        keys = ("scanned_records", "rebuilt_records", "deleted_records",
                "unsupported_records", "failed_records")
        if any(type(value.get(key)) is not int or not 0 <= value[key] <= 2**31 - 1 for key in keys):
            raise Refused()
        warnings = value.get("warnings")
        if (not isinstance(warnings, list) or len(warnings) > 128
                or any(not isinstance(warning, str) or len(warning) > 8192 for warning in warnings)):
            raise Refused()
        partial = bool(value["failed_records"] or value["unsupported_records"] or warnings)
        answer = {"uri": uri, "outcome": "completed_with_issues" if partial else "completed",
                  "mode": "vectors_only", "indexing": "partial" if partial else "completed",
                  "counters": {key: value[key] for key in keys}, "warnings_present": bool(warnings),
                  "content_revision_bound": False, "retry_safe": False}
        self.state["reindex_completed"] = answer["indexing"]
        return answer

    async def remove(self, a, *, prune=False):
        uri = a["uri"]
        action = "maintain" if prune else "remove"
        self.authorize(action, uri, strict=True)
        row = await self.stat(uri)
        if prune:
            if row is not None:
                raise OperationError({"error": "Exact URI exists; pruning refused.", "outcome": "not_started"})
            nodes = [uri]
        else:
            if row is None:
                raise OperationError({"error": "Resource not found.", "outcome": "not_started"})
            if row["isDir"] and not a.get("recursive", False):
                unsupported("Directory removal requires recursive=true.")
            nodes = await self.subtree(uri, action) if row["isDir"] else [uri]
        checks = [(action, path) for path in nodes]
        if a.get("dry_run", False):
            return {"uri": uri, "outcome": "dry_run", "paths": nodes, "snapshot": False,
                    "recursive": False if prune else a.get("recursive", False)}
        endpoint = "/fs/resources-only/" + ("prune-index" if prune else "remove")
        payload = {"uri": uri} if prune else {"uri": uri, "recursive": a.get("recursive", False)}
        value = await self.dispatch(endpoint, payload, checks)
        outcome = "pruned" if prune else "removed"
        if not isinstance(value, dict) or value.get("uri") != uri or value.get("outcome") != outcome:
            raise Refused()
        return {"uri": uri, "outcome": outcome, "scope": "exact_uri" if prune else "resource_subtree",
                "memory_cleanup": False, "retry_safe": False}

    async def audit(self, a):
        roots = self.p.scopes(a.get("scope"))
        for root in roots:
            self.p.require_action("maintain" if a.get("fix", False) else "read", root)
        hits = await self.backend.semantic("search", a["query"], roots)
        # semantic() validates the entire bounded batch before any omission.
        documents, metadata_omitted = [], 0
        for hit in hits:
            parts = hit["uri"].split("/")
            if (hit["level"], parts[-1]) in {(0, ".abstract.md"), (1, ".overview.md")} and not any(
                part in {".abstract.md", ".overview.md"} for part in parts[:-1]
            ):
                metadata_omitted += 1
            else:
                # Unexpected metadata shapes still reach the existing authorizer.
                documents.append(hit["uri"])
        uris = list(dict.fromkeys(documents))[: a.get("limit", 40)]
        # Finish every check before the first prune. Failure is never absence.
        absent, present = [], []
        for uri in uris:
            self.authorize("maintain" if a.get("fix", False) else "read", uri,
                           strict=a.get("fix", False))
            (absent if await self.stat(uri) is None else present).append(uri)
        pruned = []
        if a.get("fix", False):
            for uri in absent:
                await self.remove({"uri": uri}, prune=True)
                pruned.append(uri)
        return {"checked": len(uris), "present": present, "absent": absent, "pruned_count": len(pruned),
                "candidate_kind": "document", "metadata_omitted": metadata_omitted,
                "complete": False, "descendant_orphan_sweep": False}

    async def run(self, name, a):
        if name == "memory_write":
            return await self.write(a)
        if name == "memory_mkdir":
            return await self.mkdir(a)
        if name == "memory_rm":
            return await self.remove(a)
        if name == "memory_index_prune":
            return await self.remove(a, prune=True)
        if name == "memory_index_audit":
            return await self.audit(a)
        if name == "memory_mv":
            return await self.move(a)
        if name == "memory_reindex":
            return await self.reindex(a)
        if name == "memory_status":
            roots = self.p.scopes(a.get("uri"))
            rows = []
            for uri in roots:
                self.p.require_action("read", uri)
                row = await self.stat(uri)
                rows.append({"uri": uri, "availability": "absent" if row is None else "present"})
            return {"service": "scoped_documents", "resources": rows, "task_status": "unavailable",
                    "indexing_completion": "not_observed"}
        raise Refused()


async def call_mutation(backend, name, arguments, state):
    dry_run = name == "memory_write" and arguments.get("dry_run") is True
    if dry_run:
        state["document_dry_run"] = True
        state["preflight_stage"] = "authorization"
    value, failed = await _call_mutation(backend, name, arguments, state)
    if dry_run:
        # Fixed vocabulary only; never expose backend bodies or descendant names.
        value.update(dry_run=True, dispatched=False, preflight={
            "stage": state["preflight_stage"],
            "category": state.get("preflight_category", "unavailable" if failed else "passed"),
        })
    return value, failed


async def _call_mutation(backend, name, arguments, state):
    operation = Mutations(backend, state)
    try:
        document_write = (name == "memory_write"
                          and arguments.get("storage", "legacy-chunked") in {"legacy-chunked", "exact-directory-v2"}
                          and arguments.get("dry_run") is not True)
        cap = DOCUMENT_WRITE_SECONDS if document_write else LONG_MUTATION_SECONDS if name in LONG_MUTATION_NAMES else 20
        remaining = min(cap, backend.principal.expires - time.time())
        if remaining <= 0:
            raise Refused()
        async with asyncio.timeout(remaining):
            value = await operation.run(name, arguments)
        backend.principal.require_action("read")
        if state.get("document_committed"):
            verification = value.get("verification", {})
            if (value.get("processing_state") == "failed"
                    or isinstance(verification, dict) and verification.get("status") == "different"):
                value["error"] = "Content committed; processing or observed round-trip differs. Do not retry automatically."
                return value, True
        if name == "memory_reindex" and value.get("indexing") != "completed":
            return value, True
        if name == "memory_write" and value.get("verification") == "mismatch":
            value["error"] = "Content committed; exact round-trip verification failed. Do not retry automatically."
            return value, True
        return value, False
    except asyncio.CancelledError:
        if state.get("document_committed"):
            value = dict(state["document_committed"])
            value["error"] = "Content committed; subsequent observation cancelled."
            return value, True
        if state.get("document_write") and state.get("dispatched"):
            return dict(UNKNOWN), True
        raise
    except OperationError as error:
        # A later audit prune conflict must not hide earlier completed prunes.
        if state.get("dispatched") or state.get("effects_confirmed"):
            return dict(UNKNOWN), True
        return error.value, True
    except (Refused, BudgetExhausted, httpx.HTTPError, TimeoutError,
            ValueError, TypeError, RecursionError):
        if state.get("document_committed"):
            value = dict(state["document_committed"])
            value["error"] = "Content committed; subsequent observation unavailable."
            return value, True
        if state.get("move_committed"):
            return {"error": "Move committed; subsequent completion unavailable.",
                    "outcome": "committed", "indexing": "not_observed", "retry_safe": False}, True
        if state.get("reindex_completed"):
            return {"error": "Reindex response authority expired.",
                    "outcome": "completed" if state["reindex_completed"] == "completed" else "completed_with_issues",
                    "indexing": state["reindex_completed"], "content_revision_bound": False,
                    "retry_safe": False}, True
        if state.get("mkdir_committed"):
            return {"error": "Directory created; subsequent completion unavailable.",
                    "outcome": "committed", "resource_type": "directory",
                    "indexing": "not_observed", "retry_safe": False}, True
        if state.get("committed"):
            return {"error": "Content committed; subsequent verification unavailable.",
                    "outcome": "committed", "indexing": "deferred", "retry_safe": False}, True
        if state.get("dispatched") or state.get("effects_confirmed"):
            return dict(UNKNOWN), True
        return {"error": "Resource unavailable.", "outcome": "not_started"}, True
