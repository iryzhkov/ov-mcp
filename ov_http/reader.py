"""Per-call scoped filesystem reader; never imports the broad stdio wrapper."""
from pathlib import PurePosixPath
import math
import re

import httpx

from .auth import (Principal, Refused, BROWSE_METADATA_NAMES, contains,
                   storage_internal_name, strict_json)
from .config import Config, SEMANTIC_PROFILE, RESOURCES_PROFILE

SAFE_ERROR = "Resource unavailable."
DOC_EXTS = (".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".rst", ".pdf", ".verbatim")
HIDDEN = {".abstract.md", ".overview.md"}
ARCHIVE = {"archive", "archived", "_archive"}
BROWSE_PAGE_LIMIT = 40  # 40 canonical 1024-byte URIs fit the MCP output budget.
BROWSE_OFFSET_LIMIT = 100000


class BudgetExhausted(Exception):
    """Local request/data/traversal limit, never an authorization or backend error."""


def natural(uri: str):
    return tuple((1, int(p)) if p.isdigit() else (0, p) for p in re.split(r"(\d+)", uri))


def document(uri: str, principal: Principal) -> str:
    parts = uri.split("/")
    for i in range(3, len(parts)):
        if parts[i].endswith(DOC_EXTS):
            root = "/".join(parts[:i + 1])
            parent = "/".join(parts[:i])
            if parent.endswith(".verbatim"):
                root = parent
            # A chunk-only grant must never reveal its document ancestor.
            return root if principal.allows(root) else uri
    return uri


def archived(uri: str) -> bool:
    return bool(set(uri.split("/")) & ARCHIVE)


def wikilinks(text: str) -> list[str]:
    # Literal, forward-only scanning avoids regex backtracking on malformed prose.
    links, cursor = [], 0
    while True:
        start = text.find("[[", cursor)
        if start < 0:
            return links
        end = text.find("]]", start + 2)
        if end < 0:
            return links
        name = text[start + 2:end].split("|", 1)[0].split("#", 1)[0].strip()
        if name and len(name) <= 1024 and "[[" not in name:
            links.append(name)
        cursor = end + 2


class Backend:
    """Fixed typed REST operations; every operation rechecks grants and expiry."""
    def __init__(self, config: Config, principal: Principal, client: httpx.AsyncClient):
        self.config, self.principal, self.client = config, principal, client
        self.requests = 0
        self.bytes = 0

    def check_budget(self, request_limit: int = 128):
        # Reserve one whole bounded response before starting I/O. This may stop
        # with less than 256 KiB unused, but never reads past the aggregate cap.
        if self.requests >= min(request_limit, 128) or self.bytes + 262144 > 1048576:
            raise BudgetExhausted()

    async def _request(self, method: str, endpoint: str, *, envelope: bool = False, **kwargs):
        self.check_budget()
        self.requests += 1
        async with self.client.stream(method, self.config.backend_url + endpoint, **kwargs) as response:
            if (response.status_code != 200
                    or response.headers.get("content-encoding", "identity") != "identity"):
                raise Refused()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > 262144:
                    raise Refused()
        self.bytes += len(body)
        result = strict_json(bytes(body))
        if not isinstance(result, dict) or result.get("status") != "ok":
            raise Refused()
        return result if envelope else result.get("result")

    async def _get(self, endpoint: str, uri: str, **params):
        self.principal.require(uri)
        return await self._request("GET", endpoint, params={"uri": uri, **params})

    async def semantic(self, kind: str, query: str, roots: tuple[str, ...] | None = None) -> list[dict]:
        roots = self.principal.roots if roots is None else roots
        if (self.config.semantic_profile not in (SEMANTIC_PROFILE, RESOURCES_PROFILE)
                or kind not in ("search", "find") or not query.strip() or not roots
                or any(not self.config.admits_namespace(r) or not self.principal.allows(r) for r in roots)):
            raise Refused()
        # Namespace types must remain immutable through the following POST.
        # This preflight rejects missing/file roots, but is not an atomic lock.
        for root in roots:
            if not (await self.stat(root))["isDir"]:
                raise Refused()
        payload = {"query": query, "target_uri": list(roots), "context_type": "resource",
                   "limit": 100, "read_content": False, "include_provenance": False,
                   "telemetry": False}
        if kind == "search":
            payload.update(mode="list", search_type="semantic")
        for root in roots:
            self.principal.require(root)
        value = await self._request("POST", "/search/" + kind, json=payload)
        if (not isinstance(value, dict) or value.get("memories") != [] or value.get("skills") != []
                or not isinstance(value.get("resources"), list) or len(value["resources"]) > 100):
            raise Refused()
        hits = value["resources"]
        for hit in hits:
            if not isinstance(hit, dict):
                raise Refused()
            uri = self.principal.require(hit.get("uri"))
            if not any(contains(root, uri) for root in roots):
                raise Refused()
            score = hit.get("score")
            if (hit.get("context_type") != "resource" or type(hit.get("level")) is not int
                    or hit["level"] not in (0, 1, 2) or type(score) not in (int, float)
                    or not math.isfinite(score) or abs(score) > 1e12
                    or not isinstance(hit.get("abstract"), str) or len(hit["abstract"]) > 8192):
                raise Refused()
        return hits

    async def stat(self, uri: str) -> dict:
        result = await self._get("/fs/stat", uri)
        if not isinstance(result, dict) or type(result.get("isDir")) is not bool:
            raise Refused()
        if self.config.semantic_profile == RESOURCES_PROFILE and result.get("uri") != uri:
            raise Refused()
        size = result.get("size", 0)
        if type(size) is not int or not 0 <= size <= 2**53:
            raise Refused()
        # No arbitrary upstream metadata, parent IDs, URLs or error text.
        return {"uri": uri, "isDir": result["isDir"], "size": size}

    async def children(self, uri: str) -> list[str]:
        result = await self._get("/fs/ls", uri, simple="true")
        if not isinstance(result, list) or len(result) > 256:
            raise Refused()
        children = set()
        for child in result:
            try:
                self.principal.canonical(child)
                if (not self.principal.allows(child) or not contains(uri, child) or child == uri
                        or "/" in child[len(uri) + 1:]):
                    if self.config.semantic_profile == RESOURCES_PROFILE:
                        raise Refused()
                    continue
                children.add(child)
            except Refused:
                if self.config.semantic_profile == RESOURCES_PROFILE:
                    raise
                continue
        return sorted(children, key=natural)

    async def browse_page(self, uri: str, recursive: bool, limit: int, offset: int,
                          depth: int) -> tuple[list[str], bool]:
        if (self.config.semantic_profile != RESOURCES_PROFILE
                or type(limit) is not int or not 1 <= limit <= BROWSE_PAGE_LIMIT
                or type(offset) is not int or not 0 <= offset <= BROWSE_OFFSET_LIMIT
                or type(depth) is not int or not 1 <= depth <= 12):
            raise Refused()
        self.principal.require_action("read", uri)
        params = {"uri": uri, "offset": offset, "node_limit": limit, "output": "original",
                  "include_abstract": "false", "include_overview": "false",
                  "include_tags": "false", "show_all_hidden": "false"}
        if recursive:
            endpoint = "/fs/tree"
            params.update(level_limit=depth, directories_only="false")
        else:
            endpoint = "/fs/ls"
            params.update(simple="false", recursive="false", sort_by="name", sort_order="asc")
        page = await self._request("GET", endpoint, envelope=True, params=params)
        self.principal.require_action("read", uri)
        if not isinstance(page, dict):
            raise Refused()
        entries, more = page.get("result"), page.get("has_more")
        if (not isinstance(entries, list) or len(entries) > limit or type(more) is not bool
                or (more and len(entries) != limit)):
            raise Refused()
        paths = []
        for entry in entries:
            # Original rows preserve denied placeholders that simple ls erases.
            # Project URIs only after validating the typed row and its authority.
            if (not isinstance(entry, dict) or type(entry.get("isDir")) is not bool
                    or entry.get("access") == "denied"):
                raise Refused()
            child = entry.get("uri")
            if not isinstance(child, str):
                raise Refused()
            self.principal.require_action("read", child)
            if not contains(uri, child) or child == uri:
                raise Refused()
            relative = child[len(uri) + 1:].split("/")
            # Native listings expose ordinary dot directories but hide dot
            # files. Reserved metadata/control names are never browse entries.
            if (any(storage_internal_name(part) or part in BROWSE_METADATA_NAMES for part in relative)
                    or (relative[-1].startswith(".") and not entry["isDir"])
                    or len(relative) > (depth if recursive else 1) or child in paths):
                raise Refused()
            paths.append(child)
        return paths, more

    async def text(self, uri: str) -> str:
        value = await self._get("/content/read", uri)
        if not isinstance(value, str):
            raise Refused()
        return value


class Reader:
    def __init__(self, backend: Backend):
        self.backend = backend
        self.principal = backend.principal

    async def walk(self, root: str, max_depth: int = 12, *, request_limit: int = 128,
                   atomic: bool = False):
        self.principal.require(root)
        nodes, pending, truncated = [], [(root, 0)], False
        seen = {root}
        try:
            while pending:
                uri, depth = pending.pop()
                self.backend.check_budget(request_limit)
                children = await self.backend.children(uri)
                for child in reversed(children):
                    if child in seen:
                        continue
                    seen.add(child)
                    if len(nodes) >= 256:
                        return sorted(nodes, key=lambda n: natural(n["uri"])), True
                    self.backend.check_budget(request_limit)
                    entry = await self.backend.stat(child)
                    nodes.append(entry)
                    if entry["isDir"]:
                        if depth + 1 < max_depth:
                            pending.append((child, depth + 1))
                        else:
                            truncated = True
        except BudgetExhausted:
            if atomic:
                raise
            truncated = True
        return sorted(nodes, key=lambda n: natural(n["uri"])), truncated

    async def assemble(self, uri: str):
        st = await self.backend.stat(uri)
        if not st["isDir"]:
            return await self.backend.text(uri), [uri]
        nodes, truncated = await self.walk(uri, atomic=True)
        if truncated:
            raise BudgetExhausted()
        sources, chunks = [], []
        for node in nodes:
            part = node["uri"]
            if not node["isDir"] and not part.rsplit("/", 1)[-1].startswith("."):
                text = await self.backend.text(part)
                if text:
                    chunks.append(text if uri.endswith(".verbatim") else text.strip())
                    sources.append(part)
        if uri.endswith(".verbatim"):
            # Each verbatim part is stored as a note directory. Concatenate its
            # internal chunks, restore newlines between numbered part directories.
            groups = {}
            for source, text in zip(sources, chunks):
                key = source[len(uri) + 1:].split("/")[0]
                groups[key] = groups.get(key, "") + text
            return "\n".join(groups.values()), sources
        text = ""
        for chunk in chunks:
            separator = "" if text[-1:].isalnum() and chunk[:1].islower() else "\n\n"
            text += (separator if text else "") + chunk
        return text, sources

    async def read(self, uri: str, offset: int = 0, limit: int = 500, parts: bool = False):
        text, sources = await self.assemble(uri)
        lines = text.split("\n")
        selected = "\n".join(lines[offset:offset + limit])
        truncated = offset + limit < len(lines) or len(selected) > 24000
        result = {"uri": uri, "text": selected[:24000], "offset": offset,
                  "total_lines": len(lines), "truncated": truncated,
                  "assembly": "natural name order; original Markdown section order may differ"}
        if parts:
            result["parts"] = sources
        return result

    async def summary(self, uri: str, name: str):
        self.principal.require(uri)
        if not (await self.backend.stat(uri))["isDir"]:
            raise Refused()
        # Explicit file path avoids upstream parent-summary fallback.
        return {"uri": uri, "text": await self.backend.text(uri + "/." + name + ".md")}

    async def listing(self, uri: str | None, recursive: bool, limit: int, depth: int = 12):
        entries, truncated = [], False
        try:
            for root in self.principal.scopes(uri):
                if recursive:
                    nodes, cut = await self.walk(root, depth)
                    entries.extend(n["uri"] for n in nodes)
                    truncated |= cut
                else:
                    entries.extend(await self.backend.children(root))
        except BudgetExhausted:
            truncated = True
        entries = sorted(set(entries), key=natural)
        return {"entries": entries[:limit], "truncated": truncated or len(entries) > limit}

    async def paged_listing(self, uri: str | None, recursive: bool, limit: int,
                            depth: int = 12, offset: int = 0):
        if (type(limit) is not int or not 1 <= limit <= 100
                or type(offset) is not int or not 0 <= offset <= BROWSE_OFFSET_LIMIT):
            raise Refused()
        roots = self.principal.scopes(uri)
        # A single authorized directory makes offsets unambiguous. A file-only
        # grant never causes a parent listing or ancestor metadata request.
        if len(roots) != 1:
            raise Refused()
        root = roots[0]
        self.principal.require_action("read", root)
        if not (await self.backend.stat(root))["isDir"]:
            raise Refused()
        effective_limit = min(limit, BROWSE_PAGE_LIMIT, BROWSE_OFFSET_LIMIT + 1 - offset)
        entries, more = await self.backend.browse_page(root, recursive, effective_limit, offset, depth)
        next_offset = offset + len(entries) if more else None
        if next_offset is not None and next_offset > BROWSE_OFFSET_LIMIT:
            next_offset = None
        return {"entries": entries, "offset": offset, "limit": effective_limit,
                "has_more": more, "next_offset": next_offset, "truncated": more,
                "complete": False, "continuation_limited": more and next_offset is None,
                "depth_limit": depth if recursive else 1,
                "pagination": "best effort; concurrent edits may repeat or omit paths"}

    async def stat(self, uri: str):
        result = await self.backend.stat(uri)
        if result["isDir"]:
            nodes, cut = await self.walk(uri)
            files = [n for n in nodes if not n["isDir"]]
            result = {"uri": uri, "isDir": True, "content_bytes": sum(n["size"] for n in files),
                      "parts": len(files), "truncated": cut}
        return result

    async def candidates(self, uri: str | None, *, request_limit: int = 128):
        nodes, truncated = [], False
        try:
            for root in self.principal.scopes(uri):
                self.principal.require(root)
                self.backend.check_budget(request_limit)
                st = await self.backend.stat(root)
                if st["isDir"]:
                    children, cut = await self.walk(root, request_limit=request_limit)
                    nodes.extend(children)
                    truncated |= cut
                else:
                    nodes.append(st)
        except BudgetExhausted:
            truncated = True
        return nodes, truncated

    async def glob(self, pattern: str, uri: str | None, limit: int):
        nodes, truncated = await self.candidates(uri)
        roots = self.principal.scopes(uri)
        matches = [n["uri"] for n in nodes if any(
            PurePosixPath(n["uri"][len(r) + 1:]).full_match(pattern)
            or PurePosixPath(n["uri"].rsplit("/", 1)[-1]).full_match(pattern)
            for r in roots if contains(r, n["uri"]))]
        return {"matches": matches[:limit], "truncated": truncated or len(matches) > limit}

    async def grep(self, pattern: str, uri: str | None, case_insensitive: bool,
                   limit: int, group: bool, include_archived: bool):
        # Leave half the request allowance for reading discovered files.
        nodes, truncated = await self.candidates(uri, request_limit=64)
        matches = {}
        needle = pattern.casefold() if case_insensitive else pattern
        for node in nodes:
            path = node["uri"]
            if node["isDir"] or (not include_archived and archived(path)):
                continue
            try:
                text = await self.backend.text(path)
            except BudgetExhausted:
                truncated = True
                break
            haystack = text.casefold() if case_insensitive else text
            if needle in haystack:
                root = document(path, self.principal) if group else path
                match = matches.setdefault(root, {"uri": root, "matching_parts": 0})
                match["matching_parts"] += 1
        results = list(matches.values())
        return {"matches": results[:limit], "truncated": truncated or len(results) > limit,
                "mode": "literal substring; no regex"}

    async def semantic(self, kind: str, query: str, scope: str | None, limit: int,
                       group: bool, include_archived: bool):
        roots = None
        if self.backend.config.semantic_profile == RESOURCES_PROFILE:
            if scope is not None:
                roots = (self.principal.require(scope),)
        elif scope is not None and scope not in self.principal.roots:
            # Preserve the legacy profile: scope asserts an exact grant and
            # never changes the complete set of backend targets.
            raise Refused()
        hits = await self.backend.semantic(kind, query, roots)
        matches = {}
        for hit in sorted(hits, key=lambda h: h["score"], reverse=True):
            uri = hit["uri"]
            if not include_archived and archived(uri):
                continue
            target = document(uri, self.principal) if group else uri
            entry = matches.setdefault(target, {"uri": target, "score": hit["score"],
                                                 "abstract": hit["abstract"], "matching_parts": 0})
            entry["matching_parts"] += 1
        values = list(matches.values())
        return {"matches": values[:limit], "returned": min(len(values), limit),
                "truncated": len(hits) == 100 or len(values) > limit, "complete": False,
                "batch_limit": 100, "matching_parts_basis": "returned scoped batch only"}

    async def relations(self, uri: str):
        self.principal.require(uri)
        target_text, _ = await self.assemble(uri)
        # Reserve requests for complete backlink documents after discovery.
        nodes, truncated = await self.candidates(None, request_limit=64)
        names_complete = not truncated
        docs = sorted({document(n["uri"], self.principal) for n in nodes
                       if not n["isDir"] and not n["uri"].rsplit("/", 1)[-1].startswith(".")})
        target = document(uri, self.principal)
        target_name = target.rsplit("/", 1)[-1].removesuffix(".md")
        by_name = {}
        for doc in docs:
            by_name.setdefault(doc.rsplit("/", 1)[-1].removesuffix(".md"), []).append(doc)
        outgoing = set()
        for name in wikilinks(target_text):
            name = name.strip()
            if name.startswith("viking://"):
                try:
                    self.principal.require(name)
                    if name in docs:
                        outgoing.add(name)
                except Refused:
                    pass
            elif names_complete and len(by_name.get(name.removesuffix(".md"), [])) == 1:
                outgoing.add(by_name[name.removesuffix(".md")][0])
        backlinks = []
        for doc in docs:
            if doc == target:
                continue
            try:
                text, _ = await self.assemble(doc)
            except BudgetExhausted:
                truncated = True
                break
            links = [x.removesuffix(".md") for x in wikilinks(text)]
            if ((names_complete and len(by_name.get(target_name, [])) == 1 and target_name in links)
                    or target.removesuffix(".md") in links):
                backlinks.append(doc)
        return {"uri": uri, "wikilinks": sorted(outgoing), "backlinks": backlinks,
                "truncated": truncated,
                "stored_links": "unavailable: backend relations are not scoped before discovery"}
