"""Per-call scoped filesystem reader; never imports the broad stdio wrapper."""
from pathlib import PurePosixPath
import json
import re

import httpx

from .auth import Principal, Refused, bounded_json, canonical, contains
from .config import Config

SAFE_ERROR = "Resource unavailable."
DOC_EXTS = (".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".rst", ".pdf", ".verbatim")
HIDDEN = {".abstract.md", ".overview.md"}
ARCHIVE = {"archive", "archived", "_archive"}


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
    """Only these three typed REST operations exist. Every operation rechecks ACL/expiry."""
    def __init__(self, config: Config, principal: Principal, client: httpx.AsyncClient):
        self.config, self.principal, self.client = config, principal, client
        self.requests = 0
        self.bytes = 0

    async def _get(self, endpoint: str, uri: str, **params):
        self.principal.require(uri)
        self.requests += 1
        if self.requests > 128:
            raise Refused()
        result = await bounded_json(self.client, "GET", self.config.backend_url + endpoint,
                                    262144, params={"uri": uri, **params})
        self.bytes += len(json.dumps(result).encode())
        if self.bytes > 1048576 or not isinstance(result, dict) or result.get("status") != "ok":
            raise Refused()
        return result.get("result")

    async def stat(self, uri: str) -> dict:
        result = await self._get("/fs/stat", uri)
        if not isinstance(result, dict) or type(result.get("isDir")) is not bool:
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
                canonical(child)
                if (not self.principal.allows(child) or not contains(uri, child) or child == uri
                        or "/" in child[len(uri) + 1:]):
                    continue
                children.add(child)
            except Refused:
                continue
        return sorted(children, key=natural)

    async def text(self, uri: str) -> str:
        value = await self._get("/content/read", uri)
        if not isinstance(value, str):
            raise Refused()
        return value


class Reader:
    def __init__(self, backend: Backend):
        self.backend = backend
        self.principal = backend.principal

    async def walk(self, root: str, max_depth: int = 12):
        self.principal.require(root)
        nodes, pending, truncated = [], [(root, 0)], False
        seen = {root}
        while pending:
            uri, depth = pending.pop()
            children = await self.backend.children(uri)
            for child in reversed(children):
                if child in seen:
                    continue
                seen.add(child)
                if len(nodes) >= 256:
                    return sorted(nodes, key=lambda n: natural(n["uri"])), True
                entry = await self.backend.stat(child)
                nodes.append(entry)
                if entry["isDir"]:
                    if depth + 1 < max_depth:
                        pending.append((child, depth + 1))
                    else:
                        truncated = True
        return sorted(nodes, key=lambda n: natural(n["uri"])), truncated

    async def assemble(self, uri: str):
        st = await self.backend.stat(uri)
        if not st["isDir"]:
            return await self.backend.text(uri), [uri]
        nodes, truncated = await self.walk(uri)
        if truncated:
            raise Refused()
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
        for root in self.principal.scopes(uri):
            if recursive:
                nodes, cut = await self.walk(root, depth)
                entries.extend(n["uri"] for n in nodes)
                truncated |= cut
            else:
                entries.extend(await self.backend.children(root))
        entries = sorted(set(entries), key=natural)
        return {"entries": entries[:limit], "truncated": truncated or len(entries) > limit}

    async def stat(self, uri: str):
        result = await self.backend.stat(uri)
        if result["isDir"]:
            nodes, cut = await self.walk(uri)
            files = [n for n in nodes if not n["isDir"]]
            result = {"uri": uri, "isDir": True, "content_bytes": sum(n["size"] for n in files),
                      "parts": len(files), "truncated": cut}
        return result

    async def candidates(self, uri: str | None):
        nodes, truncated = [], False
        for root in self.principal.scopes(uri):
            st = await self.backend.stat(root)
            if st["isDir"]:
                children, cut = await self.walk(root)
                nodes.extend(children)
                truncated |= cut
            else:
                nodes.append(st)
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
        nodes, truncated = await self.candidates(uri)
        matches = {}
        needle = pattern.casefold() if case_insensitive else pattern
        for node in nodes:
            path = node["uri"]
            if node["isDir"] or (not include_archived and archived(path)):
                continue
            text = await self.backend.text(path)
            haystack = text.casefold() if case_insensitive else text
            if needle in haystack:
                root = document(path, self.principal) if group else path
                match = matches.setdefault(root, {"uri": root, "matching_parts": 0})
                match["matching_parts"] += 1
        results = list(matches.values())
        return {"matches": results[:limit], "truncated": truncated or len(results) > limit,
                "mode": "literal substring; no regex"}

    async def relations(self, uri: str):
        self.principal.require(uri)
        target_text, _ = await self.assemble(uri)
        nodes, truncated = await self.candidates(None)
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
            elif len(by_name.get(name.removesuffix(".md"), [])) == 1:
                outgoing.add(by_name[name.removesuffix(".md")][0])
        backlinks = []
        for doc in docs:
            if doc == target:
                continue
            text, _ = await self.assemble(doc)
            links = [x.removesuffix(".md") for x in wikilinks(text)]
            if ((len(by_name.get(target_name, [])) == 1 and target_name in links)
                    or target.removesuffix(".md") in links):
                backlinks.append(doc)
        return {"uri": uri, "wikilinks": sorted(outgoing), "backlinks": backlinks,
                "truncated": truncated,
                "stored_links": "unavailable: backend relations are not scoped before discovery"}
