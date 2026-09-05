#!/usr/bin/env python
"""MCP server exposing an OpenViking memory store to local agents.

OpenViking 0.2.6 ships no MCP module -- only the `ov` CLI and Python clients --
so this wraps its HTTP API. Read tools cover the whole surface an agent needs to
explore memory; the single write tool is deliberately confined to the resources
scope, because `/resources` rejects anything else ("add_resource only supports
resources scope") and agent-scope memories are written by OpenViking's own
session extraction, which is the unattended path we chose not to use.

Settings come from ~/.config/ov-mcp/config.toml, overridden by the environment.
That file is deliberately not in the repository, so no host, address or key of a
particular deployment is committed. See config.example.toml.

Credentials: OV_API_KEY, else `api_key` in that config file, else the GNOME
keyring (service=openviking key=api). No key is stored in this file or in
~/.claude.json.

Working around OpenViking 0.2.6
-------------------------------
Four server behaviours are wrong or misleading in ways an agent cannot see, so
this wrapper compensates for them. Each workaround is verified against a live
0.2.6 server; if a later release fixes the behaviour the workaround becomes a
no-op rather than a hazard.

1. `POST /fs/mv` updates the vector index for the files it can list, but hidden
   nodes (`.abstract.md`, `.overview.md`) are filtered out of that listing, so
   their index records keep pointing at the old URI. Those orphans stay at the
   top of search results and resolve to nothing. `memory_mv` therefore prunes
   them after the move, and optionally re-ingests the moved documents so their
   abstracts are indexed at the new location again.

2. `DELETE /fs` on a URI that no longer exists raises before it reaches the
   index cleanup, so an orphaned record cannot be deleted through the documented
   path. Creating a directory at the orphan URI and removing it recursively does
   reach the cleanup, which gives `memory_index_prune` a working repair.

3. `GET /content/read` returns an empty string for an ingested document, because
   OpenViking stores it as a directory of chunks, and `GET /fs/ls` with
   `recursive=true` stops one level down. An empty read is indistinguishable
   from a missing note, which is dangerous in a write-verify-delete workflow, so
   reads walk the tree here and reassemble every part.

4. A recursive `DELETE /fs` can answer "ok" having removed only part of the
   subtree, and a directory's abstract is regenerated asynchronously, so a
   delete can also be undone moments later by a pass that was already running.
   Deletes are therefore checked against the subtree they were given, and what
   an indexing pass puts back is reported rather than passed off as removed.

What ingestion does to a note's text is documented in the README, and asserted
by --selftest: Markdown keeps every line but loses its title to the directory
name, other extensions keep every word but lose whitespace at the chunk cuts,
and memory_write(verbatim=True) cuts the parts here instead so that the bytes
come back exactly.
"""

import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any

import logging

import httpx
from mcp.server.mcpserver import MCPServer

# httpx logs every request at INFO; on stdio transport that is just noise.
logging.getLogger("httpx").setLevel(logging.WARNING)

CONFIG_PATH = pathlib.Path(
    os.environ.get("OV_CONFIG")
    or pathlib.Path(os.environ.get("XDG_CONFIG_HOME", pathlib.Path.home() / ".config"))
    / "ov-mcp"
    / "config.toml"
)


def _load_config() -> dict:
    """Machine-specific settings. Absent or unreadable config is not an error --
    the defaults below plus the environment are enough to run."""
    try:
        import tomllib
        with open(CONFIG_PATH, "rb") as fh:
            return tomllib.load(fh)
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return {}
    except Exception as exc:  # malformed TOML should say so rather than vanish
        print(f"ov-mcp: ignoring {CONFIG_PATH}: {exc}", file=sys.stderr)
        return {}


_CFG = _load_config()


def _setting(key: str, env: str, default: str) -> str:
    """Environment wins, then the config file, then the built-in default."""
    if env in os.environ:
        return os.environ[env]
    if key in _CFG:
        return str(_CFG[key])
    return default


# The default points at localhost so that nothing about a particular deployment
# is baked into this file. Real hosts are named in ~/.config/ov-mcp/config.toml.
BASE_URL = _setting("base_url", "OV_BASE_URL", "http://localhost:1933").rstrip("/")
API = f"{BASE_URL}/api/v1"
AGENT = _setting("agent", "OV_AGENT", "claude-code")
TIMEOUT = float(_setting("timeout", "OV_TIMEOUT", "120"))
RESOURCES_ROOT = "viking://resources"

# OpenViking generates these beside every ingested document. They are hidden
# from `ls`, which is why the server's own mv and rm leave their index records
# behind, and why this file has to name them explicitly.
HIDDEN_PARTS = (".abstract.md", ".overview.md")

# A path segment that marks superseded material. Archived notes are near
# duplicates of the live note by definition, so they compete with it in search;
# they are hidden from results here unless asked for.
ARCHIVE_SEGMENTS = {"archive", "archived"}

# A note written with verbatim=True becomes a directory of numbered parts, each
# small enough that OpenViking stores it whole. The suffix marks the container so
# that reads rejoin the parts as they were cut, and so that search groups them as
# one document. The size is well under the parser's split threshold of about a
# thousand tokens.
VERBATIM_SUFFIX = ".verbatim"
VERBATIM_PART_CHARS = 2400

# Extensions that name a document rather than one of its chunks. A hit inside
# viking://resources/ns/note.md/section/part.md belongs to the document
# viking://resources/ns/note.md, and that is what a caller wants to be told.
DOC_EXTS = (
    ".md", ".markdown", ".txt", ".yaml", ".yml", ".json", ".toml", ".ini",
    ".conf", ".cfg", ".py", ".sh", ".lua", ".go", ".ts", ".js", ".csv",
    ".html", ".pdf", ".rst", ".org",
)


def _api_key() -> str:
    key = os.environ.get("OV_API_KEY") or _CFG.get("api_key")
    if key:
        return str(key)
    try:
        out = subprocess.run(
            ["secret-tool", "lookup", "service", "openviking", "key", "api"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    # Headless hosts have no GNOME keyring; fall back to a 0600 file.
    key_file = pathlib.Path(os.environ.get("OV_KEY_FILE", "~/.config/ov-mcp/key")).expanduser()
    try:
        if key_file.is_file():
            contents = key_file.read_text().strip()
            if contents:
                return contents
    except OSError:
        pass
    raise RuntimeError(
        "No OpenViking API key. Set OV_API_KEY, write it to ~/.config/ov-mcp/key (0600), "
        "or store it with: secret-tool store --label='OpenViking API key' service openviking key api"
    )


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_api_key()}", "X-OpenViking-Agent": AGENT}


def _call(method: str, path: str, *, params=None, json_body=None, files=None) -> Any:
    with httpx.Client(timeout=TIMEOUT) as client:
        r = client.request(method, f"{API}{path}", params=params, json=json_body,
                           files=files, headers=_headers())
    if r.status_code >= 400:
        return {"_http_error": r.status_code, "body": r.text[:400]}
    try:
        payload = r.json()
    except ValueError:
        return {"_raw": r.text[:2000]}
    if payload.get("status") != "ok":
        err = payload.get("error") or {}
        return {"_error": err.get("code", "ERROR"), "message": err.get("message", "")}
    return payload.get("result")


def _failed(result: Any) -> bool:
    return isinstance(result, dict) and ("_error" in result or "_http_error" in result)


def _error_text(result: dict) -> str:
    """One readable line out of an API error, however it was wrapped."""
    if "_error" in result:
        return f"OpenViking error [{result['_error']}]: {result.get('message', '')}".strip()
    body = result.get("body", "")
    try:
        inner = json.loads(body).get("error") or {}
        return f"OpenViking error [{inner.get('code', result['_http_error'])}]: {inner.get('message', '')}".strip()
    except (ValueError, AttributeError):
        return f"OpenViking error [HTTP {result['_http_error']}]: {str(body)[:200]}"


# --------------------------------------------------------------------------
# Filesystem helpers
#
# Every walk here is done client-side: the server's own recursive listing stops
# one level down, which silently under-reports the parts of a chunked document.
# --------------------------------------------------------------------------

def _stat(uri: str) -> dict | None:
    """Node metadata, or None when the URI does not resolve."""
    st = _call("GET", "/fs/stat", params={"uri": uri})
    return None if _failed(st) or not isinstance(st, dict) else st


def _exists(uri: str) -> bool:
    return _stat(uri) is not None


def _ls(uri: str, detail: bool = False) -> list:
    """Children of a directory, as URIs or as entry dicts.

    The detailed listing carries each entry's size and abstract, and is the more
    fragile of the two; when it fails, the plain listing plus a stat per entry
    says the same thing, and an empty answer from a directory that has children
    would silently truncate every walk built on it.
    """
    result = _call("GET", "/fs/ls", params={"uri": uri, "simple": not detail})
    if isinstance(result, list):
        return result
    if not detail:
        return []
    plain = _call("GET", "/fs/ls", params={"uri": uri, "simple": True})
    if not isinstance(plain, list):
        return []
    entries = []
    for child in plain:
        st = _stat(str(child)) or {}
        entries.append({"uri": str(child), "isDir": bool(st.get("isDir")),
                        "size": st.get("size", 0), "abstract": ""})
    return entries


def _natural_key(name: str) -> list:
    """Sort key that reads runs of digits as numbers, so part 2 precedes part 10."""
    return [int(piece) if piece.isdigit() else piece
            for piece in re.split(r"(\d+)", name)]

def _walk(uri: str, depth: int = 0) -> tuple[list[str], list[str]]:
    """Depth-first (files, directories) under uri.

    Siblings are sorted naturally, so part 2 of a document comes before part 10;
    OpenViking lists them by name, which puts `_10` between `_1` and `_2`.
    """
    files: list[str] = []
    dirs: list[str] = []
    if depth > 12:  # a chunked document nests a few levels; this is a safety net
        return files, dirs
    entries = [e for e in _ls(uri, detail=True) if e.get("uri")]
    entries.sort(key=lambda e: _natural_key(_leaf(e["uri"])))
    for entry in entries:
        child = entry["uri"]
        if entry.get("isDir"):
            dirs.append(child)
            sub_files, sub_dirs = _walk(child, depth + 1)
            files.extend(sub_files)
            dirs.extend(sub_dirs)
        else:
            files.append(child)
    return files, dirs


def _leaf(uri: str) -> str:
    return uri.rstrip("/").rsplit("/", 1)[-1]


def _document_root(uri: str) -> str:
    """The document a URI belongs to.

    Chunks live under a directory named for the ingested file, so the document
    is the shortest prefix whose last segment carries a document extension.
    A verbatim container (see memory_write) groups its parts one level higher.
    """
    parts = uri.split("/")
    for i, segment in enumerate(parts):
        if i >= 3 and segment.endswith(DOC_EXTS):
            root = "/".join(parts[: i + 1])
            parent = "/".join(parts[:i])
            if parent.endswith(".verbatim"):
                return parent
            return root
    return uri


def _is_archived(uri: str) -> bool:
    return any(segment in ARCHIVE_SEGMENTS for segment in uri.split("/"))


def _read_raw(uri: str) -> str:
    body = _call("GET", "/content/read", params={"uri": uri})
    return body if isinstance(body, str) else ""


def _reassemble_verbatim(uri: str) -> tuple[str, list[str]]:
    """Rejoin the numbered parts of a verbatim note exactly as they were cut."""
    part_dirs = sorted((entry["uri"] for entry in _ls(uri, detail=True)
                        if entry.get("uri") and entry.get("isDir")),
                       key=lambda u: _natural_key(_leaf(u)))
    chunks: list[str] = []
    used: list[str] = []
    for part_dir in part_dirs:
        files, _ = _walk(part_dir)
        text = "".join(_read_raw(f) for f in files if not _leaf(f).startswith("."))
        if text:
            chunks.append(text)
            used.append(part_dir)
    return "\n".join(chunks), used

def _join_chunks(chunks: list[str]) -> str:
    """Join stored chunks the way they were most likely cut.

    OpenViking splits a long run of text by character count, which lands in the
    middle of a word, and trims each side. Joining those with a blank line would
    break a line in half; joining a genuine section break without one would run
    two lines together. A cut that left a word split shows as an alphanumeric
    character meeting a lowercase one, and only that case is closed up.
    """
    if not chunks:
        return ""
    out = chunks[0]
    for chunk in chunks[1:]:
        mid_word = out[-1:].isalnum() and chunk[:1].islower()
        out += ("" if mid_word else "\n\n") + chunk
    return out

def _reassemble(uri: str) -> tuple[str, list[str]]:
    """Full text of a node and the parts it came from.

    A plain file reads directly. An ingested document is a directory of chunks,
    and joining them reproduces the text. How faithfully depends on how
    OpenViking chunked it, which depends on the extension it was written under:

    - Anything but Markdown is split into flat siblings numbered in document
      order (`upload_<id>_1.md`, `_2`, …), and joining them is byte-exact. That
      is verified by --selftest.
    - Markdown is split by heading into a tree of named sections, the document's
      top-level heading becomes the containing directory's name rather than
      content, and listings are sorted by name. Section order therefore survives
      only where names sort the way the document ran, so a long Markdown note can
      come back with its sections rearranged. memory_read says when that risk
      applies; storing content that must round-trip exactly under its own
      extension avoids it entirely.
    """
    direct = _read_raw(uri)
    if direct:
        return direct, [uri]
    if uri.rstrip("/").endswith(VERBATIM_SUFFIX):
        return _reassemble_verbatim(uri)
    files, _ = _walk(uri)
    visible = [f for f in files if not _leaf(f).startswith(".")]
    chunks: list[str] = []
    used: list[str] = []
    for part in visible:
        text = _read_raw(part)
        if text:
            chunks.append(text.strip())
            used.append(part)
    return _join_chunks(chunks), used


def _rm(uri: str, recursive: bool) -> Any:
    return _call("DELETE", "/fs", params={"uri": uri, "recursive": recursive})


def _prune_index(uri: str) -> bool:
    """Delete the vector-index record of a URI that no longer exists on disk.

    OpenViking's rm removes the node first and cleans the index afterwards, so
    on a missing node it raises before cleaning and the record is unreachable.
    Recreating the URI as a directory and removing it recursively runs the same
    cleanup with the node present. Every directory this has to create along the
    way is removed again -- an empty directory left behind here would look like
    an existing note to the next write.
    """
    if _exists(uri):
        return False
    segments = uri.split("/")
    created_root = None
    # viking://resources/x -> ['viking:', '', 'resources', 'x'], so index 3 is
    # the first node that may be created; the scope itself is never touched.
    for i in range(len(segments) - 1, 3, -1):
        parent = "/".join(segments[:i])
        if _exists(parent):
            break
        created_root = parent
    if _failed(_call("POST", "/fs/mkdir", json_body={"uri": uri})):
        return False
    _rm(uri, recursive=True)
    if created_root:
        _rm(created_root, recursive=True)
        if _exists(created_root):
            _rm(created_root, recursive=True)
    return True


def _prune_hidden(directories: list[str], root: str) -> int:
    """Prune the index records of the abstract and overview of each directory.

    Pruning has to recreate the URI it is pruning, so this leaves directories
    behind unless they are cleared afterwards -- and an empty directory left here
    reads as an existing note and blocks the next write to that name. The
    clean-up is checked rather than assumed, deepest node first, because a
    recursive delete can report success having removed only the top of the tree.
    """
    pruned = 0
    for directory in directories:
        for hidden in HIDDEN_PARTS:
            if _prune_index(f"{directory}/{hidden}"):
                pruned += 1
    # Unconditionally, deepest node first, rather than only where stat says the
    # node is back: stat has been seen reporting a directory as missing while
    # its children were still there, and a delete of a node that is genuinely
    # gone is a harmless error.
    for directory in sorted(set(directories), key=lambda u: -u.count("/")):
        _rm(directory, recursive=True)
    _rm(root, recursive=True)
    return pruned

def _purge(uri: str) -> dict:
    """Remove a node and every index record belonging to it.

    Two OpenViking behaviours make this more than one call. Its rm cleans the
    index only for the files it can list, which leaves the hidden abstract and
    overview of every directory in the subtree behind; those are collected
    before the deletion and pruned after it. And a recursive delete can answer
    "ok" having removed only part of the subtree, with stat then reporting the
    parent gone while its children are still there -- residue that reads back as
    a note that was supposedly deleted, and blocks the next write to that name.
    So the deletion is checked against the subtree it was given, deepest node
    first, and only reported as done when nothing is left.
    """
    files, dirs = _walk(uri)
    subtree = [uri] + dirs
    known = sorted(set(subtree + files), key=lambda u: -u.count("/"))
    removed = _rm(uri, recursive=True)
    if _failed(removed):
        return {"error": _error_text(removed)}
    for _ in range(3):
        leftovers = [node for node in known if _exists(node)]
        if not leftovers:
            break
        for node in leftovers:
            _rm(node, recursive=True)
    else:
        leftovers = [node for node in known if _exists(node)]
        if leftovers:
            return {"error": f"OpenViking reported success, but {len(leftovers)} node(s) under "
                             f"{uri} are still there, the first being {leftovers[0]}. Nothing "
                             "further was deleted; try again once its indexing has finished."}
    pruned = _prune_hidden(subtree, uri)
    return {"files": len(files), "dirs": len(dirs), "pruned": pruned}


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------

def _fmt_tree(nodes: list) -> str:
    """Indented tree. The raw per-node JSON is unreadable at any real size."""
    lines = []
    per_dir: dict[str, int] = {}
    max_files = 5  # chunked documents produce dozens of siblings; show a few
    for n in nodes:
        rel = n.get("rel_path") or n.get("uri", "")
        depth = rel.count("/")
        name = rel.rsplit("/", 1)[-1] + ("/" if n.get("isDir") else "")
        if not n.get("isDir"):
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            per_dir[parent] = per_dir.get(parent, 0) + 1
            if per_dir[parent] == max_files + 1:
                lines.append("  " * depth + "... more files (memory_ls this directory)")
            if per_dir[parent] > max_files:
                continue
        row = "  " * depth + name
        abstract = (n.get("abstract") or "").strip().replace("\n", " ")
        if abstract:
            row += "  - " + abstract[:120]
        elif not n.get("isDir"):
            row += f"  ({n.get('size', 0)}b)"
        lines.append(row)
    return "\n".join(lines)


def _fmt_hits(result: Any, limit: int, group: bool, include_archived: bool) -> str:
    """Search results, one document per line.

    Ungrouped, a single chunked document floods the list: its abstract, its
    overview and each of its chunks are separate records, so five hits routinely
    describe one note. Grouping keeps the best-scoring hit per document, prefers
    a content chunk over the generated abstract as the representative, and says
    how many other parts of that document matched.
    """
    if not isinstance(result, dict):
        return _fmt(result)
    if not group:
        lines: list[str] = []
        for bucket in ("memories", "resources"):
            hits = result.get(bucket) or []
            if hits:
                lines.append(f"## {bucket} ({len(hits)})")
            for h in hits:
                score = h.get("score")
                score_s = f"{score:.3f}" if isinstance(score, (int, float)) else "-"
                lines.append(f"- [{score_s}] {h.get('uri')}")
                abstract = (h.get("abstract") or "").strip().replace("\n", " ")
                if abstract:
                    lines.append(f"    {abstract[:300]}")
        return "\n".join(lines) if lines else "No matches."

    groups: dict[str, dict] = {}
    archived_hidden = 0
    for bucket in ("memories", "resources"):
        for h in result.get(bucket) or []:
            uri = h.get("uri") or ""
            if not uri:
                continue
            if not include_archived and _is_archived(uri):
                archived_hidden += 1
                continue
            root = _document_root(uri)
            score = h.get("score") if isinstance(h.get("score"), (int, float)) else 0.0
            generated = _leaf(uri) in HIDDEN_PARTS
            abstract = (h.get("abstract") or "").strip().replace("\n", " ")
            g = groups.setdefault(root, {
                "bucket": bucket, "score": score, "parts": 0,
                "abstract": abstract, "content_hit": not generated,
            })
            g["parts"] += 1
            g["score"] = max(g["score"], score)
            if abstract and not g["abstract"]:
                g["abstract"] = abstract
            if not generated:
                g["content_hit"] = True

    if not groups:
        note = f" ({archived_hidden} archived hits hidden)" if archived_hidden else ""
        return "No matches." + note

    # A document that matched on real content outranks one that matched only on
    # its generated abstract at the same score.
    ordered = sorted(groups.items(),
                     key=lambda kv: (kv[1]["score"] + (0.001 if kv[1]["content_hit"] else 0)),
                     reverse=True)
    lines = []
    for root, g in ordered[:limit]:
        extra = f"  ({g['parts']} matching parts)" if g["parts"] > 1 else ""
        lines.append(f"- [{g['score']:.3f}] {root}{extra}")
        if g["abstract"]:
            lines.append(f"    {g['abstract'][:300]}")
    if len(ordered) > limit:
        lines.append(f"... {len(ordered) - limit} more documents matched (raise limit)")
    if archived_hidden:
        lines.append(f"({archived_hidden} hits in archive namespaces hidden; "
                     "pass include_archived=True to see them)")
    return "\n".join(lines)


def _fmt(result: Any, *, limit_chars: int = 6000) -> str:
    """Render a result compactly: hit lists as one line each, else pretty JSON."""
    if _failed(result):
        return _error_text(result)
    if (isinstance(result, list) and result and isinstance(result[0], dict)
            and "rel_path" in result[0]):
        return _fmt_tree(result)
    text = result if isinstance(result, str) else json.dumps(result, indent=2, ensure_ascii=False)
    return text[:limit_chars] + ("\n… (truncated)" if len(text) > limit_chars else "")


server = MCPServer(
    name="ov-memory",
    instructions=(
        "Long-term memory for this machine's agents, stored in a shared OpenViking server. "
        "Search before answering questions about past work, infrastructure or decisions. "
        "Write only when the user asks you to remember something durable."
    ),
)


# --------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------

@server.tool(description=(
    "Semantic search over memories and resources, session-aware. Best first stop for 'what do I "
    "know about X'. scope narrows to a viking:// URI. Results are grouped: one line per document, "
    "not per stored chunk, because an ingested note is many records (its chunks plus a generated "
    "abstract and overview) and ungrouped results are routinely four hits from one note. Notes "
    "under an archive/ namespace are hidden unless include_archived=True."))
def memory_search(query: str, scope: str | None = None, limit: int = 8,
                  score_threshold: float | None = None, group: bool = True,
                  include_archived: bool = False) -> str:
    body: dict[str, Any] = {"query": query, "limit": max(limit * 4, 20) if group else limit}
    if scope:
        body["target_uri"] = scope
    if score_threshold is not None:
        body["score_threshold"] = score_threshold
    return _fmt_hits(_call("POST", "/search/search", json_body=body),
                     limit, group, include_archived)


@server.tool(description=(
    "Semantic search weighted toward stored resources. Use when hunting for a document rather "
    "than a recalled fact. Grouped by document like memory_search."))
def memory_find(query: str, scope: str | None = None, limit: int = 8,
                group: bool = True, include_archived: bool = False) -> str:
    body: dict[str, Any] = {"query": query, "limit": max(limit * 4, 20) if group else limit}
    if scope:
        body["target_uri"] = scope
    return _fmt_hits(_call("POST", "/search/find", json_body=body),
                     limit, group, include_archived)


@server.tool(description="Literal regex/substring search inside a subtree. Use when you know the exact string; semantic search is better for concepts.")
def memory_grep(pattern: str, uri: str = RESOURCES_ROOT, case_insensitive: bool = False) -> str:
    return _fmt(_call("POST", "/search/grep", json_body={
        "uri": uri, "pattern": pattern, "case_insensitive": case_insensitive}))


@server.tool(description="Filename glob within a subtree, e.g. '**/*.md'.")
def memory_glob(pattern: str, uri: str = RESOURCES_ROOT) -> str:
    return _fmt(_call("POST", "/search/glob", json_body={"pattern": pattern, "uri": uri}))


# --------------------------------------------------------------------------
# Navigation
# --------------------------------------------------------------------------

@server.tool(description=(
    "List one directory. Root is '/' and yields the scopes: viking://agent, resources, session, "
    "temp, user. recursive=True walks the whole subtree here, because the server's own recursive "
    "listing stops one level down and silently omits the deeper parts of a chunked document."))
def memory_ls(uri: str = "/", recursive: bool = False, limit: int = 50) -> str:
    if recursive:
        files, dirs = _walk(uri)
        entries = sorted(set(dirs + files))
    else:
        result = _call("GET", "/fs/ls", params={"uri": uri, "simple": True})
        if not isinstance(result, list):
            return _fmt(result)
        entries = [str(x) for x in result]
    total = len(entries)
    text = "\n".join(entries[:limit])
    if total > limit:
        text += f"\n... {total - limit} more of {total} entries (raise limit, or narrow the uri)"
    return text or "(empty directory)"


@server.tool(description="Directory tree with per-node abstracts. Good for orienting in an unfamiliar area of memory.")
def memory_tree(uri: str = "/", level_limit: int = 2) -> str:
    return _fmt(_call("GET", "/fs/tree", params={"uri": uri, "level_limit": level_limit}))


@server.tool(description=(
    "Metadata for one node. For a directory this reports the summed size of its content and how "
    "many parts it holds -- the server's own size field is the inode size (4096 for every "
    "directory) and says nothing about how large the document is."))
def memory_stat(uri: str) -> str:
    st = _stat(uri)
    if st is None:
        return (f"{uri} does not exist. If it still appears in search results, its index record "
                f"is an orphan: memory_index_prune('{uri}') removes it.")
    if not st.get("isDir"):
        return _fmt(st)
    files, dirs = _walk(uri)
    total = 0
    for entry_dir in [uri] + dirs:
        for entry in _ls(entry_dir, detail=True):
            if not entry.get("isDir"):
                total += int(entry.get("size") or 0)
    return _fmt({
        "uri": uri,
        "isDir": True,
        "modTime": st.get("modTime"),
        # Summed over the parts OpenViking lists. Its own generated abstract and
        # overview are hidden from listings and so are not counted here.
        "content_bytes": total,
        "parts": len(files),
        "subdirectories": len(dirs),
        "archived": _is_archived(uri),
    })


@server.tool(description=(
    "Read a stored document. An ingested note is stored as a directory of chunks, so this walks "
    "the whole subtree and returns the parts joined in document order; it never returns an empty "
    "string for a node that has content one level down. offset/limit are line numbers over the "
    "reassembled text. parts=True also lists the URIs the text was assembled from."))
def memory_read(uri: str, offset: int = 0, limit: int | None = None, parts: bool = False) -> str:
    st = _stat(uri)
    if st is None:
        return (f"{uri} does not exist. Check memory_ls on its parent. If it still appears in "
                f"search results, its index record is an orphan: memory_index_prune('{uri}').")
    text, sources = _reassemble(uri)
    if not text:
        listing = "\n".join("- " + s for s in (_ls(uri) or [])) or "  (no children)"
        abstract = _call("GET", "/content/abstract", params={"uri": uri})
        note = (f"{uri} exists but holds no readable text. Its children:\n{listing}")
        if isinstance(abstract, str) and abstract.strip():
            note += "\n\nIts abstract:\n" + abstract.strip()
        return note
    lines = text.split("\n")
    total_lines = len(lines)
    if offset or limit is not None:
        end = offset + limit if limit is not None else None
        lines = lines[offset:end]
    body = "\n".join(lines)
    header = ""
    if len(sources) > 1:
        header = f"[{uri}: reassembled from {len(sources)} parts, {total_lines} lines"
        # Markdown is chunked into a tree of heading-named sections that listings
        # sort by name, so the joined text can run out of order. Flat numbered
        # parts, which everything else is chunked into, cannot.
        if any("/" in s[len(uri) + 1:] for s in sources):
            header += "; sections are joined in name order, which may differ from the "
            header += "original order -- read individual parts with parts=True if it matters"
        header += "]\n\n"
    max_chars = 24000
    truncated = ""
    if len(body) > max_chars:
        shown = body[:max_chars].count("\n") + 1
        body = body[:max_chars]
        truncated = (f"\n… (truncated at {max_chars} characters; {total_lines} lines total, "
                     f"continue with offset={offset + shown})")
    footer = ""
    if parts:
        footer = "\n\nParts:\n" + "\n".join("- " + s for s in sources)
    return header + body + truncated + footer


@server.tool(description="One-paragraph abstract of a DIRECTORY (a document directory counts) -- cheaper than reading it in full when triaging search hits. Files have no abstract; use memory_read.")
def memory_abstract(uri: str) -> str:
    result = _call("GET", "/content/abstract", params={"uri": uri})
    if isinstance(result, dict) and "not a directory" in json.dumps(result):
        parent = uri.rsplit("/", 1)[0]
        return (uri + " is a file, and only directories carry an abstract. Try "
                "memory_abstract('" + parent + "') for its document directory, or "
                "memory_read('" + uri + "') for the text.")
    return _fmt(result)


@server.tool(description="Structured overview of a directory: what it holds and how it is organised.")
def memory_overview(uri: str) -> str:
    return _fmt(_call("GET", "/content/overview", params={"uri": uri}))


@server.tool(description=(
    "How a note connects to others: links recorded in OpenViking, the [[wikilinks]] in its own "
    "text resolved to URIs, and the notes that link back to it. OpenViking itself does not parse "
    "wikilinks, so those two halves are computed here."))
def memory_relations(uri: str) -> str:
    sections: list[str] = []
    stored = _call("GET", "/relations", params={"uri": uri})
    if _failed(stored):
        sections.append("Stored links: " + _error_text(stored))
    elif stored:
        sections.append("Stored links:\n" + _fmt(stored, limit_chars=2000))
    else:
        sections.append("Stored links: none recorded.")

    text, _ = _reassemble(uri)
    outgoing = sorted(set(re.findall(r"\[\[([^\]\|#]+)", text)))
    if outgoing:
        resolved_lines = []
        for name in outgoing:
            target = _resolve_wikilink(name)
            resolved_lines.append(f"- [[{name}]] -> {target}" if target
                                  else f"- [[{name}]] -> (no note with that name)")
        sections.append("Wikilinks in this note:\n" + "\n".join(resolved_lines))
    else:
        sections.append("Wikilinks in this note: none.")

    name = _leaf(_document_root(uri))
    for ext in DOC_EXTS:
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    hits = _call("POST", "/search/grep", json_body={
        "uri": RESOURCES_ROOT, "pattern": re.escape(f"[[{name}]]"), "case_insensitive": False})
    backlinks = sorted({_document_root(m.get("uri", ""))
                        for m in (hits.get("matches") or [])} if isinstance(hits, dict) else set())
    backlinks = [b for b in backlinks if b and b != _document_root(uri)]
    sections.append("Notes linking here:\n" + ("\n".join("- " + b for b in backlinks)
                                               if backlinks else "  none"))
    return "\n\n".join(sections)


def _resolve_wikilink(name: str) -> str | None:
    """The URI of the note a [[wikilink]] names, if one matches."""
    stem = name.strip().removesuffix(".md")
    result = _call("POST", "/search/glob", json_body={
        "pattern": f"**/{stem}.md", "uri": RESOURCES_ROOT})
    if isinstance(result, dict):
        candidates = result.get("matches") or []
    elif isinstance(result, list):
        candidates = result
    else:
        candidates = []
    for candidate in candidates:
        uri = candidate.get("uri") if isinstance(candidate, dict) else str(candidate)
        if uri and _leaf(uri) == f"{stem}.md":
            return uri
    return None


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------

def _ingest(text: str, dest_uri: str, filename: str, reason: str) -> Any:
    """Upload text and have OpenViking ingest it at dest_uri."""
    up = _call("POST", "/resources/temp_upload",
               files={"file": (filename, text.encode("utf-8"), "text/markdown")})
    if not isinstance(up, dict) or "temp_path" not in up:
        return up if _failed(up) else {"_error": "UPLOAD_FAILED", "message": str(up)[:200]}
    # `to` is the destination node, not its parent: passing a directory that
    # already exists fails with "Target URI already exists". Callers name the
    # directory, so the leaf is composed by the caller.
    return _call("POST", "/resources", json_body={
        "temp_path": up["temp_path"], "to": dest_uri, "reason": reason,
        # wait=False: return as soon as OpenViking has stored the note and enqueued
        # the embedding and semantic passes. Those call the OpenAI API over the network
        # and were what made this tool slow. The note is durable and readable on return;
        # it is only missing from semantic search until the queue drains.
        "wait": False, "timeout": TIMEOUT})


def _split_verbatim(text: str, max_chars: int = VERBATIM_PART_CHARS) -> list[str]:
    """Cut text into parts small enough that OpenViking stores each one whole.

    Splits only between two non-blank lines, so that no part begins or ends with
    whitespace that ingestion would trim, and the parts rejoin with a single
    newline exactly as they were cut.
    """
    lines = text.split("\n")
    parts: list[str] = []
    current: list[str] = []
    size = 0
    for i, line in enumerate(lines):
        breakable = (current and line.strip() and current[-1].strip()
                     and size + len(line) > max_chars)
        if breakable:
            parts.append("\n".join(current))
            current, size = [], 0
        current.append(line)
        size += len(line) + 1
    if current:
        parts.append("\n".join(current))
    return parts


def _write_verbatim(text: str, container_uri: str, filename: str,
                    reason: str) -> tuple[int, str | None]:
    """Store text as numbered parts that reassemble byte-for-byte.

    OpenViking chunks anything longer than about a thousand tokens and trims
    whitespace at the cuts, so a long note cannot be recovered character-exact
    from its chunks. Cutting it here instead, into parts it will store whole and
    into names that sort in order, keeps that guarantee for content where it
    matters -- configuration, command output, anything quoted verbatim.

    Each part is confirmed readable before the next one is written. A part can
    lag a second or two behind the call that reported it stored, and one missed
    part is a hole in the middle of a note that otherwise looks complete.
    """
    parts = _split_verbatim(text)
    if _failed(_call("POST", "/fs/mkdir", json_body={"uri": container_uri})):
        return 0, f"Could not create {container_uri}."
    for i, part in enumerate(parts, start=1):
        part_name = f"part-{i:04d}-{filename}"
        part_uri = f"{container_uri}/{part_name}"
        for attempt in (1, 2):
            written = _ingest(part, part_uri, part_name, reason)
            if _failed(written):
                return i - 1, (f"Verbatim write failed on part {i} of {len(parts)}: "
                               f"{_error_text(written)}. {i - 1} part(s) are stored at "
                               f"{container_uri}; remove them with memory_rm before retrying.")
            stored = ""
            for _ in range(6):
                stored, _sources = _reassemble(part_uri)
                if stored.strip() == part.strip():
                    break
                time.sleep(1)
            if stored.strip() == part.strip():
                break
            if attempt == 2:
                return i - 1, (f"Part {i} of {len(parts)} did not read back after being stored "
                               f"twice at {part_uri}. Nothing was lost -- the text is still in "
                               f"this conversation -- but remove {container_uri} with memory_rm "
                               "before retrying.")
            _rm(part_uri, recursive=True)
    return len(parts), None

def _snapshot(uri: str) -> str | None:
    """Best-effort copy of a node's text, so an overwrite that fails mid-way can
    still hand the old content back rather than losing it."""
    text, _ = _reassemble(uri)
    return text or None


@server.tool(description=(
    "Store a durable note. Only for things the user asked to be remembered. 'to' must be under "
    "viking://resources/; pick or create a namespace like viking://resources/projects. The note "
    "is ingested, which means OpenViking splits it into a directory of chunks and generates an "
    "abstract; memory_read joins those back, and verify=True (the default) checks that round-trip "
    "and reports exactly what changed. The filename's extension decides the chunking: a .md note "
    "is split by heading into sections that are listed in name order, so give order-sensitive "
    "content its real extension instead (config.yaml, notes.txt) and it is stored as flat numbered "
    "parts that rejoin byte-exactly. archived=True files the note under an archive/ sub-namespace, "
    "which keeps superseded material out of search results by default. Returns once the note is "
    "stored and indexing is queued, so it may not surface in memory_search for a few seconds."))
def memory_write(text: str, to: str, filename: str, reason: str = "",
                 overwrite: bool = False, archived: bool = False,
                 verbatim: bool = False, verify: bool = True) -> str:
    if not to.startswith(RESOURCES_ROOT):
        return (f"Refused: 'to' must be under {RESOURCES_ROOT}/. The agent scope is written "
                "only by OpenViking's session extraction, and /resources rejects other scopes.")
    # A note is Markdown unless the caller named another format. The extension
    # decides how OpenViking chunks the content: Markdown is split by heading
    # into a name-sorted tree, everything else into flat numbered parts, which is
    # what config and other order-sensitive text needs.
    if not filename.endswith(DOC_EXTS):
        filename += ".md"
    to = to.rstrip("/")
    if archived and not _is_archived(to):
        to = to + "/archive"
    # `to` is the destination directory; the leaf is composed below. Resolve it
    # first so an existing target can be reported (or replaced) before uploading.
    dest_uri = to + "/" + (filename + VERBATIM_SUFFIX if verbatim else filename)
    backup = None
    notes: list[str] = []
    if _exists(dest_uri) and not _walk(dest_uri)[0]:
        # An empty directory is not a note: it is residue from an interrupted
        # write or from the placeholder that index pruning has to create. Clear
        # it rather than refusing to write over nothing.
        _rm(dest_uri, recursive=True)
        notes.append(f"Cleared an empty directory that was standing at {dest_uri}.")
    if _exists(dest_uri):
        if not overwrite:
            return (f"Refused: {dest_uri} already exists. OpenViking has no overwrite flag, so "
                    "replacing a note means deleting it first. Re-run with overwrite=True to do "
                    "that, or write under a different filename. Read the existing note before "
                    "replacing it -- the delete is permanent.")
        backup = _snapshot(dest_uri)
        removed = _purge(dest_uri)
        if "error" in removed:
            return f"Overwrite aborted, nothing changed: could not delete {dest_uri}. {removed['error']}"

    if verbatim:
        stored, error = _write_verbatim(text, dest_uri, filename, reason)
        if error:
            if backup is not None:
                return (f"{error}\n\nThe previous note was already deleted. Its content is "
                        "reproduced below so it can be restored:\n\n" + backup)
            return error
        lines = [f"Stored {dest_uri} as {stored} verbatim part(s)."]
    else:
        written = _ingest(text, dest_uri, filename, reason)
        if _failed(written):
            if backup is not None:
                return (f"Write failed after the old note was deleted: {_error_text(written)}\n\n"
                        "The previous content is reproduced below so it can be restored:\n\n"
                        + backup)
            return _error_text(written)
        lines = [f"Stored {dest_uri}."]

    if verify:
        lines.append(_verify_roundtrip(dest_uri, text))
    links = _link_wikilinks(dest_uri, text)
    if links:
        lines.append(links)
    return "\n".join(notes + lines)


def _verify_roundtrip(uri: str, original: str) -> str:
    """Read the note back the way memory_read would and compare.

    A silent loss in a write-then-delete workflow destroys the only copy, so the
    write is checked rather than assumed, and the reply names which of the
    parser's reshapes happened. Three are expected and lose no text: a Markdown
    document's top-level heading becomes the name of the directory holding it,
    whitespace is trimmed where the content was cut into chunks, and sections are
    listed by name. Anything else -- missing lines, changed text -- is a warning.
    """
    def lines_of(s: str) -> list[str]:
        return [line.rstrip() for line in s.strip().split("\n") if line.strip()]

    stored, sources = _reassemble(uri)
    if stored != original:
        # A part can lag a second behind the write that reported it stored, and a
        # verification that raced it would cry loss where there is none.
        time.sleep(2)
        stored, sources = _reassemble(uri)
    if stored == original:
        return f"Verified: read back byte-for-byte from {len(sources)} part(s)."

    written, read_back = lines_of(original), lines_of(stored)
    if written == read_back:
        return f"Verified: read back line-for-line from {len(sources)} part(s)."

    title = written[0] if written and written[0].startswith("# ") else None
    if title and title not in read_back:
        written = written[1:]  # the H1 is now the name of the document directory
        if written == read_back:
            return (f"Verified: all content read back from {len(sources)} part(s). Its title line "
                    f"({title}) is now the name of the document directory, as OpenViking stores "
                    "it.")

    def squeeze(s: str) -> str:
        return re.sub(r"\s+", "", s)

    if squeeze("\n".join(written)) == squeeze(stored):
        return (f"Verified: no text lost across {len(sources)} part(s), but whitespace differs "
                "where OpenViking cut the content into chunks -- it trims each cut, and a cut that "
                "fell on a space loses it. Write with verbatim=True when the bytes have to come "
                "back exactly.")
    if sorted(written) == sorted(read_back):
        return (f"Verified: no text lost across {len(sources)} part(s), but the sections read back "
                "in a different order, because OpenViking lists them by name. Write with "
                "verbatim=True, or under a non-Markdown extension, when order matters.")
    missing = [line for line in written if line not in read_back]
    return (f"WARNING: the note was stored but reads back differently: {len(missing)} line(s) "
            f"written are not in the {len(sources)} part(s) read back. The original is still in "
            "this conversation -- keep it until the difference is understood, and consider "
            "verbatim=True, which stores the text in parts that rejoin exactly. First missing "
            "line: " + (missing[0][:120] if missing else "(none; the stored text has extra text)"))


def _link_wikilinks(uri: str, text: str) -> str:
    """Record [[wikilinks]] as real OpenViking links, best effort."""
    names = sorted(set(re.findall(r"\[\[([^\]\|#]+)", text)))
    targets = [t for t in (_resolve_wikilink(n) for n in names) if t]
    if not targets:
        return ""
    result = _call("POST", "/relations/link", json_body={
        "from_uri": uri, "to_uris": targets, "reason": "wikilink"})
    if _failed(result):
        return f"({len(targets)} wikilink(s) found but not recorded: {_error_text(result)})"
    return f"Linked {len(targets)} wikilink target(s)."


@server.tool(description="Create a directory under viking://resources/ to group related notes.")
def memory_mkdir(uri: str) -> str:
    if not uri.startswith(RESOURCES_ROOT):
        return f"Refused: only paths under {RESOURCES_ROOT}/ may be created."
    return _fmt(_call("POST", "/fs/mkdir", json_body={"uri": uri}))


@server.tool(description=(
    "Move or rename a node under viking://resources/, and repair the search index afterwards. "
    "OpenViking's own mv leaves the index records of each document's generated abstract and "
    "overview pointing at the old URI, where they outrank live notes and resolve to nothing; "
    "those orphans are pruned here. reindex=True (default) then re-ingests the moved documents so "
    "their abstracts are indexed at the new location -- set it False to move without re-ingesting, "
    "which is faster but leaves the moved notes findable only by their content."))
def memory_mv(from_uri: str, to_uri: str, reindex: bool = True) -> str:
    if not (from_uri.startswith(RESOURCES_ROOT) and to_uri.startswith(RESOURCES_ROOT)):
        return f"Refused: both paths must be under {RESOURCES_ROOT}/."
    if not _exists(from_uri):
        return f"Nothing to move: {from_uri} does not exist."
    _, old_dirs = _walk(from_uri)
    old_subtree = [from_uri] + old_dirs

    moved = _call("POST", "/fs/mv", json_body={"from_uri": from_uri, "to_uri": to_uri})
    if _failed(moved):
        return _error_text(moved)

    pruned = _prune_hidden(old_subtree, from_uri)

    lines = [f"Moved {from_uri} -> {to_uri}.",
             f"Index repaired: {pruned} stale record(s) pruned."]
    if reindex:
        documents = _documents_under(to_uri)
        if len(documents) > 20:
            lines.append(f"Skipped re-ingestion: {len(documents)} documents moved. Their content "
                         "is indexed at the new URIs; run memory_reindex on any whose abstract "
                         "should be searchable again.")
        else:
            done, failed = 0, []
            for doc in documents:
                if _reingest(doc):
                    done += 1
                else:
                    failed.append(doc)
            lines.append(f"Re-ingested {done} document(s) so their abstracts index at the new URI.")
            if failed:
                lines.append("Could not re-ingest: " + ", ".join(failed))
    else:
        lines.append("Not re-ingested: the moved notes are findable by content, but their "
                     "abstracts are no longer in the semantic index.")
    return "\n".join(lines)


def _documents_under(uri: str) -> list[str]:
    """Ingested documents at or under a URI. A document is a directory whose name
    carries a file extension; anything above that is a namespace."""
    if _leaf(uri).endswith(DOC_EXTS):
        return [uri]
    _, dirs = _walk(uri)
    documents = [d for d in dirs if _leaf(d).endswith(DOC_EXTS)]
    return [d for d in documents
            if not any(d != other and d.startswith(other + "/") for other in documents)]


def _reingest(uri: str) -> bool:
    """Rewrite a document in place so its index records match its current URI."""
    text, _ = _reassemble(uri)
    if not text:
        return False
    parent, _, filename = uri.rstrip("/").rpartition("/")
    purged = _purge(uri)
    if "error" in purged:
        return False
    up = _call("POST", "/resources/temp_upload",
               files={"file": (filename, text.encode("utf-8"), "text/markdown")})
    if not isinstance(up, dict) or "temp_path" not in up:
        return False
    written = _call("POST", "/resources", json_body={
        "temp_path": up["temp_path"], "to": uri, "reason": "reindex", "wait": False,
        "timeout": TIMEOUT})
    return not _failed(written)


@server.tool(description=(
    "Re-ingest a note (or every note under a namespace) so that its chunks, abstract and index "
    "records are rebuilt from its current content at its current URI. Use it after a move that "
    "was made without reindexing, or when search returns a note under a URI that no longer "
    "matches where it lives. Content is read back and rewritten, so nothing is lost, but the "
    "abstract is regenerated."))
def memory_reindex(uri: str, force: bool = False) -> str:
    if not uri.startswith(RESOURCES_ROOT):
        return f"Refused: only paths under {RESOURCES_ROOT}/ may be reindexed."
    if not _exists(uri):
        return f"Nothing to reindex: {uri} does not exist."
    documents = _documents_under(uri)
    if not documents:
        return f"No ingested documents under {uri}."
    if len(documents) > 20 and not force:
        return (f"{len(documents)} documents under {uri}. Each is re-read, deleted and rewritten, "
                "and its abstract is regenerated. Re-run with force=True to do all of them, or "
                "name a single note.")
    done, failed = 0, []
    for doc in documents:
        if _reingest(doc):
            done += 1
        else:
            failed.append(doc)
    text = f"Reindexed {done} document(s)."
    if failed:
        text += "\nFailed: " + ", ".join(failed)
    return text


# --------------------------------------------------------------------------
# Deleting and index repair
# --------------------------------------------------------------------------

@server.tool(description=(
    "Permanently delete a note or directory under viking://resources/. There is no trash and no "
    "undo, so run it with dry_run=True first to see exactly what goes. Deleting a directory needs "
    "recursive=True; an ingested document is stored as a directory of chunks, so removing one of "
    "those needs recursive=True too. This also prunes the index records the server's own delete "
    "leaves behind (the generated abstract and overview of every directory removed)."))
def memory_rm(uri: str, recursive: bool = False, dry_run: bool = False) -> str:
    if not uri.startswith(RESOURCES_ROOT):
        return f"Refused: only paths under {RESOURCES_ROOT}/ may be deleted."
    if uri.rstrip("/") == RESOURCES_ROOT:
        return f"Refused: {RESOURCES_ROOT} is the whole resources scope and will not be deleted."
    if not _exists(uri):
        if _prune_index(uri):
            return (f"{uri} did not exist on disk. Its leftover search-index record, if any, has "
                    "been pruned.")
        return f"Nothing to delete: {uri} does not exist."

    files, dirs = _walk(uri)
    if dry_run:
        listing = "\n".join("- " + f for f in files[:40])
        more = f"\n... and {len(files) - 40} more parts" if len(files) > 40 else ""
        return (f"dry_run: would delete {uri} with {len(files)} part(s) in {len(dirs)} "
                f"subdirectory/ies, and prune their index records.\n{listing}{more}\n"
                "Re-run with dry_run=False" + ("" if recursive or not dirs else " and recursive=True")
                + " to do it.")
    if (files or dirs) and not recursive:
        return (f"{uri} is a directory holding {len(files)} part(s). Re-run with recursive=True to "
                "remove it and its parts.")
    result = _purge(uri)
    if "error" in result:
        return result["error"]
    done = (f"Deleted {uri}: {result['files']} part(s), {result['dirs']} subdirectory/ies, "
            f"{result['pruned']} index record(s) pruned.")
    if _exists(uri):
        # OpenViking generates each directory's abstract asynchronously, and a
        # pass that was already running rewrites the directory after the delete.
        # What is left holds no content and no index records; deleting again
        # clears it once that pass has finished.
        return (done + f"\nOpenViking's indexing pass has since recreated an empty {uri}. It "
                "holds no content -- run memory_rm again to clear it.")
    return done


@server.tool(description=(
    "Remove the search-index record of a URI that no longer exists -- the repair for a hit that "
    "ranks high and then resolves to nothing. OpenViking's delete cannot do this, because it "
    "removes the node before cleaning the index and so fails on a node that is already gone. "
    "Refuses when the URI does exist; delete that with memory_rm instead."))
def memory_index_prune(uri: str) -> str:
    if not uri.startswith(RESOURCES_ROOT):
        return f"Refused: only paths under {RESOURCES_ROOT}/ may be pruned."
    if _exists(uri):
        return (f"{uri} exists, so its index record is not an orphan. Use memory_rm to delete the "
                "note itself, or memory_reindex to rebuild its records.")
    if _prune_index(uri):
        return f"Pruned the index record for {uri}. Search should stop returning it immediately."
    return f"Could not prune {uri}: the placeholder needed to reach the index cleanup could not be created."


@server.tool(description=(
    "Check whether what search returns still exists. Runs the query, resolves every hit, and "
    "reports the ones whose node is gone -- the orphaned index records that OpenViking's mv "
    "leaves behind. fix=True prunes them. Nothing lists the index directly, so a query is how "
    "orphans are found; use the query that surfaced the bad hit."))
def memory_index_audit(query: str, scope: str | None = None, limit: int = 40,
                       fix: bool = False) -> str:
    body: dict[str, Any] = {"query": query, "limit": limit}
    if scope:
        body["target_uri"] = scope
    result = _call("POST", "/search/search", json_body=body)
    if _failed(result) or not isinstance(result, dict):
        return _fmt(result)
    checked, orphans = 0, []
    for bucket in ("memories", "resources"):
        for hit in result.get(bucket) or []:
            uri = hit.get("uri")
            if not uri:
                continue
            checked += 1
            if not _exists(uri):
                orphans.append(uri)
    if not orphans:
        return f"Checked {checked} hit(s) for '{query}': every one resolves to a stored node."
    lines = [f"Checked {checked} hit(s) for '{query}'. {len(orphans)} resolve to nothing:"]
    lines += ["- " + o for o in orphans]
    if not fix:
        lines.append("Re-run with fix=True to prune these index records.")
        return "\n".join(lines)
    pruned = sum(1 for o in orphans if o.startswith(RESOURCES_ROOT) and _prune_index(o))
    lines.append(f"Pruned {pruned} of {len(orphans)}. Records outside {RESOURCES_ROOT} are left "
                 "alone: this server only writes to the resources scope.")
    return "\n".join(lines)


@server.tool(description="Health and identity of the memory server -- use to diagnose connection problems.")
def memory_status() -> str:
    return _fmt({"base_url": BASE_URL, "agent": AGENT, "status": _call("GET", "/system/status")})


def _selftest() -> int:
    """Connectivity, plus the guarantees this server makes about a stored note.

    The writes are real: they land in a scratch namespace, are read back and
    compared with what was sent, are moved to prove the index repair, and are
    then deleted. A failure here means an agent cannot tell a stored note from a
    lost one, which is the failure mode worth paying three test notes for.
    """
    print("status:", memory_status())
    print("ls:", memory_ls("/"))
    print("search:", memory_search("home assistant", limit=2)[:400])

    scratch = f"{RESOURCES_ROOT}/selftest-ov-mcp"
    failures = []
    records = "\n".join(
        f"- id: '{i:04d}'\n  name: ov-mcp selftest record {i}\n  note: "
        + "padding text for the selftest record. " * 10
        for i in range(1, 90)
    )

    # verbatim=True is the only path that promises the bytes back. It has to hold
    # for content with no blank lines and trailing spaces, which is where
    # OpenViking's own chunking trims.
    print("write (verbatim):", memory_write(records, scratch, "records.yaml",
                                            reason="ov-mcp selftest", verbatim=True))
    stored, parts = _reassemble(f"{scratch}/records.yaml{VERBATIM_SUFFIX}")
    exact = stored == records
    print(f"verbatim roundtrip: {'ok' if exact else 'MISMATCH'} ({len(parts)} parts, "
          f"{len(records)} written, {len(stored)} read back)")
    if not exact or len(parts) < 2:
        failures.append("verbatim roundtrip")

    # Ordinary ingestion promises less: no text lost, and the parts in order.
    # More than nine parts, so that sorting by name would put part 10 second.
    print("write (flat):", memory_write(records, scratch, "flat.yaml",
                                        reason="ov-mcp selftest"))
    stored, parts = _reassemble(f"{scratch}/flat.yaml")
    # Whitespace at a cut is trimmed by the parser and cannot be recovered, so
    # the guarantee checked here is that no text is lost.
    intact = re.sub(r"\s+", "", stored) == re.sub(r"\s+", "", records)
    print(f"flat roundtrip: {'ok' if intact else 'MISMATCH'} ({len(parts)} parts, "
          f"no text lost: {intact})")
    if not intact or len(parts) < 10:
        failures.append("flat roundtrip")

    # Markdown is reshaped -- title into the directory name, sections listed by
    # name -- but no line of content may go missing.
    document = "# ov-mcp selftest\n\n" + "\n\n".join(
        f"## Section {i}\n\n" + f"Line {i} of the ov-mcp selftest document. " * 40
        for i in range(1, 12)
    ) + "\n"
    print("write (markdown):", memory_write(document, scratch, "document.md",
                                            reason="ov-mcp selftest"))
    stored, parts = _reassemble(f"{scratch}/document.md")
    read_back = [line.strip() for line in stored.strip().split("\n") if line.strip()]
    lost = [line.strip() for line in document.strip().split("\n")
            if line.strip() and not line.startswith("# ") and line.strip() not in read_back]
    print(f"markdown roundtrip: {'ok' if not lost else 'MISMATCH'} ({len(parts)} parts, "
          f"{len(lost)} line(s) lost)")
    if lost:
        failures.append("markdown roundtrip")

    print("mv:", memory_mv(f"{scratch}/document.md", f"{scratch}/moved.md", reindex=False))
    orphans = [f"{scratch}/document.md/{hidden}" for hidden in HIDDEN_PARTS]
    repaired = not any(_exists(o) for o in orphans)
    print("index repair:", "ok" if repaired else "MISMATCH")
    if not repaired:
        failures.append("index repair")

    print("cleanup:", memory_rm(scratch, recursive=True))
    if failures:
        print("FAILED:", ", ".join(failures))
        return 1
    print("selftest ok")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    server.run(transport="stdio")
