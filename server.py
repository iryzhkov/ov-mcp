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
"""

import json
import os
import pathlib
import subprocess
import sys
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


def _fmt(result: Any, *, limit_chars: int = 6000) -> str:
    """Render a result compactly: hit lists as one line each, else pretty JSON."""
    if isinstance(result, dict) and ("_error" in result or "_http_error" in result):
        return _error_text(result)
    if (isinstance(result, list) and result and isinstance(result[0], dict)
            and "rel_path" in result[0]):
        return _fmt_tree(result)
    if isinstance(result, dict) and any(k in result for k in ("memories", "resources")):
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


@server.tool(description="Semantic search over memories and resources, session-aware. Best first stop for 'what do I know about X'. scope narrows to a viking:// URI.")
def memory_search(query: str, scope: str | None = None, limit: int = 8,
                  score_threshold: float | None = None) -> str:
    body: dict[str, Any] = {"query": query, "limit": limit}
    if scope:
        body["target_uri"] = scope
    if score_threshold is not None:
        body["score_threshold"] = score_threshold
    return _fmt(_call("POST", "/search/search", json_body=body))


@server.tool(description="Semantic search weighted toward stored resources. Use when hunting for a document rather than a recalled fact.")
def memory_find(query: str, scope: str | None = None, limit: int = 8) -> str:
    body: dict[str, Any] = {"query": query, "limit": limit}
    if scope:
        body["target_uri"] = scope
    return _fmt(_call("POST", "/search/find", json_body=body))


@server.tool(description="Literal regex/substring search inside a subtree. Use when you know the exact string; semantic search is better for concepts.")
def memory_grep(pattern: str, uri: str = RESOURCES_ROOT, case_insensitive: bool = False) -> str:
    return _fmt(_call("POST", "/search/grep", json_body={
        "uri": uri, "pattern": pattern, "case_insensitive": case_insensitive}))


@server.tool(description="Filename glob within a subtree, e.g. '**/*.md'.")
def memory_glob(pattern: str, uri: str = RESOURCES_ROOT) -> str:
    return _fmt(_call("POST", "/search/glob", json_body={"pattern": pattern, "uri": uri}))


@server.tool(description="List one directory. Root is '/' and yields the scopes: viking://agent, resources, session, temp, user.")
def memory_ls(uri: str = "/", recursive: bool = False, limit: int = 50) -> str:
    result = _call("GET", "/fs/ls", params={"uri": uri, "simple": True, "recursive": recursive})
    if isinstance(result, list):
        total = len(result)
        text = "\n".join(str(x) for x in result[:limit])
        if total > limit:
            text += f"\n... {total - limit} more of {total} entries (raise limit, or narrow the uri)"
        return text or "(empty directory)"
    return _fmt(result)


@server.tool(description="Directory tree with per-node abstracts. Good for orienting in an unfamiliar area of memory.")
def memory_tree(uri: str = "/", level_limit: int = 2) -> str:
    return _fmt(_call("GET", "/fs/tree", params={"uri": uri, "level_limit": level_limit}))


@server.tool(description="Metadata for one node: size, type, modification time.")
def memory_stat(uri: str) -> str:
    return _fmt(_call("GET", "/fs/stat", params={"uri": uri}))


@server.tool(description="Read a stored document. Supports offset/limit for long files.")
def memory_read(uri: str, offset: int = 0, limit: int | None = None) -> str:
    params: dict[str, Any] = {"uri": uri, "offset": offset}
    if limit is not None:
        params["limit"] = limit
    result = _call("GET", "/content/read", params=params)
    if result not in ("", None):
        return _fmt(result)
    # OpenViking stores an ingested document as a directory of chunks, so reading
    # it yields "" -- indistinguishable from an empty file. Resolve to the chunks.
    children = _call("GET", "/fs/ls", params={"uri": uri, "simple": True})
    if isinstance(children, list) and children:
        visible = [c for c in children if not str(c).rsplit("/", 1)[-1].startswith(".")]
        if len(visible) == 1:
            inner = {"uri": visible[0], "offset": offset}
            if limit is not None:
                inner["limit"] = limit
            body = _call("GET", "/content/read", params=inner)
            return f"[{uri} is a document directory; showing its single part]\n\n" + _fmt(body)
        listing = "\n".join("- " + str(c) for c in (visible or children))
        return f"[{uri} is a directory, not a file. Its parts:]\n" + listing
    return "(empty)"


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


@server.tool(description="Linked nodes for a URI -- how this memory connects to others.")
def memory_relations(uri: str) -> str:
    return _fmt(_call("GET", "/relations", params={"uri": uri}))


def _exists(uri: str) -> bool:
    """True if the URI resolves to a node. Errors count as absent."""
    st = _call("GET", "/fs/stat", params={"uri": uri})
    return isinstance(st, dict) and "_error" not in st and "_http_error" not in st


def _snapshot(uri: str) -> str | None:
    """Best-effort copy of a node's text, so an overwrite that fails mid-way can
    still hand the old content back rather than losing it."""
    body = _call("GET", "/content/read", params={"uri": uri})
    if isinstance(body, str) and body:
        return body
    children = _call("GET", "/fs/ls", params={"uri": uri, "simple": True})
    if isinstance(children, list):
        parts = []
        for c in children:
            if str(c).rsplit("/", 1)[-1].startswith("."):
                continue
            inner = _call("GET", "/content/read", params={"uri": c})
            if isinstance(inner, str) and inner:
                parts.append(inner)
        if parts:
            return "\n\n".join(parts)
    return None


def _rm(uri: str, recursive: bool) -> Any:
    return _call("DELETE", "/fs", params={"uri": uri, "recursive": recursive})


@server.tool(description="Store a durable note. Only for things the user asked to be remembered. 'to' must be under viking://resources/; pick or create a namespace like viking://resources/projects. Returns once the note is stored and indexing is queued, so it may not surface in memory_search for a few seconds.")
def memory_write(text: str, to: str, filename: str, reason: str = "",
                 overwrite: bool = False) -> str:
    if not to.startswith(RESOURCES_ROOT):
        return (f"Refused: 'to' must be under {RESOURCES_ROOT}/. The agent scope is written "
                "only by OpenViking's session extraction, and /resources rejects other scopes.")
    if not filename.endswith(".md"):
        filename += ".md"
    # `to` is the destination directory; the leaf is composed below. Resolve it
    # first so an existing target can be reported (or replaced) before uploading.
    dest_uri = to.rstrip("/") + "/" + filename
    backup = None
    if _exists(dest_uri):
        if not overwrite:
            return (f"Refused: {dest_uri} already exists. OpenViking has no overwrite flag, so "
                    "replacing a note means deleting it first. Re-run with overwrite=True to do "
                    "that, or write under a different filename. Read the existing note before "
                    "replacing it -- the delete is permanent.")
        backup = _snapshot(dest_uri)
        removed = _rm(dest_uri, recursive=True)
        if isinstance(removed, dict) and ("_error" in removed or "_http_error" in removed):
            return f"Overwrite aborted, nothing changed: could not delete {dest_uri}. {_error_text(removed)}"

    up = _call("POST", "/resources/temp_upload",
               files={"file": (filename, text.encode("utf-8"), "text/markdown")})
    if not isinstance(up, dict) or "temp_path" not in up:
        msg = f"Upload failed: {_fmt(up)}"
        if backup is not None:
            msg += ("\n\nThe previous note was already deleted. Its content is reproduced below "
                    "so it can be restored by writing it back:\n\n" + backup)
        return msg
    # `to` is the destination node, not its parent: passing a directory that
    # already exists fails with "Target URI already exists". Callers name the
    # directory, so compose the leaf here.
    written = _call("POST", "/resources", json_body={
        "temp_path": up["temp_path"], "to": dest_uri, "reason": reason,
        # wait=False: return as soon as OpenViking has stored the note and enqueued
        # the embedding and semantic passes. Those call the OpenAI API over the network
        # and were what made this tool slow. The note is durable and readable on return;
        # it is only missing from semantic search until the queue drains.
        "wait": False, "timeout": TIMEOUT})
    if backup is not None and isinstance(written, dict) and (
            "_error" in written or "_http_error" in written):
        return (f"Overwrite failed after the old note was deleted: {_error_text(written)}\n\n"
                "The previous content is reproduced below so it can be restored:\n\n" + backup)
    return _fmt(written)


@server.tool(description="Create a directory under viking://resources/ to group related notes.")
def memory_mkdir(uri: str) -> str:
    if not uri.startswith(RESOURCES_ROOT):
        return f"Refused: only paths under {RESOURCES_ROOT}/ may be created."
    return _fmt(_call("POST", "/fs/mkdir", json_body={"uri": uri}))


@server.tool(description="Move or rename a node under viking://resources/.")
def memory_mv(from_uri: str, to_uri: str) -> str:
    if not (from_uri.startswith(RESOURCES_ROOT) and to_uri.startswith(RESOURCES_ROOT)):
        return f"Refused: both paths must be under {RESOURCES_ROOT}/."
    return _fmt(_call("POST", "/fs/mv", json_body={"from_uri": from_uri, "to_uri": to_uri}))


@server.tool(description=(
    "Permanently delete a note or directory under viking://resources/. There is no trash and no "
    "undo. Use it only when the user has asked for something to be removed, or to clear a note "
    "you are replacing. Read the node first so its content is recoverable if the deletion turns "
    "out to be wrong. Deleting a directory needs recursive=True; an ingested document is stored "
    "as a directory of chunks, so removing one of those needs recursive=True too."))
def memory_rm(uri: str, recursive: bool = False) -> str:
    if not uri.startswith(RESOURCES_ROOT):
        return f"Refused: only paths under {RESOURCES_ROOT}/ may be deleted."
    if uri.rstrip("/") == RESOURCES_ROOT:
        return f"Refused: {RESOURCES_ROOT} is the whole resources scope and will not be deleted."
    if not _exists(uri):
        return f"Nothing to delete: {uri} does not exist."
    result = _rm(uri, recursive)
    if isinstance(result, dict) and ("_error" in result or "_http_error" in result):
        text = _error_text(result)
        if "recursive" in text.lower() or "directory" in text.lower():
            text += "\n(That URI is a directory. Re-run with recursive=True to remove it and its parts.)"
        return text
    return f"Deleted {uri}" + (" and its contents." if recursive else ".")


@server.tool(description="Health and identity of the memory server -- use to diagnose connection problems.")
def memory_status() -> str:
    return _fmt({"base_url": BASE_URL, "agent": AGENT, "status": _call("GET", "/system/status")})


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        print("status:", memory_status())
        print("ls:", memory_ls("/"))
        print("search:", memory_search("home assistant", limit=2)[:400])
        sys.exit(0)
    server.run(transport="stdio")
