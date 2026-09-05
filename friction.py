"""Friction spool: one JSON line per MCP tool call, appended to a local file.

This is the same spool agent99 and mcp-local-file-llm write, and the format has
to match theirs: ``<data dir>/<source>/<host>-<date>.jsonl``, one JSON object
per line. The ``toolfeedback`` command in homelab-cli reads all of them
together, so a weekly pass can rank which of these tools agents actually
struggle with instead of asking one afterwards.

What is recorded is the shape of a call: the tool, which argument names were
present, whether it failed, a redacted class of the error, and how long it
took. Never argument values or replies, because for this server those are the
contents of the memory store. Error messages are folded into a class first, so
one failure seen twenty times is one line rather than twenty.

Off unless someone asked for it: create the marker file with ``toolfeedback
enable``, or set ``TOOLFEEDBACK=1``. Writing the spool must never affect a tool
call, so every failure in here is swallowed.
"""

from __future__ import annotations

import datetime as dt
import functools
import inspect
import json
import os
import re
import secrets
import socket
import time

SOURCE = "ov-memory"

_seq = 0
_proc = secrets.token_hex(6)
_session = os.environ.get("CLAUDE_CODE_SESSION_ID") or f"anon-{secrets.token_hex(6)}"
_host = socket.gethostname().split(".")[0]


def _data_dir() -> str:
    if os.environ.get("TOOLFEEDBACK_DIR"):
        return os.environ["TOOLFEEDBACK_DIR"]
    xdg = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(xdg, "toolfeedback")


def _enabled() -> bool:
    """Whether calls are spooled.

    Off by default. This is a shared tool, and nobody else's use of it should
    start producing a record of itself because they installed it. Either way
    the spool is a file on the local machine and nothing transmits it anywhere;
    collecting it is a separate, equally deliberate step.
    """
    forced = os.environ.get("TOOLFEEDBACK")
    if forced == "1":
        return True
    if forced == "0":
        return False
    return os.path.exists(os.path.join(_data_dir(), "enabled"))


# Keep this fold identical to errClass in agent99's bridge/friction.go, err_class
# in homelab-cli's toolfeedback, and errClass in mcp-local-file-llm's
# friction.mjs. They have to agree: the report groups their events together.
_PATH_RE = re.compile(r"(?:[A-Za-z]:)?[\w.~@+-]*(?:/[\w.~@+-]+)+")
_FILE_RE = re.compile(r"\b[\w-]{2,}\.[A-Za-z]{1,5}\b")
_QUOTE_RE = re.compile(r"\"[^\"]*\"|'[^']*'")
_NUM_RE = re.compile(r"\d+")
_SPACE_RE = re.compile(r"\s+")


def err_class(text: str) -> str:
    line = str(text or "").split("\n", 1)[0]
    if line.startswith("Error: "):
        line = line[len("Error: "):]
    line = _PATH_RE.sub("<path>", line)
    line = _FILE_RE.sub("<path>", line)
    line = _QUOTE_RE.sub("<str>", line)
    line = _NUM_RE.sub("<n>", line)
    line = _SPACE_RE.sub(" ", line).strip()
    return line[:160]


def looks_failed(result) -> bool:
    """Whether a returned value is this server telling the agent it failed.

    Most tools here answer with prose and report an API failure as a line of
    text rather than by raising, so a spool that only counted exceptions would
    call every one of those a success.
    """
    if isinstance(result, str):
        return result.startswith("OpenViking error") or result.startswith("Error:")
    if isinstance(result, dict):
        return "error" in result or "_error" in result or "_http_error" in result
    return False


def _write(event: dict) -> None:
    directory = os.path.join(_data_dir(), SOURCE)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, f"{_host}-{event['ts'][:10]}.jsonl")
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "w",
              encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")


def log_call(tool: str, args: dict, ok: bool, error_text: str, started: float,
             version: str = "") -> None:
    if not _enabled():
        return
    try:
        global _seq
        _seq += 1
        event = {
            "ts": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "host": _host,
            "session": _session,
            "proc": _proc,
            "seq": _seq,
            "tool": tool,
            "ok": ok,
            "ms": int((time.monotonic() - started) * 1000),
        }
        if version:
            event["ver"] = version
        if args:
            event["args"] = sorted(args)[:24]
        if not ok:
            event["err"] = err_class(error_text)
        _write(event)
    except Exception:
        pass  # a lost event is better than a failed call


def instrument(server, version: str = "") -> None:
    """Wrap every tool this server registers from here on.

    The tools are plain functions behind a decorator rather than a single
    dispatch point, so the decorator is where all of them can be reached at
    once - and reached without a line of bookkeeping in any tool.
    """
    original = server.tool

    @functools.wraps(original)
    def tool(*d_args, **d_kwargs):
        decorate = original(*d_args, **d_kwargs)

        def wrap(func):
            signature = inspect.signature(func)

            @functools.wraps(func)
            def wrapped(*args, **kwargs):
                started = time.monotonic()
                try:
                    names = signature.bind_partial(*args, **kwargs).arguments
                except TypeError:
                    names = kwargs
                try:
                    result = func(*args, **kwargs)
                except Exception as exc:
                    log_call(func.__name__, names, False,
                             f"{type(exc).__name__}: {exc}", started, version)
                    raise
                failed = looks_failed(result)
                log_call(func.__name__, names, not failed,
                         result if failed else "", started, version)
                return result

            return decorate(wrapped)

        return wrap

    server.tool = tool
