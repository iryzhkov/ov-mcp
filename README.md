# ov-mcp

An MCP server that exposes the OpenViking memory store on homelab to local agents.

OpenViking ships no MCP module of its own — only the `ov` CLI and Python clients — so this wraps
its HTTP API over stdio. It runs on both the Asahi MacBook and gaming-pc, in each case installed at
`~/.local/lib/ov-mcp` and registered in `~/.claude.json` as the `ov-memory` server.

## Running it

The server is launched by Claude Code, not by hand:

```json
{
  "ov-memory": {
    "type": "stdio",
    "command": "/home/igor/.local/lib/ov-mcp/venv/bin/python",
    "args": ["/home/igor/.local/lib/ov-mcp/server.py"]
  }
}
```

`./venv/bin/python server.py --selftest` checks connectivity without going through MCP.

## Configuration

Settings live in `~/.config/ov-mcp/config.toml`. Copy `config.example.toml` there and edit it. That
path is deliberately outside the repository, so no address, host or key belonging to a particular
deployment is ever committed.

| Setting | Environment variable | Default | Purpose |
|---|---|---|---|
| `base_url` | `OV_BASE_URL` | `http://localhost:1933` | OpenViking API root |
| `agent` | `OV_AGENT` | `claude-code` | Sent as `X-OpenViking-Agent` |
| `timeout` | `OV_TIMEOUT` | `120` | HTTP timeout in seconds |
| `api_key` | `OV_API_KEY` | — | API key |

The environment wins over the config file, which wins over the defaults above. For the API key the
order is `OV_API_KEY`, then `api_key` in the config file, then the GNOME keyring
(`service=openviking key=api`). No key is stored in this repository or in `~/.claude.json`.

A missing config file is not an error — the server falls back to `localhost`. Malformed TOML is
reported on stderr and then ignored.

## Write semantics

Writes are confined to the `viking://resources/` scope. The agent scope is written only by
OpenViking's own session extraction, and the `/resources` endpoint rejects anything else.

OpenViking has no overwrite flag, so `memory_write(..., overwrite=True)` implements replacement as
delete-then-write. It snapshots the existing content first and hands it back in the error if either
the upload or the write fails, so a half-completed replacement does not lose the old note.

Note that a note written through `/resources` is *ingested*: OpenViking stores it as a directory of
chunks rather than as a plain file. Passing a `to` that already holds a document therefore nests a
new document directory inside it rather than replacing it — pass the parent directory and let the
leaf be composed, and use `overwrite=True` when replacing.
