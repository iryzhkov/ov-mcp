# ov-mcp

An MCP server that exposes an OpenViking memory store to local agents.

OpenViking ships no MCP module of its own — only the `ov` CLI and Python clients — so this wraps
its HTTP API over stdio. Install it wherever an agent needs the store — typically at
`~/.local/lib/ov-mcp`, registered in `~/.claude.json` as the `ov-memory` server.

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

`memory_write` verifies by default: it reads the note back the way `memory_read` does and compares
it with what was sent, so a parser that reshapes the content is reported rather than discovered
later. `archived=True` files the note under an `archive/` sub-namespace, which keeps superseded
material out of search results unless it is asked for.

### How much of a note survives a round trip

Ingestion cuts anything longer than about a thousand tokens into chunks, and what a chunk boundary
does to the text depends on the extension the note was written under. Measured against a live 0.2.6
server, and asserted by `--selftest`:

| Written as | Stored as | Comes back |
|---|---|---|
| `note.md` | a tree of sections named after their headings | every line, but the title becomes the directory's name and sections are joined in name order |
| `config.yaml`, `notes.txt`, … | flat parts numbered in document order | every word; whitespace at a cut is trimmed by the parser and cannot be recovered |
| any name, `verbatim=True` | numbered parts cut here, each small enough to be stored whole | the bytes, exactly |

So `verbatim=True` is the option for content that has to come back character-for-character —
configuration, command output, anything quoted. It costs a directory of small notes instead of one,
and search treats that directory as a single document. Prose does not need it.

### Deleting is not always instant

OpenViking generates each directory's abstract in a background pass. A delete that lands while that
pass is running can be followed by the pass recreating the directory, holding nothing but a
regenerated abstract. `memory_rm` reports it when it happens and a second call clears it; a write to
that name clears it on its own, because an empty directory is not a note.

## Working around OpenViking 0.2.6

Three server behaviours are wrong or misleading in ways an agent cannot see. Each of the
workarounds below was verified against a live 0.2.6 server; if a later release fixes the behaviour,
the workaround becomes a no-op rather than a hazard.

**`POST /fs/mv` half-updates the vector index.** It rewrites the index records of the files it can
list, but `.abstract.md` and `.overview.md` are filtered out of that listing, so their records keep
pointing at the old URI. They then outrank live notes for their subject and resolve to nothing.
`memory_mv` prunes those orphans after the move, and by default re-ingests the moved documents so
their abstracts are indexed at the new location; `reindex=False` skips that.

**`DELETE /fs` cannot clean up after it.** OpenViking removes the node first and cleans the index
second, so on a node that is already gone it raises before the cleanup runs and the orphaned record
is unreachable — there is no re-index endpoint and nothing lists index records. Creating a
directory at the orphan URI and removing it recursively does reach the cleanup, and that is what
`memory_index_prune` does. `memory_index_audit` finds the orphans in the first place: it runs a
query, resolves every hit, and reports (or with `fix=True` prunes) the ones whose node is missing.
`memory_rm` prunes the hidden records the server's own delete leaves behind, and takes `dry_run` so
an irreversible delete can be inspected first.

**Reads and deletes under-report.** `GET /content/read` returns an empty string for an ingested
document, because the content is one level down, and `GET /fs/ls?recursive=true` stops after one
level. An empty read is indistinguishable from a missing note, which is dangerous in a
write-verify-delete workflow. `memory_read` therefore walks the subtree itself and returns the parts
joined, and when a node really has no text it says so and lists what the node does hold.
`memory_ls(recursive=True)` and `memory_stat` walk the same way, so a directory reports the summed
size of its content rather than the inode size of 4096 that the server returns for every directory.

Deletes need the same scepticism: a recursive delete can answer `ok` having removed only part of the
subtree, and `stat` then reports the parent missing while its children are still there — residue
that reads back as a note which was supposedly deleted, and blocks the next write to that name.
`memory_rm` checks the subtree it was given, deepest node first, and only reports the delete as done
when nothing is left.

## Search results

An ingested note is many index records: one per chunk, plus a generated abstract and overview. Raw
results are therefore dominated by whichever note matched — four of five hits describing one
document is normal. `memory_search` and `memory_find` group hits by document, keep the best score,
prefer a content chunk over a generated abstract as the representative, and report how many other
parts matched. `group=False` returns the raw records.

## Relations

OpenViking records links but parses no `[[wikilinks]]`, so `/relations` is empty on a store whose
notes are full of them. `memory_write` resolves the wikilinks in a new note and records them as
real links, and `memory_relations` reports three things: the links OpenViking has stored, the
wikilinks in the note resolved to URIs, and the notes that link back to it.
