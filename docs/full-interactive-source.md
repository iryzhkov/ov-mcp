# Full interactive HTTP source preparation

This branch is not a deployed full-parity release. The live bounded reader remains unchanged. Mutations, safe orphan repair, qualified backend artifacts and four native host/provider checks are still required before replacing stdio.

The default semantic profile remains disabled. The existing `namespace-directories-v1` profile keeps its exact namespace-admission and scope-assertion behavior.

The opt-in `resources-directories-v052-v1` search profile requires the exact search-path source revision `7f3ae1af822d936c1d0b070537772b0f1d59122f` and the single operator ceiling `viking://resources`. This identifies the v0.5.2 search contract exercised by the isolated package proof. A changed backend artifact still needs exact source/artifact qualification; this constant does not qualify a patched image or authorize deployment.

Tokens still supply their own signed namespace grants. The profile admits narrower canonical grants beneath the ceiling, preserving the existing file canary. Search requires a directory grant; a file token can read its file metadata but cannot use the parent as a search target. The full resources token can search all its grants or pass an authorized directory as `scope` to narrow the backend target before retrieval, ranking and counts. The legacy profile continues to treat `scope` as an exact-grant assertion.

Search/find send only explicit authorized target URIs with resource context and retain whole-call refusal for an unexpected foreign URI. Archive visibility remains controlled by `include_archived`, including raw ungrouped results. Results are bounded incomplete batches, not an exhaustive inventory or cursor. The resources profile now has bounded filesystem browse paging as described below. Other traversal tools still retain their existing scan limits.

Explicit signed `ov_actions` are checked against scopes. Missing actions mean read-only even if extra scopes were requested. The per-request grant digest includes effective actions. These checks prepare the mutation authorization boundary; no additional mutation tools are exposed yet.

## Resources browse paging, source only

This paging addition is unreviewed and not deployed. Only `resources-directories-v052-v1` adds `offset` to the existing `memory_ls` and `memory_tree` tools. Disabled and legacy namespace profiles retain their catalog, argument schemas and call behavior.

Pass an exact authorized directory URI, or omit it when the token has exactly one directory grant. Multiple grants require an explicit directory to avoid a merged offset with ambiguous authority. Every request checks the current subject's signed grants, expiry and read action. It checks that exact URI with stat before listing. A file-only token receives no ancestor lookup or parent listing. Offsets are plain positions, never authority or a snapshot.

The adapter sends one bounded listing request after that stat. Limits remain 1..100 at the tool boundary, with an effective maximum of 40 paths per page to fit the 49,152-byte MCP output cap even for maximum-length canonical URIs. Offsets are 0..100,000. Follow `next_offset` with the same URI and traversal settings. `has_more` and `truncated` describe that bounded query at the time of the call. At the offset ceiling a further page can be unavailable even when `has_more` is true; `continuation_limited` reports that case. `complete` always remains false. Concurrent insertions, deletions or renames can repeat or omit entries. No snapshot or exhaustive inventory is claimed.

Nonrecursive browse uses `/fs/ls` with explicit name ascending order, original rows, offset and node_limit. Simple ls is deliberately disabled because it erases native denied placeholders before validation. The adapter projects paths only after validating each original row. Recursive ls and tree use `/fs/tree` with original output, explicit offset/node_limit and depth. Recursive ls has depth 12; tree defaults to 2 and accepts 1..12. The tree router has no sort arguments, so its backend default DFS order is retained. Both requests disable abstracts, overviews, tags and hidden files and request no extra fields. The adapter returns only paths and local bounded-page metadata. It discards upstream counts, summaries and arbitrary metadata. It refuses malformed `has_more`, excessive or duplicate entries, foreign or out-of-query URIs, unexpected hidden paths and denied placeholders as a whole call. It never fetches an unscoped global tree and then filters a page.

All three archive names, `archive`, `archived` and `_archive`, remain visible during browse. Hidden files and internal summaries/locks are not inventory entries. Unexpected dot-directory paths also refuse the page under this conservative adapter check, although upstream can expose ordinary dot directories. Existing canonical ASCII validation excludes otherwise legitimate Unicode and space-bearing names. A page containing one refuses safely; it does not skip the entry and claim exhaustion. URI policy and ordinary dot-directory coverage need a separate root decision.

Native contract inspected at upstream `7f3ae1af822d936c1d0b070537772b0f1d59122f`:

- `openviking/server/routers/filesystem.py`, ls and tree, forwards visible-node offsets and node limits and returns top-level `has_more`.
- `openviking/service/fs_service.py`, FSService.ls/tree, requests node_limit + 1, emits at most node_limit and derives `has_more`. Simple ls projects full URIs, despite the router description saying relative paths.
- `openviking/storage/viking_fs/_ops.py` and `_access.py`, visible-page listing/tree, apply namespace and native ACL handling before visible offsets. ACL-enabled resources may expose denied name/type placeholders; this adapter refuses them.
- `crates/ragfs/src/core/filesystem.rs` and `cache/wrapper.rs` implement flattened DFS tree offsets, sibling ordering and relative depth bounds. Backend work can rescan earlier visible/raw nodes and read a whole immediate directory internally. The HTTP adapter's request, response and output bounds do not establish a constant backend CPU/memory budget.
- `openviking/core/uri_validation.py`, `openviking_cli/utils/uri.py` and `openviking/utils/path_safety.py` do not impose this adapter's ASCII-only segment policy. Unicode and embedded spaces can be legitimate upstream paths; upstream target normalization may sanitize whitespace on new writes.

Focused paging fixtures cover static listings larger than 256 paths across all pages, roots and subdirectories, depth, archive visibility, per-call request/output limits, invalid offsets and limits, file-only refusal, changed grants/actions/expiry and malformed/foreign/oversized responses. These fixtures and SDK calls qualify adapter behavior only. They are not actual backend execution, production ACL or an inventory proof. Native artifact qualification remains with the root batch.

The new SDK tests use a synthetic scoped engine with higher-ranked foreign-store candidates. They demonstrate adapter request and response checks, not real vector execution, production ACL or native interactive acceptance. Exact-image package proof and eventual native acceptance are separate evidence.
