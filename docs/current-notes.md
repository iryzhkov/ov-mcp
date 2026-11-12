# Current-note retrieval

Native HTTP search and find already omit path components archive, archived and
_archive by default. They now also omit notes whose generated hit summary mentions
"superseded" and whose authorized source starts with the Markdown H1
"Superseded:". Summary prose alone never hides a current catalog. The explicit
include_archived option includes both kinds of historical content, grouped or raw.
This is bounded batch filtering, not an exhaustive inventory. Unmarked obsolete
content still needs curator review.

Move and recursive remove privately inventory exact immediate .relations.json
files under authorized directories, using the document-write metadata guard.
Denied rows, duplicate entries, directory lookalikes, other hidden controls,
oversized paths and traversal-budget failures still refuse before dispatch.
ACLs are checked against each owning directory at preflight and dispatch.
Metadata bytes and paths are never returned. Moves use the original native
no-clobber subtree transfer, preserving links and bytes without re-ingestion.
Remove deletes the requested subtree, including metadata; it does not separately
delete backups elsewhere or promise a recovery copy. Qualification uses
disposable fixtures only.
