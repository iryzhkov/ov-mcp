# Namespace-limited HTTP reader

This source slice adds an independent stateless Streamable HTTP MCP service.
The broad interactive stdio entrypoint remains `server.py`; the HTTP service never
imports it, its credential lookup, instrumentation or mutation tools.

## Document-write preflight

With the mutation profile enabled, `memory_write(dry_run=true)` performs the
default document path's guarded read-only preflight. It requires the same signed
actions, ancestors, parent and overwrite checks as publication, but never
dispatches a mutation. The explicit file-deferred-v1 path rejects this option.
No revision or backup name is reserved; a later real write observes state again.

A successful dry run returns `outcome=not_started`, `preflight_passed=true`,
`dispatched=false`, and `preflight.stage=ready`. Failure returns the ordinary
safe error plus a fixed preflight stage and category. Categories can identify
allowlisted document-node protocol failures without exposing backend messages,
private paths, details or credentials. Unknown errors remain unavailable.
This is diagnostic evidence, not permission to retry or proof of indexing.
Default writes retain their commit/unknown handling. Default document replacement
privately inventories exact immediate file `.relations.json` entries using
their authorized resource parents, with at most 128 total nodes, 12 directory
levels and 1024 UTF-8 bytes per physical source and backup URI. No metadata
paths or bodies appear in responses; other tools keep their existing refusals.

The existing closed categories are `passed`, `unavailable`,
`invalid_document_uri`, `directory_fragment_controls`,
`residual_index_state`, `context_inventory_incomplete`, `context_limit` and
`document_alias`. This bounded change adds no inventory-specific categories;
inventory refusals remain `unavailable`.

## Recovery revision observations

HTTP `memory_stat(uri, include_revision=true)` returns only `{"uri": uri, "node": descriptor}`
from the existing `GET /resources/document-node` endpoint. It requires read authority
before and after the GET and retains the reader's time, request and byte limits.
It works without mutation authority or the mutation profile. Omitted or false keeps
the ordinary stat response, including recursive directory size and part counts.

The descriptor is an existing typed directory `kind` plus `tree_revision`, or a
file `kind` plus `content_sha256` and `control_revision`. It uses the writer's
closed validator. Extra fields, foreign response URIs, absent nodes and malformed
revisions refuse. No content, filenames beneath the requested URI, private control
paths or backup paths are returned. The revision is supplied by the backend,
never inferred from displayed text. Recursive stats are omitted in this mode to
avoid combining independently observed snapshots.

A recovery caller can compare the full typed node across two observations around
its held parsed note. An unchanged observation is evidence only for that node at
those observation times. Refusal, unknown or not-found is never proof of absence,
and this read cannot clear an unknown hold or authorize replay of a write.

## Runtime interface

Use Python 3.13 and a dedicated environment with `requirements-http.lock`.
The lock pins the full qualified runtime dependency closure; `requirements-http.txt`
records the selected direct dependencies.
Start from the repository root:

```sh
python -m ov_http --config /etc/ov-http/runtime.toml
```

The config file and `backend_secret_file` must be absolute, regular files owned by
the runtime UID with no group/other permissions. Final-component symlinks are
refused. Their parent directories and launcher must be under operator custody.
The example `http-config.example.toml` contains no credentials or live deployment
selection. The secret file contains one ASCII OpenViking API key, optionally with
a trailing newline. The service does not invoke a keyring or read OV environment
variables or legacy user configuration.

Config keys are `resource`, `issuer`, `jwks_url`, `backend_url`,
`backend_secret_file`, `listen_host` and `listen_port`, plus the optional semantic
profile keys below. Defaults are loopback
and port 8098. The canonical public resource must end in exactly `/mcp`; the
issuer is exact, HTTPS and includes its trailing slash. JWKS is a pinned HTTPS
URL, never discovered from a bearer. Backend URL is a fixed HTTP(S) address ending
in `/api/v1`, with no userinfo, query or fragment. Use a trusted private transport
or HTTPS for the backend; it receives the owner-provided API key.

Traefik later terminates public TLS and forwards `/mcp`,
`/.well-known/oauth-protected-resource/mcp`. Keep `/health` private.
It must preserve the public Host and any Origin. The service checks exact public
Host and Origin on all routes and ignores forwarded authority headers.
Uvicorn proxy-header processing and access logs are disabled by the entrypoint.
Do not enable HTTP/JWT debug logging in the runtime.

Discovery publishes only the resource, issuer and `ov.read` scope. Anonymous MCP
requests get a bearer challenge with the protected-resource metadata URL.
Health is only `{"ok":true}`, not a backend readiness or version probe.

## Fixed token contract

RS256 only. Require a bounded ASCII `kid`, exact `iss`, a single string `aud`
equal to the canonical resource, nonempty `sub`, integer `iat` and `exp`,
and space-separated scope containing `ov.read`. Token lifetime is at most 300
seconds, future issued-at tolerance is 30 seconds, and expired tokens are refused.
Optional `nbf` must be an integer within that same skew. No `azp` is required.

`ov_namespaces` is a list of 1 to 16 explicit canonical roots, for example
`["viking://resources/namespaceA"]`. A root includes all descendants. Duplicates
and overlapping roots are refused. This initial contract permits ASCII path
segments using letters, digits, underscore, hyphen, period, @, +, comma and equals.
It rejects dot segments, repeated/trailing slashes, percent encoding, backslashes,
queries and fragments. There is no deny-rule language. Namespace grants must be
chosen by protected issuer configuration, never by the caller's tool arguments.

JWTs are limited to 12 KiB, decoded claims to 8 KiB and header to 1 KiB. Duplicate
JSON keys, untrusted JOSE fields and algorithm/key URL selection are refused.
JWKS is limited to 64 KiB and 16 distinct RS256 RSA public keys of 2048 to 8192
bits. Authentik's bounded certificate/thumbprint metadata is accepted but ignored;
only RSA n/e from the pinned JWKS supplies key material. This matches the
[2026.8.4 JWKS format](https://github.com/goauthentik/authentik/blob/version/2026.8.4/authentik/providers/oauth2/views/jwks.py).
The selected provider must publish signing keys with this contract; encryption
keys or other signing algorithms are refused.
Redirects, proxy environment settings and compressed upstream bodies are
refused. JWKS refresh has a five-second deadline/cooldown; successful keys remain
cached at most 60 seconds. Unknown keys trigger a bounded refresh. Required refresh
failure refuses the token; no stale-key fallback exists. One retained, shielded
refresh task has its own five-second timeout, so cancelling an authentication
awaiter does not cancel public JWKS refresh or poison its cooldown. Shutdown
cancels and awaits that task before closing the JWKS client. Backend reads remain
request-owned and cancellable. Issuance revocation is
not instant offline JWT invalidation.

Every request gets its own immutable principal with effective roots, expiry and
a digest of those roots. Each backend operation rechecks the principal before
network I/O. No principal, result, cursor or traversal cache is shared across
requests. Different grants for the same subject remain different permissions.

## Reader behavior and deliberate limits

The explicit catalog is `memory_search/find/grep/glob/ls/tree/stat/read/abstract/
overview/relations`. It contains no writes, repairs, reindexing or global status.
Unknown tool calls are refused. Caller endpoint, headers, backend address,
metadata filters, sessions and cursors are not accepted.

`memory_search` and `memory_find` currently return a clear unsupported-scope
error without any backend request. OpenViking 0.2.6's
[matched-context expansion](https://github.com/volcengine/OpenViking/blob/v0.2.6/openviking/retrieve/hierarchical_retriever.py#L336)
reads related abstracts without the target directory filter. Sending
`target_uri` and filtering the result would not establish scope isolation.
This remains the default. An explicit source-pinned profile is described below;
no live upgrade is performed by this adapter.

### Opt-in semantic profile

Only an operator-qualified backend at exact source revision
`68e66ec8998957e1af3cae8a661947fe77cd9578` may use:

```toml
semantic_profile = "namespace-directories-v1"
semantic_backend_revision = "68e66ec8998957e1af3cae8a661947fe77cd9578"
namespace_roots = ["viking://resources/namespaceA", "viking://resources/namespaceB"]
```

Unknown profiles/revisions, missing admission, duplicate roots, nested/file grants,
and mixed disabled/enabled settings are refused. Admission is a protected allowlist
of explicit top-level `viking://resources/<namespace>` directory roots. Each token
must grant only admitted roots, and only its granted roots become HTTP targets.
Before any semantic POST, every granted root must stat as an existing directory.
The operator must keep namespace root types immutable for the service lifetime.
The stat and POST are separate operations; this is an explicit deployment invariant,
not an atomic type check or generic file ACL. Configuration pins an expected
contract; it does not attest or inspect the running backend revision.

Calls use only POST `/search/find` or `/search/search` with fixed resource context,
explicit namespace targets, bounded limit, content hydration/provenance off and
search list mode. No session, image, caller filter, wildcard, cursor or default
scope is forwarded. The optional existing tool `scope` argument must exactly match
a granted namespace; it is an assertion only. The query always includes all token
grants, so caller input never chooses a file target or backend authority.

Up to 100 scoped hits are fetched per call. Archive hiding and document grouping
operate on that bounded authorized batch. Scores/previews describe returned hits;
matching-part counts cover only the batch. No complete matching count is reported,
and `complete` is always false. `truncated` marks batch/output reduction. There is
no pagination/cache or cursor. Returned resource URIs are independently validated;
a malformed or out-of-grant response fails the entire call. This defense does not
replace the backend filtering requirement. Stored relationships remain unavailable;
prose references already inside an authorized preview are not scrubbed.

Pinned source evidence places target PathScope filters before vector ranking and
counts and has no related-abstract expansion in list retrieval. Directory summary
missing/empty cases stay local. Relevant source at the exact revision is
`server/routers/search.py` FindRequest/SearchRequest and find/search routes;
`storage/viking_fs/_semantic.py` abstract/_read_abstract_file/search;
`retrieve/hierarchical_retriever.py` retrieve/_convert_to_matched_contexts;
`storage/viking_vector_index_backend.py` _build_scope_filter; and
`storage/vectordb_adapters/base.py` query/_compile_filter, all under `openviking/`.
Separate pinned-source AST fixtures exercised those method bodies with inert
storage/model boundaries. The SDK suite exercises the complete adapter HTTP path
against a capturing synthetic backend that asserts the fixed request fields and
scopes candidates before summary/content/rank/count stages. These are paired pieces
of evidence, not execution of the actual upstream HTTP server or native engine.
The suite also covers missing/empty directory summaries, L0/L1 previews, chunk
parts, archives, same-subject A/B concurrency, failed preflight, poisoned responses
and bounded/failed/redirected POSTs. Full relationships remain the existing scoped
wikilink scan; a synthetic relations field is not proof of a real backlink engine.
This profile requires native vector/backend and runtime qualification before
deployment; synthetic captures cannot establish that.

`memory_grep` uses bounded literal substring matching, not arbitrary regular
expressions. `memory_glob` matches filenames or relative paths. Both enumerate
authorized roots before reading, matching, grouping or counting. Grep groups
chunk hits by permitted document ancestor and hides archive namespaces by default.
It never groups a chunk-only grant to an ancestor outside that grant. There are
no semantic scores and no claim of a complete store-wide count.

Reads reconstruct visible chunks in natural name order, handle numbered verbatim
containers, and support line offsets/limits and source-part lists. Markdown
section order may differ from the ingested original. Abstract/overview explicitly
read their hidden file below the permitted directory. They never fall back to an
ancestor. Tree output contains paths, without automatically generated summaries.

Relations resolve wikilinks and discover backlinks by scanning authorized content.
Unrestricted stored backend relations are reported as unavailable, because their
discovery cannot be constrained first. Structured results never contain denied
targets or counts. Resolution is bounded and approximate: only uniquely named
permitted documents resolve by short name. References already written in permitted
document prose remain in that prose; this service does not redact them.
If discovery is truncated, short-name links are not resolved because an unseen
document could make the name ambiguous. Explicit URI links and backlinks from
fully read documents can still be returned with `truncated: true`.

Authentication has a five-second total deadline, including any wait for the JWKS
refresh lock. Reader calls retain a 20-second deadline. The authenticated HTTP gate
allows 135 seconds so real document writes can use a 130-second operation cap.
This covers default, legacy-chunked and exact-directory-v2 writes. Move and reindex
retain 70 seconds; dry-run and explicit file-deferred-v1 writes retain 20 seconds.
All mutation caps are also minimized by token expiry.
See full-interactive-source.md for the exact long-I/O endpoints and remaining limits. The
entrypoint limits concurrent connections/tasks to 64. A call has at most 128 backend requests, 256 traversal nodes,
12 levels, 256 children per listing, 256 KiB per upstream response and 1 MiB of
aggregate uncompressed JSON response-body data. Each request reserves one full 256 KiB
response allowance before I/O, so a scan may stop with less than that allowance
unused. Tool output is at most 48 KiB; read text is at
most 24,000 characters. Upstream redirects and compressed responses are refused.
Traversal, request and aggregate-data budgets return safe partial scan results
with explicit truncation. Grep and relations spend at most the first 64 requests
on discovery to leave allowance for content. Partial sizes, matching-part counts,
links and backlinks cover only validated observed records, not a complete scan.
A backlink document contributes nothing until its assembly is complete. An
incomplete requested document assembly fails rather than claiming full content.
Only local budget exhaustion produces partial results; denied, missing, malformed
upstream and backend failures return the same safe tool error. This is response
equivalence, not a timing-equivalence claim. Cancellation propagates through
the HTTP disconnect and async HTTP calls. A later MCP cancellation notification
cannot locate an earlier POST in the SDK's stateless mode; clients must close the
in-flight HTTP request for immediate cancellation. Reader calls retain the
20-second deadline. A disconnected mutation may still commit in the backend;
unknown outcomes must not be replayed automatically.

## Qualification boundary

Install test dependencies with `uv pip install -r requirements-http-test.lock`
and run `python -B -m pytest -q -p no:cacheprovider --basetemp "$HOME/pytest" tests`
inside an agent-a Chaldea job with asserted scratch HOME/TMPDIR. The test lock pins
the complete runtime and test closure; its input remains `requirements-http-test.txt`.

The synthetic suite uses the official SDK over real loopback HTTP, an immutable
synthetic OV fixture, locally generated RSA tokens and a locally trusted TLS JWKS
endpoint. It captures every backend method/path/query to assert scope before
retrieval. It does not contact real OV or Authentik, enroll objects, exercise
public HTTPS/Traefik or qualify a deployed image, host boundary or client renewal.
The optional image recipe and its separate runtime qualification gates are in
[http-image.md](http-image.md). Deployment source is owned by homelab-infra.
