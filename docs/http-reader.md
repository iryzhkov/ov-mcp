# Namespace-limited HTTP reader

This source slice adds an independent stateless Streamable HTTP MCP service.
The broad interactive stdio entrypoint remains `server.py`; the HTTP service never
imports it, its credential lookup, instrumentation or mutation tools.

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
`backend_secret_file`, `listen_host` and `listen_port`. Defaults are loopback
and port 8098. The canonical public resource must end in exactly `/mcp`; the
issuer is exact, HTTPS and includes its trailing slash. JWKS is a pinned HTTPS
URL, never discovered from a bearer. Backend URL is a fixed HTTP(S) address ending
in `/api/v1`, with no userinfo, query or fragment. Use a trusted private transport
or HTTPS for the backend; it receives the owner-provided API key.

Traefik later terminates public TLS and forwards `/mcp`,
`/.well-known/oauth-protected-resource/mcp`, and optionally `/health`.
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
failure refuses the token; no stale-key fallback exists. Issuance revocation is
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
A later backend capability with pre-retrieval ACL enforcement is required to
enable semantic search.

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

Authentication has a five-second total deadline, including any wait for the JWKS
refresh lock. A call has a 20-second deadline inside a 25-second authenticated
HTTP request deadline. The
entrypoint limits concurrent connections/tasks to 64. A call has at most 128 backend requests, 256 traversal nodes,
12 levels, 256 children per listing, 256 KiB per upstream response and 1 MiB of
aggregate decoded backend data. Tool output is at most 48 KiB; read text is at
most 24,000 characters. Upstream redirects and compressed responses are refused.
Traversal and result limits report explicit truncation. An incomplete document
assembly fails rather than claiming full content. Denied, missing, malformed
upstream and backend failures return the same safe tool error. This is response
equivalence, not a timing-equivalence claim. Cancellation propagates through
the HTTP disconnect and async HTTP calls. A later MCP cancellation notification
cannot locate an earlier POST in the SDK's stateless mode; clients must close the
in-flight HTTP request for immediate cancellation. All calls still have the
20-second deadline.

## Qualification boundary

The synthetic suite uses the official SDK over real loopback HTTP, an immutable
synthetic OV fixture, locally generated RSA tokens and a locally trusted TLS JWKS
endpoint. It captures every backend method/path/query to assert scope before
retrieval. It does not contact real OV or Authentik, enroll objects, exercise
public HTTPS/Traefik or qualify a deployed image, host boundary or client renewal.
No deployment or container recipe is included in this first source slice.
