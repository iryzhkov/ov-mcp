# Shared personal memory and sessions (source only)

The default is `personal_profile = "disabled"`. Existing resources profiles, canonicalization, 19-tool catalog and schemas are unchanged. Opt-in adds nine dedicated tools; personal authority never expands a resources grant.

Protected configuration fields (all required when enabled):

```toml
personal_profile = "shared-owner-v1"
personal_account = "default"
personal_user = "default"
personal_subjects = ["<approved PC subject>", "<approved laptop subject>"]
personal_backend_revision = "7adf8b5fbcaa3293ef2a0b0ed44f864477401c39"
```

The account/user must match the actual backend consumer key's registered identity. API-key mode ignores caller identity headers; this adapter never sends owner headers. Subjects may differ between hosts while deliberately sharing the one configured owner. Root must bind this to approved issuer/helper configuration and actual backend artifact evidence; a configuration string is not runtime attestation.

In addition to the existing JWT contract (`ov.read`, signed resource `ov_namespaces`, issuer/audience/300-second maximum lifetime), the issuer must emit exactly:

```json
{"ov_personal":{"account":"default","user":"default","actions":["memory.read","memory.write","session.read","session.create","session.append"]}}
```

Actions may be reduced, but must be unique and follow that order. Each action requires its corresponding `ov.personal.<action>` scope. Both configured subject approval and the signed exact-owner grant are required. Old tokens, broad namespaces, extra scopes alone and caller owner headers grant no personal authority. The authority digest includes the personal owner/actions. Authority and expiry are rechecked before and after each backend request; there is no bearer/principal cache or automatic retry. Revoked issuance does not invalidate an already signed token before expiry.

Tools and exact arguments:

- `personal_memory_browse(uri?, limit?)`: immediate children; omitted URI means own memories root.
- `personal_memory_read(uri)`: explicit text memory file, content and SHA256.
- `personal_memory_find(query, targets?, limit?)`: omitted targets become exactly own memories root. Empty, mixed or foreign targets refuse before dispatch.
- `personal_memory_create(uri, content)`: one native batch operation with `expected_absent:true`.
- `personal_memory_replace(uri, content, expected_sha256)`: one native batch operation with a byte-hash precondition.
- `personal_session_list(limit?)`: shared owner's collection, same-user sibling sessions allowed.
- `personal_session_read(session_id)`: metadata and bounded context through existing sessions API, `auto_create:false`.
- `personal_session_create()`: backend-generated ID, explicit `auto_commit_policy:null`; verifies returned policy is null.
- `personal_session_append(session_id, role, content)`: always unsupported before dispatch. See blocker below.

Writes are direct native text content under `memories/{type}/{file.md|file.txt}`, never resource ingest or synthetic extraction. Native exact-lock preconditions are supplied to `/content/batch-write`; no read-then-write CAS emulation. Indexing completion is not claimed. Post-dispatch failure, conflict or ambiguous response reports unknown with no automatic retry (conservatively including native precondition conflicts).

Canonical personal paths are exact ASCII segment identities, 1024 UTF-8 bytes maximum, segments up to 128 characters. Aliases (`~`, legacy session roots), percent encoding, traversal, backslashes, empty/dot/hidden segments and foreign owner namespaces refuse. Requests are capped by the existing 32 KiB MCP body limit. Write content is at most 16 KiB UTF-8; IDs at most 128 characters; targets at most eight; listings at most 256 received rows and 40 projected; context token budget 4096. Responses retain existing 256 KiB per upstream, 1 MiB aggregate and 48 KiB tool output limits. Structured returned URI/account/user references are recursively checked to depth 16 before projection. Search hits must also lie within the exact requested targets. Plain saved prose is content, not an authority reference.

## Append blocker and qualification limits

Pinned backend `openviking/server/routers/sessions.py:734` opens messages with `auto_create=True` and then schedules auto-commit. It exposes no atomic existing-only append or per-append automatic-commit suppression. A metadata preflight cannot guarantee either requirement against deletion/policy races. This source therefore refuses append without any backend request. No backend changes or policy editing are authorized in this task. Root must retain this blocker rather than enable a preflight workaround.

Session creation supports explicit disabling: router passes model_fields_set through to SessionService.create; its null branch sets auto_commit_policy=None rather than inheriting defaults. Backend-generated IDs avoid caller-selected session replacement. No delete, commit, extraction, automatic capture, policy editing, admin, agent, peer or arbitrary filesystem tools are exposed.

Tests use synthetic signed tokens, local TLS JWKS and the selected locked SDK/ASGI stack through Chaldea. They do not establish live identity binding, deployed backend behavior, issuer/helper changes, native host access or artifact custody. Existing producer pins are deliberately unchanged: root must rebind product hashes and add `ov_http/personal.py` to the closed image context before producing a runnable image. Existing semantic producer pins are also retained and require final root artifact/source qualification.
