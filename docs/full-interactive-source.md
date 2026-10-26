# Full interactive HTTP source preparation

This branch is not a deployed full-parity release. The live bounded reader remains unchanged. Mutations, safe orphan repair, qualified backend artifacts and four native host/provider checks are still required before replacing stdio.

The default semantic profile remains disabled. The existing `namespace-directories-v1` profile keeps its exact namespace-admission and scope-assertion behavior.

The opt-in `resources-directories-v052-v1` search profile requires the exact search-path source revision `7f3ae1af822d936c1d0b070537772b0f1d59122f` and the single operator ceiling `viking://resources`. This identifies the v0.5.2 search contract exercised by the isolated package proof. A changed backend artifact still needs exact source/artifact qualification; this constant does not qualify a patched image or authorize deployment.

Tokens still supply their own signed namespace grants. The profile admits narrower canonical grants beneath the ceiling, preserving the existing file canary. Search requires a directory grant; a file token can read its file metadata but cannot use the parent as a search target. The full resources token can search all its grants or pass an authorized directory as `scope` to narrow the backend target before retrieval, ranking and counts. The legacy profile continues to treat `scope` as an exact-grant assertion.

Search/find send only explicit authorized target URIs with resource context and retain whole-call refusal for an unexpected foreign URI. Archive visibility remains controlled by `include_archived`, including raw ungrouped results. Results are bounded incomplete batches, not an exhaustive inventory or cursor. Filesystem traversal and large-directory pagination still need completion for full parity.

Explicit signed `ov_actions` are checked against scopes. Missing actions mean read-only even if extra scopes were requested. The per-request grant digest includes effective actions. These checks prepare the mutation authorization boundary; no additional mutation tools are exposed yet.

The new SDK tests use a synthetic scoped engine with higher-ranked foreign-store candidates. They demonstrate adapter request and response checks, not real vector execution, production ACL or native interactive acceptance. Exact-image package proof and eventual native acceptance are separate evidence.
