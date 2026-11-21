"""One trailing directory slash is accepted at the tool boundary; nothing else is."""
import pytest

from ov_http.app import URI_KEYS, canonical_arguments
from ov_http.auth import Refused, canonical, resources_canonical, strip_trailing_slash
from test_http_acceptance import call
from test_http_document_write import ACTIONS, A, args, sdk_documents  # noqa: F401
from test_personal import DOC, ROOT as PERSONAL_ROOT, claims, personal  # noqa: F401

ROOT = "viking://resources"
B = "viking://resources/namespaceB"
WRITER = {"ov_actions": list(ACTIONS), "scope": "ov.read ov.write ov.maintain ov.remove"}


@pytest.mark.parametrize("raw, expected", [
    (A + "/", A),
    (A + "/sub/", A + "/sub"),
    ("viking://user/default/memories/", "viking://user/default/memories"),
    (A, A),
])
def test_single_trailing_slash_is_stripped(raw, expected):
    assert strip_trailing_slash(raw) == expected


@pytest.mark.parametrize("raw", [
    ROOT + "/", "viking://", "viking:///", "viking:/", "/", "", "a/", "resources/a/",
    A + "//", A + "///", ROOT + "//", None, 7, [A + "/"],
])
def test_roots_doubles_and_non_strings_are_untouched(raw):
    assert strip_trailing_slash(raw) is raw


ALIASES = [
    ROOT + "/", A + "//", A + "/./", A + "/../", A + "/../b/", A + "/ /", A + " /",
    A + "/a\t/", A + "/%2e%2e/", A + "/a?x/", A + "/a\\b/",
]
INTERNAL = [A + "/.relations.json/", A + "/.path.ovlock/", ROOT + "/.watch_tasks.json/"]


@pytest.mark.parametrize("raw", ALIASES + INTERNAL)
def test_resources_policy_still_refuses_other_forms_after_stripping(raw):
    with pytest.raises(Refused):
        resources_canonical(strip_trailing_slash(raw))


@pytest.mark.parametrize("raw", ALIASES)
def test_legacy_policy_still_refuses_aliases_after_stripping(raw):
    with pytest.raises(Refused):
        canonical(strip_trailing_slash(raw))


def test_boundary_covers_every_uri_argument_and_leaves_names_alone():
    raw: dict[str, object] = {key: A + "/x/" for key in URI_KEYS}
    raw.update(targets=[A + "/", A + "/y"], filename="note.md/", text="body/", query="q/")
    out = canonical_arguments(raw)
    assert all(out[key] == A + "/x" for key in URI_KEYS)
    assert out["targets"] == [A, A + "/y"]
    assert (out["filename"], out["text"], out["query"]) == ("note.md/", "body/", "q/")
    assert raw["uri"] == A + "/x/"  # The caller's mapping is not mutated.


async def both_forms(client, engine, tool, canonical_args, slashed_args):
    outcomes = []
    for arguments in (canonical_args, slashed_args):
        before = len(engine.calls)
        response, value = await call(client, tool, **arguments)
        outcomes.append((response.is_error, value, engine.calls[before:]))
    assert outcomes[0] == outcomes[1], outcomes
    return outcomes[0]


@pytest.mark.asyncio
async def test_sdk_write_dry_run_identical_for_allowed_grant(sdk_documents):
    session, engine = sdk_documents
    async with session(**WRITER) as client:
        failed, answer, calls = await both_forms(
            client, engine, "memory_write", args(dry_run=True), args(dry_run=True, to=A + "/"))
        assert not failed and answer["preflight_passed"], answer
        # Identical backend calls for both forms prove the slash never reaches the backend.
        assert calls and not engine.effects


@pytest.mark.asyncio
async def test_sdk_reads_identical_and_return_canonical_uri(sdk_documents):
    session, engine = sdk_documents
    async with session(**WRITER) as client:
        failed, answer, _ = await both_forms(
            client, engine, "memory_stat", {"uri": A}, {"uri": A + "/"})
        assert not failed and answer["uri"] == A, answer
        # This fixture does not serve listings; both forms must still fail identically.
        await both_forms(client, engine, "memory_ls", {"uri": A}, {"uri": A + "/"})


@pytest.mark.asyncio
@pytest.mark.parametrize("tool, key", [("memory_write", "to"), ("memory_stat", "uri"),
                                       ("memory_ls", "uri"), ("memory_rm", "uri")])
async def test_sdk_denied_grant_refused_identically(sdk_documents, tool, key):
    session, engine = sdk_documents
    base = args(dry_run=True) if tool == "memory_write" else {"dry_run": True} if tool == "memory_rm" else {}
    async with session(roots=(A,), **WRITER) as client:
        failed, answer, calls = await both_forms(
            client, engine, tool, {**base, key: B}, {**base, key: B + "/"})
        assert failed and answer["error"] == "Resource unavailable." and not calls
        assert not engine.effects


@pytest.mark.asyncio
@pytest.mark.parametrize("uri", [
    ROOT + "/", A + "//", A + "/./", A + "/../namespaceB/", A + " /", A + "/.abstract.md/",
    A + "/.relations.json/", A + "/.path.ovlock/",
])
async def test_sdk_other_non_canonical_forms_still_refused_before_backend(sdk_documents, uri):
    session, engine = sdk_documents
    tools = [("memory_write", args(dry_run=True, to=uri))]
    # Reads of a hidden summary file are allowed today, so only writes refuse it.
    if ".abstract.md" not in uri:
        tools += [("memory_stat", {"uri": uri}), ("memory_ls", {"uri": uri})]
    async with session(**WRITER) as client:
        for tool, arguments in tools:
            before = len(engine.calls)
            response, answer = await call(client, tool, **arguments)
            assert response.is_error, (tool, uri, answer)
            assert engine.calls[before:] == [], (tool, uri)
    assert not engine.effects


@pytest.mark.asyncio
async def test_sdk_personal_tools_share_the_boundary(personal):
    sessions, engine, _, _ = personal
    async with sessions(**claims()) as client:
        for tool, plain, slashed in [
            ("personal_memory_browse", {"uri": PERSONAL_ROOT + "/preferences"},
             {"uri": PERSONAL_ROOT + "/preferences/"}),
            ("personal_memory_find", {"query": "note", "targets": [PERSONAL_ROOT + "/preferences"]},
             {"query": "note", "targets": [PERSONAL_ROOT + "/preferences/"]}),
        ]:
            failed, value, _ = await both_forms(client, engine, tool, plain, slashed)
            assert not failed, value
        # Trimming must not smuggle duplicates past uniqueItems.
        response, _ = await call(client, "personal_memory_find", query="note",
                                 targets=[PERSONAL_ROOT + "/preferences", PERSONAL_ROOT + "/preferences/"])
        assert response.is_error
        response, _ = await call(client, "personal_memory_browse", uri=PERSONAL_ROOT + "/preferences//")
        assert response.is_error
