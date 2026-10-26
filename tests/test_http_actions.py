"""Signed action authorization, independent of backend availability."""
import time
from dataclasses import replace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from ov_http.auth import Principal, Refused, Verifier, canonical, resources_canonical
from ov_http.config import Config, RESOURCES_PROFILE, RESOURCES_REVISION, SEMANTIC_PROFILE, SEMANTIC_REVISION

ROOT = "viking://resources"
DOC = ROOT + "/notes/doc.md"


@pytest.fixture
def signed():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    config = Config(resource="https://ov.example/mcp", issuer="https://issuer.example/",
                    jwks_url="https://issuer.example/jwks/", backend_url="http://backend/api/v1",
                    backend_secret_file="/unused-synthetic-secret")
    now = int(time.time())

    def token(**changes):
        claims = {"iss": config.issuer, "aud": config.resource, "sub": "fixture",
                  "iat": now, "exp": now + 300, "scope": "ov.read",
                  "ov_namespaces": [DOC]}
        claims.update(changes)
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture"})

    return key, config, token


async def verify(signed, *, resources=False, profile_config=None, **changes):
    key, config, token = signed
    if resources:
        config = replace(config, semantic_profile=RESOURCES_PROFILE,
                         semantic_backend_revision=RESOURCES_REVISION, namespace_roots=[ROOT])
    if profile_config is not None:
        config = profile_config
    async with httpx.AsyncClient(trust_env=False) as client:
        verifier = Verifier(config, client)

        async def fixed_key(kid):
            assert kid == "fixture"
            return key.public_key()

        verifier.key = fixed_key
        return await verifier.verify(token(**changes))


@pytest.mark.asyncio
async def test_old_claims_never_gain_mutations_from_requested_scopes(signed):
    p = await verify(signed, scope="ov.read ov.write ov.remove ov.maintain")
    p.require_action("read", DOC)
    for action in ("write", "remove", "maintain"):
        with pytest.raises(Refused):
            p.require_action(action, DOC)


@pytest.mark.asyncio
async def test_explicit_actions_apply_at_both_move_ends_and_expire(signed):
    p = await verify(signed, resources=True, scope="ov.read ov.write ov.remove",
                     ov_namespaces=[ROOT], ov_actions=["read", "write", "remove"])
    p.require_action("write", DOC, ROOT + "/archive/doc.md")
    p.require_action("remove", DOC)
    with pytest.raises(Refused):
        p.require_action("maintain", DOC)
    for foreign in ("viking://user/notes", "viking://resources-other/doc.md"):
        with pytest.raises(Refused):
            p.require_action("write", DOC, foreign)
    expired = Principal(p.subject, p.roots, int(time.time()) - 1, p.grant_digest, p.actions)
    with pytest.raises(Refused):
        expired.require_action("write", DOC)


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", [
    {"ov_actions": None}, {"ov_actions": []}, {"ov_actions": "read"},
    {"ov_actions": ["write"]}, {"ov_actions": ["read", "unknown"]},
    {"ov_actions": ["read", "read"]}, {"ov_actions": ["write", "read"]},
    {"ov_actions": ["read", 1]}, {"ov_actions": ["read", "write"]},
    {"ov_actions": ["read"], "scope": "ov.read unknown"},
    {"ov_actions": ["read"], "ov_namespaces": [ROOT, DOC]},
])
async def test_invalid_signed_authority_refused(signed, changes):
    with pytest.raises(Refused):
        await verify(signed, resources=True, **changes)


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", ["disabled", "namespace"])
async def test_legacy_profiles_refuse_whole_resources_grant(signed, profile):
    config = signed[1]
    if profile == "namespace":
        config = replace(config, semantic_profile=SEMANTIC_PROFILE,
                         semantic_backend_revision=SEMANTIC_REVISION,
                         namespace_roots=[ROOT + "/notes"])
    with pytest.raises(Refused):
        await verify(signed, profile_config=config, ov_namespaces=[ROOT])


@pytest.mark.asyncio
async def test_grant_binding_changes_with_actions_but_not_ungranted_scope(signed):
    read = await verify(signed)
    extra_scope = await verify(signed, scope="ov.read ov.write")
    write = await verify(signed, scope="ov.read ov.write", ov_actions=["read", "write"])
    assert read.grant_digest == extra_scope.grant_digest
    assert read.grant_digest != write.grant_digest
    assert read.actions == ("read",)
    assert write.actions == ("read", "write")


@pytest.mark.parametrize("uri", [
    ROOT + "/", ROOT + "/../user", ROOT + "/a//b", ROOT + "/%2e%2e/a",
    ROOT + "/a?x", ROOT + "/a#b", "viking://agent/a",
])
def test_resource_root_does_not_admit_aliases_or_other_stores(uri):
    assert resources_canonical(ROOT) == ROOT
    with pytest.raises(Refused):
        canonical(ROOT)
    with pytest.raises(Refused):
        canonical(uri)
    with pytest.raises(Refused):
        resources_canonical(uri)
