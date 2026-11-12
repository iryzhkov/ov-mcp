"""Synthetic coexistence contract; production subjects come from verified JWTs."""
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import ssl

import httpx
import pytest

from ov_http.auth import Refused, Verifier
from ov_http.config import Config
from ov_http.personal import Personal
from ov_http.reader import Backend
from test_personal import PERSONAL_ACTIONS, claims, personal

NAMES = ("chaldea-laptop-ov-full-interactive", "chaldea-omarchy-pc-ov-full-interactive",
         "chaldea-laptop", "chaldea-omarchy-pc")
# Authentik uses hashed subjects, not usernames. These are fixture values only.
SUBJECTS = tuple(hashlib.sha256(("synthetic:" + name).encode()).hexdigest() for name in NAMES)
ACTIONS = ("read", "write", "remove", "maintain")


@pytest.mark.asyncio
async def test_host_subject_coexistence_config_and_grants(personal, tmp_path):
    _, _, f, c = personal
    home = Path(os.environ["HOME"]).resolve()
    assert home.name == "home" and home.parent.name == ".scratch"
    assert tmp_path.resolve().is_relative_to(home)
    path = tmp_path / "coexistence.toml"
    values = asdict(replace(c, personal_subjects=SUBJECTS))
    path.write_text("\n".join(k + " = " + json.dumps(v) for k, v in values.items()))
    path.chmod(0o600)
    c = Config.load(str(path))
    assert c.personal_subjects == SUBJECTS
    assert c.jwks_url == values["jwks_url"]
    scope = " ".join("ov." + a for a in ACTIONS) + " " + " ".join(
        "ov.personal." + a for a in PERSONAL_ACTIONS)
    async with httpx.AsyncClient(verify=ssl.create_default_context(cafile=str(f.cert))) as client:
        verifier = Verifier(c, client)
        try:
            digests = set()
            for subject in SUBJECTS:
                extra = claims(sub=subject, scope=scope, ov_actions=list(ACTIONS))
                p = await verifier.verify(f.token(["viking://resources"], **extra))
                assert p.subject == subject
                assert p.roots == ("viking://resources",)
                assert p.actions == ACTIONS
                for action in ACTIONS:
                    p.require_action(action, "viking://resources/note.md")
                with pytest.raises(Refused):
                    p.require_action("admin", "viking://resources/note.md")
                with pytest.raises(Refused):
                    p.require_action("read", "viking://user/foreign/memories/note.md")
                read_only = await verifier.verify(f.token(["viking://resources"], **{
                    **extra, "ov_actions": ["read"], "scope": scope.replace(
                        "ov.write ov.remove ov.maintain ", "")}))
                for action in ACTIONS[1:]:
                    with pytest.raises(Refused):
                        read_only.require_action(action, "viking://resources/note.md")
                assert (p.personal_account, p.personal_user) == ("default", "default")
                assert p.personal_actions == PERSONAL_ACTIONS
                digests.add(p.grant_digest)
                op = Personal(Backend(c, p, client), {})
                for action in PERSONAL_ACTIONS:
                    op.authorize(action)
                for action in ("memory.remove", "session.remove", "session.commit"):
                    with pytest.raises(Refused):
                        op.authorize(action)
                for action in PERSONAL_ACTIONS:
                    reduced = tuple(a for a in PERSONAL_ACTIONS if a != action)
                    q = await verifier.verify(f.token(["viking://resources"], **claims(
                        actions=reduced, sub=subject)))
                    with pytest.raises(Refused):
                        Personal(Backend(c, q, client), {}).authorize(action)
                for changes in (
                    {"aud": "https://jocasta.mcp.ryzhkov.dev/mcp"},
                    {"aud": "https://media.mcp.ryzhkov.dev/mcp"},
                    {"sub": "unknown-subject"},
                    {"ov_personal": {"account": "foreign", "user": "default",
                                     "actions": list(PERSONAL_ACTIONS)}},
                    {"ov_personal": {"account": "default", "user": "foreign",
                                     "actions": list(PERSONAL_ACTIONS)}},
                    {"ov_actions": list(ACTIONS) + ["admin"]},
                ):
                    with pytest.raises(Refused):
                        await verifier.verify(f.token(["viking://resources"], **{**extra, **changes}))
            assert len(digests) == 1  # Equal grants retain equal authority, not shared actor IDs.
        finally:
            await verifier.close()
