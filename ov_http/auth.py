"""Fixed-contract JWT validation. No discovery or token-selected trust inputs."""
import asyncio
import base64
from dataclasses import dataclass
import hashlib
import json
import math
import re
import time

import httpx
import jwt

from .config import Config, LEGACY_URI_POLICY, RESOURCES_URI_POLICY

RESOURCE_ROOT = "viking://resources"
ACTIONS = ("read", "write", "remove", "maintain")
URI = re.compile(r"viking://resources/(?:[A-Za-z0-9_@+.,=-]+/)*[A-Za-z0-9_@+.,=-]+\Z")
STORAGE_INTERNAL_NAMES = {".path.ovlock", ".redirect.json", ".sync_log.json"}
BROWSE_METADATA_NAMES = {".abstract.md", ".overview.md", ".relations.json"}


class Refused(Exception):
    """Safe failure with no caller or upstream details."""


def canonical(uri: str) -> str:
    if (not isinstance(uri, str) or len(uri) > 1024
            or (uri != RESOURCE_ROOT and not URI.fullmatch(uri))
            or any(p in (".", "..") for p in uri.split("/"))):
        raise Refused()
    return uri


def storage_internal_name(name: str) -> bool:
    # Qualified against upstream storage/internal_names.py at the pinned revision.
    return name in STORAGE_INTERNAL_NAMES or name.startswith(".exact.ovlock.")


def resources_canonical(uri: str) -> str:
    """Exact read identities only. Never normalize, decode, shorten or sanitize."""
    if not isinstance(uri, str):
        raise Refused()
    try:
        encoded = uri.encode("utf-8")
    except UnicodeEncodeError:
        raise Refused() from None
    if (len(encoded) > 1024 or uri != uri.strip()
            or (uri != RESOURCE_ROOT and not uri.startswith(RESOURCE_ROOT + "/"))):
        raise Refused()
    if uri == RESOURCE_ROOT:
        return uri
    for part in uri[len(RESOURCE_ROOT) + 1:].split("/"):
        # Upstream shortens components over 255 UTF-8 bytes on reads. Refuse
        # instead of authorizing one name and addressing another storage name.
        if (not part or part in (".", "..") or len(part.encode("utf-8")) > 255
                or part != part.strip() or storage_internal_name(part) or part == ".relations.json"):
            raise Refused()
        for character in part:
            if character.isascii():
                if character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@+.,=- ":
                    raise Refused()
            elif not character.isprintable() or character.isspace():
                raise Refused()
    return uri


def contains(root: str, uri: str) -> bool:
    return uri == root or uri.startswith(root + "/")


def strict_json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refused()
            result[key] = value
        return result

    def constant(_):
        raise Refused()

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    # Limit nesting and aggregate object complexity, including ignored claims.
    remaining = 16384

    def check(node, depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 24:
            raise Refused()
        if isinstance(node, float) and not math.isfinite(node):
            raise Refused()
        if isinstance(node, dict):
            for item in node.values():
                check(item, depth + 1)
        elif isinstance(node, list):
            for item in node:
                check(item, depth + 1)

    check(value)
    return value


@dataclass(frozen=True)
class Principal:
    subject: str
    roots: tuple[str, ...]
    expires: int
    grant_digest: str
    actions: tuple[str, ...] = ("read",)
    uri_policy: str = LEGACY_URI_POLICY

    def canonical(self, uri: str) -> str:
        if self.uri_policy == LEGACY_URI_POLICY:
            return canonical(uri)
        if self.uri_policy == RESOURCES_URI_POLICY:
            return resources_canonical(uri)
        raise Refused()

    def require_action(self, action: str, *uris: str) -> None:
        if (action not in ACTIONS or action not in self.actions
                or time.time() >= self.expires):
            raise Refused()
        for uri in uris:
            self.require(uri)

    def allows(self, uri: str) -> bool:
        self.canonical(uri)
        return time.time() < self.expires and any(contains(r, uri) for r in self.roots)

    def require(self, uri: str) -> str:
        if not self.allows(uri):
            raise Refused()
        return uri

    def scopes(self, requested: str | None) -> tuple[str, ...]:
        if requested is not None:
            return (self.require(requested),)
        if time.time() >= self.expires:
            raise Refused()
        return tuple(self.require(root) for root in self.roots)


async def bounded_json(client: httpx.AsyncClient, method: str, url: str,
                       maximum: int, **kwargs):
    async with client.stream(method, url, **kwargs) as response:
        if response.status_code != 200 or response.headers.get("content-encoding", "identity") != "identity":
            raise Refused()
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > maximum:
                raise Refused()
        return strict_json(bytes(body))


class Verifier:
    """One bounded key cache per service; never caches principals or bearer tokens."""
    def __init__(self, config: Config, client: httpx.AsyncClient):
        self.config = config
        self.client = client
        self.keys = {}
        self.valid_until = 0.0
        self.next_refresh = 0.0
        self.lock = asyncio.Lock()
        self.refresh_task: asyncio.Task[bool] | None = None
        self.closed = False

    async def key(self, kid: str):
        async with self.lock:
            if self.closed:
                raise Refused()
            now = time.monotonic()
            if now < self.valid_until and kid in self.keys:
                return self.keys[kid]
            if self.refresh_task is None or self.refresh_task.done():
                if now < self.next_refresh:
                    raise Refused()
                self.next_refresh = now + 5
                # Only public JWKS I/O survives a caller's cancellation.
                self.refresh_task = asyncio.create_task(self._refresh())
            refresh = self.refresh_task
        if not await asyncio.shield(refresh):
            raise Refused()
        if time.monotonic() >= self.valid_until or kid not in self.keys:
            raise Refused()
        return self.keys[kid]

    async def close(self):
        self.closed = True
        if self.refresh_task is not None:
            self.refresh_task.cancel()
            await asyncio.gather(self.refresh_task, return_exceptions=True)

    async def _refresh(self) -> bool:
        try:
            async with asyncio.timeout(5):
                doc = await bounded_json(self.client, "GET", self.config.jwks_url, 65536)
            if not isinstance(doc, dict) or set(doc) != {"keys"}:
                raise Refused()
            records = doc["keys"]
            if not isinstance(records, list) or not 1 <= len(records) <= 16:
                raise Refused()
            keys = {}
            for record in records:
                if not isinstance(record, dict):
                    raise Refused()
                key_id = record.get("kid")
                if (not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", key_id)
                        or key_id in keys or record.get("kty") != "RSA"
                        or record.get("alg") != "RS256" or record.get("use", "sig") != "sig"
                        or record.get("key_ops", ["verify"]) != ["verify"]
                        or set(record) - {"kid", "kty", "alg", "use", "key_ops", "n", "e",
                                          "x5c", "x5t", "x5t#S256"}
                        or not isinstance(record.get("n"), str) or len(record["n"]) > 1400
                        or not isinstance(record.get("e"), str) or len(record["e"]) > 8):
                    raise Refused()
                # Authentik includes certificate/thumbprint metadata. Bound
                # and ignore it; only pinned-JWKS RSA n/e supply key material.
                chain = record.get("x5c", [])
                if (not isinstance(chain, list) or len(chain) > 4
                        or any(not isinstance(c, str) or len(c) > 8192 for c in chain)
                        or any(not isinstance(record[k], str) or len(record[k]) > 128
                               for k in ("x5t", "x5t#S256") if k in record)):
                    raise Refused()
                public = {k: record[k] for k in ("kty", "n", "e")}
                key = jwt.PyJWK.from_dict(public, algorithm="RS256").key
                if not 2048 <= key.key_size <= 8192:
                    raise Refused()
                keys[key_id] = key
            self.keys = keys
            self.valid_until = time.monotonic() + 60
            return True
        except Exception:
            # A detached refresh always returns a value: no upstream diagnostic
            # or unobserved task exception escapes when all awaiters cancel.
            return False

    async def verify(self, token: str) -> Principal:
        try:
            if len(token) > 12288 or not token.isascii():
                raise Refused()
            segments = token.split(".")
            if len(segments) != 3:
                raise Refused()
            decoded = []
            for segment, maximum in zip(segments, (1024, 8192, 2048)):
                if not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
                    raise Refused()
                data = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
                if len(data) > maximum or base64.urlsafe_b64encode(data).decode().rstrip("=") != segment:
                    raise Refused()
                decoded.append(data)
            header, claims = strict_json(decoded[0]), strict_json(decoded[1])
            if (not isinstance(header, dict) or set(header) - {"alg", "kid", "typ"}
                    or header.get("alg") != "RS256" or header.get("typ", "JWT") not in ("JWT", "at+jwt")
                    or not isinstance(header.get("kid"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", header["kid"])
                    or not isinstance(claims, dict) or len(claims) > 32):
                raise Refused()
            key = await self.key(header["kid"])
            jwt.decode(token, key, algorithms=["RS256"], issuer=self.config.issuer,
                       audience=self.config.resource, leeway=30,
                       options={"require": ["iss", "aud", "exp", "iat", "sub"],
                                "strict_aud": True, "verify_iat": False})
            now = time.time()
            issued, expires = claims["iat"], claims["exp"]
            subject, scope = claims["sub"], claims.get("scope")
            if (type(issued) is not int or type(expires) is not int
                    or not 0 < expires - issued <= 300 or issued > now + 30
                    or expires <= now or not isinstance(subject, str)
                    or not 1 <= len(subject) <= 256 or any(ord(c) < 32 for c in subject)
                    or not isinstance(scope, str) or len(scope) > 512
                    or not re.fullmatch(r"[!-~]+(?: [!-~]+)*", scope)
                    or len(scope.split()) != len(set(scope.split())) or "ov.read" not in scope.split()):
                raise Refused()
            if "nbf" in claims and (type(claims["nbf"]) is not int or claims["nbf"] > now + 30):
                raise Refused()
            grants = claims.get("ov_namespaces")
            if not isinstance(grants, list) or not 1 <= len(grants) <= 16:
                raise Refused()
            uri_policy = self.config.uri_policy
            check_uri = resources_canonical if uri_policy == RESOURCES_URI_POLICY else canonical
            roots = tuple(sorted(check_uri(r) for r in grants))
            if any(contains(a, b) for i, a in enumerate(roots) for b in roots[i + 1:]):
                raise Refused()
            if self.config.namespace_roots and any(not self.config.admits_namespace(r) for r in roots):
                raise Refused()
            actions = ("read",)
            if "ov_actions" in claims:
                declared = claims["ov_actions"]
                if (not isinstance(declared, list) or not declared
                        or any(not isinstance(a, str) or a not in ACTIONS for a in declared)
                        or declared != [a for a in ACTIONS if a in declared]
                        or "read" not in declared
                        or any("ov." + a not in scope.split() for a in declared)
                        or any(s not in {"ov." + a for a in ACTIONS} for s in scope.split())):
                    raise Refused()
                actions = tuple(declared)
            # Bind continuation/cache identity to effective authority, including
            # action reductions for the same subject and namespace grants.
            authority = [roots, actions]
            if uri_policy != LEGACY_URI_POLICY:
                authority.append(uri_policy)
            digest = hashlib.sha256(json.dumps(
                authority, separators=(",", ":")).encode()).hexdigest()
            return Principal(subject, roots, expires, digest, actions, uri_policy)
        except (ValueError, TypeError, KeyError, RecursionError, jwt.PyJWTError,
                httpx.HTTPError, TimeoutError):
            raise Refused() from None
