"""Explicit, protected configuration for the independent HTTP reader."""
from dataclasses import dataclass
import os
import re
from pathlib import Path
import stat
import tomllib
from urllib.parse import urlsplit


def protected_file(path: str, maximum: int) -> bytes:
    if not Path(path).is_absolute():
        raise ValueError("protected file path must be absolute")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_size > maximum):
            raise ValueError("protected file must be owner-only, regular and bounded")
        data = os.read(fd, maximum + 1)
        if len(data) > maximum:
            raise ValueError("protected file exceeds limit")
        return data
    finally:
        os.close(fd)


def fixed_url(value: str, *, https: bool = True) -> str:
    if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() for c in value):
        raise ValueError("invalid fixed URL")
    u = urlsplit(value)
    if (u.scheme not in (("https",) if https else ("https", "http"))
            or not u.hostname or u.username or u.password or u.query or u.fragment
            or "%" in value or "\\" in value or u.port == 0):
        raise ValueError("invalid fixed URL")
    return value


SEMANTIC_REVISION = "68e66ec8998957e1af3cae8a661947fe77cd9578"
SEMANTIC_PROFILE = "namespace-directories-v1"
RESOURCES_PROFILE = "resources-directories-v052-v1"
# Search-path source qualified by the isolated v0.5.2 package proof. A changed
# backend artifact still needs its own final source/artifact qualification.
RESOURCES_REVISION = "7f3ae1af822d936c1d0b070537772b0f1d59122f"
RESOURCE_ROOT = "viking://resources"
LEGACY_URI_POLICY = "legacy-ascii-v1"
RESOURCES_URI_POLICY = "resources-utf8-read-v1"


@dataclass(frozen=True)
class Config:
    resource: str
    issuer: str
    jwks_url: str
    backend_url: str
    backend_secret_file: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 8098
    semantic_profile: str = "disabled"
    semantic_backend_revision: str = ""
    namespace_roots: tuple[str, ...] = ()
    mutation_profile: str = "disabled"
    personal_profile: str = "disabled"
    personal_account: str = ""
    personal_user: str = ""
    personal_subjects: tuple[str, ...] = ()
    personal_backend_revision: str = ""

    def __post_init__(self):
        for value in (self.resource, self.issuer, self.jwks_url):
            fixed_url(value)
        if urlsplit(self.resource).path != "/mcp":
            raise ValueError("resource must have canonical /mcp path")
        if not self.issuer.endswith("/"):
            raise ValueError("issuer must include canonical trailing slash")
        fixed_url(self.backend_url, https=False)
        if urlsplit(self.backend_url).path != "/api/v1":
            raise ValueError("backend_url must end in /api/v1")
        if type(self.listen_port) is not int or not 1 <= self.listen_port <= 65535:
            raise ValueError("invalid listen port")
        if not Path(self.backend_secret_file).is_absolute():
            raise ValueError("secret file path must be absolute")
        if self.semantic_profile not in ("disabled", SEMANTIC_PROFILE, RESOURCES_PROFILE):
            raise ValueError("unknown semantic profile")
        if self.mutation_profile not in ("disabled", "resources-document-mutations-v1"):
            raise ValueError("unknown mutation profile")
        if self.mutation_profile != "disabled" and self.semantic_profile != RESOURCES_PROFILE:
            raise ValueError("mutation profile requires the resources read profile")
        if self.personal_profile not in ("disabled", "shared-owner-v1"):
            raise ValueError("unknown personal profile")
        if self.personal_profile == "disabled":
            if (self.personal_account or self.personal_user or self.personal_subjects
                    or self.personal_backend_revision):
                raise ValueError("disabled personal profile cannot bind an owner")
        else:
            if (not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", v)
                        for v in (self.personal_account, self.personal_user))
                    or not isinstance(self.personal_subjects, (list, tuple))
                    or not 1 <= len(self.personal_subjects) <= 16
                    or any(not isinstance(s, str) or not 1 <= len(s) <= 256
                           or any(ord(c) < 33 for c in s) for s in self.personal_subjects)
                    or len(set(self.personal_subjects)) != len(self.personal_subjects)
                    or self.personal_backend_revision != "ffcf2972d73d5d54e01924da1ba04d72fb69d41b"):
                raise ValueError("personal profile requires exact owner, subjects and backend pin")
        object.__setattr__(self, "personal_subjects", tuple(self.personal_subjects))
        roots = self.namespace_roots
        if not isinstance(roots, (list, tuple)) or len(roots) > 16:
            raise ValueError("invalid namespace admission")
        if self.semantic_profile == RESOURCES_PROFILE:
            if tuple(roots) != (RESOURCE_ROOT,):
                raise ValueError("resources profile requires the resources root alone")
        elif any(not isinstance(r, str) or not re.fullmatch(
                r"viking://resources/[A-Za-z0-9_@+,=-][A-Za-z0-9_.@+,=-]{0,127}", r) for r in roots):
            raise ValueError("admit explicit top-level namespace directories only")
        if len(set(roots)) != len(roots):
            raise ValueError("duplicate namespace admission")
        object.__setattr__(self, "namespace_roots", tuple(sorted(roots)))
        if self.semantic_profile == "disabled":
            if self.semantic_backend_revision != "" or roots:
                raise ValueError("disabled profile cannot select semantic backend or namespaces")
        else:
            expected = RESOURCES_REVISION if self.semantic_profile == RESOURCES_PROFILE else SEMANTIC_REVISION
            if self.semantic_backend_revision != expected or not roots:
                raise ValueError("semantic profile requires exact backend revision and namespace admission")

    @property
    def uri_policy(self) -> str:
        # Runtime profile selects authority rules; bearer claims cannot select them.
        return RESOURCES_URI_POLICY if self.semantic_profile == RESOURCES_PROFILE else LEGACY_URI_POLICY

    def admits_namespace(self, root: str) -> bool:
        if self.semantic_profile == RESOURCES_PROFILE:
            return root == RESOURCE_ROOT or root.startswith(RESOURCE_ROOT + "/")
        return root in self.namespace_roots

    @property
    def origin(self) -> str:
        u = urlsplit(self.resource)
        return f"{u.scheme}://{u.netloc}"

    @property
    def authority(self) -> str:
        return urlsplit(self.resource).netloc

    @property
    def metadata_url(self) -> str:
        return self.origin + "/.well-known/oauth-protected-resource/mcp"

    @classmethod
    def load(cls, path: str) -> "Config":
        return cls(**tomllib.loads(protected_file(path, 16384).decode("utf-8")))

    def secret(self) -> str:
        key = protected_file(self.backend_secret_file, 4096).decode("ascii").strip()
        if not key or any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise ValueError("invalid backend secret file")
        return key
