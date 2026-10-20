"""Explicit, protected configuration for the independent HTTP reader."""
from dataclasses import dataclass
import os
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


@dataclass(frozen=True)
class Config:
    resource: str
    issuer: str
    jwks_url: str
    backend_url: str
    backend_secret_file: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 8098

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
