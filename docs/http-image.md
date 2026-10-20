# HTTP reader image source

Build only the independent HTTP reader. Deployment and configuration source is
in homelab-infra's ov_http_compose role. This recipe does not publish an image.
The complete pinned requirements-http.lock closure is downloaded as binary wheels
at build time, then installed offline in the runtime stage. No package install
runs on a service host. A platform without all required wheels fails the build.

The builder must select and review an immutable official Python 3.13 slim image
reference, including its real registry digest. There is deliberately no default,
invented digest or latest tag. Supply PYTHON_BASE as
docker.io/library/python:3.13-<reviewed-variant>@sha256:<verified-digest>.
Record the exact platform/base manifest, source commit/tree, lock blob and resulting
image digest in the operator build receipt. A source label alone is an assertion,
not proof of provenance. SOURCE_REVISION must be the actual reviewed 40-hex commit.

BuildKit command shape, with these reviewed inputs already set:

```sh
docker build --build-arg PYTHON_BASE="$PYTHON_BASE" \
  --build-arg SOURCE_REVISION="$SOURCE_REVISION" -t ov-http:reviewed .
```

Run this only on an authorized image builder. Review the base's Python 3.13
version, CA bundle and OS support. BuildKit supplies the offline runtime RUN.
The image runs as fixed UID:GID 8098:8098, with no login account or writable HOME.
Only ov_http Python source and the lock enter the image. No stdio entrypoint,
backend data, configuration or credentials enter the build context.
Deployment binds two exact read-only files at /etc/ov-http/runtime.toml and
/etc/ov-http/backend-key, each owned by 8098:8098, mode0600. Root-owned mode0600
secrets fail the reader's ownership check. Protect all host path ancestors.

`python -m ov_http --config /etc/ov-http/runtime.toml --check-config` validates
the actual protected TOML and key, emits no values, and exits before application
or network-client construction. It does not contact the backend or issuer.
This enables a one-shot preactivation container with the same user, mounts,
read-only root and dropped capabilities. It proves local configuration only.

Before activation, qualify the actual digest under those restrictions: read
/etc/resolv.conf and /etc/hosts, traverse system CA directories, resolve the
fixed JWKS host and complete verified HTTPS to the pinned JWKS endpoint.
Then check private /health, discovery, preserved canonical public Host/Origin
and anonymous /mcp refusal. Do not enroll credentials to repair DNS/CA failures.
The source recipe, Python CLI tests and a parsed Compose file do not establish
these image runtime properties. Nonroot image execution and actual host
network/Traefik/native-client acceptance remain separate operator gates.
Semantic behavior remains disabled unless separately qualified as described
in http-reader.md; packaging never upgrades OpenViking.
