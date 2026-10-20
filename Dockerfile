# Supply an operator-reviewed docker.io/library/python:3.13-...@sha256 reference.
# No default base or publishing target is selected by source.
ARG PYTHON_BASE
FROM ${PYTHON_BASE} AS dependencies
ARG PYTHON_BASE
RUN python -c 'import re,sys; assert sys.version_info[:2] == (3,13); assert re.fullmatch(r"docker.io/library/python:3\.13[-.a-z0-9]*@sha256:[0-9a-f]{64}",sys.argv[1])' "$PYTHON_BASE"
WORKDIR /build
COPY requirements-http.lock .
RUN python -m pip download --disable-pip-version-check --no-cache-dir \
    --only-binary=:all: --no-deps -r requirements-http.lock -d /wheels

FROM ${PYTHON_BASE} AS runtime
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=${SOURCE_REVISION}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/nonexistent
COPY --from=dependencies /wheels /wheels
COPY requirements-http.lock /build/requirements-http.lock
RUN --network=none python -m pip install --disable-pip-version-check --no-cache-dir \
    --no-index --find-links=/wheels --no-deps -r /build/requirements-http.lock \
    && rm -rf /wheels /build
WORKDIR /app
COPY ov_http /app/ov_http
RUN python -c 'import re,sys; assert sys.version_info[:2] == (3,13); assert re.fullmatch("[0-9a-f]{40}",sys.argv[1])' "$SOURCE_REVISION" \
    && mkdir -p /etc/ov-http \
    && touch /etc/ov-http/runtime.toml /etc/ov-http/backend-key \
    && chown 8098:8098 /etc/ov-http/runtime.toml /etc/ov-http/backend-key \
    && chmod 0600 /etc/ov-http/runtime.toml /etc/ov-http/backend-key \
    && chmod 0755 / /etc /etc/ssl /etc/ssl/certs /etc/ov-http /app \
    && chmod -R a+rX,go-w /app/ov_http \
    && python -c 'import ssl; ssl.create_default_context()'
USER 8098:8098
ENTRYPOINT ["python", "-m", "ov_http", "--config", "/etc/ov-http/runtime.toml"]
