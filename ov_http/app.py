"""Dedicated stateless HTTP MCP entrypoint and explicit reader catalog."""
import asyncio
from contextlib import asynccontextmanager
import json
import logging
import ssl
import time

import httpx
import jsonschema
from mcp.server import Server
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool, ToolAnnotations
from starlette.responses import JSONResponse
from starlette.routing import Route

from .auth import Principal, Refused, Verifier
from .config import Config, RESOURCES_PROFILE
from .personal import PERSONAL_ACTIONS, PERSONAL_SPECS, PERSONAL_READ_ONLY, call_personal
from .reader import Backend, BudgetExhausted, Reader, SAFE_ERROR
from .mutations import DOCUMENT_WRITE_SECONDS, MUTATION_SPECS, READ_ONLY, UNKNOWN, call_mutation

WRITE_ADMISSION_SECONDS = DOCUMENT_WRITE_SECONDS + 15
REFRESHABLE_LIFETIME_SECONDS = WRITE_ADMISSION_SECONDS + 15
WRITE_ACTIONS = frozenset({"write", "remove", "maintain"})

STRING = {"type": "string", "minLength": 1, "maxLength": 1024}
URI_ARG = {**STRING, "description": "Canonical viking://resources/... URI within this token's grants."}
LIMIT = {"type": "integer", "minimum": 1, "maximum": 100}
BOOL = {"type": "boolean"}
SPECS = {
    "memory_search": ("Scoped semantic search requires the operator-pinned namespace profile. Bounded, incomplete batch.",
                      {"query": STRING, "scope": {**URI_ARG, "description": "Optional authorized directory. The resources profile narrows retrieval; the legacy profile asserts an exact grant."},
                       "limit": LIMIT, "group": BOOL,
                       "include_archived": BOOL}, ["query"]),
    "memory_find": ("Scoped semantic find requires the operator-pinned namespace profile. Bounded, incomplete batch.",
                    {"query": STRING, "scope": {**URI_ARG, "description": "Optional authorized directory. The resources profile narrows retrieval; the legacy profile asserts an exact grant."},
                       "limit": LIMIT, "group": BOOL,
                     "include_archived": BOOL}, ["query"]),
    "memory_grep": ("Literal substring search over authorized files only. Bounded; grouped by document by default.",
                    {"pattern": STRING, "uri": URI_ARG, "case_insensitive": BOOL, "limit": LIMIT,
                     "group": BOOL, "include_archived": BOOL}, ["pattern"]),
    "memory_glob": ("Bounded filename glob over authorized trees only.",
                    {"pattern": STRING, "uri": URI_ARG, "limit": LIMIT}, ["pattern"]),
    "memory_ls": ("List authorized children. Omitted URI lists each granted root's children.",
                  {"uri": URI_ARG, "recursive": BOOL, "limit": LIMIT}, []),
    "memory_tree": ("Bounded authorized directory tree. Returns paths without upstream ancestor summaries.",
                    {"uri": URI_ARG, "level_limit": {"type": "integer", "minimum": 1, "maximum": 12},
                     "limit": LIMIT}, []),
    "memory_stat": ("Safe metadata; directory sizes sum visible authorized content. "
                    "include_revision=true returns only uri and an existing typed node snapshot, without recursive stats.",
                    {"uri": URI_ARG, "include_revision": BOOL}, ["uri"]),
    "memory_read": ("Read a file or reassemble chunked document in natural name order. Offset and limit are lines.",
                    {"uri": URI_ARG, "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
                     "limit": {"type": "integer", "minimum": 1, "maximum": 2000}, "parts": BOOL,
                     "storage": {"type": "string", "enum": ["legacy-chunked", "exact-directory-v2"]}}, ["uri"]),
    "memory_abstract": ("Read this authorized directory's hidden abstract. No parent fallback.",
                        {"uri": URI_ARG}, ["uri"]),
    "memory_overview": ("Read this authorized directory's hidden overview. No parent fallback.",
                        {"uri": URI_ARG}, ["uri"]),
    "memory_relations": ("Resolve wikilinks and backlinks within authorized trees. Stored relations unavailable.",
                         {"uri": URI_ARG}, ["uri"]),
}


def schema(name, profile="disabled"):
    _, properties, required = {**SPECS, **MUTATION_SPECS, **PERSONAL_SPECS}[name]
    if profile == RESOURCES_PROFILE and name in ("memory_ls", "memory_tree"):
        properties = {**properties, "offset": {"type": "integer", "minimum": 0, "maximum": 100000,
                      "description": "Visible-node offset. Reauthorized each call; best effort under concurrent edits. Page cap 40. Multiple grants require an explicit directory URI."}}
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


def result(value, error=False):
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(text.encode()) > 49152:
        text, error = json.dumps({"error": "Output limit exceeded; narrow the request."}), True
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=error)


class SecurityGate:
    def __init__(self, app, config, verifier):
        self.app, self.config, self.verifier = app, config, verifier

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = scope.get("headers", [])
        hosts = [v for k, v in headers if k.lower() == b"host"]
        origins = [v for k, v in headers if k.lower() == b"origin"]
        if (hosts != [self.config.authority.encode()] or
                (origins and origins != [self.config.origin.encode()])):
            return await JSONResponse({"error": "Invalid request origin."}, status_code=403)(scope, receive, send)
        path = scope.get("path", "")
        if path in ("/health", "/.well-known/oauth-protected-resource/mcp"):
            return await self.app(scope, receive, send)
        if path != "/mcp" or scope.get("query_string"):
            return await JSONResponse({"error": "Not found."}, status_code=404)(scope, receive, send)
        authorization = [v for k, v in headers if k.lower() == b"authorization"]
        try:
            if len(authorization) != 1 or len(authorization[0]) > 12300:
                raise Refused()
            value = authorization[0].decode("ascii")
            if not value.startswith("Bearer "):
                raise Refused()
            async with asyncio.timeout(5):
                principal = await self.verifier.verify(value[7:])
            if (scope.get("method") == "POST"
                    and self.config.mutation_profile != "disabled"
                    and WRITE_ACTIONS.intersection(principal.actions)
                    and principal.expires - principal.issued >= REFRESHABLE_LIFETIME_SECONDS
                    and principal.expires - time.time() < WRITE_ADMISSION_SECONDS):
                logging.getLogger(__name__).warning("ov-http admission lifetime-refused")
                raise Refused()
        except (Refused, UnicodeError, TimeoutError):
            challenge = ('Bearer resource_metadata="' + self.config.metadata_url +
                         '", scope="ov.read"')
            return await JSONResponse({"error": "Invalid bearer token."}, status_code=401,
                                      headers={"WWW-Authenticate": challenge, "Cache-Control": "no-store"})(
                                          scope, receive, send)
        scope = dict(scope)
        scope["ov.principal"] = principal
        scope["ov.operation"] = {}
        # A stateless POST has no durable session for a later cancellation
        # notification. Its HTTP disconnect must cancel in-flight backend work.
        messages = asyncio.Queue(maxsize=1)

        async def relay():
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                await messages.put(message)

        # Shared ceiling accommodates document writes; per-tool caps stay separate.
        request_task = asyncio.create_task(self.app(scope, messages.get, send))
        disconnect_task = asyncio.create_task(relay())
        try:
            done, _ = await asyncio.wait({request_task, disconnect_task}, timeout=DOCUMENT_WRITE_SECONDS + 5,
                                         return_when=asyncio.FIRST_COMPLETED)
            if not done:
                timeout_value = UNKNOWN if scope["ov.operation"].get("dispatched") else {"error": "Request timeout."}
                await JSONResponse(timeout_value, status_code=408)(scope, receive, send)
            if request_task.done():
                await request_task
        finally:
            for task in (request_task, disconnect_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(request_task, disconnect_task, return_exceptions=True)


def create_app(config: Config, *, jwks_ssl_context: ssl.SSLContext | None = None):
    # Constructed once by protected runtime configuration, never from request data.
    if jwks_ssl_context is not None and not isinstance(jwks_ssl_context, ssl.SSLContext):
        raise ValueError("JWKS test trust must be an SSLContext")
    backend_key = config.secret()
    backend_client = httpx.AsyncClient(
        headers={"X-API-Key": backend_key, "X-OpenViking-Agent": "ov-http-reader", "Accept-Encoding": "identity"},
        timeout=10, trust_env=False, follow_redirects=False,
        limits=httpx.Limits(max_connections=16, max_keepalive_connections=8))
    jwks_client = httpx.AsyncClient(timeout=5, trust_env=False, follow_redirects=False,
                                   headers={"Accept-Encoding": "identity"},
                                   verify=jwks_ssl_context if jwks_ssl_context is not None else True,
                                   limits=httpx.Limits(max_connections=2, max_keepalive_connections=2))
    verifier = Verifier(config, jwks_client)

    catalog = {**SPECS, **MUTATION_SPECS} if config.mutation_profile != "disabled" else SPECS

    if config.personal_profile != "disabled":
        catalog = {**catalog, **PERSONAL_SPECS}

    async def list_tools(ctx, params):
        return ListToolsResult(tools=[
            Tool(name=name, description=description, input_schema=schema(name, config.semantic_profile),
                 annotations=ToolAnnotations(read_only_hint=name in SPECS or name in READ_ONLY or name in PERSONAL_READ_ONLY,
                                             destructive_hint=name not in SPECS and name not in READ_ONLY and name not in PERSONAL_READ_ONLY,
                                             idempotent_hint=name in SPECS or name in READ_ONLY or name in PERSONAL_READ_ONLY,
                                             open_world_hint=False))
            for name, (description, _, _) in catalog.items()
        ])

    async def call_tool(ctx, params):
        try:
            name, arguments = params.name, params.arguments or {}
            if name not in catalog:
                return result({"error": "Tool unavailable."}, True)
            jsonschema.validate(arguments, schema(name, config.semantic_profile))
            request = ctx.request
            principal = request.scope.get("ov.principal") if request is not None else None
            if not isinstance(principal, Principal):
                raise Refused()
            if name in PERSONAL_SPECS:
                backend = Backend(config, principal, backend_client)
                value, error = await call_personal(backend, name, arguments, request.scope["ov.operation"])
                return result(value, error)
            # Verify every supplied URI before any upstream query, even disabled tools.
            for key in ("uri", "scope"):
                if key in arguments:
                    principal.require(arguments[key])
            if name in ("memory_search", "memory_find") and config.semantic_profile == "disabled":
                return result({"error": "Scoped semantic search unavailable: pinned namespace profile required. "
                              "Use memory_grep or memory_glob."}, True)
            backend = Backend(config, principal, backend_client)
            if name in MUTATION_SPECS:
                value, error = await call_mutation(backend, name, arguments, request.scope["ov.operation"])
                return result(value, error)
            reader = Reader(backend)
            async with asyncio.timeout(20):
                if name in ("memory_search", "memory_find"):
                    value = await reader.semantic(name.removeprefix("memory_"), arguments["query"],
                                                  arguments.get("scope"), arguments.get("limit", 10),
                                                  arguments.get("group", True),
                                                  arguments.get("include_archived", False))
                elif (name in ("memory_ls", "memory_tree")
                        and config.semantic_profile == RESOURCES_PROFILE):
                    value = await reader.paged_listing(
                        arguments.get("uri"),
                        name == "memory_tree" or arguments.get("recursive", False),
                        arguments.get("limit", 100 if name == "memory_tree" else 50),
                        arguments.get("level_limit", 2) if name == "memory_tree" else 12,
                        arguments.get("offset", 0))
                elif name == "memory_ls":
                    value = await reader.listing(arguments.get("uri"), arguments.get("recursive", False),
                                                 arguments.get("limit", 50))
                elif name == "memory_tree":
                    value = await reader.listing(arguments.get("uri"), True, arguments.get("limit", 100),
                                                 arguments.get("level_limit", 2))
                elif name == "memory_grep":
                    value = await reader.grep(arguments["pattern"], arguments.get("uri"),
                                              arguments.get("case_insensitive", False), arguments.get("limit", 50),
                                              arguments.get("group", True), arguments.get("include_archived", False))
                elif name == "memory_glob":
                    value = await reader.glob(arguments["pattern"], arguments.get("uri"),
                                              arguments.get("limit", 50))
                elif name in ("memory_abstract", "memory_overview"):
                    value = await reader.summary(arguments["uri"], name.removeprefix("memory_"))
                elif name == "memory_stat":
                    value = await reader.stat(arguments["uri"], arguments.get("include_revision", False))
                elif name == "memory_relations":
                    value = await reader.relations(arguments["uri"])
                else:
                    value = await reader.read(arguments["uri"], arguments.get("offset", 0),
                                              arguments.get("limit", 500), arguments.get("parts", False),
                                              arguments.get("storage", "legacy-chunked"))
            if time.time() >= principal.expires:
                raise Refused()
            return result(value)
        except jsonschema.ValidationError:
            return result({"error": "Invalid tool arguments."}, True)
        except (Refused, BudgetExhausted, httpx.HTTPError, TimeoutError, ValueError, TypeError, RecursionError):
            return result({"error": SAFE_ERROR}, True)

    server = Server("ov-http-reader", version="0.1.0", on_list_tools=list_tools, on_call_tool=call_tool,
                    get_tool_input_schema=lambda name: schema(name, config.semantic_profile) if name in catalog else None)

    async def health(request):
        return JSONResponse({"ok": True})

    async def metadata(request):
        return JSONResponse({"resource": config.resource, "authorization_servers": [config.issuer],
                             "scopes_supported": (["ov.read", "ov.write", "ov.remove", "ov.maintain"]
                                                  if config.mutation_profile != "disabled" else ["ov.read"])
                                                  + (["ov.personal." + a for a in PERSONAL_ACTIONS]
                                                     if config.personal_profile != "disabled" else []),
                             "bearer_methods_supported": ["header"]})

    sdk_app = server.streamable_http_app(
        json_response=True, stateless_http=True, max_request_body_size=32768,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=[config.authority],
            allowed_origins=[config.origin]),
        custom_starlette_routes=[
            Route("/health", health, methods=["GET"]),
            Route("/.well-known/oauth-protected-resource/mcp", metadata, methods=["GET"]),
        ])
    sdk_lifespan = sdk_app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app):
        async with backend_client, jwks_client, sdk_lifespan(app):
            try:
                yield
            finally:
                await verifier.close()

    sdk_app.router.lifespan_context = lifespan
    return SecurityGate(sdk_app, config, verifier)
