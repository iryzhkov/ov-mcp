"""Closed resources document-write protocol; no parser or private-stage forwarding."""

import asyncio
import hashlib
import re
import secrets
from collections import Counter

import httpx

from .auth import Refused, contains
from .reader import DOC_EXTS, BudgetExhausted, Reader

CONTRACT_PATH = "/resources/document-write-contract"
CONTRACT = {"contract": "resources-document-write", "version": 1}
NODE_PATH = "/resources/document-node"
WRITE_PATH = "/resources/document-write"
HASH = re.compile(r"^[a-f0-9]{64}$")
TREE = re.compile(r"^tree-sha256:[a-f0-9]{64}$")
CONTROL = re.compile(r"^file-controls-v1-sha256:[a-f0-9]{64}$")
STATES = {
    "not_started",
    "target_unchanged",
    "rolled_back",
    "rollback_failed",
    "rollback_unavailable",
    "unknown",
    "committed",
}


def node(value, *, absent=True):
    if not isinstance(value, dict):
        raise Refused()
    kind = value.get("kind")
    if absent and kind == "absent" and set(value) == {"kind"}:
        return dict(value)
    if kind == "file" and set(value) == {"kind", "content_sha256", "control_revision"}:
        if (
            isinstance(value["content_sha256"], str)
            and HASH.fullmatch(value["content_sha256"])
            and isinstance(value["control_revision"], str)
            and CONTROL.fullmatch(value["control_revision"])
        ):
            return dict(value)
    if kind == "directory" and set(value) == {"kind", "tree_revision"}:
        if isinstance(value["tree_revision"], str) and TREE.fullmatch(
            value["tree_revision"]
        ):
            return dict(value)
    raise Refused()


# Input is already capped at 1 MiB; bound comparison allocations independently.
MAX_EQUIVALENCE_LINES = 16384


def parsed_equivalence(original, observed, sources, target):
    """Classify bounded parsed comparisons without erasing words or proving aliases."""
    if (
        original.count("\n") > MAX_EQUIVALENCE_LINES
        or observed.count("\n") > MAX_EQUIVALENCE_LINES
    ):
        raise BudgetExhausted()

    # Reader strips outer chunk boundaries. As in the original verifier, ignore
    # blank lines and trailing line whitespace, never internal spaces/indentation.
    def lines(text):
        return [line.rstrip() for line in text.strip().split("\n") if line.strip()]

    written, read_back = lines(original), lines(observed)
    heading = False
    if written and written[0].startswith("# ") and written[0] not in read_back:
        title = written[0][2:]
        # A missing title is only represented structurally when an ACTUAL
        # Reader source includes that exact directory component beneath target.
        heading = any(
            source.startswith(target + "/")
            and title in source[len(target) + 1 :].split("/")[:-1]
            for source in sources
        )
        if heading:
            written = written[1:]
    if written == read_back:
        return (
            "title_directory_and_boundary_whitespace"
            if heading
            else "boundary_line_whitespace"
        )
    if Counter(written) == Counter(read_back):
        return "title_directory_and_line_order" if heading else "line_order"
    if (
        not heading
        and written
        and written[0].startswith("# ")
        and written[0] not in read_back
        and Counter(written[1:]) == Counter(read_back)
        and any(
            source.startswith(target + "/") and "/" in source[len(target) + 1 :]
            for source in sources
        )
    ):
        # Nested Reader sources do not prove an alias retains this title.
        # Exactly one missing first H1 is inconclusive, never equivalence.
        return "unavailable_transformation"
    return None


class DocumentWriter:
    """One conditional publication; owning backend provides private preparation."""

    def __init__(self, operation):
        self.m = operation
        self.p = operation.p
        self.target = ""
        self.backup = None

    def checks(self, paths, actions):
        result = []
        for path in paths:
            for action in actions:
                self.p.require_action(action, path)
                result.append((action, path))
        return result

    async def observe(self, uri):
        self.p.require_action("read", uri)
        value = await self.m.request("GET", NODE_PATH, params={"uri": uri},
                                     error_projection=self.project_observation_error)
        self.p.require_action("read", uri)
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("result"), dict)
            or set(value["result"]) != {"uri", "node"}
            or value["result"]["uri"] != uri
        ):
            raise Refused()
        return node(value["result"]["node"])

    def project_observation_error(self, status, error):
        # Read-only diagnostics use exact allowlisted protocol text, never details.
        categories = {
            "Document URI must be canonical resources content": "invalid_document_uri",
            "Directory fragment controls are unsupported": "directory_fragment_controls",
            "Resource document has residual index state": "residual_index_state",
            "Document context inventory incomplete": "context_inventory_incomplete",
            "Document context limit exceeded": "context_limit",
            "Document aliases are unsupported": "document_alias",
        }
        if status in {400, 409}:
            message = error.get("message")
            if isinstance(message, str) and message in categories:
                self.m.state["preflight_category"] = categories[message]

    async def contract(self):
        self.p.require_action("read")
        value = await self.m.request("GET", CONTRACT_PATH)
        if (
            not isinstance(value, dict)
            or value.get("result") != CONTRACT
            or type(value["result"].get("version")) is not int
        ):
            from .mutations import unsupported

            unsupported(
                "Required document-write contract unavailable; no document write dispatched."
            )
        self.p.require_action("read")

    def project_error(self, status, error):
        from .mutations import OperationError

        # Only typed target-relative states and one declared backup observation
        # are projected; private stages, messages and foreign details are discarded.
        details = error.get("details")
        if (
            not isinstance(details, dict)
            or details.get("uri") != self.target
            or details.get("content_state") not in STATES
            or details.get("processing_state", "unobserved")
            not in {"unobserved", "failed"}
        ):
            raise Refused()
        state = details["content_state"]
        answer = {
            "uri": self.target,
            "outcome": state,
            "content_state": state,
            "processing_state": details.get("processing_state", "unobserved"),
            "error": "Document write did not return a successful publication.",
            "backup_state": "unobserved",
            "retry_safe": False,
        }
        if state == "committed":
            self.m.state["document_committed"] = answer
        copies = details.get("retained_copies")
        if self.backup is not None and isinstance(copies, list) and len(copies) == 1:
            copy = copies[0]
            try:
                if (
                    not isinstance(copy, dict)
                    or set(copy) != {"uri", "node"}
                    or copy["uri"] != self.backup
                ):
                    raise Refused()
                retained = (
                    None if copy["node"] is None else node(copy["node"], absent=False)
                )
                self.p.require_action("read", self.backup)
                answer["retained_copies"] = [{"uri": self.backup, "node": retained}]
                if retained is not None:
                    answer["backup_state"] = "retained"
            except (Refused, ValueError, TypeError):
                pass
        # State is about the target only: backup/parent effects are unobserved.
        self.m.state["dispatched"] = False
        raise OperationError(answer)

    def ack(self, value, expected, representation, digest):
        required = {
            "uri",
            "node",
            "input_sha256",
            "representation",
            "content_state",
            "processing_state",
            "backup",
            "cleanup_state",
        }
        if (
            not isinstance(value, dict)
            or set(value) != required
            or value["uri"] != self.target
            or value["input_sha256"] != digest
            or value["representation"] != representation
            or value["content_state"] != "committed"
            or value["processing_state"] not in {"accepted", "failed", "unobserved"}
            or value["cleanup_state"] not in {"complete", "retained", "unknown"}
        ):
            raise Refused()
        current = node(value["node"], absent=False)
        if current["kind"] != ("file" if representation == "raw_file" else "directory"):
            raise Refused()
        if current["kind"] == "file" and current["content_sha256"] != digest:
            raise Refused()
        backup = value["backup"]
        if self.backup is None:
            if backup is not None:
                raise Refused()
        else:
            if (
                not isinstance(backup, dict)
                or set(backup) != {"uri", "node"}
                or backup["uri"] != self.backup
            ):
                raise Refused()
            old = node(backup["node"], absent=False)
            if old["kind"] != expected["kind"]:
                raise Refused()
            if (
                old["kind"] == "file"
                and old["content_sha256"] != expected["content_sha256"]
            ):
                raise Refused()
            backup = {"uri": self.backup, "node": old}
        return {
            "uri": self.target,
            "node": current,
            "input_sha256": digest,
            "representation": representation,
            "content_state": "committed",
            "outcome": "committed",
            "processing_state": value["processing_state"],
            "backup": backup,
            "cleanup_state": value["cleanup_state"],
            "indexing": "not_revision_bound",
            "searchable_completion": False,
            "retry_safe": False,
            "verification": {
                "status": "not_requested",
                "observation": "not_linearizable",
            },
        }

    async def verify(self, answer, raw):
        result: dict = {
            "status": "unavailable",
            "observation": "post_commit_not_linearizable",
        }
        try:
            if await self.observe(self.target) != answer["node"]:
                result["status"] = "concurrent_change"
                return result
            # Reuse the actual Reader and its existing finite traversal/budgets.
            text, sources = await Reader(self.m.backend).assemble(self.target)
            if await self.observe(self.target) != answer["node"]:
                result["status"] = "concurrent_change"
            else:
                result.update(
                    status="exact" if text.encode("utf-8") == raw else "different",
                    parts=len(sources),
                    complete=True,
                )
                if (
                    result["status"] == "different"
                    and answer["representation"] == "parsed_directory"
                ):
                    reshape = parsed_equivalence(
                        raw.decode("utf-8"), text, sources, self.target
                    )
                    if reshape == "unavailable_transformation":
                        result.update(
                            status="unavailable_transformation",
                            complete=False,
                            explanation="Content committed; every remaining body line and duplicate count matches, "
                            "but title retention is not proven under the parser transformation. "
                            "Verification is inconclusive, not verified equivalence.",
                        )
                    elif reshape is not None:
                        result.update(
                            status="equivalent_reshaped",
                            reshape=reshape,
                            explanation="Parsed Reader observation retains every nonblank line and duplicate count "
                            "after the stated boundary-whitespace, evidenced title-directory, "
                            "or line-order reshape; internal spaces and indentation are preserved.",
                        )
        except BudgetExhausted:
            result["status"] = "unavailable_budget"
            result["complete"] = False
        except asyncio.CancelledError:
            result["status"] = "unavailable_cancelled"
        except (
            Refused,
            httpx.HTTPError,
            TimeoutError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            pass
        return result

    async def write(self, a):
        from .mutations import OperationError, unsupported

        self.m.state["document_write"] = True
        if "expected_sha256" in a:
            raise OperationError({
                "error": "Default document writes use observed node CAS; expected_sha256 requires storage=file-deferred-v1.",
                "outcome": "not_started", "supported": False,
            })
        to, filename = a["to"], a["filename"]
        if (
            not isinstance(filename, str)
            or "/" in filename
            or filename
            in {".watch_tasks.json", ".watch_tasks.json.bak", ".watch_tasks.json.tmp"}
        ):
            raise Refused()
        self.m.authorize("write", to, to + "/" + filename, strict=True)
        if not filename.endswith(DOC_EXTS):
            filename += ".md"
        if a.get("archived", False) and not set(to.split("/")) & {
            "archive",
            "archived",
            "_archive",
        }:
            to += "/archive"
        self.target = (
            to + "/" + filename + (".verbatim" if a.get("verbatim", False) else "")
        )
        self.m.authorize("write", to, self.target, strict=True)
        if self.target in self.p.roots:
            raise Refused()
        raw, reason = a["text"].encode("utf-8"), a.get("reason", "")
        if len(raw) > 1048576 or len(reason.encode("utf-8")) > 1024:
            raise Refused()
        actions = ("read", "write", "maintain")
        generated = [
            self.target,
            self.target + "/.abstract.md",
            self.target + "/.overview.md",
        ]
        if a.get("verbatim", False):
            generated += [
                self.target + "/0001",
                self.target + "/0001/0000.md",
                self.target + "/0001/.abstract.md",
                self.target + "/0001/.overview.md",
            ]
        # A namespace grant covers the declared target subtree, including
        # backend-owned parsed member names; private stage paths are not guessed.
        checks = self.checks([to, *generated], actions) + self.m.ancestor_checks(
            self.target
        )
        self.m.state["preflight_stage"] = "parent"
        await self.m.existing_parent(self.target, "write")
        self.m.state["preflight_stage"] = "target_node"
        expected = await self.observe(self.target)
        if expected["kind"] != "absent" and not a.get("overwrite", False):
            raise OperationError(
                {
                    "uri": self.target,
                    "error": "Target exists; no write dispatched.",
                    "outcome": "not_started",
                    "conflict": True,
                }
            )
        representation = (
            "verbatim"
            if a.get("verbatim", False)
            else "raw_file"
            if expected["kind"] == "file"
            else "ingest"
        )
        if expected["kind"] != "absent":
            self.m.state["preflight_stage"] = "subtree"
            checks += self.checks(generated, ("remove",))
            paths = (
                await self.m.subtree(self.target, "read")
                if expected["kind"] == "directory"
                else [self.target]
            )
            checks += self.checks(paths, ("read", "write", "maintain", "remove"))
            self.m.state["preflight_stage"] = "backup"
            archive = (
                to
                if set(to.split("/")) & {"archive", "archived", "_archive"}
                else to + "/archive"
            )
            self.backup = archive + "/" + filename + ".backup-" + secrets.token_hex(8)
            self.m.authorize("write", self.backup, strict=True)
            if (
                self.backup in self.p.roots
                or contains(self.target, self.backup)
                or contains(self.backup, self.target)
            ):
                raise Refused()
            backup_paths = [
                self.backup,
                self.backup + "/.abstract.md",
                self.backup + "/.overview.md",
            ]
            backup_paths += [self.backup + path[len(self.target) :] for path in paths]
            checks += self.checks([archive, *backup_paths], actions)
            checks += self.m.ancestor_checks(self.backup)
            # No archive-parent auto-creation or absence inferred from stat errors.
            await self.m.existing_parent(self.backup, "write")
            if await self.observe(self.backup) != {"kind": "absent"}:
                unsupported(
                    "Generated backup destination is not absent; no write dispatched."
                )
        payload = {
            "target_uri": self.target,
            "source_name": filename,
            "text": a["text"],
            "reason": reason,
            "representation": representation,
            "expected": expected,
        }
        if self.backup is not None:
            payload["backup_uri"] = self.backup
        self.m.state["preflight_stage"] = "contract"
        await self.contract()
        for action, uri in checks:
            self.p.require_action(action, uri)
        self.m.state["preflight_stage"] = "ready"
        if a.get("dry_run") is True:
            return {"outcome": "not_started", "preflight_passed": True,
                    "retry_safe": False, "indexing": "not_observed"}
        value = await self.m.request(
            "POST",
            WRITE_PATH,
            effect=True,
            precondition_conflicts=False,
            error_projection=self.project_error,
            json=payload,
        )
        answer = self.ack(
            value.get("result") if isinstance(value, dict) else None,
            expected,
            {
                "ingest": "parsed_directory",
                "raw_file": "raw_file",
                "verbatim": "verbatim_directory",
            }[representation],
            hashlib.sha256(raw).hexdigest(),
        )
        # Record typed commit before verification, later expiry or cancellation.
        self.m.state["document_committed"] = answer
        if a.get("verify", True):
            answer["verification"] = await self.verify(answer, raw)
        return answer
