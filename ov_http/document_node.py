"""Closed typed document-node descriptors shared by reads and writes."""

import re

from .auth import Refused

NODE_PATH = "/resources/document-node"
HASH = re.compile(r"^[a-f0-9]{64}$")
TREE = re.compile(r"^tree-sha256:[a-f0-9]{64}$")
CONTROL = re.compile(r"^file-controls-v1-sha256:[a-f0-9]{64}$")


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
