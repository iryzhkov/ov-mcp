"""Build the reviewed HTTP context on a GitHub-hosted runner; never start the app."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

BASE = "docker.io/library/python:3.13-slim-trixie@sha256:fea139ecc0ab98360ead50b38872df6d42cf3503bec83215461224cbef0c8269"
BASE_CONFIG = "sha256:174c59289bb55d8266f1669fa4b2893ea11d0a0555f027884bd83aeabc7b2bd0"
# Native-incident product bytes qualified by Chaldea 288cfcaf-f20b-4cfe-a325-5d148d9015dd.
# Other context inputs retain the prior reviewed public integration pins.
INPUTS = {
    "Dockerfile": "f9cd4e1d68c4e79fe818476aee9c9eec1754cd82d83631f3497754c5699f9230",
    "requirements-http.lock": "9a2d3ee2755958f1053729c36ed28f26290d830aee0f6abd4e0d9d24d2bc41a7",
    "ov_http/__init__.py": "3ab2b85dfb48c88b2cb8375956dbc4b619775b8332596357cbaf12f7cb9497dc",
    "ov_http/__main__.py": "645edce5c993b36ed74f42ef734d79d50ce0b836dbd4705b9ea8d59bce0bb6e1",
    "ov_http/app.py": "b02ddd1532e69e22b63eaa2eb22a80fd12f3f2bafd7939a43dae270c2ad98167",
    "ov_http/auth.py": "74b38a42ae65fd15f686c26b9f3866a8bb2c935a836f122b9008e8313fe8b093",
    "ov_http/config.py": "e02fc83629be65ebf40252450306f7787f1bc35b7f8cbfa017c77b73b7646fa9",
    "ov_http/document_write.py": "a1988cd9dfb84b93885dc6814feab3dcbc2d94a97a9738ab8d7b323949f436bf",
    "ov_http/mutations.py": "8affa7e8b1200e2b633545c621c38d9138eb76a89074357027c304c2e4a6136e",
    "ov_http/reader.py": "aede8416bdcb756b6b5e709f7ce63af66a5f5d40975c680f3d28254cbe7dfe88",
}
OUT = Path("http-image-artifact")
CONTEXT = Path(".scratch/context")
LIMIT = 400 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode), f"Not a regular file: {path}")


def write_json(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n")


def stage_context():
    CONTEXT.mkdir(parents=True, exist_ok=False)
    require(Path("ov_http").is_dir() and not Path("ov_http").is_symlink(), "Invalid ov_http directory")
    require({str(p) for p in Path("ov_http").iterdir()} ==
            {p for p in INPUTS if p.startswith("ov_http/")}, "Unexpected ov_http entries")
    records = []
    for name, expected in INPUTS.items():
        source = Path(name)
        regular(source)
        data = source.read_bytes()
        require(digest(data) == "sha256:" + expected, f"Changed reviewed input: {name}")
        target = CONTEXT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        regular(target)
        require(file_digest(target) == digest(data), f"Context copy mismatch: {name}")
        records.append({"path": name, "bytes": len(data), "sha256": expected})
    return records


def normalized_config(config):
    # Docker <28.2 adds container-only defaults; <29 also includes empty OCI fields.
    # https://docs.docker.com/engine/deprecated/#non-standard-fields-in-image-inspect
    defaults = {
        "Hostname": "", "Domainname": "", "User": "", "Image": "", "WorkingDir": "",
        "MacAddress": "", "StopSignal": "", "AttachStdin": False, "AttachStdout": False,
        "AttachStderr": False, "Tty": False, "OpenStdin": False, "StdinOnce": False,
        "ArgsEscaped": False, "NetworkDisabled": False, "Env": None, "Cmd": None,
        "Entrypoint": None, "Volumes": None, "OnBuild": None, "Labels": None,
        "ExposedPorts": None, "Shell": None, "Healthcheck": None, "StopTimeout": None,
    }
    return {key: value for key, value in config.items()
            if key not in defaults or
            not (value == defaults[key] or defaults[key] is None and value in ([], {}))}


def archive_custody(path, inspect, prefix):
    """Verify saved config and uncompressed layers without extracting tar paths."""
    regular(path)
    require(0 < path.stat().st_size < LIMIT, "Archive exceeds 400 MiB bound")
    with tarfile.open(path, "r:") as archive:
        def read_member(name):
            member = archive.getmember(name)
            require(member.isfile(), f"Nonregular archive member: {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"Unreadable archive member: {name}")
            return stream
        with read_member("manifest.json") as stream:
            manifest_bytes = stream.read()
        manifest = json.loads(manifest_bytes)
        require(len(manifest) == 1, "Expected one saved image")
        entry = manifest[0]
        with read_member(entry["Config"]) as stream:
            config_bytes = stream.read()
        config = json.loads(config_bytes)
        require(digest(config_bytes) == inspect["Id"], "Saved config/image ID mismatch")
        require(config["rootfs"]["diff_ids"] == inspect["RootFS"]["Layers"], "RootFS mismatch")
        require(normalized_config(config["config"]) == normalized_config(inspect["Config"]), "Image Config mismatch")
        require(config["os"] == "linux" and config["architecture"] == "amd64", "Wrong image platform")
        require(len(entry["Layers"]) == len(config["rootfs"]["diff_ids"]), "Layer count mismatch")
        layers = []
        for name, expected in zip(entry["Layers"], config["rootfs"]["diff_ids"]):
            with read_member(name) as stream:
                magic = stream.read(2)
                stream.seek(0)
                layer = gzip.GzipFile(fileobj=stream) if magic == b"\x1f\x8b" else stream
                layer_hash = hashlib.sha256()
                for chunk in iter(lambda: layer.read(1024 * 1024), b""):
                    layer_hash.update(chunk)
                actual = "sha256:" + layer_hash.hexdigest()
            require(actual == expected, f"Saved layer mismatch: {name}")
            layers.append({"member": name, "diff_id": actual})
    (OUT / f"{prefix}-save-manifest.json").write_bytes(manifest_bytes)
    (OUT / f"{prefix}-config.json").write_bytes(config_bytes)
    return {"image_id": inspect["Id"], "saved_config_bytes": len(config_bytes), "Config": inspect["Config"],
            "RootFS": inspect["RootFS"], "saved_layers": layers}


def main():
    revision = os.environ["GITHUB_SHA"]
    run_id = os.environ["GITHUB_RUN_ID"]
    require(re.fullmatch("[0-9a-f]{40}", revision), "Invalid run commit")
    require(re.fullmatch("[0-9]+", run_id), "Invalid run ID")
    OUT.mkdir(exist_ok=False)
    commands = []

    def run(*args):
        result = subprocess.run(args, stdout=subprocess.PIPE, check=False)
        commands.append({"argv": list(args), "exit_code": result.returncode})
        require(result.returncode == 0, f"Command failed: {args[0]}")
        return result.stdout

    try:
        require(run("git", "rev-parse", "HEAD").decode().strip() == revision, "Checkout/run commit mismatch")
        tree = run("git", "rev-parse", "HEAD^{tree}").decode().strip()
        require(re.fullmatch("[0-9a-f]{40}", tree), "Invalid source tree")
        inputs = stage_context()
        write_json("source.json", {"commit": revision, "tree": tree, "run_id": run_id,
                                  "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "context_files": inputs})
        print(json.dumps({"commit": revision, "tree": tree, "context_files": inputs}), flush=True)
        versions = {
            "docker": run("docker", "version").decode(),
            "buildx": run("docker", "buildx", "version").decode(),
            "builder": run("docker", "buildx", "inspect", "default").decode(),
            "image_store": json.loads(run("docker", "info", "--format", "{{json .DriverStatus}}")),
            "runner_image": os.environ.get("ImageVersion", "unreported"),
            "runner_cpus": os.cpu_count(),
        }
        write_json("versions.json", versions)
        require("io.containerd.snapshotter.v1" not in str(versions["image_store"]),
                "Unsupported containerd image store; requires classic config-digest image IDs")
        raw = run("docker", "buildx", "imagetools", "inspect", "--raw", BASE)
        # Some buildx versions append a display newline. Preserve only bytes matching the pin.
        if digest(raw) != BASE.split("@")[1] and raw.endswith(b"\n"):
            raw = raw[:-1]
        require(digest(raw) == BASE.split("@")[1], "Pinned base manifest bytes mismatch")
        base_manifest = json.loads(raw)
        require(base_manifest["schemaVersion"] == 2 and "layers" in base_manifest, "Expected platform manifest")
        require(base_manifest["config"]["digest"] == BASE_CONFIG, "Unexpected base config descriptor")
        (OUT / "base-manifest.json").write_bytes(raw)
        run("docker", "pull", "--platform", "linux/amd64", BASE)
        base_inspect = json.loads(run("docker", "image", "inspect", BASE))[0]
        require(base_inspect["Id"] == BASE_CONFIG, "Pulled base config mismatch")
        run("docker", "image", "save", "--output", ".scratch/base.tar", BASE)
        base = archive_custody(Path(".scratch/base.tar"), base_inspect, "base")
        require(len(base_manifest["layers"]) == len(base["RootFS"]["Layers"]), "Base descriptor/layer count mismatch")
        require(base_manifest["config"]["size"] == base["saved_config_bytes"], "Base config descriptor size mismatch")
        Path(".scratch/base.tar").unlink()
        base.update({"reference": BASE, "manifest_digest": digest(raw),
                     "config_descriptor": base_manifest["config"],
                     "layer_descriptors": base_manifest["layers"],
                     "compressed_blob_verification": "Docker pull digest verification; saved layers checked against config diff_ids"})
        write_json("base.json", base)
        tag = f"ov-http-artifact:run-{run_id}"
        run("docker", "buildx", "build", "--builder", "default", "--load",
            "--platform", "linux/amd64", "--provenance=false",
            "--build-arg", f"PYTHON_BASE={BASE}", "--build-arg", f"SOURCE_REVISION={revision}",
            "--tag", tag, "--iidfile", str(OUT / "image-id.txt"),
            "--metadata-file", str(OUT / "build-metadata.json"),
            "--file", str(CONTEXT / "Dockerfile"), str(CONTEXT))
        image = json.loads(run("docker", "image", "inspect", tag))[0]
        require((OUT / "image-id.txt").read_text().strip() == image["Id"], "Build/image ID mismatch")
        require(image["Config"]["User"] == "8098:8098", "Unexpected runtime user")
        require(image["Config"]["Labels"]["org.opencontainers.image.revision"] == revision, "Source label mismatch")
        require(image["RootFS"]["Layers"][:len(base["RootFS"]["Layers"])] == base["RootFS"]["Layers"], "Base RootFS mismatch")
        archive = OUT / "image.tar"
        run("docker", "image", "save", "--output", str(archive), tag)
        custody = archive_custody(archive, image, "image")
        custody.update({"tag": tag, "archive": "image.tar", "archive_bytes": archive.stat().st_size,
                        "archive_sha256": file_digest(archive),
                        "distribution_manifest_digest": None,
                        "distribution_manifest_gap": "No registry export; image ID is the config digest, not a distribution digest.",
                        "resource_bounds": "ubuntu-24.04 hosted runner, 15 minute job; no per-build CPU/memory limits. Homelab 2 CPU/2 GiB gate remains separate.",
                        "runtime_acceptance": "Not performed; no application container started."})
        write_json("image.json", custody)
        (OUT / "image.tar.sha256").write_text(f"{file_digest(archive).split(':')[1]}  image.tar\n")
    finally:
        write_json("command-status.json", commands)
    for path in OUT.iterdir():
        regular(path)
    require(sum(p.stat().st_size for p in OUT.iterdir()) < LIMIT, "Artifact exceeds 400 MiB bound")


if __name__ == "__main__":
    main()
