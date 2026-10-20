"""The preactivation path validates protected files without creating clients."""
import sys
import shlex
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from ov_http import __main__ as cli


def files(tmp_path):
    secret = tmp_path / "backend-key"
    secret.write_text("synthetic-key-only")
    secret.chmod(0o600)
    config = tmp_path / "runtime.toml"
    config.write_text(
        'resource = "https://ov.example.invalid/mcp"\n'
        'issuer = "https://auth.example.invalid/ov/"\n'
        'jwks_url = "https://auth.example.invalid/ov/jwks/"\n'
        'backend_url = "http://127.0.0.1:1933/api/v1"\n'
        f'backend_secret_file = "{secret}"\n'
        'listen_host = "0.0.0.0"\nlisten_port = 8098\n')
    config.chmod(0o600)
    return config, secret


def run_check(config):
    with mock.patch.object(sys, "argv", ["ov_http", "--config", str(config), "--check-config"]), \
         mock.patch.object(cli, "create_app", side_effect=AssertionError("app constructed")), \
         mock.patch.object(cli.uvicorn, "run", side_effect=AssertionError("server started")), \
         mock.patch("socket.socket", side_effect=AssertionError("network used")):
        cli.main()


@pytest.mark.parametrize("reference,accepted", [
    ("docker.io/library/python:3.13-slim-bookworm@sha256:" + "a" * 64, True),
    ("docker.io/library/python:3.13-slim", False),
    ("docker.io/library/python:latest@sha256:" + "a" * 64, False),
    ("docker.io/library/python:3x13-slim@sha256:" + "a" * 64, False),
    ("docker.io/library/python:3.12-slim@sha256:" + "a" * 64, False),
])
def test_image_base_guard(reference, accepted):
    # Execute the actual build guard with synthetic input. No image is pulled.
    source = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    line = next(line for line in source.splitlines() if line.startswith("RUN python -c"))
    command = shlex.split(line.removeprefix("RUN "))
    result = subprocess.run([sys.executable, *command[1:-1], reference], capture_output=True)
    assert (result.returncode == 0) == accepted


def test_check_is_silent_and_offline(tmp_path, capsys):
    config, _ = files(tmp_path)
    run_check(config)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("fault", ["config-mode", "key-mode", "key-owner", "key-link", "schema", "key-content"])
def test_check_refuses_safely(tmp_path, capsys, fault):
    config, secret = files(tmp_path)
    if fault == "config-mode":
        config.chmod(0o644)
    elif fault == "key-mode":
        secret.chmod(0o644)
    elif fault == "key-owner":
        original = cli.Config.secret
        def wrong_owner(self):
            import os
            with mock.patch("ov_http.config.os.geteuid", return_value=os.geteuid() + 1):
                return original(self)
        with mock.patch.object(cli.Config, "secret", wrong_owner):
            with pytest.raises(SystemExit) as caught:
                run_check(config)
        assert caught.value.code == 2
        assert capsys.readouterr().err == "Invalid protected runtime configuration or secret file.\n"
        return
    elif fault == "key-link":
        target = tmp_path / "target"
        secret.rename(target)
        secret.symlink_to(target)
    elif fault == "schema":
        with config.open("a") as stream:
            stream.write('unknown = "synthetic-key-only"\n')
    else:
        secret.write_text("synthetic key with spaces")
    with pytest.raises(SystemExit) as caught:
        run_check(config)
    assert caught.value.code == 2
    assert capsys.readouterr().err == "Invalid protected runtime configuration or secret file.\n"
