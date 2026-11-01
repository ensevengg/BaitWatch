import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
SETUP = ROOT / "run" / "setup.sh"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_setup_script_parses():
    result = subprocess.run(["bash", "-n", str(SETUP)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_preflight_rejects_docker_27_without_running_anything_else(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    uv_marker = tmp_path / "uv-called"
    _write_executable(
        bindir / "docker",
        """#!/usr/bin/env bash
case "$1" in
  info) exit 0 ;;
  version) echo "27.0.7" ;;
  *) echo "unexpected docker call: $*" >&2; exit 1 ;;
esac
""",
    )
    _write_executable(
        bindir / "uv",
        f"""#!/usr/bin/env bash
echo called >> "{uv_marker}"
exit 0
""",
    )
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    result = subprocess.run(
        ["bash", str(SETUP)],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=tmp_path,
        env=env,
    )
    assert result.returncode != 0
    assert "28" in result.stderr
    assert "27" in result.stderr
    assert not uv_marker.exists()


def test_setup_script_shellcheck_if_available():
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        pytest.skip("shellcheck is not installed")
    result = subprocess.run([shellcheck, str(SETUP)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
