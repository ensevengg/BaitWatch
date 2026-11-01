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


def _fake_toolchain(
    tmp_path: Path, *, docker_ps: str, errors: str = "[]", scan_exit: int = 5
) -> dict:
    report = tmp_path / "report.json"
    report.write_text(
        '{"verdict": "BLOCK", "run": {"scan_id": "s1", "http_hits": [{}], "errors": '
        + errors
        + "}}",
        encoding="utf-8",
    )
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_executable(
        bindir / "docker",
        f"""#!/usr/bin/env bash
case "$1" in
  info|pull|image|network|build) exit 0 ;;
  version) echo "29.1.3" ;;
  ps) {docker_ps} ;;
  *) echo "unexpected docker call: $*" >&2; exit 1 ;;
esac
""",
    )
    _write_executable(
        bindir / "uv",
        f"""#!/usr/bin/env bash
[ "$1" = sync ] && exit 0
shift 2
if [ "$1" = baitwatch ]; then
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --json ]; then cp "{report}" "$2"; fi
    shift
  done
  exit {scan_exit}
fi
[ "$1" = python ] && shift
exec "{shutil.which("python") or "python3"}" "$@"
""",
    )
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    return env


def _run_setup(env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SETUP)], capture_output=True, text=True, timeout=60, env=env)


def test_setup_passes_with_a_clean_block_report(tmp_path):
    result = _run_setup(_fake_toolchain(tmp_path, docker_ps="exit 0"))
    assert result.returncode == 0, result.stderr
    assert "setup: OK" in result.stdout


def test_leftover_check_fails_when_docker_cannot_list(tmp_path):
    result = _run_setup(_fake_toolchain(tmp_path, docker_ps="exit 1"))
    assert result.returncode != 0
    assert "could not list containers" in result.stderr
    assert "setup: OK" not in result.stdout


def test_staging_cleanup_error_fails_setup(tmp_path):
    errors = '[{"code": "STAGING_CLEANUP", "message": "x"}]'
    result = _run_setup(_fake_toolchain(tmp_path, docker_ps="exit 0", errors=errors))
    assert result.returncode != 0
    assert "STAGING_CLEANUP" in result.stderr


def test_failed_scan_reports_labelled_leftovers_without_removing_them(tmp_path):
    result = _run_setup(_fake_toolchain(tmp_path, docker_ps="echo abc123", scan_exit=3))
    assert result.returncode != 0
    assert "scan-labelled resources exist" in result.stderr
    assert "expected exit 5 (BLOCK), got 3" in result.stderr
    assert "unexpected docker call" not in result.stderr
