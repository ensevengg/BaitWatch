"""Day 6 chaos: hostile repository shapes through real detonate() fail closed."""

import json
import os
import socket
import time
from pathlib import Path, PurePosixPath

import pytest

from run.evidence import State
from run.honeytokens import generate_tokens
from run.sandbox import SandboxConfig
from run.staging import StagingLimits

pytestmark = pytest.mark.docker
PYTHON_IMAGE = "python:3.12-alpine"
CANARY = "DO-NOT-COPY-THIS-FIXTURE"

# Planted into the staged copy of every scan, so the cage's /repo view
# legitimately holds them and their parent directories.
PLANTED = {token.location for token in generate_tokens().tokens}
PLANTED |= {str(PurePosixPath(loc).parent) for loc in PLANTED}
PLANTED.discard(".")


def assert_scan_ran_without_errors(evidence) -> None:
    # A plain command scan is never complete: the decoy did not run, so the
    # verdict can never be ALLOW.
    assert not evidence.errors, [error.model_dump_json() for error in evidence.errors]
    assert evidence.status == "incomplete"
    assert evidence.components.decoy == State.NOT_RUN
    for component in ("sandbox", "dns_sink", "http_sink", "tls_sink", "trace"):
        assert getattr(evidence.components, component) == State.COMPLETE


@pytest.mark.parametrize("shape", ["empty", "only-empty-git-dir"])
def test_degenerate_repo_shapes_stage_and_scan(
    tmp_path,
    recorded_sandbox,
    run_scan,
    tree_digest,
    assert_no_leftovers,
    assert_staging_gone,
    shape,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    if shape == "only-empty-git-dir":
        (repo / ".git").mkdir()
    before = tree_digest(repo)
    evidence = run_scan(repo)
    assert_scan_ran_without_errors(evidence)
    if shape == "only-empty-git-dir":
        assert evidence.staging_exclusions == [".git"]
    else:
        assert evidence.staging_exclusions == []
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


def test_five_thousand_file_repo_scans_within_limits(
    tmp_path, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    repo = tmp_path / "repo"
    repo.mkdir()
    for bucket in range(5):
        target = repo / f"bucket-{bucket}"
        target.mkdir()
        for index in range(1000):
            (target / f"file-{bucket}-{index:04}.txt").write_text("filler line\n")
    before = tree_digest(repo)
    started = time.monotonic()
    evidence = run_scan(repo)
    print(f"5000-file scan wall time: {time.monotonic() - started:.1f}s")
    assert_scan_ran_without_errors(evidence)
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


@pytest.mark.parametrize("kind", ["single-file", "total"])
def test_size_limits_refuse_staging_and_fail_closed(
    tmp_path,
    recorded_sandbox,
    run_scan,
    tree_digest,
    assert_no_leftovers,
    assert_staging_gone,
    kind,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    if kind == "single-file":
        (repo / "big.bin").write_bytes(b"x" * 2048)
        limits = StagingLimits(max_file_bytes=1024, max_bytes=1024 * 1024)
    else:
        (repo / "a.bin").write_bytes(b"x" * 3000)
        (repo / "b.bin").write_bytes(b"x" * 3000)
        limits = StagingLimits(max_file_bytes=8192, max_bytes=4096)
    before = tree_digest(repo)
    evidence = run_scan(repo, config=SandboxConfig(staging=limits))
    assert evidence.status == "error"
    assert [error.code for error in evidence.errors] == ["SANDBOX_SETUP"]
    assert "byte limit" in evidence.errors[0].message
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


NAME_CHECK = """\
import json, os, sys
expected = set(json.loads(sys.argv[1]))
planted = set(json.loads(sys.argv[2]))
actual = set()
for root, dirs, files in os.walk("/repo"):
    for name in dirs + files:
        actual.add(os.path.relpath(os.path.join(root, name), "/repo"))
diff = sorted((actual - planted) ^ expected)
print("NAMES_OK" if not diff else "NAMES_BAD " + json.dumps(diff))
"""


def test_unicode_and_odd_names_survive_staging_intact(
    tmp_path, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    repo = tmp_path / "repo"
    repo.mkdir()
    names = [
        "café.md",  # NFC
        "café.md",  # NFD: same look, distinct bytes
        "‮report.txt",  # right-to-left override
        "line1\nline2.txt",  # newline in the name
        "--leading-dash.sh",  # looks like a flag
        "n" * 251 + ".txt",  # 255 bytes, the name-length bound
    ]
    for name in names:
        (repo / name).write_text("content\n")
    before = tree_digest(repo)
    evidence = run_scan(
        repo,
        ["python", "-c", NAME_CHECK, json.dumps(sorted(names)), json.dumps(sorted(PLANTED))],
        config=SandboxConfig(image=PYTHON_IMAGE),
    )
    assert_scan_ran_without_errors(evidence)
    result = evidence.tool_log[0]
    assert result.exit_code == 0, result.model_dump_json()
    assert "NAMES_OK" in result.stdout, result.stdout
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


SYMLINK_CHECK = """\
import json, os, pathlib, stat, sys
expectations = json.loads(sys.argv[1])
canary = sys.argv[2].encode()
problems = []
for name, want in expectations.items():
    path = pathlib.Path("/repo") / name
    if not path.is_symlink():
        problems.append({"name": name, "error": "not a symlink"})
        continue
    target = os.readlink(path)
    if target != want["target"]:
        problems.append({"name": name, "target": target})
    if "exists" in want and path.exists() != want["exists"]:
        problems.append({"name": name, "exists": path.exists()})
for root, dirs, files in os.walk("/repo"):
    for name in files:
        entry = pathlib.Path(root) / name
        if stat.S_ISREG(os.lstat(entry).st_mode) and canary in entry.read_bytes():
            problems.append({"canary": name})
print("SYMLINKS_OK" if not problems else "SYMLINKS_BAD " + json.dumps(problems))
"""


def test_host_escaping_symlinks_are_kept_as_links(
    tmp_path, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "host-only.txt"
    outside.write_text(CANARY)
    (repo / "etc-link").symlink_to("/etc/passwd")
    (repo / "home-link").symlink_to(Path.home())
    (repo / "escape-link").symlink_to(outside)
    (repo / "up-link").symlink_to("..")
    (repo / "loop-link").symlink_to("loop-link")
    (repo / "dangling-link").symlink_to("missing-target.txt")
    (repo / "subdir").mkdir()
    (repo / "subdir" / "marker.txt").write_text("inside\n")
    (repo / "dir-link").symlink_to("subdir")
    expectations = {
        "etc-link": {"target": "/etc/passwd", "exists": True},
        "home-link": {"target": str(Path.home())},
        "escape-link": {"target": str(outside), "exists": False},
        "up-link": {"target": "..", "exists": True},
        "loop-link": {"target": "loop-link", "exists": False},
        "dangling-link": {"target": "missing-target.txt", "exists": False},
        "dir-link": {"target": "subdir", "exists": True},
    }
    before = tree_digest(repo)
    evidence = run_scan(
        repo,
        ["python", "-c", SYMLINK_CHECK, json.dumps(expectations), CANARY],
        config=SandboxConfig(image=PYTHON_IMAGE),
    )
    assert_scan_ran_without_errors(evidence)
    result = evidence.tool_log[0]
    assert result.exit_code == 0, result.model_dump_json()
    assert "SYMLINKS_OK" in result.stdout, result.stdout
    assert evidence.file_diffs == []
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


SCRIPT_CHECK = """\
import pathlib, subprocess
print("CRLF_BYTES", b"\\r\\n" in pathlib.Path("/repo/crlf.sh").read_bytes())
print("BOM_BYTES", pathlib.Path("/repo/bom.sh").read_bytes().startswith(b"\\xef\\xbb\\xbf"))
for name in ("crlf.sh", "bom.sh"):
    run = subprocess.run(["sh", f"/repo/{name}"], capture_output=True, text=True, timeout=10)
    print("RAN", name, "exit", run.returncode)
    print("OUT", repr(run.stdout)[:200])
    print("ERR", repr(run.stderr)[:200])
print("SCRIPTS_DONE")
"""


def test_crlf_and_bom_scripts_run_inside_the_cage_and_are_recorded(
    tmp_path, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "crlf.sh").write_bytes(b"echo crlf-ran\r\nexit 5\r\n")
    (repo / "bom.sh").write_bytes(b"\xef\xbb\xbf echo bom-ran\n")
    before = tree_digest(repo)
    evidence = run_scan(
        repo, ["python", "-c", SCRIPT_CHECK], config=SandboxConfig(image=PYTHON_IMAGE)
    )
    assert_scan_ran_without_errors(evidence)
    result = evidence.tool_log[0]
    assert result.exit_code == 0, result.model_dump_json()
    assert "CRLF_BYTES True" in result.stdout, result.stdout
    assert "BOM_BYTES True" in result.stdout, result.stdout
    assert "SCRIPTS_DONE" in result.stdout, result.stdout
    assert evidence.file_diffs == []
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


@pytest.mark.parametrize("kind", ["fifo", "socket", "device-names"])
def test_special_files_are_reported_without_hanging_staging(
    tmp_path,
    recorded_sandbox,
    run_scan,
    tree_digest,
    assert_no_leftovers,
    assert_staging_gone,
    kind,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    if kind == "fifo":
        os.mkfifo(repo / "pipe.fifo")
    elif kind == "socket":
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(repo / "implant.sock"))
        listener.close()
    else:
        for name in ("sda", "tty0", "null"):
            (repo / name).write_text("regular file, only named like a device\n")
    before = tree_digest(repo)
    started = time.monotonic()
    evidence = run_scan(repo)
    elapsed = time.monotonic() - started
    assert elapsed < 45, "staging hung on a special file"
    if kind == "device-names":
        assert_scan_ran_without_errors(evidence)
    else:
        assert evidence.status == "error"
        assert [error.code for error in evidence.errors] == ["SANDBOX_SETUP"]
        assert "device, socket, or FIFO" in evidence.errors[0].message
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


@pytest.mark.skipif(
    os.geteuid() == 0, reason="root reads chmod-000 entries, so no lock would fail staging"
)
@pytest.mark.parametrize("kind", ["file", "directory"])
def test_unreadable_source_entries_are_reported_not_skipped(
    tmp_path,
    recorded_sandbox,
    run_scan,
    tree_digest,
    assert_no_leftovers,
    assert_staging_gone,
    kind,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("A benign fixture.\n")
    if kind == "file":
        locked = repo / "secret.txt"
        locked.write_text("owner-only\n")
    else:
        locked = repo / "locked-dir"
        locked.mkdir()
        (locked / "inner.txt").write_text("inner\n")
    # Digest while readable; a locked entry can't be hashed.
    before = tree_digest(repo)
    os.chmod(locked, 0o000)
    try:
        evidence = run_scan(repo)
    finally:
        os.chmod(locked, 0o755 if kind == "directory" else 0o644)
    assert evidence.status == "error"
    assert [error.code for error in evidence.errors] == ["SANDBOX_SETUP"]
    assert "Permission denied" in evidence.errors[0].message
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)
