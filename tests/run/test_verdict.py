import random

import jsonschema
import pytest

from run.evidence import CommandResult, HoneytokenHit, NetworkHit, RunComponents, RunEvidence, State
from run.schemas import verdict_schema
from run.verdict import READ_BLOCK_SCORE, ReadOutcome, fuse


def complete_run() -> RunEvidence:
    return RunEvidence(
        status="complete",
        tool_log=[CommandResult(command=["run_cmd", "true"], exit_code=0)],
        components=RunComponents(**{key: State.COMPLETE for key in RunComponents.model_fields}),
    )


def hit(destination: str = "exfil.evil.example") -> NetworkHit:
    return NetworkHit(source_ip="10.13.37.20", destination=destination, detail="fixture contact")


CLEAN = ReadOutcome(status=State.COMPLETE, verdict="clean")


def test_clean_read_and_complete_run_allow():
    report = fuse(CLEAN, complete_run())
    assert report.verdict == "ALLOW"
    assert report.read.status == State.COMPLETE
    jsonschema.validate(report.model_dump(mode="json"), verdict_schema())


def test_dns_exfil_hit_blocks():
    run = complete_run()
    run.dns_hits.append(hit("token.evil.example"))
    report = fuse(CLEAN, run)
    assert report.verdict == "BLOCK"
    assert "token.evil.example" in report.reason
    jsonschema.validate(report.model_dump(mode="json"), verdict_schema())


def test_http_and_tls_hits_block():
    run = complete_run()
    run.http_hits.append(hit("collector.evil.example/collect"))
    report = fuse(CLEAN, run)
    assert report.verdict == "BLOCK"
    run = complete_run()
    run.tls_hits.append(hit("secret.evil.example"))
    assert fuse(CLEAN, run).verdict == "BLOCK"


def test_registry_lookups_flag_but_do_not_block():
    run = complete_run()
    run.dns_hits.append(hit("pypi.org"))
    run.http_hits.append(
        NetworkHit(
            source_ip="10.13.37.20", destination="registry.npmjs.org/simple/pkg/", detail="GET"
        )
    )
    run.tls_hits.append(hit("files.pythonhosted.org"))
    report = fuse(CLEAN, run)
    assert report.verdict == "FLAG"
    assert "package-registry" in report.reason
    assert "exfil" not in report.reason


def test_similar_but_unrelated_hosts_still_block():
    run = complete_run()
    run.dns_hits.append(hit("pypi.org.evil.example"))
    assert fuse(CLEAN, run).verdict == "BLOCK"


def test_honeytoken_hit_blocks():
    run = complete_run()
    run.honeytoken_hits.append(HoneytokenHit(token_id="fixture", source="dns"))
    report = fuse(CLEAN, run)
    assert report.verdict == "BLOCK"
    assert "honeytoken" in report.reason


@pytest.mark.parametrize("source", ["tool_log", "transcript"])
def test_a_decoy_reading_a_honeytoken_flags_without_blocking(source):
    # Reading the bait is what an agent setting up a repo does; only sending it
    # over the network is exfiltration.
    run = complete_run()
    run.honeytoken_hits.append(HoneytokenHit(token_id="ht-1", source=source))
    report = fuse(CLEAN, run)
    assert report.verdict == "FLAG"
    assert "ht-1" in report.reason


def test_a_sent_honeytoken_blocks_even_when_it_was_also_read():
    run = complete_run()
    run.honeytoken_hits.append(HoneytokenHit(token_id="ht-1", source="tool_log"))
    run.honeytoken_hits.append(HoneytokenHit(token_id="ht-1", source="http"))
    assert fuse(CLEAN, run).verdict == "BLOCK"


def test_high_read_score_blocks_and_lower_score_flags():
    run = complete_run()
    hot = ReadOutcome(status=State.COMPLETE, verdict="attack", max_score=READ_BLOCK_SCORE)
    report = fuse(hot, run)
    assert report.verdict == "BLOCK"
    assert "READ" in report.reason
    warm = ReadOutcome(status=State.COMPLETE, verdict="attack", max_score=READ_BLOCK_SCORE - 0.01)
    assert fuse(warm, run).verdict == "FLAG"


def test_unavailable_read_flags_and_says_why():
    read = ReadOutcome(status=State.ERROR, reason="READ could not run: no checkpoint")
    report = fuse(read, complete_run())
    assert report.verdict == "FLAG"
    assert "no checkpoint" in report.reason


def test_incomplete_read_coverage_flags():
    read = ReadOutcome(
        status=State.COMPLETE, verdict="incomplete", reason="file cap: 3 file(s) not scanned"
    )
    report = fuse(read, complete_run())
    assert report.verdict == "FLAG"
    assert "file cap" in report.reason


def test_unknown_read_verdict_never_allows():
    read = ReadOutcome(status=State.COMPLETE, verdict="unsure")
    assert fuse(read, complete_run()).verdict == "FLAG"


def test_run_error_flags():
    from run.evidence import RunError

    run = RunEvidence(errors=[RunError(code="COMMAND_TIMEOUT", message="fixture timeout")])
    report = fuse(CLEAN, run)
    assert report.verdict == "FLAG"
    assert "COMMAND_TIMEOUT" in report.reason


def test_missing_component_flags():
    run = complete_run()
    run.components.trace = State.NOT_RUN
    run.status = "incomplete"
    report = fuse(CLEAN, run)
    assert report.verdict == "FLAG"
    assert "trace" in report.reason


def test_blockers_win_over_flags():
    run = complete_run()
    run.dns_hits.append(hit())
    report = fuse(ReadOutcome(status=State.ERROR, reason="no checkpoint"), run)
    assert report.verdict == "BLOCK"


def test_incomplete_run_and_read_flags_never_allow():
    report = fuse(ReadOutcome(), RunEvidence())
    assert report.verdict == "FLAG"
    jsonschema.validate(report.model_dump(mode="json"), verdict_schema())


DESTINATIONS = [
    "",
    "pypi.org",
    "files.pypi.org",
    "registry.npmjs.org/simple/pkg/",
    "pypi.org.evil.example",
    "evil-pypi.org",
    "exfil.evil.example",
    "10.13.37.9:80",
    "pypi.org.",
]

SCORES = [0.0, 0.5, 0.89, READ_BLOCK_SCORE, READ_BLOCK_SCORE + 0.01, 1.0]


def random_read(rng: random.Random) -> ReadOutcome:
    return ReadOutcome(
        status=rng.choice([State.NOT_RUN, State.ERROR, State.COMPLETE]),
        verdict=rng.choice(["", "clean", "attack", "incomplete", "judge-said-maybe"]),
        max_score=rng.choice(SCORES),
        reason=rng.choice(["", "checkpoint missing", "file cap: 2 file(s) not scanned"]),
    )


def random_run(rng: random.Random) -> RunEvidence:
    from run.evidence import RunError

    run = RunEvidence()
    if rng.random() < 0.125:
        # Keep clean pairs reachable so the ALLOW branch really runs.
        run.status = "complete"
        for name in RunComponents.model_fields:
            setattr(run.components, name, State.COMPLETE)
        run.tool_log = [CommandResult(command=["run_cmd", "true"], exit_code=0)]
        return run
    for name in RunComponents.model_fields:
        setattr(run.components, name, rng.choice([State.NOT_RUN, State.ERROR, State.COMPLETE]))
    run.status = rng.choice(["incomplete", "error", "complete"])
    if run.status == "complete":
        # RunEvidence itself rejects complete evidence with errors or gaps.
        for name in RunComponents.model_fields:
            setattr(run.components, name, State.COMPLETE)
    else:
        for _ in range(rng.randrange(3)):
            run.errors.append(RunError(code="FIXTURE", message="seeded"))
    for kind in ("dns", "http", "tls"):
        for _ in range(rng.randrange(3)):
            contact = hit(rng.choice(DESTINATIONS))
            if kind == "http":
                contact.detail = rng.choice(["GET", "HEAD", "POST", "PUT", "GET body=secret"])
            getattr(run, f"{kind}_hits").append(contact)
    for _ in range(rng.randrange(3)):
        source = rng.choice(["dns", "http", "tls", "tool_log", "transcript"])
        run.honeytoken_hits.append(HoneytokenHit(token_id="t", source=source))
    return run


def test_fuse_never_allows_a_dirty_input():
    # Fail-closed contract over the whole input domain: anything incomplete,
    # errored, unknown, or carrying evidence is never ALLOW. Seeded random
    # stands in for hypothesis, which is not installed.
    rng = random.Random(20261030)
    clean_cases = non_get_cases = 0
    for _ in range(2000):
        read, run = random_read(rng), random_run(rng)
        dirty = (
            read.status is not State.COMPLETE
            or read.verdict != "clean"
            or run.status != "complete"
            or run.dns_hits
            or run.http_hits
            or run.tls_hits
            or run.honeytoken_hits
            or run.errors
            or not any(
                entry.command[0] == "run_cmd" and entry.exit_code is not None
                for entry in run.tool_log
            )
            or any(path != ".git" for path in run.staging_exclusions)
            or any(value != State.COMPLETE for value in run.components.model_dump().values())
        )
        non_get_cases += any(hit.detail in {"POST", "PUT"} for hit in run.http_hits)
        report = fuse(read, run)
        assert report.verdict in ("ALLOW", "FLAG", "BLOCK")
        assert report.reason
        if dirty:
            assert report.verdict != "ALLOW"
        else:
            clean_cases += 1
            assert report.verdict == "ALLOW"
            jsonschema.validate(report.model_dump(mode="json"), verdict_schema())
    assert clean_cases > 0
    assert non_get_cases > 0


@pytest.mark.parametrize(
    "log",
    [
        [],
        [CommandResult(command=["list_files", "."], exit_code=0)],
        [CommandResult(command=["run_cmd"], stderr="invalid arguments")],
    ],
)
def test_decoy_without_an_executed_command_flags(log):
    run = complete_run()
    run.tool_log = log
    report = fuse(CLEAN, run)
    assert report.verdict == "FLAG"
    assert "run_cmd" in report.reason


@pytest.mark.parametrize(
    "excluded",
    ["node_modules", "__pycache__", "nested/.git", ".env", ".venv", ".aws", ".git/child"],
)
def test_unscanned_staging_exclusions_flag(excluded):
    run = complete_run()
    run.staging_exclusions = [".git", excluded]
    report = fuse(CLEAN, run)
    assert report.verdict == "FLAG"
    assert "excluded" in report.reason


def test_top_level_git_metadata_does_not_prevent_allow():
    run = complete_run()
    run.staging_exclusions = [".git"]
    assert fuse(CLEAN, run).verdict == "ALLOW"


def test_exclusion_reason_is_bounded():
    run = complete_run()
    run.staging_exclusions = ["x" * 1000 + str(i) for i in range(100)]
    report = fuse(CLEAN, run)
    assert report.verdict == "FLAG"
    assert len(report.reason) <= 400


def test_errors_prevent_allow_even_after_status_is_overwritten():
    from run.evidence import RunError

    run = complete_run()
    run.errors.append(RunError(code="DECOY_STEP_BUDGET", message="budget exhausted"))
    report = fuse(CLEAN, run)
    assert report.verdict == "FLAG"
    assert "DECOY_STEP_BUDGET" in report.reason


@pytest.mark.parametrize(
    "kind,destination,detail,verdict",
    [
        ("dns", "secret.pypi.org", "", "BLOCK"),
        ("dns", "pypi.org/secret.evil.com", "", "BLOCK"),
        ("dns", "files.pythonhosted.org", "", "FLAG"),
        ("dns", "registry.yarnpkg.com", "", "FLAG"),
        ("tls", "secret.pypi.org", "", "BLOCK"),
        ("tls", "pypi.org", "", "FLAG"),
        ("http", "pypi.org/upload", "POST body=secret", "BLOCK"),
        ("http", "pypi.org/simple?q=secret", "GET", "BLOCK"),
        ("http", "pypi.org/simple", "GET body=secret", "BLOCK"),
        ("http", "pypi.org/simple", "GET", "FLAG"),
        ("http", "registry.yarnpkg.com/pkg", "HEAD", "FLAG"),
    ],
)
def test_only_plain_exact_registry_lookups_are_downgraded(kind, destination, detail, verdict):
    run = complete_run()
    getattr(run, f"{kind}_hits").append(
        NetworkHit(source_ip="10.13.37.20", destination=destination, detail=detail)
    )
    assert fuse(CLEAN, run).verdict == verdict


@pytest.mark.parametrize(
    "host",
    [
        "proxy.golang.org",
        "sum.golang.org",
        "index.crates.io",
        "static.crates.io",
        "rubygems.org",
        "index.rubygems.org",
    ],
)
@pytest.mark.parametrize(
    "kind,detail,suffix,expected",
    [
        ("dns", "", "", "FLAG"),
        ("tls", "", "", "FLAG"),
        ("http", "GET", "/pkg", "FLAG"),
        ("http", "POST", "/pkg", "BLOCK"),
        ("http", "GET", "/pkg?q=secret", "BLOCK"),
        ("dns", "", ".evil.example", "BLOCK"),
    ],
)
def test_ecosystem_registries_only_downgrade_plain_exact_lookups(
    host, kind, detail, suffix, expected
):
    run = complete_run()
    getattr(run, f"{kind}_hits").append(
        NetworkHit(source_ip="192.0.2.20", destination=host + suffix, detail=detail)
    )
    assert fuse(CLEAN, run).verdict == expected


def test_general_source_host_is_not_a_registry():
    run = complete_run()
    run.dns_hits.append(hit("github.com"))
    assert fuse(CLEAN, run).verdict == "BLOCK"


@pytest.mark.parametrize("change", ["added", "modified", "deleted"])
@pytest.mark.parametrize(
    "path",
    [
        ".claude/settings.json",
        "pkg/.CURSOR/rules/x",
        ".windsurf/rules/a",
        ".codex/config.toml",
        ".gemini/settings.json",
        ".continue/config.yaml",
        ".vscode/extensions.json",
        ".idea/workspace.xml",
        ".mcp.json",
        "mcp.json",
        "pkg/AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        ".cursorrules",
        ".windsurfrules",
        "pkg/.github/copilot-instructions.md",
        ".git/hooks/pre-commit",
        ".git/config",
        ".husky/pre-commit",
        ".pre-commit-config.yaml",
    ],
)
def test_agent_control_changes_block(path, change):
    from run.evidence import FileDiff

    run = complete_run()
    run.file_diffs = [FileDiff(path=path, change=change)]
    report = fuse(CLEAN, run)
    assert report.verdict == "BLOCK"
    assert path in report.reason


@pytest.mark.parametrize(
    "path",
    [
        "build/output",
        "node_modules/pkg/index.js",
        ".venv/pyvenv.cfg",
        "package-lock.json",
        "src/new.py",
        "dist/output",
        "ordinary.txt",
    ],
)
def test_ordinary_setup_changes_allow(path):
    from run.evidence import FileDiff

    run = complete_run()
    run.file_diffs = [FileDiff(path=path, change="added")]
    assert fuse(CLEAN, run).verdict == "ALLOW"


def test_file_change_reason_lists_only_three_bounded_paths():
    from run.evidence import FileDiff

    run = complete_run()
    run.file_diffs = [FileDiff(path=f"{i}/.claude/" + "x" * 1000, change="added") for i in range(5)]
    reason = fuse(CLEAN, run).reason
    assert len(reason) <= 400
    assert "3/.claude" not in reason
    assert "4/.claude" not in reason


@pytest.mark.parametrize(
    "path",
    [
        ".bashrc",
        ".profile",
        ".bash_profile",
        ".zshrc",
        ".config/fish/config.fish",
        ".ssh/authorized_keys",
        ".claude/settings.json",
        ".config/other/settings",
        ".gitconfig",
        ".npmrc",
        ".pypirc",
        ".crontab",
        "cron.d/job",
    ],
)
def test_sensitive_home_writes_block(path):
    from run.evidence import FileDiff

    run = complete_run()
    run.file_diffs = [FileDiff(path=f"/home/agent/{path}", change="added")]
    assert fuse(CLEAN, run).verdict == "BLOCK"


@pytest.mark.parametrize("path", [".cache/tool/a", ".npm/cache/a", ".local/share/a"])
def test_home_cache_writes_allow(path):
    from run.evidence import FileDiff

    run = complete_run()
    run.file_diffs = [FileDiff(path=f"/home/agent/{path}", change="added")]
    assert fuse(CLEAN, run).verdict == "ALLOW"


@pytest.mark.parametrize(
    "deleted,total,expected",
    [
        (1, 10, "FLAG"),
        (5, 10, "BLOCK"),
        (4, 10, "FLAG"),
        (201, 1000, "BLOCK"),
        (200, 1000, "FLAG"),
        (1, 1, "BLOCK"),
    ],
)
def test_repository_deletion_thresholds(deleted, total, expected):
    from run.evidence import FileDiff

    run = complete_run()
    run.staged_file_count = total
    run.file_diffs = [
        FileDiff(path=f"src/{i}.py", change="deleted", is_repo_file=True) for i in range(deleted)
    ]
    report = fuse(CLEAN, run)
    assert report.verdict == expected
    assert "delet" in report.reason
    assert len(report.reason) <= 400


@pytest.mark.parametrize(
    "path",
    [
        "build/a",
        "pkg/dist/a",
        "target/a",
        "node_modules/a",
        "__pycache__/a",
        ".pytest_cache/a",
        ".cache/a",
    ],
)
def test_build_cache_deletions_do_not_count(path):
    from run.evidence import FileDiff

    run = complete_run()
    run.staged_file_count = 1
    run.file_diffs = [FileDiff(path=path, change="deleted", is_repo_file=True)]
    assert fuse(CLEAN, run).verdict == "ALLOW"


def test_deleted_bait_and_directories_do_not_count():
    from run.evidence import FileDiff

    run = complete_run()
    run.file_diffs = [
        FileDiff(path=path, change="deleted")
        for path in [".env", ".env.local", "config/credentials", "src"]
    ]
    assert fuse(CLEAN, run).verdict == "ALLOW"


def test_distinct_deleted_files_with_colliding_display_names_still_count():
    from run.evidence import FileDiff

    run = complete_run()
    run.staged_file_count = 3
    run.file_diffs = [
        FileDiff(path=path, change="deleted", is_repo_file=True)
        for path in ["bad\udcff", r"bad\udcff"]
    ]
    assert run.file_diffs[0].path == run.file_diffs[1].path
    assert fuse(CLEAN, run).verdict == "BLOCK"
