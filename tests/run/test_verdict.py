import random

import jsonschema

from run.evidence import HoneytokenHit, NetworkHit, RunComponents, RunEvidence, State
from run.schemas import verdict_schema
from run.verdict import READ_BLOCK_SCORE, ReadOutcome, fuse


def complete_run() -> RunEvidence:
    return RunEvidence(
        status="complete",
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
    run.http_hits.append(hit("registry.npmjs.org/simple/pkg/"))
    run.tls_hits.append(hit("files.pypi.org"))
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
    for bucket in (run.dns_hits, run.http_hits, run.tls_hits):
        for _ in range(rng.randrange(3)):
            bucket.append(hit(rng.choice(DESTINATIONS)))
    for _ in range(rng.randrange(3)):
        run.honeytoken_hits.append(HoneytokenHit(token_id="t", source="dns"))
    return run


def test_fuse_never_allows_a_dirty_input():
    # Fail-closed contract over the whole input domain: anything incomplete,
    # errored, unknown, or carrying evidence is never ALLOW. Seeded random
    # stands in for hypothesis, which is not installed.
    rng = random.Random(20261030)
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
            or any(value != State.COMPLETE for value in run.components.model_dump().values())
        )
        report = fuse(read, run)
        assert report.verdict in ("ALLOW", "FLAG", "BLOCK")
        assert report.reason
        if dirty:
            assert report.verdict != "ALLOW"
        else:
            jsonschema.validate(report.model_dump(mode="json"), verdict_schema())
