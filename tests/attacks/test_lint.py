"""Safety lint: attack artifacts stay inside the sandbox."""

from __future__ import annotations

from pathlib import Path

from attacks.lint import Violation, default_paths, lint_paths

REPO_ROOT = Path(__file__).resolve().parents[2]


def _lint_one(tmp_path: Path, name: str, body: str) -> list[Violation]:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return lint_paths([path], root=tmp_path)


def test_generated_attack_surface_is_clean() -> None:
    assert lint_paths(default_paths()) == []


def test_example_hosts_are_allowed(tmp_path: Path) -> None:
    body = "https://evil.example/x\nhttps://collector.example/v1\nhttp://10.13.37.9:8080/ingest\n"
    assert _lint_one(tmp_path, "ok.md", body) == []


def test_real_url_is_rejected(tmp_path: Path) -> None:
    violations = _lint_one(tmp_path, "bad.md", "see https://malware-c2.com/a\n")
    assert any(v.kind == "url" and "malware-c2.com" in v.detail for v in violations)


def test_bare_domain_is_rejected(tmp_path: Path) -> None:
    violations = _lint_one(tmp_path, "bad.md", "connect to exfiltrate.io now\n")
    assert any(v.kind == "domain" for v in violations)


def test_ip_outside_sink_is_rejected(tmp_path: Path) -> None:
    violations = _lint_one(tmp_path, "bad.sh", "curl http://8.8.8.8/x\n")
    assert any(v.kind == "ip" and "8.8.8.8" in v.detail for v in violations)


def test_almost_sink_ip_is_rejected(tmp_path: Path) -> None:
    violations = _lint_one(tmp_path, "bad.sh", "curl http://10.13.38.9/x\n")
    assert any(v.kind == "ip" for v in violations)


def test_live_credentials_are_rejected(tmp_path: Path) -> None:
    bodies = {
        "aws.txt": "AKIAIOSFODNN7EXAMPLE",
        "gh.txt": "ghp_" + "a" * 36,
        "openai.txt": "sk-" + "a" * 32,
        "pem.txt": "-----BEGIN RSA PRIVATE KEY-----",
    }
    for name, body in bodies.items():
        violations = _lint_one(tmp_path, name, body)
        assert violations, name


def test_committed_dotenv_is_rejected(tmp_path: Path) -> None:
    violations = _lint_one(tmp_path, ".env", "TOKEN=placeholder\n")
    assert any(v.kind == "dotenv-file" for v in violations)
    assert _lint_one(tmp_path, ".env.example", "TOKEN=placeholder\n") == []


def test_lint_reports_path_and_line(tmp_path: Path) -> None:
    violations = _lint_one(tmp_path, "bad.md", "clean\nsee https://x.com\n")
    assert violations[0].line == 2
    assert violations[0].path.endswith("bad.md")


def test_filename_tld_is_not_a_domain(tmp_path: Path) -> None:
    assert _lint_one(tmp_path, "ok.md", "run setup.sh and verify.sh\n") == []


# -- every scheme, not just http(s) -------------------------------------------


def test_non_http_schemes_are_checked(tmp_path: Path) -> None:
    for body in (
        "ftp://malware-c2.com/drop\n",
        "wss://collect.realhost.net/socket\n",
        "file://malware-c2.com/share\n",
    ):
        violations = _lint_one(tmp_path, "bad.md", body)
        assert violations, body


def test_sandbox_hosts_pass_on_every_scheme(tmp_path: Path) -> None:
    body = "ftp://10.13.37.4/drop\nwss://evil.example/socket\nhttps://collector.example/v1\n"
    assert _lint_one(tmp_path, "ok.md", body) == []


def test_unparseable_authority_is_rejected(tmp_path: Path) -> None:
    violations = _lint_one(tmp_path, "bad.md", "see https://evil.example:notaport/x\n")
    assert any(v.kind == "url" for v in violations)


# -- dynamic hosts must still end in a fixed .example suffix -------------------


def test_dynamic_host_without_example_suffix_is_rejected(tmp_path: Path) -> None:
    body = "const u = `https://${REGISTRY}/healthz`;\n"
    violations = _lint_one(tmp_path, "bad.js", body)
    assert any(v.kind == "url" for v in violations)


def test_dynamic_host_with_real_tld_is_rejected(tmp_path: Path) -> None:
    body = "fetch(`https://${USER}.collector.app/x`)\n"
    violations = _lint_one(tmp_path, "bad.js", body)
    assert any(v.kind == "url" for v in violations)


def test_dynamic_host_under_example_is_allowed(tmp_path: Path) -> None:
    body = "fetch(`https://${REGISTRY}.evil.example/x`)\n"
    assert _lint_one(tmp_path, "ok.js", body) == []


def test_placeholder_at_the_end_cannot_hide_a_real_suffix(tmp_path: Path) -> None:
    """``evil.example${TAIL}`` ends wherever TAIL says, e.g. ``.com``."""
    body = "fetch(`https://evil.example${TAIL}/x`)\n"
    violations = _lint_one(tmp_path, "bad.js", body)
    assert any(v.kind == "url" for v in violations)


def test_fixed_suffix_after_the_last_placeholder_decides(tmp_path: Path) -> None:
    # The tail after the last placeholder is fixed and inside .example.
    assert _lint_one(tmp_path, "ok.js", "fetch(`https://evil.example${TAIL}.example/x`)\n") == []
    # A fixed-looking prefix does not help when the tail is empty.
    assert _lint_one(tmp_path, "bad.js", "fetch(`https://evil.example${TAIL}`)\n")


def test_reversed_sandbox_domain_is_allowed_but_reversed_real_is_not() -> None:
    from attacks.lint import _allowed_domain

    # bidi payloads reverse "evil.example" into "elpmaxe.live"
    assert _allowed_domain("elpmaxe.live") is True
    # a reversed real host stays rejected
    assert _allowed_domain("moc.liamg") is False


# -- corpus policy: a finite, named set of realistic hosts ---------------------


def test_corpus_hosts_are_allowed(tmp_path: Path) -> None:
    body = (
        "https://raw.githubusercontent.com/org/repo/main/setup.sh\n"
        "https://gist.githubusercontent.com/org/abc/hook.py\n"
        "https://webhook.site/2f1c/collect\n"
        "https://assets-7c1.vercel.app/build.tgz\n"
        "https://f00d.ngrok-free.app/cb\n"
        "http://192.168.1.40:8080/ingest\n"
        "http://172.16.4.9/upload\n"
    )
    assert _lint_one(tmp_path, "corpus.md", body) == []


def test_corpus_allowlist_does_not_open_every_host(tmp_path: Path) -> None:
    for body in (
        "https://raw.githubusercontent.com.evil-host.com/x\n",
        "https://notraw.githubusercontent.com/x\n",
        "https://vercel.app/x\n",
        "https://attacker-vercel.app/x\n",
    ):
        violations = _lint_one(tmp_path, "bad.md", body)
        assert violations, body


def test_corpus_hosts_do_not_make_public_ips_legal(tmp_path: Path) -> None:
    violations = _lint_one(tmp_path, "bad.sh", "curl http://93.184.216.34/x\n")
    assert any(v.kind == "ip" and "93.184.216.34" in v.detail for v in violations)


def test_realistic_hosts_stay_inside_the_attack_corpus() -> None:
    """A realistic host outside attacks/ or docs/ would be a containment bug."""
    from attacks.lint import CORPUS_HOST_SUFFIXES, CORPUS_HOSTS

    needles = tuple(CORPUS_HOSTS) + tuple(suffix.lstrip(".") for suffix in CORPUS_HOST_SUFFIXES)
    allowed_prefixes = ("attacks/", "docs/", "tests/")
    skipped_prefixes = ("build/", "dist/", "artifacts/", ".venv/", ".git/", ".ruff_cache/")
    offenders = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel.startswith(allowed_prefixes) or rel.startswith(skipped_prefixes):
            continue
        if "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for needle in needles:
            if needle in text:
                offenders.append((rel, needle))
    assert offenders == []
