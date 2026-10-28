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


def test_reversed_sandbox_domain_is_allowed_but_reversed_real_is_not() -> None:
    from attacks.lint import _allowed_domain

    # bidi payloads reverse "evil.example" into "elpmaxe.live"
    assert _allowed_domain("elpmaxe.live") is True
    # a reversed real host stays rejected
    assert _allowed_domain("moc.liamg") is False
