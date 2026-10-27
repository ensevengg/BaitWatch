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
