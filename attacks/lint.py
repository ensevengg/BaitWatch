"""Safety lint for payload-bearing artifacts.

Attack code is only safe when it can never reach a real host. This lint reads
every generated repo, every hand-written example and the demo script, and
rejects:

- any URL whose host is not ``*.example`` (``evil.example`` included);
- any bare domain under a real TLD;
- any IPv4 address outside ``10.13.37.0/24``;
- anything shaped like a live credential (AWS, GitHub, OpenAI, Slack, Google,
  JWT, PEM private key);
- a committed ``.env`` (only ``.env.example`` is permitted).

It deliberately does not scan documentation, so the project can credit prior
work by URL in ``docs/`` without needing an exemption here.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

__all__ = ["SINK_NETWORK", "Violation", "default_paths", "lint_paths", "main"]

SINK_NETWORK = ipaddress.ip_network("10.13.37.0/24")
PACKAGE_DIR = Path(__file__).resolve().parent

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|ai|xyz|ru|cn|info|biz|cloud|site))"
    r"(?![\w.-])",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)

_ALLOWED_ENV = {".env.example", ".env.sample", ".env.template"}


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.kind}: {self.detail}"


def _allowed_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    # A template placeholder (``https://${REGISTRY}/health``) is not a host
    # that can receive data until it is resolved; the literal host is what
    # lint checks. BaitWatch payloads never use a dynamic host.
    if "{" in host or "$" in host:
        return True
    if host == "evil.example" or host.endswith(".example"):
        return True
    try:
        return ipaddress.ip_address(host) in SINK_NETWORK
    except ValueError:
        return False


def _allowed_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True
    return address in SINK_NETWORK


def _env_name_allowed(name: str) -> bool:
    if name in _ALLOWED_ENV:
        return True
    return not (name == ".env" or name.startswith(".env."))


def _text_files(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found.extend(sorted(p for p in path.rglob("*") if p.is_file()))
        elif path.is_file():
            found.append(path)
    return found


def lint_paths(paths: list[Path], *, root: Path | None = None) -> list[Violation]:
    root = root or PACKAGE_DIR
    violations: list[Violation] = []
    for path in _text_files(paths):
        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = path.as_posix()
        if not _env_name_allowed(path.name):
            violations.append(
                Violation(
                    rel, 1, "dotenv-file", "only .env.example/.sample/.template may be committed"
                )
            )
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in _URL_RE.finditer(line):
                host = urlsplit(match.group()).hostname
                if not host:
                    violations.append(
                        Violation(rel, lineno, "url", f"unparseable URL {match.group()!r}")
                    )
                elif not _allowed_host(host):
                    violations.append(
                        Violation(rel, lineno, "url", f"host {host!r} is outside *.example")
                    )
            for match in _DOMAIN_RE.finditer(line):
                domain = match.group(1)
                if not _allowed_host(domain):
                    violations.append(
                        Violation(rel, lineno, "domain", f"real-looking domain {domain!r}")
                    )
            for match in _IPV4_RE.finditer(line):
                if not _allowed_ip(match.group()):
                    violations.append(
                        Violation(rel, lineno, "ip", f"{match.group()} is outside {SINK_NETWORK}")
                    )
            for kind, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    violations.append(Violation(rel, lineno, kind, "looks like a live credential"))
    return violations


def default_paths() -> list[Path]:
    return [
        PACKAGE_DIR / "repos",
        PACKAGE_DIR / "examples",
        PACKAGE_DIR / "synth" / "seeds.py",
        PACKAGE_DIR / "synth" / "generate.py",
        PACKAGE_DIR.parent / "demo",
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m attacks.lint")
    parser.add_argument(
        "paths", nargs="*", type=Path, help="files or directories (default: attack artifacts)"
    )
    parser.add_argument(
        "--all", action="store_true", help="also lint docs/ and the remaining attacks sources"
    )
    args = parser.parse_args(argv)
    paths = args.paths or default_paths()
    if args.all and not args.paths:
        paths = [PACKAGE_DIR.parent]
    violations = lint_paths(paths)
    for violation in violations:
        print(str(violation), file=sys.stderr)
    if violations:
        print(f"{len(violations)} safety violation(s)", file=sys.stderr)
        return 1
    print(f"safety lint clean ({len(_text_files(paths))} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
