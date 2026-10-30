"""Safety lint for payload-bearing artifacts.

Attack code is only dangerous when it can reach a real host *by accident*.
This lint reads every generated repo, every hand-written example and the demo
script, and rejects:

- any URL whose host is outside the sandbox hosts and the corpus allowlist;
- any bare domain under a real TLD that is not on that allowlist;
- any IPv4 address outside the sandbox network or RFC 1918 space;
- anything shaped like a live credential (AWS, GitHub, OpenAI, Slack, Google,
  JWT, PEM private key);
- a committed ``.env`` (only ``.env.example`` is permitted).

Two host policies apply. The sandbox policy (``*.example`` and
``10.13.37.0/24``) is the default for tooling and fixtures. The corpus policy
adds a short, named allowlist of realistic services, because the training split
must look like a real repository: attacks there target
``raw.githubusercontent.com``, ``webhook.site``, ``*.vercel.app``,
``*.ngrok-free.app`` and private addresses instead of ``evil.example``. The
allowlist is finite, so a typo or a random pasted domain still fails. Nothing
in this repository contacts an allowlisted host: fixtures stub their sockets and
the RUN cage has no route out.

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

__all__ = [
    "CORPUS_HOSTS",
    "CORPUS_HOST_SUFFIXES",
    "SINK_NETWORK",
    "Violation",
    "allowed_host",
    "default_paths",
    "lint_paths",
    "main",
]

SINK_NETWORK = ipaddress.ip_network("10.13.37.0/24")
PACKAGE_DIR = Path(__file__).resolve().parent

# Realistic corpus hosts. Named, not wildcarded, so the exemption stays finite
# and reviewable; suffixes are the two delegated DNS shapes the plan asks for.
CORPUS_HOSTS = frozenset(
    {
        "raw.githubusercontent.com",
        "gist.githubusercontent.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "webhook.site",
        "requestbin.net",
    }
)
CORPUS_HOST_SUFFIXES = (
    ".ngrok.io",
    ".ngrok-free.app",
    ".vercel.app",
    ".trycloudflare.com",
)
CORPUS_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
# Realistic corpus addresses may use private space, but not the block reserved
# for the sandbox sink: 10.13.38.9 must stay an error, not a plausible host.
SANDBOX_RESERVED = ipaddress.ip_network("10.13.0.0/16")

_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>)\]]+")
_DOMAIN_RE = re.compile(
    r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|ai|xyz|ru|cn|info|biz|cloud|site|app|shop|online|"
    r"top|live|pro|me|tv|cc|store|tech|space|website|link|click|download|"
    r"stream|zip|mov|fit|icu|rest|surf|monster))"
    r"(?![\w.-])",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_PLACEHOLDER_RE = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{[^}]*\}")
_NETWORK_SCHEMES = {"http", "https", "ftp", "ftps", "ws", "wss"}

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


def _fixed_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    if not host:
        return False
    if host == "evil.example" or host == "example" or host.endswith(".example"):
        return True
    if host in CORPUS_HOSTS or host.endswith(CORPUS_HOST_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return _allowed_address(address)


def _allowed_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if address in SINK_NETWORK:
        return True
    if address in SANDBOX_RESERVED:
        return False
    return any(address in network for network in CORPUS_NETWORKS)


def _allowed_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    if not host:
        return False
    placeholders = list(_PLACEHOLDER_RE.finditer(host))
    if placeholders:
        # A placeholder can expand to anything, including a different TLD.
        # Only the literal text after the LAST placeholder is fixed, so that
        # tail has to be the allowed suffix: ``${REGISTRY}.evil.example``
        # passes, ``evil.example${TAIL}`` does not (TAIL could be ``.com``).
        # The fixed tail must start with a dot: without one, an empty
        # placeholder expansion could join it to the preceding label, e.g.
        # ``evil${SUB}webhook.site`` becoming the unlisted ``evilwebhook.site``.
        raw_tail = host[placeholders[-1].end() :]
        if raw_tail and not raw_tail.startswith("."):
            return False
        return _fixed_host(raw_tail.strip("."))
    return _fixed_host(host)


def allowed_host(host: str) -> bool:
    """The lint's host policy, exposed so tests assert the same rule."""
    return _allowed_host(host)


def _allowed_domain(domain: str) -> bool:
    if _allowed_host(domain):
        return True
    # Bidirectional payloads reverse a hostname so it no longer looks like a
    # URL: ``evil.example`` becomes ``elpmaxe.live``.  The bare token is only
    # safe when its reverse is a sandbox host — that keeps the exemption narrow
    # while still catching a reversed real domain.
    return _allowed_host(domain[::-1])


def _allowed_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True
    return _allowed_address(address)


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
                raw = match.group()
                try:
                    parts = urlsplit(raw)
                    _ = parts.port  # a malformed port must not pass as a host
                    host = parts.hostname
                except ValueError:
                    violations.append(Violation(rel, lineno, "url", f"unparseable URL {raw!r}"))
                    continue
                scheme = parts.scheme.lower()
                # Every scheme is parsed.  A network scheme must have a host;
                # a scheme with an authority but no host is malformed.
                if host is None:
                    if scheme in _NETWORK_SCHEMES or parts.netloc:
                        violations.append(Violation(rel, lineno, "url", f"unparseable URL {raw!r}"))
                    continue
                if not _allowed_host(host):
                    violations.append(
                        Violation(rel, lineno, "url", f"host {host!r} is outside *.example")
                    )
            for match in _DOMAIN_RE.finditer(line):
                domain = match.group(1)
                if not _allowed_domain(domain):
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
        PACKAGE_DIR / "synth" / "training.py",
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
