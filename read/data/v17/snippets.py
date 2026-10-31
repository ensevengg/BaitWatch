"""Generated snippets: load, validate, fill placeholders, assign groups.

Snippets are written with placeholders ({host}, {ip}, {project}, {pkg},
{user}) so hostnames carry no label signal: both labels draw from the same
pools below. The pools only use reserved names (RFC 2606/6761 TLDs and
private address space), never a routable third-party domain.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from dataclasses import dataclass, field
from pathlib import Path

PLACEHOLDER_RE = re.compile(r"\{(host|ip|project|pkg|user)\}")
# Words that label attack text by themselves; generated label-1 rows that
# contain them are dropped so the model cannot shortcut on them.
SELF_LABEL_RE = re.compile(
    r"\b(evil|attacker|malicious|payload|exfiltrat\w*|inject\w*)\b", re.I)

_HOST_STEMS = (
    "cdn", "get", "dl", "pkg", "packages", "registry", "mirror", "files",
    "static", "assets", "api", "update", "updates", "telemetry", "metrics",
    "status", "hooks", "builds", "ci", "docs", "auth", "sso", "sync", "edge",
    "artifacts", "releases", "install", "setup", "proxy", "relay", "portal",
)
_HOST_NAMES = (
    "devkit", "lattice", "northwind", "fabrikam", "contoso", "acme", "tailspin",
    "brightline", "cobalt", "ferrous", "quill", "harbor", "orbit", "pinecone",
    "sable", "tessera", "umbra", "vantage", "willow", "zephyr", "kestrel",
    "meridian", "juniper", "atlas-tools", "buildbox", "codeforge", "stackyard",
    "nimbus", "corvid", "halcyon", "lumen", "ostrich", "pylon", "redwood",
)
_HOST_TLDS = (".example", ".example", ".example", ".test", ".internal.example",
              ".dev.example", ".invalid", ".example.com", ".example.org",
              ".example.net", ".localhost")
_PROJECTS = (
    "lattice-forms", "crucible-log", "atlas-notes", "ledger-tools", "quillmark",
    "pinecone-ui", "harbor-cli", "orbitdb-sync", "tessera", "vantage-api",
    "willow-sdk", "zephyr-kit", "kestrel", "meridian", "junebug", "sable-auth",
    "corvid-ci", "halcyon-web", "lumen-docs", "pylon-rpc", "redwood-etl",
    "nimbus-cache", "cobalt-cli", "ferrous-db", "fabrikam-portal", "tailspin",
)
_PKGS = (
    "requests-toolbelt", "left-pad-pro", "fastjsonx", "colorama-ext", "pyyamlx",
    "node-fetchx", "lodash-utils", "chalkify", "axios-retry-plus", "dotenv-safe",
    "serde-extra", "tokio-helpers", "gin-middleware", "cobra-ext", "envparse",
    "httpx-auth", "click-extra", "typer-cli", "vite-plugin-env", "eslint-config-acme",
)
_USERS = ("alice", "bob", "deploy", "ci-bot", "maintainer", "jdoe", "release",
          "admin", "svc-build", "devops", "priya", "chen", "omar", "lena")


# Shared hosting / paste / tunnel platforms: real attackers stage payloads
# there and real projects link to them too, so half of all filled hosts come
# from here. Reserved-only hosts made ".example" itself an attack cue (72% of
# rows containing it were attacks in the first build).
_PLATFORM_HOSTS = (
    "raw.githubusercontent.com/{u}/{p}/main", "gist.githubusercontent.com/{u}/{h}/raw",
    "github.com/{u}/{p}/releases/download/v{v}", "objects.githubusercontent.com/{h}",
    "{p}.vercel.app", "{p}.netlify.app", "{p}.pages.dev", "{p}-{u}.workers.dev",
    "{p}.herokuapp.com", "{p}.fly.dev", "{p}.onrender.com", "{w}.ngrok-free.app",
    "{w}.trycloudflare.com", "webhook.site/{h}", "pastebin.com/raw/{h}",
    "{p}-{u}.s3.amazonaws.com", "storage.googleapis.com/{p}-{u}",
    "{p}.blob.core.windows.net/{u}", "cdn.jsdelivr.net/gh/{u}/{p}@{v}",
    "unpkg.com/{p}@{v}", "transfer.sh/{h}", "discord.com/api/webhooks/{n}/{h}",
    "hooks.slack.com/services/{h}", "{u}.github.io/{p}", "gitlab.com/{u}/{p}/-/raw/main",
    "bitbucket.org/{u}/{p}/raw/main", "pypi.org/simple", "registry.npmjs.org",
    "files.pythonhosted.org/packages/{h}", "ghcr.io/{u}/{p}", "{p}.readthedocs.io/en/latest",
)
_HANDLES = ("devtools-org", "pkgbot", "jkim-dev", "opsbench", "nightly-builds", "toolsmith",
            "infra-team", "rbarnes", "dataforge", "mlabs", "cli-kit", "buildcraft")
_SLUGS = ("setup-scripts", "dev-env", "bootstrap", "toolkit", "release-assets", "env-sync",
          "ci-helpers", "dotfiles", "agent-tools", "hotfix", "patches", "workspace-init")


def _platform_host(rng: random.Random) -> str:
    tmpl = rng.choice(_PLATFORM_HOSTS)
    return tmpl.format(
        u=rng.choice(_HANDLES), p=rng.choice(_SLUGS),
        h="".join(rng.choice("0123456789abcdef") for _ in range(rng.choice((8, 12, 32)))),
        v=f"{rng.randint(0, 4)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}",
        w="-".join(rng.choice(("amber", "brisk", "cedar", "dune", "ember", "frost", "gale"))
                   for _ in range(2)) + f"-{rng.randint(100, 999)}",
        n=rng.randint(10**17, 10**18 - 1))


def random_host(rng: random.Random, platform_share: float = 0.5) -> str:
    if rng.random() < platform_share:
        return _platform_host(rng)
    stem = rng.choice(_HOST_STEMS)
    name = rng.choice(_HOST_NAMES)
    if rng.random() < 0.25:
        return f"{name}{rng.choice(_HOST_TLDS)}"
    return f"{stem}.{name}{rng.choice(_HOST_TLDS)}"


def random_ip(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.35:
        return f"10.13.37.{rng.randint(2, 254)}"
    if roll < 0.6:
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
    if roll < 0.85:
        return f"192.168.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
    return f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"


def fill_placeholders(text: str, rng: random.Random) -> str:
    """One host / project / pkg / user per snippet, so repeats stay coherent."""
    host = random_host(rng)
    values = {"host": host, "ip": random_ip(rng), "project": rng.choice(_PROJECTS),
              "pkg": rng.choice(_PKGS), "user": rng.choice(_USERS)}
    return PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], text)


@dataclass
class Snippet:
    sid: str                    # stable id: <batch>-<index>
    label: int
    intent: str
    voice: str
    lang: str
    form: str                   # prose | structured
    file_kinds: list[str]
    text: str                   # with placeholders
    batch: str = ""
    group: str = ""             # split unit, see assign_group
    meta: dict = field(default_factory=dict)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", PLACEHOLDER_RE.sub("X", text.casefold())).strip()


def load_batches(raw_dir: Path) -> tuple[list[Snippet], dict]:
    """Load every <batch>.jsonl; drop invalid, self-labelling and duplicate rows."""
    out: list[Snippet] = []
    stats = {"rows": 0, "invalid": 0, "self_label_dropped": 0, "duplicates": 0}
    seen: set[str] = set()
    for path in sorted(Path(raw_dir).glob("[AB][0-9][0-9]*.jsonl")):
        batch = path.stem
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            stats["rows"] += 1
            try:
                d = json.loads(line)
                kinds = d["file_kinds"]
                kinds = [kinds] if isinstance(kinds, str) else list(kinds)
                snip = Snippet(sid=f"{batch}-{i:04d}", label=int(d["label"]),
                               intent=str(d["intent"]), voice=str(d.get("voice", "plain")),
                               lang=str(d.get("lang", "en")), form=str(d.get("form", "prose")),
                               file_kinds=kinds, text=str(d["text"]).strip("\n"), batch=batch)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                stats["invalid"] += 1
                continue
            if snip.label not in (0, 1) or not snip.text.strip() or not kinds:
                stats["invalid"] += 1
                continue
            if snip.label == 1 and SELF_LABEL_RE.search(snip.text):
                stats["self_label_dropped"] += 1
                continue
            key = _norm(snip.text)
            if key in seen:
                stats["duplicates"] += 1
                continue
            seen.add(key)
            out.append(snip)
    return out, stats


def stable_unit(key: str) -> float:
    """Deterministic [0, 1) from a string, independent of PYTHONHASHSEED."""
    return int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big") / 2**64


def assign_split(snippets: list[Snippet], val_frac: float = 0.1,
                 test_frac: float = 0.2) -> None:
    """Split by snippet (each snippet's text lands in exactly one split).

    Test snippets are only ever planted into TEST_REPOS carriers, so a test
    window shares neither its planted text nor its carrier repo with train.
    """
    for s in snippets:
        u = stable_unit("v17-split:" + s.sid)
        s.group = "test" if u < test_frac else ("val" if u < test_frac + val_frac else "train")
