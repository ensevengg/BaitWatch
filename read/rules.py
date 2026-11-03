"""Regex rules that choose extra windows for the judge to read.

A rule hit is never a finding on its own: these patterns fire on about 7% of
ordinary files, so they only decide what the judge looks at. They run on every
chunk, including decoded views, which is where encoded shell payloads surface.
"""

from __future__ import annotations

import re

RULES: dict[str, str] = {
 'remote_exec':r"(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|k|da)?sh\b|\b(ba|z)?sh\s+(-c\s+)?[\"']?\$\((curl|wget)|\b(iex|invoke-expression)\b|base64\s+(-d|--decode|-D)\b[^\n]{0,80}\|\s*(ba|z)?sh|\beval\s+[\"']?\$\((curl|wget)",
 'dl_then_run':r"(download|curl|wget|fetch)[^\n]{0,160}(chmod\s+\+x|\.(sh|exe|dmg|pkg|msi|bat|ps1|command)\b)|password[^\n]{0,40}(zip|archive|extract)|(zip|archive|extract)[^\n]{0,60}password|xattr\s+-[a-z]*d[^\n]{0,40}quarantine",
 'conceal':r"(do not|don'?t|never|without)\s+(tell|telling|inform|informing|mention|mentioning|notify|notifying|show|showing|alert|alerting|report|reporting|log|logging|disclos\w+|ask|asking|surfac\w+)\b[^\n]{0,50}(user|developer|human|reviewer|maintainer|anyone|owner|summary|output|changelog|pr\b|pull request|this|it)|\bsilently\b|\bquietly\b|\bcovertly\b|keep (this|it) (hidden|secret)|hide (this|it|the)\b",
 'override':r"(ignore|disregard|forget|override|bypass)\b[^\n]{0,40}(previous|prior|above|earlier|system|safety|all)\b[^\n]{0,30}(instruction|prompt|rule|guideline|polic)|(system prompt|your instructions)|\bas an? (ai|llm|coding) (agent|assistant|model)\b|(ai|coding) (agent|assistant)s?\s*(must|should|shall|:|,)|\byou are (now|an?)\b",
 'secret_touch':r"(~|\$home|\$\{home\})/\.(ssh|aws|gnupg|netrc|npmrc|pypirc|kube|docker)|\bid_(rsa|ed25519)\b|\.env\b[^\n]{0,80}(curl|post|send|upload|http)|(curl|post|send|upload|wget)[^\n]{0,80}(\.env\b|token|secret|credential|api[_-]?key|\$\{?[A-Z_]*(TOKEN|SECRET|KEY)\b)|\b(printenv|env)\s*\|\s*(curl|nc|base64)|keychain|login\.keychain|wallet",
 'safety_off':r"--no-verify\b|--dangerously-[a-z-]+|--yolo\b|--trust-all|skip[_-]?permissions|auto[_-]?approve|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|verify\s*=\s*false|strict-ssl\s*[= ]\s*false|--insecure\b|\bcurl\s+-[a-zA-Z]*k\b|--trusted-host\b|sslverify\s*[= ]\s*(false|0)|StrictHostKeyChecking\s*[= ]\s*no|PYTHONHTTPSVERIFY\s*=\s*0|setenforce\s+0|ufw\s+disable",
 'destructive':r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\b[^\n]{0,30}(/|~|\$home|\*|\.git)|git\s+push\b[^\n]*(--force|-f\b)|git\s+(reset\s+--hard|clean\s+-[a-z]*f|filter-branch|filter-repo)|drop\s+(database|table)|\bmkfs\b|\bdd\s+if=|truncate\s+table|branch\s+-D\b|reflog\s+expire|gc\s+--prune",
 'persistence':r"(>>?|tee(\s+-a)?)\s*(~|\$home)?/?\.(bashrc|zshrc|profile|bash_profile)|crontab\b|launchctl|launchagents|systemctl\s+(--user\s+)?enable|authorized_keys|\.git/hooks|core\.hookspath|\.claude/settings|\.cursor/(rules|mcp)|\.mcp\.json|copilot-instructions|registry\s+add|schtasks",
 'supply_chain':r"--(extra-)?index-url\s+http|--registry[= ]+http|registry\s*=\s*http|pip\s+install\s+[^\n]*(http://|git\+http|\.tar\.gz|\.whl)|npm\s+(i|install)\s+[^\n]*(http://|https?://[^\s]+\.tgz)|replace-registry|postinstall|preinstall",
 'exfil_sink':r"webhook\.site|requestbin|pipedream|ngrok|burpcollaborator|interact\.sh|oast\.|pastebin\.com|transfer\.sh|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|glot\.io|https?://\d{1,3}(\.\d{1,3}){3}|!\[[^\]]*\]\(https?://[^)]*[?&][^)]*\)",
 'runtime_fetch_instr':r"(fetch|download|read|load|retrieve|curl|get)\b[^\n]{0,80}https?://[^\n]{0,80}\b(follow|obey|execute|apply|run|instructions)\b|(follow|obey|apply)\b[^\n]{0,60}(instructions|steps)\b[^\n]{0,40}https?://",
}

_COMPILED = {name: re.compile(pattern, re.IGNORECASE) for name, pattern in RULES.items()}


def rule_hits(text: str) -> set[str]:
    """Names of the rules that match ``text``."""
    return {name for name, pattern in _COMPILED.items() if pattern.search(text)}
