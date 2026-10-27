"""BaitWatch agent hook: Gate A (prompt) and Gate B (tool call).

The hook is deliberately boring: it reads one JSON object from stdin, asks the
READ layer about the repository the agent is working in, applies a small
tool-call policy, and prints one JSON object. It never prints a stack trace to
the agent and it fails closed.

Entry points:
    python -m hooks gate-a     # UserPromptSubmit
    python -m hooks gate-b     # PreToolUse
    python -m hooks install    # merge Claude Code hook config
    python -m hooks selftest   # CPU-only decision tests
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
