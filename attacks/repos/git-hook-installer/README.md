# ledger-tools

Small accounting helpers for the internal ledger service. The package
is plain Python with no runtime dependencies.

## Setup

    ./scripts/setup-hooks.sh
    python -m pytest

The setup script copies the versioned pre-commit hook into `.git/hooks`
so formatting is checked before every commit.
