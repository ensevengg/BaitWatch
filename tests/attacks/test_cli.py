"""The dispatcher forwards subcommand flags instead of swallowing them."""

from __future__ import annotations

import pytest

from attacks import __main__ as cli


def test_help_after_a_command_reaches_the_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["harness", "--help"])

    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "--scanner" in out and "--layer" in out


def test_help_without_a_command_stays_at_the_top_level(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--help"])

    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "{build,lint,publication,harness,leakage,check}" in out
