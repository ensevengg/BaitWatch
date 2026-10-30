from pathlib import Path

import pytest
from docker.errors import ImageNotFound

from run.evidence import State
from run.sandbox import Sandbox, SandboxConfig, SandboxError
from run.verdict import ReadOutcome, fuse
from tests.run.test_sandbox_failures import fake_client


def test_default_cage_image():
    assert SandboxConfig().image == "baitwatch-cage:1"


def test_missing_cage_image_fails_closed(repo):
    client = fake_client()
    client.images.get.side_effect = ImageNotFound("missing")
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError, match="python -m run.cage build"), sandbox:
        pytest.fail("missing image must not start a scan")
    report = fuse(ReadOutcome(status=State.COMPLETE, verdict="clean"), sandbox.evidence)
    assert report.verdict == "FLAG"
    assert not client.networks.create.called


@pytest.mark.docker
def test_default_cage_has_setup_toolchain(repo: Path, engine, assert_no_leftovers):
    sandbox = Sandbox(repo)
    with sandbox:
        result = sandbox.run_command(
            [
                "sh",
                "-ec",
                "python --version; python3 --version; pip --version; curl --version; "
                "git --version; make --version; bash --version; node --version; npm --version; "
                'test -s /etc/ssl/certs/ca-certificates.crt; test "$(id -u)" = 65532',
            ]
        )
    assert result.exit_code == 0, result.stderr
    assert not sandbox.evidence.errors
    assert_no_leftovers(sandbox.evidence)
