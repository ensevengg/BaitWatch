from pathlib import Path

import pytest

RUN_TESTS = Path(__file__).parent


def pytest_collection_modifyitems(config, items):
    # Scoped here so the shared pytest.ini does not put a deadline on READ's suites.
    if not config.pluginmanager.hasplugin("timeout"):
        return
    for item in items:
        if RUN_TESTS in item.path.parents:
            item.add_marker(pytest.mark.timeout(60))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    (path / "README.md").write_text("A benign fixture.\n")
    return path
