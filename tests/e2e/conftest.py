from pathlib import Path

import pytest

E2E_TESTS = Path(__file__).parent


def pytest_collection_modifyitems(config, items):
    # Scoped here so the shared pytest.ini does not put a deadline on READ's suites.
    if not config.pluginmanager.hasplugin("timeout"):
        return
    for item in items:
        if E2E_TESTS in item.path.parents:
            item.add_marker(pytest.mark.timeout(120))
