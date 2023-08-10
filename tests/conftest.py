from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser):
    parser.addoption(
        "--skip-slow", action="store_true", default=False, help="skip slow tests"
    )


def pytest_configure(config: pytest.Config):
    config.addinivalue_line("markers", "slow: mark test as slow to run")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]):
    skip_slow = pytest.mark.skip(reason="skip-slow requested")
    for item in items:
        if "slow" in item.keywords and config.getoption("--skip-slow"):
            item.add_marker(skip_slow)
