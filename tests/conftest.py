import pytest
import os
from unittest.mock import patch


def pytest_configure(config):
    """Configure pytest"""
    os.environ["TESTING"] = "true"


@pytest.fixture
def mock_databases():
    """Mock the database initialization"""
    with patch("yarobot.app.DATABASES", ({}, {}, {}, {})):
        with patch("yarobot.initialization.PESTUDIO_STRINGS", {}):
            yield
