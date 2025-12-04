import pytest
import os
from unittest.mock import patch


def pytest_configure(config):
    """Configure pytest"""
    os.environ["TESTING"] = "true"


@pytest.fixture
def mock_databases():
    """Mock the database initialization"""
    with patch("src.app.DATABASES", ({}, {}, {}, {})):
        with patch("src.initialization.PESTUDIO_STRINGS", {}):
            yield
