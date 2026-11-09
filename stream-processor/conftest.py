"""
conftest.py — pytest configuration for stream-processor tests.

Adds the stream-processor directory to sys.path so all test modules
can import stream-processor packages (otlp_decoder, config, etc.)
without a package install step.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))


def pytest_configure(config: object) -> None:
    config.addinivalue_line(  # type: ignore[union-attr]
        "markers",
        "integration: marks tests that require demo-app/ on PYTHONPATH "
        "(skipped automatically when observability.normalization is not importable)",
    )
