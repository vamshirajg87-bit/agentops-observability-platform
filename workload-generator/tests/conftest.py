"""
workload-generator/tests/conftest.py

pytest configuration for workload-generator tests.

Adds workload-generator/ to sys.path so the test modules can import the
workload_generator package without a package install.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
