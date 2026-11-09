"""
trace-viewer/tests/conftest.py

pytest configuration for trace-viewer tests.

Adds trace-viewer/ to sys.path so all test modules can import
reconstruction and future trace-viewer modules without a package install.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
