"""
db-bootstrap/tests/conftest.py

pytest configuration for db-bootstrap tests.

Adds db-bootstrap/ to sys.path so the test modules can import bootstrap
without a package install.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
