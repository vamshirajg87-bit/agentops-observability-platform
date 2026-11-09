"""
alerting/tests/conftest.py

pytest configuration for alerting tests.

Adds alerting/ to sys.path so all test modules can import alert_models,
alert_identity, alert_policy and future alerting modules without a package
install.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
