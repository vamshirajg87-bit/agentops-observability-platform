"""
rca-analyzer/tests/conftest.py

pytest configuration for rca-analyzer tests.

Adds rca-analyzer/ to sys.path so all test modules can import
rca_models, rca_trace, and future rca-analyzer modules without a
package install.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
