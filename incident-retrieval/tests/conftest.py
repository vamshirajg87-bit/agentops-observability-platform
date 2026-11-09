"""
incident-retrieval/tests/conftest.py

pytest configuration for incident-retrieval tests.

Adds incident-retrieval/ to sys.path so all test modules can import
incident_document and future incident-retrieval modules without a
package install.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
