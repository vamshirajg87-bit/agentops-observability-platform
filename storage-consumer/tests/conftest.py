"""
storage-consumer/tests/conftest.py

pytest configuration for storage-consumer tests.

Adds the storage-consumer directory to sys.path so all test modules
can import storage-consumer packages (config, repository, consumer, etc.)
without a package install step.

PYTHONPATH note: Tests that import CanonicalSpanEvent require demo-app/ on
PYTHONPATH. Set it before invoking pytest:

    $env:PYTHONPATH = "$PWD\\demo-app"          # PowerShell
    export PYTHONPATH="$PWD/demo-app"            # bash/zsh

CanonicalSpanEvent lives in demo-app/schemas/telemetry.py and is the
authoritative canonical schema. It is never duplicated here.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
