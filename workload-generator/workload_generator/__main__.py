"""
workload_generator/__main__.py

Makes `python -m workload_generator` run the command-line entry point.
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
