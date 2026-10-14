"""
Main execution module for cape_report_generator.
Enables running via: python -m cape_report_generator
"""

import sys
import os

pkg_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(pkg_dir)
for p in [pkg_dir, parent_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from cape_report_generator.cli import run_cli
except ImportError:
    from cli import run_cli

if __name__ == "__main__":
    sys.exit(run_cli())
