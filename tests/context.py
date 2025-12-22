"""
Test context - provides import path for tests
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cryptogenesis  # noqa: E402, F401  # Imported to make package available to tests
