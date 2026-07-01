"""
Shared pytest setup: put backend/src on sys.path so tests can import the
IDS modules the same flat way the application does (e.g. `import
data_preprocessing`), matching how main.py / model_evaluation.py insert
`src` onto the path at runtime.
"""
import os
import sys

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
