"""Compatibility import for the JDT source-edit helper.

All JDT subprocess orchestration lives in :mod:`codegraph.java.service`.
"""

from codegraph.java.service import ensure_java_import

__all__ = ["ensure_java_import"]
