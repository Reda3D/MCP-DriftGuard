"""MCP DriftGuard — deterministic contract-drift monitoring for MCP servers.

The package is intentionally small and dependency-light. The analysis path is
pure, offline and reproducible: given the same inputs it must produce
byte-identical reports on every platform.
"""

from __future__ import annotations

__all__ = ["__version__", "SNAPSHOT_SCHEMA_VERSION", "POLICY_SCHEMA_VERSION"]

__version__ = "0.1.0"

#: Version of the snapshot document format understood by this build.
SNAPSHOT_SCHEMA_VERSION = "1"

#: Version of the policy document format understood by this build.
POLICY_SCHEMA_VERSION = 1
