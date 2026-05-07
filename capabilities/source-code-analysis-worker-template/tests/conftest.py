"""Shared test fixtures for source-code-analysis-worker-template.

Workers/ and tools/ are loaded by the runtime as plain file paths, not as
installed packages. Tests reach them by putting both directories on
``sys.path`` so they can be imported as top-level modules.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for sub in ("workers", "tools"):
    path = _ROOT / sub
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
