from __future__ import annotations

# Wrapper that the `prosze` console_script invokes.
# Ensures prosze_core.py (sibling of this package) is importable, then
# delegates to prosze_cli.__main__.
import os
import sys

_PROJ = os.path.abspath(os.path.dirname(__file__))
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

from prosze_cli.__main__ import main

if __name__ == "__main__":
    main()
