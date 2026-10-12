from __future__ import annotations

# Wrapper that the `prosze` console_script invokes.
# Ensures prosze_proxy.py (sibling of this package) is importable, then
# delegates to prosze_cli.__main__.
import os
import sys

_PROJ = os.path.abspath(os.path.dirname(__file__))
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

_proxy = os.path.join(_PROJ, "prosze_proxy.py")
if _proxy not in sys.modules:
    import importlib.util

    _spec = importlib.util.spec_from_file_location("prosze_proxy", _proxy)
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    sys.modules["prosze_proxy"] = _mod

from prosze_cli.__main__ import main

if __name__ == "__main__":
    main()
