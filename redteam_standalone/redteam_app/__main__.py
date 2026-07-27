import sys
import os

_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

try:
    from .app import run_app
except ImportError:
    from app import run_app

if __name__ == "__main__":
    run_app(debug=True)

