"""Ensure backend/ is on sys.path so tests can `import webhooks`, `import server`."""
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))
