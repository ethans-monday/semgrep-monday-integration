"""Add the project root to sys.path so tests can import semgrep_client, monday_client, sync."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
