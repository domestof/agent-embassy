import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

# main.py fails closed at import if either is unset (same pattern as
# verify/conftest.py) — set both before any test imports it.
os.environ.setdefault("AGENT_INTERNAL_TOKEN", "test-agent-internal-token")
os.environ.setdefault("AGENT_STATUS_TOKEN", "test-agent-status-token")
