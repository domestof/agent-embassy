import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

# main.py fails closed at import if unset (see its ADMIN_INTERNAL_TOKEN
# check) — every test file imports main, so this must be set before any of
# them do, hence here rather than in a fixture.
os.environ.setdefault("ADMIN_INTERNAL_TOKEN", "test-admin-internal-token")
# Same reasoning: main.py imports introspection.py, which fails closed at
# import if unset.
os.environ.setdefault("TIER3_INTROSPECTION_SECRET", "test-tier3-introspection-secret")
# Same again: main.py imports agent_handoff.py (Tier 3's internal-agent
# handoff), which fails closed at import if unset.
os.environ.setdefault("AGENT_INTERNAL_TOKEN", "test-agent-internal-token")
