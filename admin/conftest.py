import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

# Must be set before any test module imports auth/main — auth.py,
# keycloak_client.py, and tier1_client.py all fail closed (raise at import
# time) if their respective credentials are unset.
os.environ.setdefault("ADMIN_UI_USERNAME", "testadmin")
os.environ.setdefault("ADMIN_UI_PASSWORD", "testpass")
os.environ.setdefault("KEYCLOAK_ADMIN_USERNAME", "testkcadmin")
os.environ.setdefault("KEYCLOAK_ADMIN_PASSWORD", "testkcpass")
os.environ.setdefault("ADMIN_INTERNAL_TOKEN", "test-admin-internal-token")
# agent_client.py fails closed at import too (step 10).
os.environ.setdefault("AGENT_STATUS_TOKEN", "test-agent-status-token")
