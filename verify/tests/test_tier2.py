import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import keycloak_auth
import main as app_module

ISSUER = keycloak_auth.KEYCLOAK_ISSUER
AUDIENCE = keycloak_auth.KEYCLOAK_AUDIENCE


@pytest.fixture
def keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture(autouse=True)
def stub_jwks(monkeypatch, keypair):
    """Stands in for fetching Keycloak's real JWKS over the network — the
    same kind of network-boundary mock Tier 1's tests already use for
    fetch_challenge_file, keeping the actual signature/claims verification
    (jwt.decode) real rather than mocked."""
    _private_key, public_key = keypair

    class FakeSigningKey:
        def __init__(self, key):
            self.key = key

    class FakeJWKSClient:
        def get_signing_key_from_jwt(self, token):
            return FakeSigningKey(public_key)

    monkeypatch.setattr(keycloak_auth, "_get_jwks_client", lambda: FakeJWKSClient())


@pytest.fixture
def client():
    return TestClient(app_module.app)


def make_token(private_key, *, issuer=ISSUER, audience=AUDIENCE, expires_in=300, azp="example-partner"):
    now = int(time.time())
    claims = {"iss": issuer, "aud": audience, "iat": now, "exp": now + expires_in, "azp": azp, "sub": "svc-account"}
    return jwt.encode(claims, private_key, algorithm="RS256")


def test_valid_cert_and_token_succeeds(client, keypair):
    private_key, _ = keypair
    token = make_token(private_key)
    resp = client.get(
        "/tier2/check",
        headers={"Authorization": f"Bearer {token}", "X-SSL-Client-Verify": "SUCCESS"},
    )
    assert resp.status_code == 200
    assert resp.headers["X-Verified-Client"] == "example-partner"


def test_missing_client_verify_header_rejected(client, keypair):
    private_key, _ = keypair
    token = make_token(private_key)
    resp = client.get("/tier2/check", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_client_verify_failed_rejected(client, keypair):
    # This is what nginx forwards when ssl_verify_client didn't get a cert
    # signed by our CA — must not be treated as success.
    private_key, _ = keypair
    token = make_token(private_key)
    resp = client.get(
        "/tier2/check",
        headers={"Authorization": f"Bearer {token}", "X-SSL-Client-Verify": "FAILED:self signed certificate"},
    )
    assert resp.status_code == 401


def test_missing_bearer_token_rejected(client):
    resp = client.get("/tier2/check", headers={"X-SSL-Client-Verify": "SUCCESS"})
    assert resp.status_code == 401


def test_expired_token_rejected(client, keypair):
    private_key, _ = keypair
    token = make_token(private_key, expires_in=-10)
    resp = client.get(
        "/tier2/check",
        headers={"Authorization": f"Bearer {token}", "X-SSL-Client-Verify": "SUCCESS"},
    )
    assert resp.status_code == 401


def test_wrong_issuer_rejected(client, keypair):
    private_key, _ = keypair
    token = make_token(private_key, issuer="http://attacker.example/realms/fake")
    resp = client.get(
        "/tier2/check",
        headers={"Authorization": f"Bearer {token}", "X-SSL-Client-Verify": "SUCCESS"},
    )
    assert resp.status_code == 401


def test_wrong_audience_rejected(client, keypair):
    private_key, _ = keypair
    token = make_token(private_key, audience="some-other-service")
    resp = client.get(
        "/tier2/check",
        headers={"Authorization": f"Bearer {token}", "X-SSL-Client-Verify": "SUCCESS"},
    )
    assert resp.status_code == 401


def test_token_signed_by_wrong_key_rejected(client):
    # A different key pair than the one stub_jwks exposes as the "real"
    # Keycloak signing key — simulates a forged/self-signed token.
    forged_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = make_token(forged_key)
    resp = client.get(
        "/tier2/check",
        headers={"Authorization": f"Bearer {token}", "X-SSL-Client-Verify": "SUCCESS"},
    )
    assert resp.status_code == 401
