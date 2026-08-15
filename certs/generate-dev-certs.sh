#!/usr/bin/env bash
# Generates a throwaway CA + server cert + one example partner client cert,
# for local Tier 2 mTLS testing (and, with a real hostname, as the starting
# point for a real deployment's mTLS CA -- see README's "Hardening the mTLS
# CA for production" section for what changes after this script runs).
# Never commit ca.key anywhere, and see the README for locking down its
# on-disk permissions once a real hostname is in use.
set -euo pipefail
cd "$(dirname "$0")"

DAYS=3650
HOSTNAME="${1:-localhost}"

if [ -f ca.key ]; then
  if [ ! -f public.crt ] || [ ! -f public.key ]; then
    # A checkout from before public.crt/public.key existed (added for the
    # :8444 real-HTTPS listener) has ca.key/server.crt/server.key but not
    # these two -- and docker-compose.yml now bind-mounts them by exact
    # path, so Docker would otherwise materialize each as an empty
    # directory, crashing nginx on every listener, not just :8444 (found by
    # adversarial review, 2026-08-11). Repair path: copy from the existing
    # server cert, same as a fresh run does below -- do NOT regenerate the
    # CA here, that would invalidate every already-issued client cert
    # (e.g. client-example-partner.crt) signed by the old one.
    cp server.crt public.crt
    cp server.key public.key
    echo "certs/ had ca.key but was missing public.crt/public.key (added by a newer version of this script) — generated them from the existing server certificate, CA and client certs untouched."
    exit 0
  fi
  echo "certs/ already generated (ca.key exists) — delete certs/*.key certs/*.crt certs/*.srl first to regenerate (e.g. with a different hostname)."
  exit 0
fi

# CA
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/O=Agent Embassy Dev/CN=Agent Embassy Dev CA" -out ca.crt 2>/dev/null

# nginx mTLS server cert (:8443 in dev, :443 in production -- see
# nginx/default.conf). CN/SAN must match the hostname clients connect to;
# SAN is required, not optional -- CN-only certs fail hostname verification
# in most modern TLS stacks (Go's crypto/tls, curl/OpenSSL 1.1.0+).
SAN="DNS:${HOSTNAME}"
if [ "$HOSTNAME" = "localhost" ]; then
  SAN="${SAN},IP:127.0.0.1"
fi
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -subj "/O=Agent Embassy Dev/CN=${HOSTNAME}" -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -extfile <(printf "subjectAltName=%s" "$SAN") -out server.crt 2>/dev/null

# Public (non-mTLS) HTTPS cert for Tier 0/1's :8444 listener. In dev this is
# just a copy of the same self-signed identity -- in a real deployment,
# certs/refresh-public-cert.sh overwrites public.crt/public.key with a real
# Let's Encrypt cert, and nginx's config never needs to know which mode it's
# in, since it always reads these same two fixed filenames.
cp server.crt public.crt
cp server.key public.key

# Example partner client cert (stands in for a real pilot supplier's cert)
openssl genrsa -out client-example-partner.key 2048 2>/dev/null
openssl req -new -key client-example-partner.key \
  -subj "/O=Example Partner Ltd/CN=example-partner" -out client-example-partner.csr 2>/dev/null
openssl x509 -req -in client-example-partner.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -out client-example-partner.crt 2>/dev/null

rm -f server.csr client-example-partner.csr

echo "Generated for hostname '${HOSTNAME}': ca.crt/ca.key, server.crt/server.key, public.crt/public.key, client-example-partner.crt/client-example-partner.key"
