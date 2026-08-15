#!/usr/bin/env bash
# Copies a freshly issued/renewed Let's Encrypt certificate (from
# certs/letsencrypt/live/<hostname>/, written by the certbot service in
# docker-compose.prod.yml) into the fixed public.crt/public.key filenames
# nginx's :8444 listener always reads (see nginx/default.conf) -- keeps
# nginx's config domain-agnostic, the same design already used for the
# dev self-signed cert (certs/generate-dev-certs.sh).
#
# Run once manually after the first `certbot certonly` issuance (see
# README's "Running a production pilot deployment" section), and wire as
# `--deploy-hook` on the certbot service's `renew` invocation for
# subsequent renewals once confirmed working.
set -euo pipefail
cd "$(dirname "$0")"

LIVE_DIR=$(find letsencrypt/live -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)
if [ -z "$LIVE_DIR" ]; then
  echo "No certificate found under certs/letsencrypt/live/ -- run the initial certbot certonly issuance first (see README)." >&2
  exit 1
fi

cp "$LIVE_DIR/fullchain.pem" public.crt
cp "$LIVE_DIR/privkey.pem" public.key

echo "Copied $LIVE_DIR -> certs/public.crt, certs/public.key"

docker compose exec static nginx -s reload
echo "Reloaded nginx."
