# OpenBao production setup (one-time, per deployment)

This runs once against a freshly started `openbao` container in the
production overlay (`docker compose -f docker-compose.yml -f
docker-compose.prod.yml up -d openbao`). Local dev doesn't need any of
this — dev mode (`docker-compose.yml` alone) is auto-unsealed with no
tokens to manage.

Every command below passes `-e BAO_ADDR=http://127.0.0.1:8200` — required,
not optional: the `bao` CLI defaults to `https://127.0.0.1:8200` regardless
of what the server's own listener config says, and openbao.hcl's listener
has `tls_disable = true` (see that file's own comment for why). Confirmed
live: every command below fails with "server gave HTTP response to HTTPS
client" without it.

## 1. Initialize

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec \
  -e BAO_ADDR=http://127.0.0.1:8200 openbao \
  bao operator init -key-shares=5 -key-threshold=3
```

This prints **5 unseal keys and one initial root token, exactly once.**
Store all 5 keys and the root token offline (password manager, split among
people) immediately — OpenBao has no recovery path if they're lost; the
raft data on disk becomes permanently unreadable without them.

## 2. Unseal

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec \
  -e BAO_ADDR=http://127.0.0.1:8200 openbao \
  bao operator unseal   # repeat 3x, a distinct key each time
```

**This step is required again after every container restart.** Raft
persists the encrypted data to the `openbao-data` volume, but the seal
state does not persist — that's the whole point of Shamir. Don't script
around this with a hardcoded key; it would defeat the reason manual unseal
was chosen over an auto-unseal option in the first place: OpenBao's only
non-cloud-KMS auto-unseal option needs a second already-unsealed instance
to act as key server, which is circular at this scale.

## 3. Log in with the root token, enable KV v2, create a scoped policy

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec \
  -e BAO_ADDR=http://127.0.0.1:8200 openbao bao login
```

This prompts for the root token interactively (input is masked, matching
Vault-compatible CLI behavior OpenBao inherits) and stores it in the
container at `~/.vault-token` for subsequent commands in this same
container — **don't** pass it as `-e BAO_TOKEN=<root token>` on the command
line instead: that lands in your host shell's history and is visible via
`ps`/`/proc/<pid>/cmdline` to any other local user for the command's
duration. It persists across separate `exec` invocations (not tied to one
shell session) as long as the `openbao` container itself isn't recreated,
which is why steps 3 and 4 below don't need to repeat the login.

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec \
  -e BAO_ADDR=http://127.0.0.1:8200 openbao bao secrets enable -path=secret kv-v2

# -T (disables pseudo-TTY allocation) is required for the heredoc below to
# actually reach the container's stdin -- confirmed live, the policy write
# silently doesn't get the piped content without it.
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec -T \
  -e BAO_ADDR=http://127.0.0.1:8200 \
  openbao bao policy write admin-tier2-secrets - <<'EOF'
path "secret/data/tier2-clients/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/tier2-clients/*" { capabilities = ["list", "read", "delete"] }
EOF
```

## 4. Mint a scoped token for the admin UI

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec \
  -e BAO_ADDR=http://127.0.0.1:8200 openbao \
  bao token create -policy=admin-tier2-secrets -period=8760h -orphan
```

Put the resulting token — **not** the root token, **not** any of the
unseal keys — into `.env` as `OPENBAO_TOKEN`, then `docker compose -f
docker-compose.yml -f docker-compose.prod.yml up -d admin` to pick it up
(see README's "Running a production pilot deployment" step 3 for why this
is a separate step rather than a boot-time requirement, and for why it
must be `up -d`, not `restart` — confirmed live, 2026-08-12: `restart`
doesn't reread `.env` or recreate the container, so it silently leaves
`OPENBAO_TOKEN` empty). The root token should not be used for day-to-day
operation; keep it offline for recovery only.

Note: OpenBao's own default `max_ttl` silently caps the `-period=8760h`
(1 year) requested above to 768h (32 days) — visible as a `WARNING` in
`bao token create`'s own output, confirmed live. This is OpenBao's
out-of-the-box system default, not a bug in this runbook — but
`admin/openbao_client.py` never calls the renew-self endpoint, so despite
being a periodic (not fixed-expiry) token, nothing in this codebase
actually renews it before that window closes. **The token will genuinely
stop working after 32 days** unless an operator manually re-runs `bao
token renew <token>` (or repeats this step to mint a new one) before
then — not yet automated; a real operational gap, disclosed here rather
than glossed over.

## What this stores

Exactly one thing today: Tier 2 partner client secrets, written by the
admin UI (`admin/openbao_client.py`) as a mirror/backup of what Keycloak
already holds as the source of truth — at `secret/tier2-clients/<client_id>`
via KV v2. Nothing else reads from or writes to OpenBao yet.
