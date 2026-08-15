# Production config for OpenBao -- used only via docker-compose.prod.yml's
# overlay (local dev keeps running OpenBao's dev-mode invocation directly in
# docker-compose.yml, in-memory and auto-unsealed, unaffected by this file).
#
# storage "raft": OpenBao's own docs mark the file backend explicitly "not
# production recommended" (no transactional guarantees, no HA); raft is the
# recommended default even single-node. No retry_join -- deliberately one
# node, no clustering, matching this project's "no HA at 2-party pilot
# scale" scope.
# path is /openbao/file, not the more obviously-named /openbao/data,
# specifically because it's the one raft-suitable path that already exists
# inside the official image with openbao:openbao ownership baked in --
# confirmed live that mounting the named volume at any OTHER path gets it
# created by the Docker daemon as root:root (the image has no /openbao/data
# at all), which the openbao process (uid 100, non-root) then can't write
# to; Docker's volume copy-up behavior only inherits ownership when the
# mount target matches an existing image path exactly. The "file" name is
# a legacy holdover from that path's original purpose (the file storage
# backend, explicitly NOT what's used here) rather than a description of
# what's stored in it now.
storage "raft" {
  path    = "/openbao/file"
  node_id = "agent-embassy-1"
}

# tls_disable: OpenBao has no published host port in either compose file --
# it's reached only over Docker's internal network, the same trust boundary
# `verify` and `admin` already accept in plain HTTP when talking to
# Keycloak. This is a disclosed tradeoff, not a silent deviation from
# OpenBao's own hardening guidance (which recommends TLS everywhere) -- see
# the README's production deployment section.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://openbao:8200"
cluster_addr = "http://openbao:8201"

# No `seal` stanza: omitting it defaults to manual Shamir unseal. The only
# real auto-unseal alternative without a cloud KMS -- OpenBao's own
# "transit" seal -- needs a second, already-unsealed OpenBao/Vault instance
# to act as the key server, which is circular and not worth operating at
# this scale. See openbao/SETUP.md for the manual unseal runbook.
#
# No `disable_mlock` line: OpenBao 2.x has actually DROPPED support for it
# (confirmed live -- the container refuses to boot with it present,
# "OpenBao has dropped support for mlock... remove the line"), not merely
# deprecated it as some older Vault-derived docs/examples suggest.
ui = true
