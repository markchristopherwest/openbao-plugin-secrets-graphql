#!/usr/bin/env bash
# run.sh -- build the plugin, start OpenBao in dev mode, register/enable
# the engine, and exercise the full lifecycle end-to-end.
set -euo pipefail

readonly PLUGIN_NAME="openbao-plugin-secrets-graphql"
readonly PLUGIN_DIR="./bao/plugins"
readonly MOUNT_PATH="gql"
readonly BAO_ADDR_DEFAULT="http://127.0.0.1:8200"
readonly ROOT_TOKEN="root"

# Upstream GraphQL server (graphql-server-go); override via env.
readonly GQL_URL="${GQL_URL:-http://127.0.0.1:9090/query}"
readonly GQL_USERNAME="${GQL_USERNAME:-admin}"
readonly GQL_PASSWORD="${GQL_PASSWORD:-changeme}"

export BAO_ADDR="${BAO_ADDR:-$BAO_ADDR_DEFAULT}"
export BAO_TOKEN="$ROOT_TOKEN"

BAO_PID=""

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ -n "$BAO_PID" ]] && kill -0 "$BAO_PID" 2>/dev/null; then
    log "Stopping OpenBao (pid $BAO_PID)"
    kill "$BAO_PID" || true
  fi
}
trap cleanup EXIT

require() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }

build() {
  log "Building plugin"
  mkdir -p "$PLUGIN_DIR"
  CGO_ENABLED=0 go build -o "${PLUGIN_DIR}/${PLUGIN_NAME}" \
    "./cmd/${PLUGIN_NAME}"
}

start_bao() {
  log "Starting OpenBao dev server"
  bao server -dev \
    -dev-root-token-id="$ROOT_TOKEN" \
    -dev-plugin-dir="$PLUGIN_DIR" \
    -log-level=info &
  BAO_PID=$!

  # Wait for the API to come up rather than sleeping blind.
  for _ in $(seq 1 30); do
    if bao status >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  fail "OpenBao did not become ready"
}

register_plugin() {
  log "Registering plugin"
  local sha
  sha="$(sha256sum "${PLUGIN_DIR}/${PLUGIN_NAME}" | cut -d' ' -f1)"
  bao plugin register -sha256="$sha" secret "$PLUGIN_NAME"

  log "Enabling at ${MOUNT_PATH}/"
  bao secrets enable -path="$MOUNT_PATH" "$PLUGIN_NAME"
}

configure() {
  log "Writing config"
  bao write "${MOUNT_PATH}/config" \
    username="$GQL_USERNAME" \
    password="$GQL_PASSWORD" \
    url="$GQL_URL"

  log "Writing role (returns a leased token: lease_id expected below)"
  bao write "${MOUNT_PATH}/role/my-role" \
    username="$GQL_USERNAME" \
    password="$GQL_PASSWORD" \
    ttl=300 max_ttl=3600
}

exercise() {
  log "Reading creds"
  local lease_id
  lease_id="$(bao read -field=lease_id "${MOUNT_PATH}/creds/my-role")"
  [[ -n "$lease_id" ]] || fail "creds read returned no lease_id"
  log "Issued lease: ${lease_id}"

  log "Renewing lease"
  bao lease renew "$lease_id"

  log "Revoking lease"
  bao lease revoke "$lease_id"

  log "Rotating root credentials"
  bao write -f "${MOUNT_PATH}/config/rotate-root"

  log "Lifecycle OK"
}

main() {
  require go
  require bao
  require sha256sum

  build
  start_bao
  register_plugin
  configure
  exercise

  log "Dev server still running (pid ${BAO_PID}); ctrl-c to stop"
  wait "$BAO_PID"
}

main "$@"
