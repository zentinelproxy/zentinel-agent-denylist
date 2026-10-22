#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request.
#
# Every request comes from 127.0.0.1, so the IP rules need runs of their own:
#   1. path and User-Agent rules (over the Unix socket and over gRPC): an
#      ordinary request is forwarded (200); /admin, /.env and a sqlmap
#      User-Agent get 403 and never reach the upstream; /public is forwarded;
#   2. --block-ips 127.0.0.1: the client is refused (403);
#   3. --block-ips 0.0.0.0/0 --allow-ips 127.0.0.1 (default deny): the
#      allowlisted client is forwarded, and path rules still apply to it.
# Each run also checks that with the agent stopped the request is refused.

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}

smoke() {
    python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name denylist "$@"
}

for transport in uds grpc; do
    echo "=== denylist agent over $transport: path and User-Agent rules"
    smoke --transport "$transport" \
        --agent-arg=--block-paths=/admin,/.env \
        --agent-arg=--block-user-agents=sqlmap,nikto \
        --agent-arg=--block-ips=192.0.2.0/24 \
        --clean '{"name": "ordinary request", "path": "/smoke", "headers": {"User-Agent": "Mozilla/5.0"}}' \
        --case '{"name": "/admin blocked", "path": "/admin", "expect": 403}' \
        --case '{"name": "/admin/users blocked", "path": "/admin/users?id=1", "expect": 403}' \
        --case '{"name": "/.env blocked", "path": "/.env", "expect": 403}' \
        --case '{"name": "sqlmap User-Agent blocked", "path": "/smoke", "headers": {"User-Agent": "sqlmap/1.7.2#stable"}, "expect": 403}' \
        --case '{"name": "/public allowed", "path": "/public/index.html", "expect": 200}'
done

echo "=== denylist agent: blocked client IP"
smoke --agent-arg=--block-ips=127.0.0.1 \
    --clean '{"name": "request from a blocked IP", "path": "/smoke", "expect": 403}'

echo "=== denylist agent: default deny with an allowlisted client IP"
smoke --agent-arg=--block-ips=0.0.0.0/0,::/0 --agent-arg=--allow-ips=127.0.0.1 \
    --agent-arg=--block-paths=/admin \
    --clean '{"name": "request from an allowlisted IP", "path": "/smoke"}' \
    --case '{"name": "/admin still blocked for an allowlisted IP", "path": "/admin", "expect": 403}'
