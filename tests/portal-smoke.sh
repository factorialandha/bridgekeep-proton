#!/usr/bin/env bash
# Smoke test for the portal image: starts read-only, unprivileged and with no
# network but its own, prints a claim code, answers /healthz, refuses a
# foreign Host header, and sends the security headers.
set -euo pipefail
IMAGE=${PORTAL_IMAGE:-bridgekeep-portal:local}
name=bk-portal-smoke-$$
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$name" --read-only --tmpfs /tmp:size=16m --tmpfs /data:uid=10003,gid=10003,mode=0700 \
  --cap-drop ALL --security-opt no-new-privileges:true --memory 192m --pids-limit 64 "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  docker exec "$name" python -P -m portal health 2>/dev/null && break
  sleep 1
done
docker exec "$name" python -P -m portal health || { docker logs "$name"; echo "FAIL: no healthz"; exit 1; }

# Read the log first: with pipefail, `docker logs | grep -q` fails whenever grep
# exits on the match while docker logs is still writing (SIGPIPE, exit 141).
logs=$(docker logs "$name" 2>&1)
grep -Eq 'Enter +[A-Z2-7]{4}(-[A-Z2-7]{4}){5}' <<<"$logs" \
  || { printf '%s\n' "$logs"; echo "FAIL: no claim code in the log"; exit 1; }
echo "ok: claim code printed"

[[ $(docker exec "$name" id -u) == 10003 ]] || { echo "FAIL: not uid 10003"; exit 1; }
echo "ok: runs as 10003"

# The commit it was built from, for the footer (empty without a git checkout).
got=$(docker exec "$name" python -P -c 'from portal import hoststatus; print(hoststatus.build_commit())')
[[ $got == "${PORTAL_COMMIT:-}" ]] || { echo "FAIL: built-from commit is '$got', expected '${PORTAL_COMMIT:-}'"; exit 1; }
echo "ok: built from '${got:-unknown}'"

probe() { # host -> "status csp"
  docker exec "$name" python -P -c '
import http.client, sys
c = http.client.HTTPConnection("127.0.0.1", 8443, timeout=5)
c.request("GET", "/claim", headers={"Host": sys.argv[1]})
r = c.getresponse()
print(r.status, "csp" if "script-src" in (r.getheader("Content-Security-Policy") or "") else "nocsp")' "$1"
}
[[ $(probe localhost:8443) == "200 csp" ]] || { echo "FAIL: claim page"; exit 1; }
echo "ok: claim page with CSP"
[[ $(probe evil.example) == 421* ]] || { echo "FAIL: foreign Host accepted"; exit 1; }
echo "ok: foreign Host refused"
echo "portal smoke test passed"
