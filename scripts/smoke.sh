#!/usr/bin/env bash
# Smoke test for the v1 pico-api. Assumes the binary is already running
# on $HOST:$PORT with $PICO_API_TOKEN set.
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
TOK="${PICO_API_TOKEN:?must be set}"
BASE="http://$HOST:$PORT"
HDR=(-H "Authorization: Bearer $TOK" -H "content-type: application/json")

pass=0
fail=0

expect() {
  local label="$1"
  local want="$2"
  local got="$3"
  if [ "$got" = "$want" ]; then
    echo "  ok  $label ($got)"
    pass=$((pass + 1))
  else
    echo "  FAIL $label want=$want got=$got"
    fail=$((fail + 1))
  fi
}

http_code() {
  curl -sS -o /dev/null -w "%{http_code}" "$@"
}

code=$(http_code "$BASE/v1/livez")
expect "livez" 200 "$code"

code=$(http_code "$BASE/v1/sandboxes")
expect "no-auth-sandboxes" 401 "$code"

resp=$(curl -sS -X POST "$BASE/v1/sandboxes" "${HDR[@]}" -d '{"ports":[3000]}')
ID=$(echo "$resp" | jq -r .id)
[ -n "$ID" ] && [ "$ID" != "null" ] || { echo "FAIL create: $resp"; exit 1; }
echo "  ok  created $ID"

code=$(http_code "$BASE/v1/sandboxes/$ID" "${HDR[@]}")
expect "get" 200 "$code"

code=$(http_code "$BASE/v1/sandboxes" "${HDR[@]}")
expect "list" 200 "$code"

code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/exec" "${HDR[@]}" \
  -d '{"command":"echo","args":["smoke"]}')
expect "exec" 200 "$code"

code=$(http_code -X PUT "$BASE/v1/sandboxes/$ID/files" "${HDR[@]}" \
  -d '{"path":"smoke.txt","content":"hi"}')
expect "files-put" 200 "$code"

code=$(http_code "$BASE/v1/sandboxes/$ID/files?path=smoke.txt" "${HDR[@]}")
expect "files-get" 200 "$code"

code=$(http_code "$BASE/v1/sandboxes/$ID/files?dir=." "${HDR[@]}")
expect "files-list" 200 "$code"

code=$(http_code "$BASE/v1/sandboxes/$ID/files?path=../../etc/passwd" "${HDR[@]}")
expect "files-traversal-400" 400 "$code"

code=$(http_code "$BASE/v1/sandboxes?limit=10000" "${HDR[@]}")
expect "list-oversized-400" 400 "$code"

# SSH test must happen before stop since stop kills the VM
resp=$(curl -sS "$BASE/v1/sandboxes/$ID/ssh" "${HDR[@]}")
SSH_HOST=$(echo "$resp" | jq -r .host)
SSH_PORT=$(echo "$resp" | jq -r .port)
SSH_USER=$(echo "$resp" | jq -r .username)
SSH_KEY=$(echo "$resp" | jq -r .private_key)
[ "$SSH_HOST" = "localhost" ] || { echo "FAIL ssh-info host: $resp"; exit 1; }
[ -n "$SSH_PORT" ] && [ "$SSH_PORT" != "null" ] || { echo "FAIL ssh-info port: $resp"; exit 1; }
[ -n "$SSH_USER" ] && [ "$SSH_USER" != "null" ] || { echo "FAIL ssh-info user: $resp"; exit 1; }
[ -n "$SSH_KEY" ] && [ "$SSH_KEY" != "null" ] || { echo "FAIL ssh-info key: $resp"; exit 1; }

# Test the actual SSH connection.
if [ "${SMOKE_TEST_SSH:-1}" = "1" ]; then
  SSH_KEY_FILE=$(mktemp)
  echo "$SSH_KEY" > "$SSH_KEY_FILE"
  chmod 600 "$SSH_KEY_FILE"
  SSH_ERR=$(mktemp)
  if ssh \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    -o ConnectionAttempts=1 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i "$SSH_KEY_FILE" \
    -p "$SSH_PORT" \
    "$SSH_USER@$SSH_HOST" \
    "echo smoke-ssh-ok" 2>"$SSH_ERR" | grep -q "smoke-ssh-ok"; then
    echo "  ok  ssh-info (connected and executed command)"
    pass=$((pass + 1))
  else
    echo "  FAIL ssh-info (failed to connect/execute)"
    sed 's/^/       /' "$SSH_ERR"
    fail=$((fail + 1))
  fi
  rm -f "$SSH_KEY_FILE" "$SSH_ERR"
else
  echo "  skip ssh-info connection test (SMOKE_TEST_SSH=0)"
fi

tresp=$(curl -sS -X POST "$BASE/v1/sandboxes/$ID/tasks" "${HDR[@]}" \
  -d '{"prompt":"1","agent":"sleep","timeout_secs":5}')
TID=$(echo "$tresp" | jq -r .id)
[ -n "$TID" ] && [ "$TID" != "null" ] || { echo "FAIL task start: $tresp"; exit 1; }
echo "  ok  task $TID"

events=$(curl -sS "$BASE/v1/sandboxes/$ID/tasks/$TID/events" "${HDR[@]}")
if echo "$events" | grep -q "data:"; then
  echo "  ok  task-events"
  pass=$((pass + 1))
else
  echo "  FAIL task-events no SSE data"
  fail=$((fail + 1))
fi

state=""
for _ in $(seq 1 20); do
  state=$(curl -sS "$BASE/v1/sandboxes/$ID/tasks/$TID" "${HDR[@]}" | jq -r .state)
  if [ "$state" = "Completed" ] || [ "$state" = "Failed" ] || [ "$state" = "Cancelled" ]; then
    break
  fi
  sleep 0.25
done
expect "task-completed" "Completed" "$state"

# Suspend/Resume lifecycle
code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/suspend" "${HDR[@]}")
expect "suspend" 204 "$code"

state=$(curl -sS "$BASE/v1/sandboxes/$ID" "${HDR[@]}" | jq -r .state)
expect "state-after-suspend" "Suspended" "$state"

code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/exec" "${HDR[@]}" \
  -d '{"command":"echo","args":["during-suspend"]}')
expect "exec-while-suspended-conflict" 409 "$code"

code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/suspend" "${HDR[@]}")
expect "suspend-idempotent" 204 "$code"

state=$(curl -sS "$BASE/v1/sandboxes/$ID" "${HDR[@]}" | jq -r .state)
expect "state-after-idempotent-suspend" "Suspended" "$state"

code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/resume" "${HDR[@]}")
expect "resume" 204 "$code"

state=$(curl -sS "$BASE/v1/sandboxes/$ID" "${HDR[@]}" | jq -r .state)
expect "state-after-resume" "Running" "$state"

code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/resume" "${HDR[@]}")
expect "resume-idempotent" 204 "$code"

state=$(curl -sS "$BASE/v1/sandboxes/$ID" "${HDR[@]}" | jq -r .state)
expect "state-after-idempotent-resume" "Running" "$state"

code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/exec" "${HDR[@]}" \
  -d '{"command":"echo","args":["after-resume"]}')
expect "exec-after-resume" 200 "$code"

code=$(http_code -X POST "$BASE/v1/sandboxes/nonexistent/suspend" "${HDR[@]}")
expect "suspend-missing-404" 404 "$code"

code=$(http_code -X POST "$BASE/v1/sandboxes/nonexistent/resume" "${HDR[@]}")
expect "resume-missing-404" 404 "$code"

code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/keepalive" "${HDR[@]}")
expect "keepalive" 204 "$code"

code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/stop" "${HDR[@]}")
expect "stop" 204 "$code"

state=$(curl -sS "$BASE/v1/sandboxes/$ID" "${HDR[@]}" | jq -r .state)
expect "state-after-stop" "Stopped" "$state"

code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/exec" "${HDR[@]}" \
  -d '{"command":"echo","args":["after-stop"]}')
expect "exec-after-stop-conflict" 409 "$code"

code=$(http_code -X POST "$BASE/v1/sandboxes/$ID/purge" "${HDR[@]}")
expect "purge" 204 "$code"

code=$(http_code "$BASE/v1/sandboxes/$ID" "${HDR[@]}")
expect "get-after-purge" 404 "$code"

echo
echo "passed: $pass, failed: $fail"
[ "$fail" -eq 0 ]
