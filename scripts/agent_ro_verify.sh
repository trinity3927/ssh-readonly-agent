#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

# Set this before running.
HOST='REPLACE_WITH_HOST_OR_IP'

if [[ "${HOST}" == 'REPLACE_WITH_HOST_OR_IP' ]]; then
  echo "ERROR: Edit HOST in this script before running."
  exit 1
fi

USER_NAME='agent_ro'
TARGET="${USER_NAME}@${HOST}"
FAIL=0
SSH_OPTS=(
  -o LogLevel=ERROR
  -o ControlMaster=auto
  -o ControlPersist=60
  -o ControlPath=/tmp/agent_ro_verify_%C
)

cleanup_control_socket() {
  ssh "${SSH_OPTS[@]}" -O exit "${TARGET}" >/dev/null 2>&1 || true
}
trap cleanup_control_socket EXIT

run_expect_ok() {
  local label="$1"
  local cmd="$2"
  echo "  + ${label}"
  if ! ssh "${SSH_OPTS[@]}" "${TARGET}" "${cmd}"; then
    echo "    FAIL: command should succeed"
    FAIL=1
  fi
}

run_expect_optional_ok() {
  local label="$1"
  local cmd="$2"
  echo "  + ${label}"
  if ! ssh "${SSH_OPTS[@]}" "${TARGET}" "${cmd}"; then
    echo "    note: skipped (path/repo may not exist on this host)"
  fi
}

run_expect_denied() {
  local label="$1"
  local cmd="$2"
  local out rc
  echo "  - ${label}"
  if out="$(ssh "${SSH_OPTS[@]}" "${TARGET}" "${cmd}" 2>&1)"; then
    rc=0
  else
    rc=$?
  fi

  if [[ "${rc}" -ne 0 && "${out}" == *"DENY:"* ]]; then
    echo "    denied as expected"
  else
    echo "    FAIL: expected DENY"
    echo "    output: ${out}"
    FAIL=1
  fi
}

echo "[1/3] Positive checks (should succeed)..."
run_expect_ok "directory metadata" 'ls -ld /etc'
run_expect_ok "find sshd config" 'find /etc -maxdepth 2 -name sshd_config'
run_expect_ok "cat small file" 'cat /etc/hostname'
run_expect_ok "stat passwd" 'stat /etc/passwd'

echo "  + search ssh config (rg or grep -R)"
if ! ssh "${SSH_OPTS[@]}" "${TARGET}" 'rg -n ForceCommand /etc/ssh'; then
  if ! ssh "${SSH_OPTS[@]}" "${TARGET}" 'grep -Rn ForceCommand /etc/ssh'; then
    echo "    FAIL: neither rg nor grep -R succeeded"
    FAIL=1
  fi
fi

run_expect_optional_ok "git log sample" 'git -C /home/samtheman/ssh-readonly-agent log --oneline -n 5'
run_expect_optional_ok "git show sample" 'git -C /home/samtheman/ssh-readonly-agent show --name-only --oneline HEAD~1'

echo "[2/3] Negative checks (should be denied)..."
run_expect_denied "write attempt" 'touch /tmp/should_fail'
run_expect_denied "dangerous find option" 'find /tmp -delete'
run_expect_denied "disallowed git subcommand" 'git -C /home status'
run_expect_denied "disallowed shell" 'bash -lc "id"'
run_expect_denied "interactive ssh session" ''

if [[ "${FAIL}" -eq 0 ]]; then
  echo "[3/3] Verify done: PASS"
else
  echo "[3/3] Verify done: FAIL"
  exit 1
fi
