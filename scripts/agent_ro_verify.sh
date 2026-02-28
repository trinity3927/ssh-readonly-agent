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

echo "[1/3] Positive checks (should succeed)..."
ssh "${TARGET}" 'ls -la /etc'
ssh "${TARGET}" 'find /etc -maxdepth 2 -name sshd_config'
ssh "${TARGET}" 'cat /etc/ssh/sshd_config | head -n 5'
ssh "${TARGET}" 'stat /etc/passwd'
ssh "${TARGET}" 'rg sshd /etc/ssh || grep -R sshd /etc/ssh'
ssh "${TARGET}" 'git -C /home log --oneline -n 5 || true'
ssh "${TARGET}" 'git -C /home show --name-only --oneline HEAD~1 || true'

echo "[2/3] Negative checks (should be denied)..."
set +e
ssh "${TARGET}" 'touch /tmp/should_fail'
ssh "${TARGET}" 'find /tmp -delete'
ssh "${TARGET}" 'git -C /home status'
ssh "${TARGET}" 'bash -lc "id"'
ssh "${TARGET}"
set -e

echo "[3/3] Verify done. Denied commands should show: DENY: ..."
