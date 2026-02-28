#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

USER_NAME='agent_ro'
DISPATCHER='/usr/local/sbin/agent_ro_dispatch.py'
SSHD_MATCH='/etc/ssh/sshd_config.d/90-agent-ro.conf'
ACL_STATE_DIR='/var/lib/agent-ro-setup'
ACL_STATE_FILE="${ACL_STATE_DIR}/acl_state_v1.txt"
REMOVE_USER="${REMOVE_USER:-0}"
REMOVE_ACLS="${REMOVE_ACLS:-0}"
ALLOWED_DIRS=(/home /srv /opt /var/log /etc /var/lib/docker /mnt /data /media)

if ! command -v sudo >/dev/null 2>&1; then
  echo "ERROR: sudo is required."
  exit 1
fi

echo "[1/5] Removing SSH Match config (if present)..."
sudo rm -f "${SSHD_MATCH}"

echo "[2/5] Removing dispatcher (if present)..."
sudo rm -f "${DISPATCHER}"

echo "[3/5] Restoring SSH host key private file permissions..."
sudo setfacl -b /etc/ssh/ssh_host_*_key 2>/dev/null || true
sudo chown root:root /etc/ssh/ssh_host_*_key 2>/dev/null || true
sudo chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true

echo "[4/5] Validating and reloading sshd..."
sudo sshd -t
sudo systemctl reload ssh || sudo systemctl reload sshd || sudo systemctl restart ssh.socket

echo "[5/5] Optional cleanup..."
if [[ "${REMOVE_ACLS}" == "1" ]] && command -v setfacl >/dev/null 2>&1; then
  for dir in "${ALLOWED_DIRS[@]}"; do
    if [[ -e "${dir}" ]]; then
      sudo setfacl -Rx "u:${USER_NAME}" "${dir}" 2>/dev/null || true
    fi
  done
  sudo rm -f "${ACL_STATE_FILE}" || true
  sudo rmdir "${ACL_STATE_DIR}" 2>/dev/null || true
fi

if [[ "${REMOVE_USER}" == "1" ]]; then
  sudo userdel -r "${USER_NAME}" 2>/dev/null || true
fi

echo "Rollback complete."
