#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

USER_NAME_DEFAULT='agent_ro'
DISPATCHER_DEFAULT='/usr/local/sbin/agent_ro_dispatch.py'
POLICY_DIR_DEFAULT='/etc/agent-ro'
POLICY_FILE_DEFAULT='/etc/agent-ro/policy.json'
LOG_DIR_DEFAULT='/var/log/agent-ro'

SSHD_MAIN_DEFAULT='/etc/ssh/sshd_config'
SSHD_DROPIN_DEFAULT='/etc/ssh/sshd_config.d/90-agent-ro.conf'
MAIN_BLOCK_BEGIN_DEFAULT='# BEGIN AGENT_RO_MANAGED_BLOCK v2'
MAIN_BLOCK_END_DEFAULT='# END AGENT_RO_MANAGED_BLOCK v2'

STATE_DIR_DEFAULT='/var/lib/agent-ro-setup'
MANIFEST_DEFAULT='/var/lib/agent-ro-setup/install-manifest.json'
ACL_MANIFEST_DIR_DEFAULT='/var/lib/agent-ro-setup/acls'

MANIFEST_FILE="${MANIFEST_FILE:-${MANIFEST_DEFAULT}}"
REMOVE_USER="${REMOVE_USER:-1}"
REMOVE_ACLS="${REMOVE_ACLS:-1}"
PURGE_STATE="${PURGE_STATE:-1}"
LEGACY_SWEEP_ACLS="${LEGACY_SWEEP_ACLS:-0}"

declare -a ACL_MANIFEST_FILES=()

USER_NAME="${USER_NAME_DEFAULT}"
DISPATCHER_PATH="${DISPATCHER_DEFAULT}"
POLICY_FILE="${POLICY_FILE_DEFAULT}"
POLICY_DIR="${POLICY_DIR_DEFAULT}"
LOG_DIR="${LOG_DIR_DEFAULT}"
SSHD_MAIN="${SSHD_MAIN_DEFAULT}"
SSHD_DROPIN="${SSHD_DROPIN_DEFAULT}"
MAIN_BLOCK_BEGIN="${MAIN_BLOCK_BEGIN_DEFAULT}"
MAIN_BLOCK_END="${MAIN_BLOCK_END_DEFAULT}"
STATE_DIR="${STATE_DIR_DEFAULT}"
ACL_MANIFEST_DIR="${ACL_MANIFEST_DIR_DEFAULT}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/agent_ro_rollback.sh [OPTIONS]

Defaults:
  - full uninstall (REMOVE_USER=1)
  - ACL cleanup from manifests (REMOVE_ACLS=1)
  - state purge (PURGE_STATE=1)

Options:
  --keep-user            Keep agent_ro user/home
  --keep-acls            Skip ACL removal
  --keep-state           Keep /var/lib/agent-ro-setup
  --legacy-acl-sweep     Also attempt broad legacy ACL cleanup (risky)
  -h, --help             Show help

Environment overrides:
  REMOVE_USER, REMOVE_ACLS, PURGE_STATE, LEGACY_SWEEP_ACLS, MANIFEST_FILE
USAGE
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

to_bool() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) echo 1 ;;
    *) echo 0 ;;
  esac
}

repair_ssh_host_keys() {
  sudo setfacl -b /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || true
  sudo chown root:root /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || true
  sudo chmod 600 /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || true
}

strip_managed_block_from_main() {
  local tmp_current tmp_clean

  if ! sudo test -f "${SSHD_MAIN}"; then
    return
  fi

  tmp_current="$(mktemp)"
  tmp_clean="$(mktemp)"
  sudo cat "${SSHD_MAIN}" > "${tmp_current}"

  awk -v begin="${MAIN_BLOCK_BEGIN}" -v end="${MAIN_BLOCK_END}" '
    $0 == begin {skip=1; next}
    $0 == end {skip=0; next}
    !skip {print}
  ' "${tmp_current}" > "${tmp_clean}"

  if ! cmp -s "${tmp_current}" "${tmp_clean}"; then
    sudo install -m 600 -o root -g root "${tmp_clean}" "${SSHD_MAIN}"
  fi

  rm -f "${tmp_current}" "${tmp_clean}"
}

validate_and_reload_sshd() {
  local sshd_bin=''

  if command -v sshd >/dev/null 2>&1; then
    sshd_bin="$(command -v sshd)"
  elif [[ -x /usr/sbin/sshd ]]; then
    sshd_bin='/usr/sbin/sshd'
  else
    echo 'WARN: sshd binary not found; skipping sshd validation/reload.'
    return
  fi

  sudo "${sshd_bin}" -t

  if sudo systemctl reload sshd >/dev/null 2>&1; then
    return
  fi
  if sudo systemctl reload ssh >/dev/null 2>&1; then
    return
  fi
  if sudo service sshd reload >/dev/null 2>&1; then
    return
  fi
  if sudo service ssh reload >/dev/null 2>&1; then
    return
  fi
  if sudo systemctl restart sshd >/dev/null 2>&1; then
    echo 'WARN: used sshd restart fallback.'
    return
  fi
  if sudo systemctl restart ssh >/dev/null 2>&1; then
    echo 'WARN: used ssh restart fallback.'
    return
  fi

  echo 'WARN: unable to reload/restart ssh service.'
}

load_manifest_overrides() {
  local line

  if ! sudo test -f "${MANIFEST_FILE}"; then
    return
  fi

  while IFS= read -r line; do
    case "${line}" in
      USER_NAME=*) USER_NAME="${line#USER_NAME=}" ;;
      DISPATCHER=*) DISPATCHER_PATH="${line#DISPATCHER=}" ;;
      POLICY_FILE=*) POLICY_FILE="${line#POLICY_FILE=}" ;;
      POLICY_DIR=*) POLICY_DIR="${line#POLICY_DIR=}" ;;
      LOG_DIR=*) LOG_DIR="${line#LOG_DIR=}" ;;
      SSHD_MAIN=*) SSHD_MAIN="${line#SSHD_MAIN=}" ;;
      SSHD_DROPIN=*) SSHD_DROPIN="${line#SSHD_DROPIN=}" ;;
      MAIN_BLOCK_BEGIN=*) MAIN_BLOCK_BEGIN="${line#MAIN_BLOCK_BEGIN=}" ;;
      MAIN_BLOCK_END=*) MAIN_BLOCK_END="${line#MAIN_BLOCK_END=}" ;;
      STATE_DIR=*) STATE_DIR="${line#STATE_DIR=}" ;;
      ACL_MANIFEST_DIR=*) ACL_MANIFEST_DIR="${line#ACL_MANIFEST_DIR=}" ;;
      ACL=*) ACL_MANIFEST_FILES+=("${line#ACL=}") ;;
    esac
  done < <(sudo python3 - "${MANIFEST_FILE}" <<'PY'
import os
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    raise SystemExit(0)

def emit(name, value):
    if isinstance(value, str) and value:
        print(f"{name}={value}")

emit("USER_NAME", data.get("user_name"))
emit("DISPATCHER", data.get("dispatcher_file"))
emit("POLICY_FILE", data.get("policy_file"))
emit("POLICY_DIR", os.path.dirname(data.get("policy_file", "")))
emit("LOG_DIR", data.get("log_dir"))
emit("SSHD_MAIN", data.get("sshd_main"))
emit("SSHD_DROPIN", data.get("sshd_dropin"))
emit("MAIN_BLOCK_BEGIN", data.get("main_block_begin"))
emit("MAIN_BLOCK_END", data.get("main_block_end"))
emit("STATE_DIR", data.get("state_dir"))
if isinstance(data.get("acl_manifest_files"), list):
    for item in data["acl_manifest_files"]:
        if isinstance(item, str) and item:
            print(f"ACL={item}")
emit("ACL_MANIFEST_DIR", data.get("acl_manifest_dir"))
PY
)
}

remove_acl_entries_from_manifest() {
  local manifest path removed=0 failed=0

  if ! command -v setfacl >/dev/null 2>&1; then
    echo 'WARN: setfacl not available; skipping ACL removal.'
    return
  fi

  for manifest in "${ACL_MANIFEST_FILES[@]}"; do
    if ! sudo test -f "${manifest}"; then
      continue
    fi
    while IFS= read -r path; do
      [[ -z "${path}" ]] && continue
      if sudo setfacl -x "u:${USER_NAME}" "${path}" 2>/dev/null; then
        removed=$((removed + 1))
      else
        failed=$((failed + 1))
      fi
    done < <(sudo cat "${manifest}")
  done

  echo "ACL removal summary: removed=${removed}, failed=${failed}"
}

legacy_acl_sweep() {
  local dir
  local legacy_dirs=(/home /srv /opt /var/log /etc /var/lib/docker /mnt /data /media)

  if ! command -v setfacl >/dev/null 2>&1; then
    return
  fi

  echo 'WARN: running broad legacy ACL sweep.'
  for dir in "${legacy_dirs[@]}"; do
    if [[ -e "${dir}" ]]; then
      sudo setfacl -Rx "u:${USER_NAME}" "${dir}" 2>/dev/null || true
    fi
  done
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --keep-user)
        REMOVE_USER=0
        shift
        ;;
      --keep-acls)
        REMOVE_ACLS=0
        shift
        ;;
      --keep-state)
        PURGE_STATE=0
        shift
        ;;
      --legacy-acl-sweep)
        LEGACY_SWEEP_ACLS=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
  done
}

main() {
  parse_args "$@"

  if ! command -v sudo >/dev/null 2>&1; then
    fail 'sudo is required'
  fi

  REMOVE_USER="$(to_bool "${REMOVE_USER}")"
  REMOVE_ACLS="$(to_bool "${REMOVE_ACLS}")"
  PURGE_STATE="$(to_bool "${PURGE_STATE}")"
  LEGACY_SWEEP_ACLS="$(to_bool "${LEGACY_SWEEP_ACLS}")"

  trap repair_ssh_host_keys EXIT INT TERM

  echo '[1/6] Loading manifest metadata (if present)...'
  load_manifest_overrides

  echo '[2/6] Removing SSH policy wiring...'
  sudo rm -f "${SSHD_DROPIN}"
  strip_managed_block_from_main

  echo '[3/6] Removing dispatcher and policy files...'
  sudo rm -f "${DISPATCHER_PATH}"
  sudo rm -f "${POLICY_FILE}"
  sudo rmdir "${POLICY_DIR}" 2>/dev/null || true

  echo '[4/6] ACL cleanup...'
  if [[ "${REMOVE_ACLS}" == '1' ]]; then
    remove_acl_entries_from_manifest
    if [[ "${LEGACY_SWEEP_ACLS}" == '1' ]]; then
      legacy_acl_sweep
    fi
  else
    echo 'Skipping ACL removal (--keep-acls or REMOVE_ACLS=0).'
  fi

  echo '[5/6] Validating/reloading sshd...'
  validate_and_reload_sshd

  echo '[6/6] Removing user and state...'
  if [[ "${REMOVE_USER}" == '1' ]]; then
    sudo userdel -r "${USER_NAME}" 2>/dev/null || true
  else
    echo 'Keeping user/home (--keep-user or REMOVE_USER=0).'
  fi

  sudo rm -rf "${LOG_DIR}" 2>/dev/null || true

  if [[ "${PURGE_STATE}" == '1' ]]; then
    sudo rm -rf "${STATE_DIR}" 2>/dev/null || true
  else
    sudo rm -f "${MANIFEST_FILE}" 2>/dev/null || true
  fi

  echo 'Repairing SSH host private key permissions (safety guard)...'
  repair_ssh_host_keys

  echo 'Rollback complete.'
}

main "$@"
