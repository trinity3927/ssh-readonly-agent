#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

USER_NAME='agent_ro'
USER_HOME='/home/agent_ro'
if command -v nologin >/dev/null 2>&1; then
  DEFAULT_USER_SHELL="$(command -v nologin)"
else
  DEFAULT_USER_SHELL='/bin/false'
fi
USER_SHELL="${USER_SHELL:-${DEFAULT_USER_SHELL}}"

DISPATCHER_SRC="${SCRIPT_DIR}/agent_ro_dispatch.py"
DISPATCHER_DST='/usr/local/sbin/agent_ro_dispatch.py'
POLICY_DIR='/etc/agent-ro'
POLICY_FILE="${POLICY_DIR}/policy.json"
LOG_DIR='/var/log/agent-ro'

SSHD_MAIN='/etc/ssh/sshd_config'
SSHD_DROPIN='/etc/ssh/sshd_config.d/90-agent-ro.conf'
MAIN_BLOCK_BEGIN='# BEGIN AGENT_RO_MANAGED_BLOCK v2'
MAIN_BLOCK_END='# END AGENT_RO_MANAGED_BLOCK v2'

STATE_DIR='/var/lib/agent-ro-setup'
MANIFEST_FILE="${STATE_DIR}/install-manifest.json"
ACL_MANIFEST_DIR="${STATE_DIR}/acls"
BACKUP_BASE_DIR="${STATE_DIR}/backups"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
BACKUP_DIR="${BACKUP_BASE_DIR}/${RUN_ID}"

DEFAULT_ALLOWED_ROOTS=(/etc /var/log)
HOME_SECRET_EXCLUDES=(
  '.ssh'
  '.gnupg'
  '.aws'
  '.kube'
  '.docker'
  '.config/gcloud'
  '.local/share/keyrings'
  '.pki'
)

PUBKEY="${PUBKEY:-}"
HOME_TARGET="${HOME_TARGET:-}"
ALLOWED_ROOTS_RAW="${ALLOWED_ROOTS:-}"
EXTRA_ALLOWED_ROOTS_RAW="${EXTRA_ALLOWED_ROOTS:-}"
APPLY_ACL="${APPLY_ACL:-0}"
FORCE_ACL="${FORCE_ACL:-0}"
NO_PROMPT="${NO_PROMPT:-0}"
AGENT_RO_LOGGING="${AGENT_RO_LOGGING:-1}"
MAX_CMD_SECONDS="${MAX_CMD_SECONDS:-20}"
MAX_OUTPUT_BYTES="${MAX_OUTPUT_BYTES:-1048576}"

MODE='install'
if [[ "${1:-}" == 'install' || "${1:-}" == 'rollback' ]]; then
  MODE="$1"
  shift
fi
if [[ "${MODE}" == 'rollback' ]]; then
  exec "${SCRIPT_DIR}/agent_ro_rollback.sh" "$@"
fi

declare -a CLI_EXTRA_ROOTS=()
declare -a ALLOWED_ROOTS=()
declare -a NEW_ACL_MANIFEST_FILES=()
declare -a PREV_ACL_MANIFEST_FILES=()
declare -a ACL_MANIFEST_FILES=()
declare -a BACKUP_RECORDS=()

BACKUP_DIR_CREATED=0
SSHD_CHANGED=0
SSHD_MODE='dropin'
LEGACY_INSTALL_DETECTED=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/agent_ro_setup.sh [install] [OPTIONS] [PUBKEY]
  scripts/agent_ro_setup.sh rollback [ROLLBACK_OPTIONS]

Options:
  --pubkey <key>             SSH public key line (single line)
  --extra-root <dir>         Additional allowed root (repeatable)
  --home-target <dir>        Override invoking-user home target
  --apply-acl                Apply ACLs (opt-in; default disabled)
  --force-acl                Force ACL re-apply behavior for automation
  --max-cmd-seconds <n>      Command timeout policy (default: 20)
  --max-output-bytes <n>     Max streamed output policy (default: 1048576)
  --enable-logging           Enable syslog audit logging (default)
  --disable-logging          Disable syslog audit logging
  --no-prompt                Non-interactive mode (no extra-root prompt)
  -h, --help                 Show help

Environment knobs:
  PUBKEY, HOME_TARGET, ALLOWED_ROOTS, EXTRA_ALLOWED_ROOTS,
  APPLY_ACL, FORCE_ACL, NO_PROMPT,
  MAX_CMD_SECONDS, MAX_OUTPUT_BYTES, AGENT_RO_LOGGING
USAGE
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

to_bool() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) echo 1 ;;
    *) echo 0 ;;
  esac
}

validate_positive_int() {
  local name="$1"
  local value="$2"
  if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
    fail "${name} must be a positive integer"
  fi
  if [[ "${value}" -le 0 ]]; then
    fail "${name} must be > 0"
  fi
}

append_csv_values() {
  local raw="$1"
  local -n out_ref="$2"
  local item trimmed

  IFS=',' read -r -a _values <<<"${raw}"
  for item in "${_values[@]}"; do
    trimmed="$(trim "${item}")"
    [[ -z "${trimmed}" ]] && continue
    out_ref+=("${trimmed}")
  done
}

canonicalize_existing_dir() {
  local input_path="$1"
  python3 - "${input_path}" <<'PY'
import os
import sys

p = os.path.expanduser(sys.argv[1])
if not os.path.isabs(p):
    print("", end="")
    raise SystemExit(1)
real = os.path.realpath(p)
if not os.path.isdir(real):
    print("", end="")
    raise SystemExit(1)
print(real)
PY
}

dedupe_in_place() {
  local -n list_ref="$1"
  local -A seen=()
  local item
  local -a out=()
  for item in "${list_ref[@]}"; do
    [[ -z "${item}" ]] && continue
    if [[ -z "${seen["${item}"]+x}" ]]; then
      seen["${item}"]=1
      out+=("${item}")
    fi
  done
  list_ref=("${out[@]}")
}

repair_ssh_host_keys() {
  sudo setfacl -b /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || true
  sudo chown root:root /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || true
  sudo chmod 600 /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || true
}

ensure_backup_dir() {
  if [[ "${BACKUP_DIR_CREATED}" -eq 1 ]]; then
    return
  fi
  sudo install -d -m 700 -o root -g root "${BACKUP_DIR}"
  BACKUP_DIR_CREATED=1
}

backup_file() {
  local src="$1"
  local rel dest

  if ! sudo test -e "${src}"; then
    return
  fi

  ensure_backup_dir
  rel="${src#/}"
  dest="${BACKUP_DIR}/${rel}"
  sudo install -d -m 700 -o root -g root "$(dirname "${dest}")"
  sudo cp -a -- "${src}" "${dest}"
  BACKUP_RECORDS+=("${src}|${dest}")
}

install_if_changed() {
  local src="$1"
  local dst="$2"
  local mode="$3"
  local owner="$4"
  local group="$5"

  if sudo test -f "${dst}" && sudo cmp -s "${src}" "${dst}"; then
    sudo chown "${owner}:${group}" "${dst}"
    sudo chmod "${mode}" "${dst}"
    return 1
  fi

  backup_file "${dst}"
  sudo install -m "${mode}" -o "${owner}" -g "${group}" "${src}" "${dst}"
  return 0
}

resolve_home_target() {
  local invoker_user='' passwd_home=''

  if [[ -n "${HOME_TARGET}" ]]; then
    return
  fi

  invoker_user="${SUDO_USER:-${USER:-}}"
  if [[ -z "${invoker_user}" ]]; then
    invoker_user="$(id -un 2>/dev/null || true)"
  fi
  if [[ -n "${invoker_user}" ]]; then
    passwd_home="$(getent passwd "${invoker_user}" | awk -F: '{print $6}' || true)"
  fi

  if [[ -n "${passwd_home}" ]]; then
    HOME_TARGET="${passwd_home}"
  elif [[ -n "${invoker_user}" ]]; then
    HOME_TARGET="/home/${invoker_user}"
  else
    HOME_TARGET='/home'
  fi
}

prompt_extra_roots() {
  local answer extra
  if [[ "${NO_PROMPT}" == '1' ]]; then
    return
  fi
  if [[ ! -t 0 ]]; then
    return
  fi

  read -r -p 'Add additional allowed root directories? [y/N]: ' answer
  case "${answer}" in
    y|Y|yes|YES)
      while true; do
        read -r -p 'Extra allowed root (blank to finish): ' extra
        extra="$(trim "${extra}")"
        [[ -z "${extra}" ]] && break
        CLI_EXTRA_ROOTS+=("${extra}")
      done
      ;;
    *)
      ;;
  esac
}

build_allowed_roots() {
  local -a requested=()
  local candidate canonical

  if [[ -n "${ALLOWED_ROOTS_RAW}" ]]; then
    append_csv_values "${ALLOWED_ROOTS_RAW}" requested
  else
    requested=("${DEFAULT_ALLOWED_ROOTS[@]}" "${HOME_TARGET}")
  fi

  append_csv_values "${EXTRA_ALLOWED_ROOTS_RAW}" requested
  requested+=("${CLI_EXTRA_ROOTS[@]}")

  ALLOWED_ROOTS=()
  for candidate in "${requested[@]}"; do
    canonical="$(canonicalize_existing_dir "${candidate}" 2>/dev/null || true)"
    if [[ -z "${canonical}" ]]; then
      echo "WARN: skipping invalid root '${candidate}' (must be an existing absolute directory)"
      continue
    fi
    ALLOWED_ROOTS+=("${canonical}")
  done
  dedupe_in_place ALLOWED_ROOTS

  if [[ "${#ALLOWED_ROOTS[@]}" -eq 0 ]]; then
    fail 'no valid allowed roots were resolved'
  fi
}

load_previous_acl_manifest_files() {
  local line
  PREV_ACL_MANIFEST_FILES=()

  if ! sudo test -f "${MANIFEST_FILE}"; then
    return
  fi

  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    PREV_ACL_MANIFEST_FILES+=("${line}")
  done < <(sudo python3 - "${MANIFEST_FILE}" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    raise SystemExit(0)

for item in data.get("acl_manifest_files", []):
    if isinstance(item, str) and item:
        print(item)
PY
)
}

collect_acl_manifest_files() {
  ACL_MANIFEST_FILES=("${PREV_ACL_MANIFEST_FILES[@]}" "${NEW_ACL_MANIFEST_FILES[@]}")
  dedupe_in_place ACL_MANIFEST_FILES
}

write_policy_file() {
  local tmp_roots tmp_policy

  tmp_roots="$(mktemp)"
  tmp_policy="$(mktemp)"
  printf '%s\n' "${ALLOWED_ROOTS[@]}" > "${tmp_roots}"

  python3 - "${tmp_roots}" "${tmp_policy}" "${MAX_CMD_SECONDS}" "${MAX_OUTPUT_BYTES}" "${AGENT_RO_LOGGING}" <<'PY'
import json
import sys
from pathlib import Path

roots_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
max_seconds = int(sys.argv[3])
max_bytes = int(sys.argv[4])
logging = str(sys.argv[5]).strip().lower() in {"1", "true", "yes", "on"}

roots = []
seen = set()
for raw in roots_path.read_text(encoding="utf-8").splitlines():
    item = raw.strip()
    if not item or item in seen:
        continue
    seen.add(item)
    roots.append(item)

policy = {
    "version": 2,
    "allowed_commands": ["find", "rg", "cat", "ls", "stat", "git", "grep"],
    "allowed_roots": roots,
    "max_cmd_seconds": max_seconds,
    "max_output_bytes": max_bytes,
    "logging": logging,
}
out_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

  sudo install -d -m 755 -o root -g root "${POLICY_DIR}"
  if install_if_changed "${tmp_policy}" "${POLICY_FILE}" 644 root root; then
    :
  fi

  rm -f "${tmp_roots}" "${tmp_policy}"
}

write_sshd_dropin() {
  local tmp
  tmp="$(mktemp)"
  cat > "${tmp}" <<EOF_DROPIN
Match User ${USER_NAME}
    PubkeyAuthentication yes
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitTTY no
    PermitUserRC no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    GatewayPorts no
    ForceCommand ${DISPATCHER_DST}
EOF_DROPIN

  sudo install -d -m 755 -o root -g root "$(dirname "${SSHD_DROPIN}")"
  if install_if_changed "${tmp}" "${SSHD_DROPIN}" 644 root root; then
    SSHD_CHANGED=1
  fi
  rm -f "${tmp}"
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
    backup_file "${SSHD_MAIN}"
    sudo install -m 600 -o root -g root "${tmp_clean}" "${SSHD_MAIN}"
    SSHD_CHANGED=1
  fi

  rm -f "${tmp_current}" "${tmp_clean}"
}

apply_managed_block_to_main() {
  local tmp_current tmp_clean
  tmp_current="$(mktemp)"
  tmp_clean="$(mktemp)"

  sudo cat "${SSHD_MAIN}" > "${tmp_current}"
  awk -v begin="${MAIN_BLOCK_BEGIN}" -v end="${MAIN_BLOCK_END}" '
    $0 == begin {skip=1; next}
    $0 == end {skip=0; next}
    !skip {print}
  ' "${tmp_current}" > "${tmp_clean}"

  cat >> "${tmp_clean}" <<EOF_MAIN

${MAIN_BLOCK_BEGIN}
Match User ${USER_NAME}
    PubkeyAuthentication yes
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitTTY no
    PermitUserRC no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    GatewayPorts no
    ForceCommand ${DISPATCHER_DST}
${MAIN_BLOCK_END}
EOF_MAIN

  if ! cmp -s "${tmp_current}" "${tmp_clean}"; then
    backup_file "${SSHD_MAIN}"
    sudo install -m 600 -o root -g root "${tmp_clean}" "${SSHD_MAIN}"
    SSHD_CHANGED=1
  fi

  rm -f "${tmp_current}" "${tmp_clean}"
}

supports_dropin_config() {
  if [[ ! -d /etc/ssh/sshd_config.d ]]; then
    return 1
  fi
  if ! sudo test -f "${SSHD_MAIN}"; then
    return 1
  fi
  if sudo grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "${SSHD_MAIN}"; then
    return 0
  fi
  return 1
}

configure_sshd() {
  if supports_dropin_config; then
    SSHD_MODE='dropin'
    write_sshd_dropin
    strip_managed_block_from_main
  else
    SSHD_MODE='main_block'
    if sudo test -f "${SSHD_DROPIN}"; then
      backup_file "${SSHD_DROPIN}"
      sudo rm -f "${SSHD_DROPIN}"
      SSHD_CHANGED=1
    fi
    apply_managed_block_to_main
  fi
}

validate_and_reload_sshd() {
  local sshd_bin=''

  if command -v sshd >/dev/null 2>&1; then
    sshd_bin="$(command -v sshd)"
  elif [[ -x /usr/sbin/sshd ]]; then
    sshd_bin='/usr/sbin/sshd'
  else
    fail 'sshd binary not found'
  fi

  sudo "${sshd_bin}" -t

  if [[ "${SSHD_CHANGED}" -eq 0 ]]; then
    echo 'No sshd config changes detected; skipping reload.'
    return
  fi

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

  fail 'unable to reload/restart ssh service safely'
}

stream_acl_paths() {
  local root="$1"
  local -a prune_args=()
  local secret

  if [[ "${root}" == '/etc' ]]; then
    sudo find "${root}" \
      \( -path '/etc/ssh/ssh_host_rsa_key' -o -path '/etc/ssh/ssh_host_ecdsa_key' -o -path '/etc/ssh/ssh_host_ed25519_key' \) \
      -prune -o -print0
    return
  fi

  if [[ "${root}" == "${HOME_TARGET}" ]]; then
    for secret in "${HOME_SECRET_EXCLUDES[@]}"; do
      prune_args+=( -path "${HOME_TARGET}/${secret}" -o -path "${HOME_TARGET}/${secret}/*" -o )
    done
    if (( ${#prune_args[@]} > 0 )); then
      unset 'prune_args[${#prune_args[@]}-1]'
      sudo find "${root}" \( "${prune_args[@]}" \) -prune -o -print0
      return
    fi
  fi

  sudo find "${root}" -print0
}

apply_acl_for_root() {
  local root="$1"
  local safe_root manifest_tmp manifest_path
  local count=0 errors=0 path

  safe_root="${root#/}"
  safe_root="${safe_root//\//_}"
  manifest_tmp="$(mktemp)"
  manifest_path="${ACL_MANIFEST_DIR}/${RUN_ID}_${safe_root}.lst"

  echo "  -> ${root}"
  while IFS= read -r -d '' path; do
    if sudo setfacl -m "u:${USER_NAME}:rX" "${path}" 2>/dev/null; then
      printf '%s\n' "${path}" >> "${manifest_tmp}"
      count=$((count + 1))
    else
      errors=$((errors + 1))
    fi
  done < <(stream_acl_paths "${root}")

  if [[ -s "${manifest_tmp}" ]]; then
    sudo install -d -m 700 -o root -g root "${ACL_MANIFEST_DIR}"
    sudo install -m 600 -o root -g root "${manifest_tmp}" "${manifest_path}"
    NEW_ACL_MANIFEST_FILES+=("${manifest_path}")
  fi

  rm -f "${manifest_tmp}"
  echo "     applied: ${count}, skipped: ${errors}"
}

apply_acls_if_enabled() {
  local root

  NEW_ACL_MANIFEST_FILES=()

  if [[ "${APPLY_ACL}" != '1' ]]; then
    echo 'ACL step disabled (APPLY_ACL=0).'
    return
  fi
  if ! command -v setfacl >/dev/null 2>&1; then
    echo "WARN: setfacl not found; skipping ACL write pass."
    return
  fi

  echo 'Applying ACLs (opt-in enabled)...'
  if [[ "${FORCE_ACL}" == '1' ]]; then
    echo 'FORCE_ACL=1 set; performing full ACL pass.'
  fi

  for root in "${ALLOWED_ROOTS[@]}"; do
    apply_acl_for_root "${root}"
  done
}

write_manifest() {
  local tmp_roots tmp_acl tmp_backups tmp_manifest
  local acl_enabled logging_enabled

  tmp_roots="$(mktemp)"
  tmp_acl="$(mktemp)"
  tmp_backups="$(mktemp)"
  tmp_manifest="$(mktemp)"

  printf '%s\n' "${ALLOWED_ROOTS[@]}" > "${tmp_roots}"
  printf '%s\n' "${ACL_MANIFEST_FILES[@]}" > "${tmp_acl}"
  printf '%s\n' "${BACKUP_RECORDS[@]}" > "${tmp_backups}"

  acl_enabled="$(to_bool "${APPLY_ACL}")"
  logging_enabled="$(to_bool "${AGENT_RO_LOGGING}")"

  python3 - "${tmp_roots}" "${tmp_acl}" "${tmp_backups}" "${tmp_manifest}" <<PY
import json
import os
import sys
from datetime import datetime, timezone

roots_file, acl_file, backups_file, out_file = sys.argv[1:]

def read_lines(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]

roots = read_lines(roots_file)
acl_files = read_lines(acl_file)
backup_entries = []
for line in read_lines(backups_file):
    if "|" not in line:
        continue
    src, backup = line.split("|", 1)
    backup_entries.append({"source": src, "backup": backup})

manifest = {
    "version": 2,
    "installed_at": datetime.now(timezone.utc).isoformat(),
    "run_id": "${RUN_ID}",
    "user_name": "${USER_NAME}",
    "user_home": "${USER_HOME}",
    "user_shell": "${USER_SHELL}",
    "home_target": "${HOME_TARGET}",
    "allowed_roots": roots,
    "policy_file": "${POLICY_FILE}",
    "dispatcher_file": "${DISPATCHER_DST}",
    "sshd_mode": "${SSHD_MODE}",
    "sshd_dropin": "${SSHD_DROPIN}",
    "sshd_main": "${SSHD_MAIN}",
    "main_block_begin": "${MAIN_BLOCK_BEGIN}",
    "main_block_end": "${MAIN_BLOCK_END}",
    "acl_enabled": ${acl_enabled},
    "acl_manifest_files": acl_files,
    "state_dir": "${STATE_DIR}",
    "acl_manifest_dir": "${ACL_MANIFEST_DIR}",
    "log_dir": "${LOG_DIR}",
    "max_cmd_seconds": int("${MAX_CMD_SECONDS}"),
    "max_output_bytes": int("${MAX_OUTPUT_BYTES}"),
    "logging": ${logging_enabled},
    "backup_dir": "${BACKUP_DIR}" if int("${BACKUP_DIR_CREATED}") == 1 else "",
    "backups": backup_entries,
    "legacy_install_detected": ${LEGACY_INSTALL_DETECTED},
}

with open(out_file, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

  sudo install -d -m 700 -o root -g root "${STATE_DIR}"
  sudo install -m 600 -o root -g root "${tmp_manifest}" "${MANIFEST_FILE}"

  rm -f "${tmp_roots}" "${tmp_acl}" "${tmp_backups}" "${tmp_manifest}"
}

ensure_user() {
  if ! id -u "${USER_NAME}" >/dev/null 2>&1; then
    sudo useradd -m -d "${USER_HOME}" -s "${USER_SHELL}" "${USER_NAME}"
  fi

  sudo usermod -d "${USER_HOME}" -s "${USER_SHELL}" "${USER_NAME}"
  sudo usermod -L "${USER_NAME}" || true
  sudo install -d -m 700 -o "${USER_NAME}" -g "${USER_NAME}" "${USER_HOME}"

  if id -nG "${USER_NAME}" 2>/dev/null | tr ' ' '\n' | grep -qx 'sudo'; then
    sudo gpasswd -d "${USER_NAME}" sudo >/dev/null || true
  fi
  if id -nG "${USER_NAME}" 2>/dev/null | tr ' ' '\n' | grep -qx 'wheel'; then
    sudo gpasswd -d "${USER_NAME}" wheel >/dev/null || true
  fi
  if id -nG "${USER_NAME}" 2>/dev/null | tr ' ' '\n' | grep -qx 'admin'; then
    sudo gpasswd -d "${USER_NAME}" admin >/dev/null || true
  fi
}

install_authorized_key() {
  local tmp_auth

  if [[ -z "${PUBKEY}" ]]; then
    if [[ -t 0 ]]; then
      read -r -p 'Paste SSH public key line: ' PUBKEY
    else
      fail 'provide pubkey as positional arg, --pubkey, or PUBKEY env var'
    fi
  fi

  PUBKEY="$(printf '%s' "${PUBKEY}" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [[ -z "${PUBKEY}" ]] && fail 'public key cannot be empty'
  [[ "${PUBKEY}" == *$'\n'* ]] && fail 'public key must be a single line'
  [[ "${PUBKEY}" != ssh-* ]] && fail 'invalid public key format (must start with ssh-)'

  sudo install -d -m 700 -o "${USER_NAME}" -g "${USER_NAME}" "${USER_HOME}/.ssh"

  tmp_auth="$(mktemp)"
  printf '%s\n' "${PUBKEY}" > "${tmp_auth}"

  if ! sudo test -f "${USER_HOME}/.ssh/authorized_keys" || ! sudo cmp -s "${tmp_auth}" "${USER_HOME}/.ssh/authorized_keys"; then
    sudo install -m 600 -o "${USER_NAME}" -g "${USER_NAME}" "${tmp_auth}" "${USER_HOME}/.ssh/authorized_keys"
  fi

  rm -f "${tmp_auth}"
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --pubkey)
        [[ "$#" -ge 2 ]] || fail '--pubkey requires a value'
        PUBKEY="$2"
        shift 2
        ;;
      --extra-root)
        [[ "$#" -ge 2 ]] || fail '--extra-root requires a value'
        CLI_EXTRA_ROOTS+=("$2")
        shift 2
        ;;
      --home-target)
        [[ "$#" -ge 2 ]] || fail '--home-target requires a value'
        HOME_TARGET="$2"
        shift 2
        ;;
      --apply-acl)
        APPLY_ACL=1
        shift
        ;;
      --force-acl)
        FORCE_ACL=1
        shift
        ;;
      --no-prompt)
        NO_PROMPT=1
        shift
        ;;
      --max-cmd-seconds)
        [[ "$#" -ge 2 ]] || fail '--max-cmd-seconds requires a value'
        MAX_CMD_SECONDS="$2"
        shift 2
        ;;
      --max-output-bytes)
        [[ "$#" -ge 2 ]] || fail '--max-output-bytes requires a value'
        MAX_OUTPUT_BYTES="$2"
        shift 2
        ;;
      --enable-logging)
        AGENT_RO_LOGGING=1
        shift
        ;;
      --disable-logging)
        AGENT_RO_LOGGING=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        break
        ;;
      -* )
        fail "unknown option: $1"
        ;;
      *)
        if [[ -z "${PUBKEY}" ]]; then
          PUBKEY="$1"
          shift
        else
          fail "unexpected positional argument: $1"
        fi
        ;;
    esac
  done

  if [[ "$#" -gt 0 ]]; then
    fail "unexpected trailing arguments: $*"
  fi
}

main() {
  parse_args "$@"

  if ! command -v sudo >/dev/null 2>&1; then
    fail 'sudo is required'
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    fail 'python3 is required'
  fi
  if [[ ! -f "${DISPATCHER_SRC}" ]]; then
    fail "dispatcher source not found at ${DISPATCHER_SRC}"
  fi

  validate_positive_int 'MAX_CMD_SECONDS' "${MAX_CMD_SECONDS}"
  validate_positive_int 'MAX_OUTPUT_BYTES' "${MAX_OUTPUT_BYTES}"

  AGENT_RO_LOGGING="$(to_bool "${AGENT_RO_LOGGING}")"
  APPLY_ACL="$(to_bool "${APPLY_ACL}")"
  FORCE_ACL="$(to_bool "${FORCE_ACL}")"
  NO_PROMPT="$(to_bool "${NO_PROMPT}")"

  trap repair_ssh_host_keys EXIT INT TERM

  if ! sudo test -f "${MANIFEST_FILE}"; then
    if sudo test -f "${DISPATCHER_DST}" || sudo test -f "${SSHD_DROPIN}"; then
      LEGACY_INSTALL_DETECTED=1
    fi
  fi

  resolve_home_target
  prompt_extra_roots
  build_allowed_roots
  load_previous_acl_manifest_files

  echo '[1/8] Creating/locking agent user...'
  ensure_user

  echo '[2/8] Installing SSH key...'
  install_authorized_key

  echo "[3/8] Installing dispatcher to ${DISPATCHER_DST}..."
  sudo install -d -m 755 -o root -g root "$(dirname "${DISPATCHER_DST}")"
  if install_if_changed "${DISPATCHER_SRC}" "${DISPATCHER_DST}" 755 root root; then
    :
  fi

  echo "[4/8] Writing policy file ${POLICY_FILE}..."
  write_policy_file

  echo '[5/8] Updating sshd policy wiring...'
  configure_sshd

  echo '[6/8] Validating/reloading sshd...'
  validate_and_reload_sshd

  echo '[7/8] ACL step...'
  apply_acls_if_enabled
  collect_acl_manifest_files

  echo '[8/8] Writing install manifest...'
  write_manifest

  sudo install -d -m 755 -o root -g root "${LOG_DIR}"

  echo 'Repairing SSH host private key permissions (safety guard)...'
  repair_ssh_host_keys

  echo
  echo "Completed setup for ${USER_NAME}."
  echo "Mode: ${SSHD_MODE}; Allowed roots: ${ALLOWED_ROOTS[*]}"
  if [[ "${APPLY_ACL}" == '1' ]]; then
    echo 'ACL mode: enabled'
  else
    echo 'ACL mode: disabled (opt-in)'
  fi
  echo "Next: run ./scripts/agent_ro_verify.sh <host>"
}

main "$@"
