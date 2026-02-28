#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

# Usage:
#   ./agent_ro_setup.sh '<ssh-public-key-line>'
#   PUBKEY='<ssh-public-key-line>' ./agent_ro_setup.sh
PUBKEY="${PUBKEY:-REPLACE_WITH_AGENT_PUBLIC_KEY}"
if [[ "${#}" -ge 1 ]]; then
  PUBKEY="$1"
fi

USER_NAME='agent_ro'
USER_SHELL="${USER_SHELL:-/bin/bash}"
DISPATCHER='/usr/local/sbin/agent_ro_dispatch.py'
SSHD_MATCH='/etc/ssh/sshd_config.d/90-agent-ro.conf'
DEFAULT_ALLOWED_DIRS=(/home /srv /opt /var/log /etc /var/lib/docker /mnt /data /media)
ALLOWED_DIRS=()
HOME_TARGET="${HOME_TARGET:-}"
HOME_SECRET_EXCLUDE_PROFILE='home-secret-excludes-v1'
HOME_SECRET_EXCLUDES=(
  ".ssh"
  ".gnupg"
  ".aws"
  ".kube"
  ".docker"
  ".config/gcloud"
  ".local/share/keyrings"
  ".pki"
)
ACL_STATE_DIR='/var/lib/agent-ro-setup'
ACL_STATE_FILE="${ACL_STATE_DIR}/acl_state_v1.txt"
APPLY_ACL="${APPLY_ACL:-0}"
SKIP_ACL="${SKIP_ACL:-0}"
FORCE_ACL="${FORCE_ACL:-0}"
CHANGED=0
SPIN_IDX=0
SPIN_LAST_MS=0
SPIN_FRAME_INTERVAL_MS="${SPIN_FRAME_INTERVAL_MS:-180}"
SPIN_BLINK_HOLD_MS="${SPIN_BLINK_HOLD_MS:-1000}"
SPIN_BLINK_UNTIL_MS=0

repair_ssh_host_keys() {
  sudo setfacl -b /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || true
  sudo chown root:root /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || true
  sudo chmod 600 /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || true
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
    HOME_TARGET="/home"
  fi
}

build_allowed_dirs() {
  local dir
  local -A seen=()

  ALLOWED_DIRS=()
  for dir in "${DEFAULT_ALLOWED_DIRS[@]}"; do
    if [[ "${dir}" == "/home" ]]; then
      dir="${HOME_TARGET}"
    fi
    if [[ -z "${dir}" ]]; then
      continue
    fi
    if [[ -z "${seen["${dir}"]+x}" ]]; then
      ALLOWED_DIRS+=("${dir}")
      seen["${dir}"]=1
    fi
  done
}

stream_acl_paths() {
  local dir="$1"
  local secret_dir
  local -a prune_args=()

  if [[ "${dir}" == "/etc" ]]; then
    sudo find "${dir}" \
      \( -path '/etc/ssh/ssh_host_rsa_key' -o -path '/etc/ssh/ssh_host_ecdsa_key' -o -path '/etc/ssh/ssh_host_ed25519_key' \) \
      -prune -o -print0
    return
  fi

  if [[ "${dir}" == "${HOME_TARGET}" ]]; then
    for secret_dir in "${HOME_SECRET_EXCLUDES[@]}"; do
      prune_args+=( -path "${HOME_TARGET}/${secret_dir}" -o -path "${HOME_TARGET}/${secret_dir}/*" -o )
    done
    if (( ${#prune_args[@]} > 0 )); then
      unset 'prune_args[${#prune_args[@]}-1]'
      sudo find "${dir}" \( "${prune_args[@]}" \) -prune -o -print0
    else
      sudo find "${dir}" -print0
    fi
    return
  fi

  sudo find "${dir}" -print0
}

pulse_progress() {
  local done="$1"
  local total="$2"
  local label="$3"
  local pct frame now_ms
  local frames=(
    "[o-----]" "[-o----]" "[--o---]" "[---o--]" "[----o-]" "[-----o]" "[------]"
    "[----o-]" "[---o--]" "[--o---]" "[-o----]" "[o-----]" "[------]"
  )

  if (( total <= 0 )); then
    pct=100
  else
    pct=$((done * 100 / total))
    if (( pct > 100 )); then
      pct=100
    fi
  fi

  now_ms="$(date +%s%3N 2>/dev/null || echo $((EPOCHSECONDS * 1000)))"
  if (( SPIN_LAST_MS == 0 )); then
    SPIN_LAST_MS="${now_ms}"
  fi

  if (( SPIN_BLINK_UNTIL_MS > now_ms )); then
    :
  elif (( now_ms - SPIN_LAST_MS >= SPIN_FRAME_INTERVAL_MS )); then
    SPIN_IDX=$(( (SPIN_IDX + 1) % ${#frames[@]} ))
    SPIN_LAST_MS="${now_ms}"
    if [[ "${frames[${SPIN_IDX}]}" == "[------]" ]]; then
      SPIN_BLINK_UNTIL_MS=$((now_ms + SPIN_BLINK_HOLD_MS))
    else
      SPIN_BLINK_UNTIL_MS=0
    fi
  fi

  frame="${frames[${SPIN_IDX}]}"
  printf '\r    %-8s %3d%% (%d/%d) %s' "${frame}" "${pct}" "${done}" "${total}" "${label}"
}

apply_acl_with_progress() {
  local dir="$1"
  local acl_spec="u:${USER_NAME}:rX"
  local total processed batch_size path acl_error_count
  local -a batch

  batch_size=256
  batch=()
  acl_error_count=0

  echo "  -> ${dir} (indexing paths...)"
  if ! total="$(stream_acl_paths "${dir}" | tr -cd '\0' | wc -c | tr -d '[:space:]')"; then
    return 1
  fi

  if (( total == 0 )); then
    echo "    no paths found; skipped."
    return 0
  fi
  echo "    ${total} paths"
  if [[ "${dir}" == "${HOME_TARGET}" ]]; then
    echo "    exclusions: ${HOME_SECRET_EXCLUDES[*]}"
  fi

  processed=0
  while IFS= read -r -d '' path; do
    batch+=("${path}")
    if (( ${#batch[@]} >= batch_size )); then
      if ! sudo setfacl -m "${acl_spec}" "${batch[@]}" 2>/dev/null; then
        for path in "${batch[@]}"; do
          if ! sudo setfacl -m "${acl_spec}" "${path}" 2>/dev/null; then
            acl_error_count=$((acl_error_count + 1))
          fi
        done
      fi
      processed=$((processed + ${#batch[@]}))
      pulse_progress "${processed}" "${total}" "${dir}"
      batch=()
    fi
  done < <(stream_acl_paths "${dir}")

  if (( ${#batch[@]} > 0 )); then
    if ! sudo setfacl -m "${acl_spec}" "${batch[@]}" 2>/dev/null; then
      for path in "${batch[@]}"; do
        if ! sudo setfacl -m "${acl_spec}" "${path}" 2>/dev/null; then
          acl_error_count=$((acl_error_count + 1))
        fi
      done
    fi
    processed=$((processed + ${#batch[@]}))
    pulse_progress "${processed}" "${total}" "${dir}"
  fi

  printf '\n'
  if (( acl_error_count > 0 )); then
    echo "    note: ${acl_error_count} paths skipped (ACL unsupported or denied)."
  fi
  return 0
}

if [[ -z "${PUBKEY}" || "${PUBKEY}" == 'REPLACE_WITH_AGENT_PUBLIC_KEY' ]]; then
  if [[ -t 0 ]]; then
    read -r -p "Public key file path [~/.ssh/id_ed25519.pub]: " PUBKEY_PATH
    PUBKEY_PATH="${PUBKEY_PATH:-$HOME/.ssh/id_ed25519.pub}"
    if [[ -f "${PUBKEY_PATH}" ]]; then
      PUBKEY="$(cat "${PUBKEY_PATH}")"
    else
      read -r -p "Paste SSH public key line: " PUBKEY
    fi
  else
    echo "ERROR: provide pubkey as argument or PUBKEY env var."
    echo "Usage: ./agent_ro_setup.sh '<ssh-public-key-line>'"
    exit 1
  fi
fi

PUBKEY="$(printf '%s' "${PUBKEY}" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
if [[ -z "${PUBKEY}" ]]; then
  echo "ERROR: public key cannot be empty."
  exit 1
fi
if [[ "${PUBKEY}" == *$'\n'* ]]; then
  echo "ERROR: public key must be a single line."
  exit 1
fi
if [[ "${PUBKEY}" != ssh-* ]]; then
  echo "ERROR: invalid public key format (expected line starting with ssh-)."
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "ERROR: sudo is required."
  exit 1
fi

# Resolve invoking-user home target and compute effective ACL paths.
resolve_home_target
build_allowed_dirs

# Safety: if interrupted during ACL work, still restore SSH host key perms.
trap repair_ssh_host_keys EXIT INT TERM

echo "[1/6] Creating locked user ${USER_NAME} (no shell login, no sudo)..."
if ! id -u "${USER_NAME}" >/dev/null 2>&1; then
  sudo useradd -m -d "/home/${USER_NAME}" -s "${USER_SHELL}" "${USER_NAME}"
  CHANGED=1
fi
sudo usermod -d "/home/${USER_NAME}" -s "${USER_SHELL}" "${USER_NAME}"
sudo usermod -L "${USER_NAME}"
if id -nG "${USER_NAME}" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
  sudo gpasswd -d "${USER_NAME}" sudo >/dev/null
  CHANGED=1
fi

echo "[2/6] Installing SSH key..."
sudo install -d -m 700 -o "${USER_NAME}" -g "${USER_NAME}" "/home/${USER_NAME}/.ssh"
tmp_auth="$(mktemp)"
printf '%s\n' "${PUBKEY}" > "${tmp_auth}"
if ! sudo test -f "/home/${USER_NAME}/.ssh/authorized_keys" || ! sudo cmp -s "${tmp_auth}" "/home/${USER_NAME}/.ssh/authorized_keys"; then
  sudo install -m 600 -o "${USER_NAME}" -g "${USER_NAME}" "${tmp_auth}" "/home/${USER_NAME}/.ssh/authorized_keys"
  CHANGED=1
fi
rm -f "${tmp_auth}"
sudo chown "${USER_NAME}:${USER_NAME}" "/home/${USER_NAME}/.ssh/authorized_keys"
sudo chmod 600 "/home/${USER_NAME}/.ssh/authorized_keys"

echo "[3/6] Installing forced-command dispatcher at ${DISPATCHER}..."
tmp_dispatcher="$(mktemp)"
cat > "${tmp_dispatcher}" <<'PY'
#!/usr/bin/env python3
import os
import shlex
import shutil
import sys

ALLOWED = {
    "find": shutil.which("find"),
    "rg": shutil.which("rg"),
    "cat": shutil.which("cat"),
    "ls": shutil.which("ls"),
    "stat": shutil.which("stat"),
    "git": shutil.which("git"),
    "grep": shutil.which("grep"),
}

BAD_FIND = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
ALLOWED_GIT_SUBCMDS = {"log", "show"}


def deny(msg: str, code: int = 126) -> None:
    print(f"DENY: {msg}", file=sys.stderr)
    sys.exit(code)


cmdline = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
if not cmdline:
    deny("interactive shell disabled; run a remote command")

try:
    argv = shlex.split(cmdline, posix=True)
except ValueError as exc:
    deny(f"parse error: {exc}")

if not argv:
    deny("empty command")

cmd = argv[0]
if cmd not in {"find", "rg", "cat", "ls", "stat", "git", "grep"}:
    deny("command not allowed")

if cmd == "find":
    for token in argv[1:]:
        if token in BAD_FIND:
            deny(f"find option not allowed: {token}")

if cmd == "grep":
    has_recursive = any(
        token == "-R"
        or token == "-r"
        or (token.startswith("-") and ("R" in token[1:] or "r" in token[1:]))
        for token in argv[1:]
    )
    if not has_recursive:
        deny("grep allowed only as rg fallback with -R/-r")

if cmd == "git":
    i = 1
    while i < len(argv):
        token = argv[i]
        if token in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"):
            i += 2
            continue
        if token.startswith("--git-dir=") or token.startswith("--work-tree=") or token.startswith("--namespace=") or token.startswith("--config-env="):
            i += 1
            continue
        if token.startswith("-"):
            i += 1
            continue
        break

    if i >= len(argv):
        deny("git subcommand required")

    sub = argv[i]
    if sub not in ALLOWED_GIT_SUBCMDS:
        deny("only 'git log' and 'git show' are allowed")

    for token in argv[i + 1:]:
        if token in {"--ext-diff", "--exec-path", "--output"} or token.startswith("--output="):
            deny(f"git option not allowed: {token}")

    argv.insert(i, "--no-pager")

bin_path = ALLOWED.get(cmd)
if not bin_path:
    if cmd == "rg":
        deny("rg not installed; use grep -R fallback")
    deny(f"{cmd} not available")

env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "LC_CTYPE", "TERM")}
env["PATH"] = "/usr/bin:/bin"
if cmd == "git":
    env["GIT_PAGER"] = "cat"
    env["PAGER"] = "cat"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"

os.execvpe(bin_path, argv, env)
PY

if ! sudo test -f "${DISPATCHER}" || ! sudo cmp -s "${tmp_dispatcher}" "${DISPATCHER}"; then
  sudo install -m 755 -o root -g root "${tmp_dispatcher}" "${DISPATCHER}"
  CHANGED=1
fi
rm -f "${tmp_dispatcher}"

echo "[4/6] Writing sshd Match block..."
tmp_sshd="$(mktemp)"
cat > "${tmp_sshd}" <<'SSHEOF'
Match User agent_ro
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
    ForceCommand /usr/local/sbin/agent_ro_dispatch.py
SSHEOF
if ! sudo test -f "${SSHD_MATCH}" || ! sudo cmp -s "${tmp_sshd}" "${SSHD_MATCH}"; then
  sudo install -m 644 -o root -g root "${tmp_sshd}" "${SSHD_MATCH}"
  CHANGED=1
fi
rm -f "${tmp_sshd}"

echo "[5/6] Validating and reloading sshd..."
sudo sshd -t
if [[ "${CHANGED}" -eq 1 ]]; then
  sudo systemctl reload ssh || sudo systemctl reload sshd || sudo systemctl restart ssh.socket
else
  echo "No config changes detected; skipping ssh reload."
fi

echo "[6/6] Applying read/traverse ACLs on allowed directories..."
if [[ "${APPLY_ACL}" != "1" ]]; then
  echo "ACL step disabled by default (APPLY_ACL=0)."
  echo "Set APPLY_ACL=1 to enable ACL writes after reviewing targets."
elif [[ "${SKIP_ACL}" == "1" ]]; then
  echo "Skipping ACL step (SKIP_ACL=1)."
elif command -v setfacl >/dev/null 2>&1; then
  echo "ACL targets: ${ALLOWED_DIRS[*]}"
  echo "Home target: ${HOME_TARGET}"
  ACL_SIGNATURE="${USER_NAME}|${HOME_SECRET_EXCLUDE_PROFILE}|$(printf '%s:' "${ALLOWED_DIRS[@]}")"
  PREV_SIGNATURE="$(sudo cat "${ACL_STATE_FILE}" 2>/dev/null || true)"

  if [[ "${FORCE_ACL}" != "1" && "${PREV_SIGNATURE}" == "${ACL_SIGNATURE}" ]]; then
    echo "ACL signature unchanged; skipping ACL apply."
    echo "Set FORCE_ACL=1 to reapply."
  else
    ACL_FAILED=0
    for dir in "${ALLOWED_DIRS[@]}"; do
      if [[ -e "${dir}" ]]; then
        if ! apply_acl_with_progress "${dir}"; then
          echo "WARN: failed to set ACL on ${dir}"
          ACL_FAILED=1
        fi
      else
        echo "  -> ${dir} (missing, skipped)"
      fi
    done

    if [[ "${ACL_FAILED}" -eq 0 ]]; then
      sudo install -d -m 755 -o root -g root "${ACL_STATE_DIR}"
      printf '%s\n' "${ACL_SIGNATURE}" | sudo tee "${ACL_STATE_FILE}" >/dev/null
    else
      echo "WARN: ACL step had failures; signature state not updated."
      echo "Re-run with FORCE_ACL=1 after fixing the failing paths/filesystems."
    fi
  fi
else
  echo "WARN: setfacl not found. Install 'acl' package if you need per-path ACL grants."
fi

echo "Repairing SSH host private key permissions (safety guard)..."
repair_ssh_host_keys

echo
echo "Completed setup for ${USER_NAME}."
echo "Next: run ./agent_ro_verify.sh after setting HOST."
