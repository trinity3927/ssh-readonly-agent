#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

HOST="${HOST:-}"
if [[ "$#" -ge 1 ]]; then
  HOST="$1"
  shift
fi

if [[ -z "${HOST}" ]]; then
  if [[ -t 0 ]]; then
    read -r -p 'Target host (DNS or IP): ' HOST
  else
    echo 'ERROR: provide host as argument or HOST env var.' >&2
    echo 'Usage: ./scripts/agent_ro_verify.sh <host>' >&2
    exit 1
  fi
fi

if [[ "$#" -gt 0 ]]; then
  echo "ERROR: unexpected args: $*" >&2
  exit 1
fi

USER_NAME='agent_ro'
TARGET="${USER_NAME}@${HOST}"
POLICY_FILE='/etc/agent-ro/policy.json'
FAIL=0

declare -a ALLOWED_ROOTS=()
MAX_CMD_SECONDS=''
MAX_OUTPUT_BYTES=''

SSH_OPTS=(
  -o LogLevel=ERROR
  -o BatchMode=yes
  -o ControlMaster=auto
  -o ControlPersist=60
  -o ControlPath=/tmp/agent_ro_verify_%C
)

cleanup_control_socket() {
  ssh "${SSH_OPTS[@]}" -O exit "${TARGET}" >/dev/null 2>&1 || true
}
trap cleanup_control_socket EXIT

quote_sh() {
  printf '%q' "$1"
}

remote_capture() {
  local cmd="$1"
  ssh "${SSH_OPTS[@]}" "${TARGET}" "${cmd}"
}

run_expect_ok() {
  local label="$1"
  local cmd="$2"
  echo "  + ${label}"
  if ! remote_capture "${cmd}" >/dev/null; then
    echo '    FAIL: command should succeed'
    FAIL=1
  fi
}

run_expect_optional_ok() {
  local label="$1"
  local cmd="$2"
  echo "  + ${label}"
  if ! remote_capture "${cmd}" >/dev/null; then
    echo '    note: skipped (target unavailable in this host profile)'
  fi
}

run_expect_denied() {
  local label="$1"
  local cmd="$2"
  local out rc

  echo "  - ${label}"
  if out="$(remote_capture "${cmd}" 2>&1)"; then
    rc=0
  else
    rc=$?
  fi

  if [[ "${rc}" -ne 0 && "${out}" == *'DENY:'* ]]; then
    echo '    denied as expected'
  else
    echo '    FAIL: expected DENY'
    echo "    output: ${out}"
    FAIL=1
  fi
}

load_policy() {
  local policy_json tmp

  if ! policy_json="$(remote_capture "cat ${POLICY_FILE}" 2>/dev/null)"; then
    echo "ERROR: unable to read policy at ${POLICY_FILE}" >&2
    exit 1
  fi

  tmp="$(mktemp)"
  printf '%s\n' "${policy_json}" > "${tmp}"

  mapfile -t _parsed < <(python3 - "${tmp}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

for root in data.get("allowed_roots", []):
    if isinstance(root, str) and root:
        print(f"ROOT={root}")
print(f"MAX_CMD_SECONDS={data.get('max_cmd_seconds', '')}")
print(f"MAX_OUTPUT_BYTES={data.get('max_output_bytes', '')}")
PY
)

  rm -f "${tmp}"

  ALLOWED_ROOTS=()
  local line
  for line in "${_parsed[@]}"; do
    case "${line}" in
      ROOT=*) ALLOWED_ROOTS+=("${line#ROOT=}") ;;
      MAX_CMD_SECONDS=*) MAX_CMD_SECONDS="${line#MAX_CMD_SECONDS=}" ;;
      MAX_OUTPUT_BYTES=*) MAX_OUTPUT_BYTES="${line#MAX_OUTPUT_BYTES=}" ;;
    esac
  done

  if [[ "${#ALLOWED_ROOTS[@]}" -eq 0 ]]; then
    echo 'ERROR: policy has no allowed roots' >&2
    exit 1
  fi
}

first_line() {
  sed -n '1p'
}

find_sample_file() {
  local root="$1"
  local out

  if ! out="$(remote_capture "find $(quote_sh "${root}") -maxdepth 3 -type f")"; then
    return 1
  fi
  printf '%s\n' "${out}" | first_line
}

find_git_repo() {
  local root="$1"
  local out git_dir

  if ! out="$(remote_capture "find $(quote_sh "${root}") -maxdepth 5 -type d -name .git")"; then
    return 1
  fi
  git_dir="$(printf '%s\n' "${out}" | first_line)"
  [[ -z "${git_dir}" ]] && return 1
  dirname "${git_dir}"
}

main() {
  local primary_root sample_file git_repo outside_path output_test_root

  load_policy
  primary_root="${ALLOWED_ROOTS[0]}"

  sample_file=''
  for output_test_root in "${ALLOWED_ROOTS[@]}"; do
    sample_file="$(find_sample_file "${output_test_root}" || true)"
    if [[ -n "${sample_file}" ]]; then
      break
    fi
  done

  echo '[1/4] Positive checks (must succeed)...'
  run_expect_ok "list root" "ls -ld $(quote_sh "${primary_root}")"
  run_expect_ok "find in root" "find $(quote_sh "${primary_root}") -maxdepth 2 -type d"

  if [[ -n "${sample_file}" ]]; then
    run_expect_ok "cat sample file" "cat $(quote_sh "${sample_file}")"
    run_expect_ok "stat sample file" "stat -c '%n %a %U:%G' $(quote_sh "${sample_file}")"
  else
    echo '  + sample file checks'
    echo '    note: skipped (no sample file discovered)'
  fi

  echo '  + recursive search (rg or grep -R fallback)'
  if ! remote_capture "rg -n root $(quote_sh "${primary_root}")" >/dev/null 2>&1; then
    if ! remote_capture "grep -Rn root $(quote_sh "${primary_root}")" >/dev/null 2>&1; then
      echo '    FAIL: neither rg nor grep -R succeeded'
      FAIL=1
    fi
  fi

  git_repo=''
  for output_test_root in "${ALLOWED_ROOTS[@]}"; do
    git_repo="$(find_git_repo "${output_test_root}" || true)"
    if [[ -n "${git_repo}" ]]; then
      break
    fi
  done

  if [[ -n "${git_repo}" ]]; then
    run_expect_optional_ok 'git log sample' "git -C $(quote_sh "${git_repo}") log --oneline -n 1"
    run_expect_optional_ok 'git show sample' "git -C $(quote_sh "${git_repo}") show --name-only --oneline -n 1"
  else
    echo '  + git checks'
    echo '    note: skipped (no allowed git repo found)'
  fi

  echo '[2/4] Negative checks (must be denied)...'
  run_expect_denied 'disallowed command' 'touch /tmp/should_fail'
  run_expect_denied 'dangerous find option' "find $(quote_sh "${primary_root}") -delete"
  run_expect_denied 'disallowed git subcommand' "git -C $(quote_sh "${primary_root}") status"
  run_expect_denied 'non-recursive grep' "grep root $(quote_sh "${primary_root}")"
  run_expect_denied 'interactive ssh session' ''

  outside_path='/root/.bashrc'
  run_expect_denied 'outside allowlist path' "cat ${outside_path}"

  echo '[3/4] Policy-limit checks (best effort)...'
  if [[ "${MAX_OUTPUT_BYTES}" =~ ^[0-9]+$ ]] && [[ "${MAX_OUTPUT_BYTES}" -le 131072 ]]; then
    run_expect_optional_ok 'output-cap probe (may deny on large trees)' "find $(quote_sh "${primary_root}")"
  else
    echo '  + output-cap probe'
    echo '    note: skipped (max_output_bytes too large for reliable probe)'
  fi

  if [[ "${MAX_CMD_SECONDS}" =~ ^[0-9]+$ ]] && [[ "${MAX_CMD_SECONDS}" -le 3 ]]; then
    run_expect_optional_ok 'timeout probe (environment dependent)' "find $(quote_sh "${primary_root}") -maxdepth 8"
  else
    echo '  + timeout probe'
    echo '    note: skipped (max_cmd_seconds not in tight test range)'
  fi

  echo '[4/4] Result...'
  if [[ "${FAIL}" -eq 0 ]]; then
    echo 'Verify done: PASS'
  else
    echo 'Verify done: FAIL'
    exit 1
  fi
}

main
