# ssh-readonly-agent

Provision a locked SSH account (`agent_ro`) for read-only remote evidence collection with explicit command and path policy enforcement.

## What this kit enforces

- Public-key SSH login for `agent_ro` only.
- No interactive shell, no TTY, no forwarding.
- ForceCommand dispatcher with command allowlist:
  - `find`
  - `rg` (preprocessor options `--pre`/`--pre-glob` are denied)
  - `grep` (recursive only: `-R/-r`, `--recursive`, `--dereference-recursive`, or `--directories recurse`)
  - `cat`
  - `ls` (without a path, defaults to the first allowed root)
  - `stat`
  - `git log` (requires `-C <repo-path>` in allowed roots)
  - `git show` (requires `-C <repo-path>` in allowed roots)
- Path allowlist enforcement in dispatcher using resolved real paths.
  - Includes file-valued options (for example `grep -f`, `grep --exclude-from`, `rg --file`, `rg --ignore-file`).
- Runtime safety limits per command:
  - timeout (`max_cmd_seconds`)
  - streamed output cap (`max_output_bytes`)
- Syslog/journal audit events for allow/deny decisions (enabled by default).

## Default policy footprint

Conservative defaults:

- `/etc`
- `/var/log`
- invoking-user home directory (auto-detected; override with `HOME_TARGET`)

You can add more roots interactively (TTY prompt) or non-interactively via env/flags.

## Files

- `scripts/agent_ro_setup.sh` - setup/install entrypoint (also supports `rollback` mode)
- `scripts/agent_ro_dispatch.py` - dispatcher source installed to `/usr/local/sbin/agent_ro_dispatch.py`
- `scripts/agent_ro_verify.sh` - policy-aware verification script
- `scripts/agent_ro_rollback.sh` - full uninstall / rollback
- `docs/TROUBLESHOOTING.md` - common issues and fixes

## Managed host state

- Policy: `/etc/agent-ro/policy.json`
- Install manifest: `/var/lib/agent-ro-setup/install-manifest.json`
- ACL touched-path manifests: `/var/lib/agent-ro-setup/acls/*.lst`
- Dispatcher: `/usr/local/sbin/agent_ro_dispatch.py`
- SSHD wiring:
  - preferred: `/etc/ssh/sshd_config.d/90-agent-ro.conf`
  - fallback: managed block in `/etc/ssh/sshd_config`

## Prerequisites

- Linux host with OpenSSH server.
- `sudo` access.
- `python3` on target host.
- Optional for ACL writes: `setfacl` (`acl` package).

## Quick Start

1. Copy this repo folder to the target host.
2. Run setup with the agent public key:

```bash
./scripts/agent_ro_setup.sh 'ssh-ed25519 AAAA... comment'
```

or:

```bash
PUBKEY='ssh-ed25519 AAAA... comment' ./scripts/agent_ro_setup.sh
```

If running in a TTY, setup can prompt to add extra allowed roots.

3. Optional: enable ACL writes (default is off):

```bash
APPLY_ACL=1 ./scripts/agent_ro_setup.sh 'ssh-ed25519 AAAA... comment'
```

4. Verify from your client machine:

```bash
./scripts/agent_ro_verify.sh <host-or-ip>
```

## Setup options

```bash
./scripts/agent_ro_setup.sh [install] [OPTIONS] [PUBKEY]
```

Common options:

- `--pubkey <key>`
- `--extra-root <dir>` (repeatable)
- `--home-target <dir>`
- `--apply-acl`
- `--force-acl`
- `--max-cmd-seconds <n>`
- `--max-output-bytes <n>`
- `--disable-logging` / `--enable-logging`
- `--no-prompt`

Useful env vars:

- `ALLOWED_ROOTS=/etc,/var/log,/home/alice` (replace defaults)
- `EXTRA_ALLOWED_ROOTS=/srv/data,/opt/reports` (append)
- `HOME_TARGET=/home/alice`
- `APPLY_ACL=1`

## Rollback / uninstall

Full uninstall is the default behavior:

```bash
./scripts/agent_ro_rollback.sh
```

or through setup wrapper:

```bash
./scripts/agent_ro_setup.sh rollback
```

Default rollback behavior:

- Removes `agent_ro` user/home.
- Removes dispatcher, policy file, SSHD wiring.
- Removes ACL entries using manifest-recorded touched paths.
- Purges state under `/var/lib/agent-ro-setup`.

Optional rollback flags:

- `--keep-user`
- `--keep-acls`
- `--keep-state`
- `--legacy-acl-sweep` (broad fallback cleanup for old installs; use with care)

## Quality checks

Run local checks before deployment changes:

```bash
bash -n scripts/agent_ro_setup.sh
bash -n scripts/agent_ro_rollback.sh
bash -n scripts/agent_ro_verify.sh
python3 -m py_compile scripts/agent_ro_dispatch.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

CI runs the same checks on push and pull requests.

## Security notes

- ACL writes are opt-in (`APPLY_ACL=1`).
- Home secret paths are excluded from home ACL recursion.
- `/etc/ssh/ssh_host_*_key` files are excluded from ACL recursion and repaired to strict permissions.
- Denied commands return explicit `DENY: ...` reason messages.
