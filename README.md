# ssh-readonly-agent

Standalone kit to provision an SSH account (`agent_ro`) for read-only remote evidence collection.

## What it enforces

- SSH login for `agent_ro` via public key only.
- Non-interactive command execution only (no interactive shell, no TTY, no forwarding).
- Allowed commands only:
  - `find`
  - `rg`
  - `cat`
  - `ls`
  - `stat`
  - `git log`
  - `git show`
  - `grep -R` fallback if `rg` is missing
- Opt-in ACL grants (`rX`) when `APPLY_ACL=1` on these effective paths:
  - `/home/<invoking-user> /srv /opt /var/log /etc /var/lib/docker /mnt /data /media`
- Home secret-path exclusions are always enforced:
  - `.ssh .gnupg .aws .kube .docker .config/gcloud .local/share/keyrings .pki`

## Files

- `scripts/agent_ro_setup.sh` - idempotent setup/provision script.
- `scripts/agent_ro_verify.sh` - positive/negative SSH policy checks.
- `scripts/agent_ro_rollback.sh` - optional rollback/cleanup script.
- `docs/TROUBLESHOOTING.md` - common issues and fixes.

## Prerequisites

- Linux host with OpenSSH server.
- `sudo` access.
- Optional but recommended for ACL grants: `acl` package (`setfacl`).

## Quick Start

1. Copy this folder to the target host.
2. Edit `scripts/agent_ro_setup.sh` and set `PUBKEY='...'`.
3. Run setup (safe default, no ACL writes):

```bash
bash scripts/agent_ro_setup.sh
```

4. If you want ACL grants, enable them explicitly:

```bash
APPLY_ACL=1 bash scripts/agent_ro_setup.sh
```

5. Edit `scripts/agent_ro_verify.sh` and set `HOST='...'`.
6. Run verify from another machine:

```bash
bash scripts/agent_ro_verify.sh
```

## Useful run modes

Enable ACL writes:

```bash
APPLY_ACL=1 bash scripts/agent_ro_setup.sh
```

Skip ACL pass even when ACL is enabled:

```bash
APPLY_ACL=1 SKIP_ACL=1 bash scripts/agent_ro_setup.sh
```

Force ACL reapply:

```bash
APPLY_ACL=1 FORCE_ACL=1 bash scripts/agent_ro_setup.sh
```

Override detected home target:

```bash
HOME_TARGET=/home/samtheman bash scripts/agent_ro_setup.sh
```

Tune scanner timing in step 6:

```bash
SPIN_FRAME_INTERVAL_MS=240 SPIN_BLINK_HOLD_MS=1500 bash scripts/agent_ro_setup.sh
```

## Rollback

Base rollback (keeps user):

```bash
bash scripts/agent_ro_rollback.sh
```

Rollback + remove `agent_ro` user:

```bash
REMOVE_USER=1 bash scripts/agent_ro_rollback.sh
```

Rollback + remove ACL entries written by setup (can be slow):

```bash
REMOVE_ACLS=1 bash scripts/agent_ro_rollback.sh
```

## Security Notes

- Setup includes a safety guard that restores strict SSH host-key file perms (`600`) to avoid SSH daemon lockout.
- `/etc/ssh/ssh_host_*_key` is excluded from recursive ACL application.
- Home ACL recursion is scoped to the invoking user's home directory with strict secret-folder exclusions.
- If a filesystem does not support POSIX ACLs, setup will continue and report skipped paths.
