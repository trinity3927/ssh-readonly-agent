# Troubleshooting

## `DENY: missing policy file` or policy parse errors

Symptom:
- Commands via `agent_ro` are denied with policy load errors.

Checks:

```bash
sudo ls -l /etc/agent-ro/policy.json
sudo sed -n '1,220p' /etc/agent-ro/policy.json
sudo python3 -m json.tool /etc/agent-ro/policy.json >/dev/null
```

Fix:
- Re-run setup to regenerate policy and manifest:

```bash
./scripts/agent_ro_setup.sh 'ssh-ed25519 AAAA... comment'
```

## SSH handshake/reset issues after ACL operations

Symptom:
- `kex_exchange_identification: read: Connection reset by peer`

Likely cause:
- SSH host private key permissions drifted.

Fix:

```bash
sudo setfacl -b /etc/ssh/ssh_host_*_key
sudo chown root:root /etc/ssh/ssh_host_*_key
sudo chmod 600 /etc/ssh/ssh_host_*_key
sudo sshd -t
sudo systemctl restart sshd || sudo systemctl restart ssh
```

## `sshd -t` fails during setup

Checks:

```bash
sudo sshd -t
sudo ls -l /etc/ssh/sshd_config.d/
sudo sed -n '1,220p' /etc/ssh/sshd_config
sudo sed -n '1,220p' /etc/ssh/sshd_config.d/90-agent-ro.conf
```

Notes:
- Setup prefers drop-in config when `/etc/ssh/sshd_config.d/*.conf` is included.
- Otherwise it writes a managed block in `/etc/ssh/sshd_config`.

## Setup skips roots as invalid

Symptom:
- Setup warns a root is skipped.

Cause:
- Root is not an absolute path, does not exist, or is not a directory.

Fix:
- Provide valid absolute directories via `--extra-root`, `ALLOWED_ROOTS`, or `EXTRA_ALLOWED_ROOTS`.

## ACL apply is slow

Cause:
- Recursive ACL writes across large trees are I/O heavy.

Options:

```bash
# keep ACL disabled (default)
./scripts/agent_ro_setup.sh 'ssh-ed25519 AAAA... comment'

# enable only when needed
APPLY_ACL=1 ./scripts/agent_ro_setup.sh 'ssh-ed25519 AAAA... comment'
```

## `setfacl: Operation not supported`

Cause:
- Target filesystem does not support POSIX ACLs.

Behavior:
- ACL step reports skips/failures; setup still completes.

Action:
- Accept skip for unsupported filesystems or remove those roots from allowlist.

## Verify script failures

Checks:

```bash
./scripts/agent_ro_verify.sh <host>
sudo ls -l /usr/local/sbin/agent_ro_dispatch.py
sudo sed -n '1,220p' /etc/agent-ro/policy.json
```

Common causes:
- Wrong host/key pair used from client.
- Policy roots do not include expected paths.
- `rg` not installed (verify falls back to `grep -R`).

## Rollback did not remove old ACLs from legacy installs

Cause:
- Manifest-based ACL cleanup only removes ACL entries recorded in touched-path manifests.
- Very old installs may not have those manifests.

Action:
- Run rollback with explicit legacy sweep (broad operation):

```bash
./scripts/agent_ro_rollback.sh --legacy-acl-sweep
```

Use this only when required.
