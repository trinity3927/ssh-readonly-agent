# Troubleshooting

## SSH reset or handshake failure after setup

Symptom:
- `kex_exchange_identification: read: Connection reset by peer`

Likely cause:
- Host private key permissions are too open.

Fix:

```bash
sudo setfacl -b /etc/ssh/ssh_host_*_key
sudo chown root:root /etc/ssh/ssh_host_*_key
sudo chmod 600 /etc/ssh/ssh_host_*_key
sudo sshd -t
sudo systemctl restart ssh || sudo systemctl restart ssh.socket
```

## Step 6 feels stuck

Cause:
- ACL recursion over large trees (especially `/var/lib/docker`, `/mnt`) is I/O heavy.

Options:

```bash
bash scripts/agent_ro_setup.sh
```

Enable ACL writes only when needed:

```bash
APPLY_ACL=1 bash scripts/agent_ro_setup.sh
```

Force reapply explicitly:

```bash
APPLY_ACL=1 FORCE_ACL=1 bash scripts/agent_ro_setup.sh
```

## `setfacl: Operation not supported`

Cause:
- Target filesystem does not support POSIX ACLs.

Behavior:
- Script continues and reports skipped paths.

Action:
- Accept the skip for those mount points, or remove unsupported paths from `ALLOWED_DIRS` in setup script.

## `sshd -t` fails on setup

Check syntax and includes:

```bash
sudo sshd -t
sudo ls -l /etc/ssh/sshd_config.d/
sudo sed -n '1,200p' /etc/ssh/sshd_config.d/90-agent-ro.conf
```

## Verify script denies everything

Check that you used the right key and host:
- `PUBKEY` in `agent_ro_setup.sh` must be the agent public key.
- `HOST` in `agent_ro_verify.sh` must resolve/reach the target host.

Also verify the forced command exists:

```bash
sudo ls -l /usr/local/sbin/agent_ro_dispatch.py
```

## Local SSH private key became unreadable by SSH

Symptom:
- `Permissions 0640 for '/home/<user>/.ssh/id_ed25519' are too open.`

Cause:
- ACL or mode drift on private keys.

Fix current user quickly:

```bash
setfacl -Rb ~/.ssh
chmod 700 ~/.ssh
find ~/.ssh -maxdepth 1 -type f -name 'id_*' ! -name '*.pub' -exec chmod 600 {} +
find ~/.ssh -maxdepth 1 -type f -name '*.pub' -exec chmod 644 {} +
```

Prevention in this kit:
- ACL writes are opt-in (`APPLY_ACL=1`).
- Home ACL recursion is limited to the invoking user home and excludes secret directories.
