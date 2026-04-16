# SSH Shadow profile

## Overview

The `ssh-shadow` profile exposes a real OpenSSH endpoint that presents a shadow GCS workstation to attackers while isolating live runtime state.

Components:

- `shadow-sync`: continuously mirrors selected live artifacts into `./shadow/base`.
- `ssh-shadow`: OpenSSH service (host `22` -> container `2222`) with a forced-command wrapper that creates a **per-session jail root** and runs trace/detection logic.

## Start / stop

```bash
SSH_SHADOW_HOST_PORT=2222 docker compose --profile ssh-shadow up -d --build shadow-sync ssh-shadow
```

Stop:

```bash
docker compose --profile ssh-shadow down
```

## Login

Weak-credential usernames (all mapped to the same shadow workflow):

- `gcs`, `admin`, `ubuntu`, `pi`, `support`, `operator`, `guest`, `test`

Per-user weak credentials (default):

- `gcs:gcs123!`
- `admin:admin`
- `ubuntu:ubuntu`
- `pi:raspberry`
- `support:support`
- `operator:operator`
- `guest:guest`
- `test:test`

Optional override (space-separated `user:pass` pairs):

- `SSH_SHADOW_CREDENTIALS="gcs:gcs123! admin:admin ..."`

Example:

```bash
ssh -p ${SSH_SHADOW_HOST_PORT:-22} admin@<host-ip>
```

> Only one active interactive session is allowed. Additional connections receive a short `console busy` message and disconnect.

### SSH exec semantics

- If `SSH_ORIGINAL_COMMAND` is present (for example `ssh admin@host "uname -a"`), `ssh-shadow` now runs a non-interactive exec path and returns real stdout/stderr + exit code from `/bin/bash -lc "<command>"`.
- If `SSH_ORIGINAL_COMMAND` is empty, `ssh-shadow` starts the interactive shell path.
- Host identity is set at runtime/container level (`hostname` + `/etc/hostname`) to `gcs-shadow` by default, and `fakebin` shims keep command output consistent for common probes.

## Mirrored sources

`shadow-sync` mirrors into `./shadow/base`:

- `./qgc/data/Documents/QGroundControl` -> `./shadow/base/home/gcs/Documents/QGroundControl`
- `./qgc/data/.config` -> `./shadow/base/home/gcs/.config`
- `./qgc/data/.cache` -> `./shadow/base/home/gcs/.cache`
- `./logs/qgc` -> `./shadow/base/var/log/qgc`
- `./logs/mavproxy` -> `./shadow/base/var/log/mavproxy`

Timestamps are preserved with `rsync -a`. Shadow sync excludes known noisy/transient cache paths (`mesa_shader_cache`, `gstreamer-1.0`, etc.) to avoid permission/churn failures during session startup.

## Session model (current workspace projection)

For each accepted SSH session:

1. create `./shadow/sessions/<session_id>/workspace` from a **light subset** of mirrored base data
2. only copy required session data (`Documents/QGroundControl`, `.config`, sanitized `.cache`, qgc/mavproxy logs)
3. project `/home/<user>/Documents/QGroundControl` to the per-session workspace path and map common absolute read paths via `fakebin` wrappers (for example `find /home/<user>/Documents/QGroundControl` and `ls /var/log/qgc`)
4. expose `/var/log/qgc` and `/var/log/mavproxy` via stable symlinks to `/shadow/base/var/log/...` (read-focused workstation view)
5. launch interactive shell directly (no `proot`) for Docker/seccomp reliability
6. non-interactive SSH exec requests use the same session workspace but run via `exec-original-command.sh` (not the interactive shell wrapper)

This removes the failing `proot`/`ptrace` dependency and avoids heavy full-tree login-time cloning.

## Logs and evidence

Successful sessions:

- `./logs/ssh-shadow/sessions/<session_id>/session.json`
- `./logs/ssh-shadow/sessions/<session_id>/tty.transcript`
- `./logs/ssh-shadow/sessions/<session_id>/commands.jsonl`
- `./logs/ssh-shadow/sessions/<session_id>/events.jsonl`
- `./logs/ssh-shadow/sessions/<session_id>/strace*`
- `./logs/ssh-shadow/sessions/<session_id>/evidence/*`
- `./logs/ssh-shadow/sessions/<session_id>/diff/diff_summary.json`
- `./logs/ssh-shadow/sessions/<session_id>/diff/files/...` (only created/modified files)

Session workspaces are **not retained** after session end. `ssh-shadow` captures diff/evidence artifacts and then removes `shadow/sessions/<session_id>` (and any matching `shadow/jails/<session_id>` path if present) to avoid disk bloat.

Pre-auth / scan / failed-auth activity:

- `./logs/ssh-shadow/preauth.jsonl`

Observed preauth event types:

- `connect`
- `banner_or_probe`
- `invalid_user`
- `auth_failed`
- `auth_success`
- `auth_attempt` (when sshd emits userauth-request lines)
- `disconnect`

## Sensitive behavior policy

The trace agent now uses staged policy signals:

- `suspicious` events (observe only): `scp` / `sftp`, downloaders (`wget`, `curl`, `tftp`, `nc`), `chmod +x`, inline `*-c`, reverse-shell-like syntax
- `payload_captured` (terminate): attacker-provenance artifacts only (downloaded/dropped via shell command provenance) in attacker-controlled paths such as `home/<user>`, `tmp`, `var/tmp`, `opt`
- payload confidence requires provenance (`download` or `shell_create`) plus preparation/execution context (`chmod +x` or execution), not just new-file heuristics
- hard exclusions for payload logic: `home/<user>/.cache/**`, `var/log/**` (including qgc/mavproxy), `*.stdout`, `*.stderr`, ffmpeg log churn
- `idle_timeout` (terminate): interactive shell inactivity timeout via `TMOUT`

On high-confidence payload capture or idle timeout, `ssh-shadow` writes `termination_reason`, records events, and captures evidence hashes/files.


## Fake sudo / fake root behavior

`ssh-shadow` now exposes a session-local fake privilege escalation surface:

- `sudo -l` returns plausible NOPASSWD output
- `sudo su -`, `sudo -s`, `sudo bash`, `sudo sh -c ...` enter/execute in fake-root mode
- fake-root identity surface: `whoami -> root`, `id -> uid=0(root) gid=0(root) groups=0(root)`, root-style prompt
- root-sensitive writes are mapped into session workspace only (`/root/**`, `/etc/ssh/sshd_config`, `/etc/crontab`, fake service state)
- service operations (`systemctl`, `service`, `pkill -HUP sshd`) update session-local fake state and do not affect container init/services

This does **not** grant real root or real sudo privileges.

## Automated verifier

Run:

```bash
SSH_SHADOW_HOST_PORT=2222 ./scripts/verify_ssh_shadow.sh
```

Verifier coverage:

1. compose config/build/up
2. mirror propagation into `./shadow/base`
3. `qgc` + `ssh-shadow` availability
4. single-session lock behavior
5. successful jail login for multiple weak usernames
6. command/tty/trace logs
7. preauth auth-failure + auth-success logging
8. payload-capture disconnect (for example create + chmod executable script in `/tmp`)
9. session write isolation from live `./qgc/data`
10. watcher health check

## Limitations / non-goals

- Isolation currently uses per-session workspace projection (not kernel `chroot` and not `proot`).
- Process/service realism is lightweight (`fakebin` wrappers for `ps`, `systemctl`, `ss`).
- Designed for interaction capture and containment, not full host emulation.
