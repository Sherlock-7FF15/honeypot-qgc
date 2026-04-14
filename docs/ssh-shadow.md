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

Password for all listed users:

- `${SSH_SHADOW_PASSWORD:-gcs123!}`

Optional user override (space-separated list):

- `SSH_SHADOW_USERS="gcs admin ubuntu ..."`

Example:

```bash
ssh -p ${SSH_SHADOW_HOST_PORT:-22} admin@<host-ip>
```

> Only one active interactive session is allowed. Additional connections receive a short `console busy` message and disconnect.

## Mirrored sources

`shadow-sync` mirrors into `./shadow/base`:

- `./qgc/data/Documents/QGroundControl` -> `./shadow/base/home/gcs/Documents/QGroundControl`
- `./qgc/data/.config` -> `./shadow/base/home/gcs/.config`
- `./qgc/data/.cache` -> `./shadow/base/home/gcs/.cache`
- `./logs/qgc` -> `./shadow/base/var/log/qgc`
- `./logs/mavproxy` -> `./shadow/base/var/log/mavproxy`

Timestamps are preserved with `rsync -a`.

## Session model (current proot jail)

For each accepted SSH session:

1. create `./shadow/jails/<session_id>/rootfs`
2. copy mirrored base data into that jail root
3. launch attacker shell through `proot -R <jail_root>`

This is the single session filesystem source of truth (legacy `active-workspace` logic removed). Attacker writes remain inside the session jail and do not modify `./qgc/data`.

## Logs and evidence

Successful sessions:

- `./logs/ssh-shadow/sessions/<session_id>/session.json`
- `./logs/ssh-shadow/sessions/<session_id>/tty.transcript`
- `./logs/ssh-shadow/sessions/<session_id>/commands.jsonl`
- `./logs/ssh-shadow/sessions/<session_id>/events.jsonl`
- `./logs/ssh-shadow/sessions/<session_id>/strace*`
- `./logs/ssh-shadow/sessions/<session_id>/evidence/*`

Pre-auth / scan / failed-auth activity:

- `./logs/ssh-shadow/preauth.jsonl`

Observed preauth event types:

- `connect`
- `banner_or_probe`
- `invalid_user`
- `auth_failed`
- `auth_success`
- `disconnect`

## Sensitive behavior policy

The trace agent terminates sessions on sensitive behavior, including:

- `scp` / `sftp`
- downloaders: `wget`, `curl`, `tftp`
- `chmod +x`
- inline execution: `python -c`, `bash -c`, `sh -c`
- reverse-shell-like patterns
- newly created executable/script/binary artifacts in the jailed workspace

On detection it records events, captures hashes/files to evidence, writes termination reason, and disconnects.

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
8. sensitive-command disconnect (`wget`)
9. session write isolation from live `./qgc/data`
10. watcher health check

## Limitations / non-goals

- Jailing currently uses `proot` for portability; this is not kernel `chroot` isolation.
- Process/service realism is lightweight (`fakebin` wrappers for `ps`, `systemctl`, `ss`).
- Designed for interaction capture and containment, not full host emulation.
