# SSH Shadow profile

## Overview

The `ssh-shadow` profile adds a real OpenSSH endpoint that presents a shadow GCS workstation to attackers while isolating the live `qgc` runtime.

Components:

- `shadow-sync`: continuously mirrors selected live artifacts into `./shadow/base`.
- `ssh-shadow`: OpenSSH service (host `22` -> container `2222`) with a forced command wrapper that creates a per-session jail and runs trace/detection logic.

## Start / stop

```bash
SSH_SHADOW_HOST_PORT=2222 docker compose --profile ssh-shadow up -d --build shadow-sync ssh-shadow
```

Stop:

```bash
docker compose --profile ssh-shadow down
```

## Login

Single account:

- username: `gcs`
- password: `${SSH_SHADOW_PASSWORD:-gcs123!}`
- host port: `${SSH_SHADOW_HOST_PORT:-22}` (container always listens on `2222`)

Example:

```bash
ssh -p ${SSH_SHADOW_HOST_PORT:-22} gcs@<host-ip>
```

> Only one active interactive session is allowed. Additional connections receive a short "console busy" message and disconnect.

## Mirrored sources

`shadow-sync` mirrors into `./shadow/base`:

- `./qgc/data/Documents/QGroundControl` -> `./shadow/base/home/gcs/Documents/QGroundControl`
- `./qgc/data/.config` -> `./shadow/base/home/gcs/.config`
- `./qgc/data/.cache` -> `./shadow/base/home/gcs/.cache`
- `./logs/qgc` -> `./shadow/base/var/log/qgc`
- `./logs/mavproxy` -> `./shadow/base/var/log/mavproxy`

Timestamps are preserved using `rsync -a`.

## Session isolation model

For each accepted SSH session:

1. create `./shadow/sessions/<session_id>/workspace` from `./shadow/base`
2. build per-session jail root at `./shadow/jails/<session_id>/rootfs`
3. launch attacker shell via `proot -R <jail_root>` so `/` is jailed and `/shadow` is not visible

Attacker writes stay in the session workspace and do not modify `./qgc/data`.

## Logs and evidence

Per-session logs are stored under:

- `./logs/ssh-shadow/sessions/<session_id>/`

Pre-auth / failed-auth / scanning activity is stored separately in:

- `./logs/ssh-shadow/preauth.jsonl`

Artifacts include:

- `session.json` (metadata + termination reason)
- `tty.transcript` (TTY transcript)
- `commands.jsonl` (timestamped command + cwd)
- `events.jsonl` (structured security/session events)
- `strace*` (file/exec trace output)
- `evidence/file_hashes.json` and copied suspicious files

Pre-auth event types include:

- `connect`
- `banner_or_probe`
- `invalid_user`
- `auth_failed`
- `auth_success`
- `disconnect`

## Sensitive behavior policy

The trace agent detects and terminates session on sensitive behavior, including:

- `scp` / `sftp`
- downloaders: `wget`, `curl`, `tftp`
- `chmod +x`
- `python -c`, `bash -c`, `sh -c`
- `nc`/reverse-shell-like patterns
- newly created executable/suspicious script/binary files in workspace

On detection it records a structured event, captures file hashes and copies evidence, writes termination reason, and disconnects.

## Automated verifier

Run:

```bash
SSH_SHADOW_HOST_PORT=2222 ./scripts/verify_ssh_shadow.sh
```

The verifier checks:

1. compose config/build/up
2. mirror propagation into `./shadow/base`
3. qgc + ssh-shadow are up
4. single-session lock behavior
5. successful login in jailed root + expected paths
6. command/tty/trace logs
7. failed-auth and success events in `preauth.jsonl`
8. sensitive-command disconnect (`wget`)
9. workspace isolation from live `./qgc/data`
10. watcher still running

## Limitations / non-goals

- Process/service/network realism is lightweight (PATH wrappers for `ps`, `systemctl`, `ss`), not a full init-system emulation.
- This profile is designed for interaction capture and containment, not high-fidelity host emulation.
