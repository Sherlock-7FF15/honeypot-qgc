# SSH Shadow profile

## Overview

The `ssh-shadow` profile adds a real OpenSSH endpoint that presents a shadow GCS workstation to attackers while isolating the live `qgc` runtime.

Components:

- `shadow-sync`: continuously mirrors selected live artifacts into `./shadow/base`.
- `ssh-shadow`: OpenSSH service (host `22` -> container `2222`) with a forced command wrapper that creates a per-session workspace and runs trace/detection logic.

## Start / stop

```bash
docker compose --profile ssh-shadow up -d --build shadow-sync ssh-shadow
```

Stop:

```bash
docker compose --profile ssh-shadow down
```

## Login

Single account:

- username: `gcs`
- password: `${SSH_SHADOW_PASSWORD:-gcs123!}`

Example:

```bash
ssh gcs@<host-ip>
```

> Only one active interactive session is allowed. Additional connections receive a short "console busy" message and disconnect.

## Mirrored sources

`shadow-sync` mirrors into `./shadow/base`:

- `./qgc/data` -> `./shadow/base/home/gcs/Documents/QGroundControl`
- `./logs/qgc` -> `./shadow/base/var/log/qgc`
- `./logs/mavproxy` -> `./shadow/base/var/log/mavproxy`

Timestamps are preserved using `rsync -a`.

## Session isolation model

For each accepted SSH session:

1. create `./shadow/sessions/<session_id>/workspace`
2. copy `./shadow/base` into that workspace
3. launch the attacker shell in that per-session workspace

Attacker writes stay in the session workspace and do not modify `./qgc/data`.

## Logs and evidence

Per-session logs are stored under:

- `./logs/ssh-shadow/sessions/<session_id>/`

Artifacts include:

- `session.json` (metadata + termination reason)
- `tty.transcript` (TTY transcript)
- `commands.jsonl` (timestamped command + cwd)
- `events.jsonl` (structured security/session events)
- `strace*` (file/exec trace output)
- `evidence/file_hashes.json` and copied suspicious files

## Sensitive behavior policy

The trace agent detects and terminates session on sensitive behavior, including:

- `scp` / `sftp`
- downloaders: `wget`, `curl`, `tftp`
- `chmod +x`
- `python -c`, `bash -c`, `sh -c`
- `nc`/reverse-shell-like patterns
- newly created executable/suspicious script/binary files in workspace

On detection it records a structured event, captures file hashes and copies evidence, writes termination reason, and disconnects.

## Limitations / non-goals

- Process/service/network realism is lightweight (PATH wrappers for `ps`, `systemctl`, `ss`), not a full init-system emulation.
- This profile is designed for interaction capture and containment, not high-fidelity host emulation.
