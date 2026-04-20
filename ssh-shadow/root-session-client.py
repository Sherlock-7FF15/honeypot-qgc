#!/usr/bin/env python3
import array
import json
import os
import socket
import sys

SOCK_PATH = "/run/ssh-shadow/root-launch.sock"


def send(req, pass_stdio=False):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK_PATH)
    payload = (json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8")
    if pass_stdio:
        fds = array.array("i", [0, 1, 2])
        s.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds.tobytes())])
    else:
        s.sendall(payload)
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    if not data:
        return {"ok": False, "rc": 98, "stderr": "empty response from root-session-daemon"}
    return json.loads(data.decode("utf-8").strip())


def main():
    if len(sys.argv) < 2:
        print("usage: root-session-client.py {selftest|prepare|cleanup|launch} ...", file=sys.stderr)
        return 2

    action = sys.argv[1]
    if action == "selftest":
        req = {"action": "selftest", "session_rootfs": sys.argv[2]}
        resp = send(req)
    elif action == "prepare":
        session_dir = os.environ.get("SESSION_DIR", "")
        req = {
            "action": "prepare",
            "base_root": sys.argv[2],
            "session_rootfs": sys.argv[3],
            "login_user": sys.argv[4],
            "session_dir": session_dir,
        }
        resp = send(req)
    elif action == "cleanup":
        req = {"action": "cleanup", "session_work_dir": sys.argv[2]}
        resp = send(req)
    elif action == "launch":
        if len(sys.argv) < 5:
            print("usage: root-session-client.py launch <session_rootfs> <login_user> <cmd> [args...]", file=sys.stderr)
            return 2
        tty_path = os.environ.get("SSH_TTY") or None
        if not tty_path:
            try:
                tty_path = os.ttyname(0)
            except Exception:
                tty_path = None
        req = {
            "action": "launch",
            "session_rootfs": sys.argv[2],
            "login_user": sys.argv[3],
            "argv": sys.argv[4:],
            "home": f"/home/{sys.argv[3]}",
            "honeypot_hostname": os.environ.get("HONEYPOT_HOSTNAME", "gcs-shadow"),
            "session_dir": os.environ.get("SESSION_DIR", ""),
            "workspace": "/",
            "baseline_file": "/tmp/ssh-shadow/session/baseline_files.txt",
            "baseline_meta": "/tmp/ssh-shadow/session/baseline_meta.json",
            "shadow_workspace": "/",
            "cmd_log": "/tmp/ssh-shadow/session/commands.jsonl",
            "tty_path": tty_path,
        }
        resp = send(req, pass_stdio=True)
    else:
        print(f"unknown action: {action}", file=sys.stderr)
        return 2

    if not resp.get("ok"):
        msg = resp.get("stderr") or resp.get("stdout") or "request failed"
        if msg:
            print(msg, file=sys.stderr)
        rc = resp.get("rc", 1)
        try:
            return int(1 if rc is None else rc)
        except Exception:
            return 1

    out = resp.get("stdout")
    if out:
        print(out, end="")
    rc = resp.get("rc", 0)
    try:
        return int(0 if rc is None else rc)
    except Exception:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
