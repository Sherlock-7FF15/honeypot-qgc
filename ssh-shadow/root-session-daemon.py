#!/usr/bin/env python3
import fcntl
import json
import os
import socket
import struct
import subprocess
import termios
import traceback

SOCK_PATH = "/run/ssh-shadow/root-launch.sock"


def run_cmd(argv, env=None, pass_fds=None, stdin_fd=None, stdout_fd=None, stderr_fd=None, preexec_fn=None):
    proc = subprocess.Popen(
        argv,
        env=env,
        pass_fds=tuple(pass_fds or ()),
        stdin=stdin_fd if stdin_fd is not None else subprocess.DEVNULL,
        stdout=stdout_fd if stdout_fd is not None else subprocess.PIPE,
        stderr=stderr_fd if stderr_fd is not None else subprocess.PIPE,
        text=False,
        preexec_fn=preexec_fn,
    )
    if stdout_fd is None and stderr_fd is None:
        out, err = proc.communicate()
    else:
        proc.wait()
        out, err = b"", b""
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def recv_json_and_fds(conn):
    data = b""
    fds = []
    while b"\n" not in data:
        chunk, ancdata, _, _ = conn.recvmsg(65536, socket.CMSG_LEN(3 * struct.calcsize("i")))
        if not chunk:
            break
        data += chunk
        for level, ctype, cdata in ancdata:
            if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
                ints = array_from_bytes(cdata)
                fds.extend(ints)
    if not data:
        return None, []
    line = data.split(b"\n", 1)[0]
    return json.loads(line.decode("utf-8")), fds


def array_from_bytes(b):
    size = struct.calcsize("i")
    return [struct.unpack("i", b[i:i+size])[0] for i in range(0, len(b), size) if i + size <= len(b)]


def send_json(conn, obj):
    conn.sendall((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))


def handle(req, fds):
    action = req.get("action")
    launcher = "/opt/ssh-shadow/root-session-launch.sh"
    if action == "selftest":
        rc, out, err = run_cmd([launcher, "--selftest", req["session_rootfs"]])
        return {"ok": rc == 0, "rc": rc, "stdout": out, "stderr": err}
    if action == "prepare":
        rc, out, err = run_cmd([launcher, "--prepare-session-rootfs", req["base_root"], req["session_rootfs"], req["login_user"], req.get("session_dir", "")])
        return {"ok": rc == 0, "rc": rc, "stdout": out, "stderr": err}
    if action == "cleanup":
        rc, out, err = run_cmd([launcher, "--cleanup-session-rootfs", req["session_work_dir"]])
        return {"ok": rc == 0, "rc": rc, "stdout": out, "stderr": err}
    if action == "launch":
        if len(fds) < 3:
            return {"ok": False, "rc": 125, "stderr": "missing stdio file descriptors"}
        stdin_fd, stdout_fd, stderr_fd = fds[:3]
        tty_fd = None
        tty_path = req.get("tty_path")
        if tty_path:
            try:
                tty_fd = os.open(tty_path, os.O_RDWR | os.O_NOCTTY)
                stdin_fd = stdout_fd = stderr_fd = tty_fd
            except Exception:
                tty_fd = None
        env = {
            "HOME": req.get("home", f"/home/{req['login_user']}"),
            "USER": req["login_user"],
            "LOGNAME": req["login_user"],
            "PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
            "HONEYPOT_HOSTNAME": req.get("honeypot_hostname", "gcs-shadow"),
            "SESSION_DIR": "/tmp/ssh-shadow/session",
            "WORKSPACE": "/",
            "BASELINE_FILE": "/tmp/ssh-shadow/session/baseline_files.txt",
            "BASELINE_META": "/tmp/ssh-shadow/session/baseline_meta.json",
            "LOGIN_USER": req.get("login_user", ""),
            "SHADOW_WORKSPACE": "/",
            "SHADOW_LOGIN_USER": req.get("login_user", ""),
            "CMD_LOG": "/tmp/ssh-shadow/session/commands.jsonl",
            "SSH_SHADOW_SANDBOX": "1",
        }
        argv = [launcher, req["session_rootfs"], req["login_user"], *req.get("argv", [])]

        def preexec_attach_tty():
            try:
                os.setsid()
            except Exception:
                pass
            try:
                fcntl.ioctl(stdin_fd, termios.TIOCSCTTY, 0)
            except Exception:
                pass

        pass_fds = [stdin_fd, stdout_fd, stderr_fd]
        if tty_fd is not None:
            pass_fds.append(tty_fd)

        rc, _, _ = run_cmd(
            argv,
            env=env,
            pass_fds=pass_fds,
            stdin_fd=stdin_fd,
            stdout_fd=stdout_fd,
            stderr_fd=stderr_fd,
            preexec_fn=preexec_attach_tty,
        )
        if tty_fd is not None:
            try:
                os.close(tty_fd)
            except Exception:
                pass
        return {"ok": rc == 0, "rc": int(rc)}
    return {"ok": False, "rc": 2, "stderr": f"unknown action: {action}"}


def main():
    if os.path.exists(SOCK_PATH):
        os.unlink(SOCK_PATH)
    os.makedirs(os.path.dirname(SOCK_PATH), exist_ok=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK_PATH)
    os.chmod(SOCK_PATH, 0o660)
    try:
        import grp
        gid = grp.getgrnam("honeypot").gr_gid
        os.chown(SOCK_PATH, 0, gid)
    except Exception:
        pass
    srv.listen(64)

    while True:
        conn, _ = srv.accept()
        with conn:
            try:
                req, fds = recv_json_and_fds(conn)
                if req is None:
                    continue
                resp = handle(req, fds)
            except Exception as exc:
                resp = {"ok": False, "rc": 99, "stderr": f"daemon exception: {exc}\n{traceback.format_exc()}"}
            finally:
                for fd in (fds if 'fds' in locals() else []):
                    try:
                        os.close(fd)
                    except Exception:
                        pass
            send_json(conn, resp)


if __name__ == "__main__":
    main()
