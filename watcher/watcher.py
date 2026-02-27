import os
import time
import json
import hashlib
import shutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- config ---
LOG_FILE = Path(os.getenv("WATCHER_LOG", "/logs/watcher/events.fs.jsonl"))
UPLOAD_ROOT = Path(os.getenv("UPLOAD_ROOT", "/uploads/fs"))
WATCH_DIRS = [p for p in os.getenv("WATCH_DIRS", "/qgc-data/Documents/QGroundControl:/qgc-data/tmp").split(":") if p]

MAX_BYTES = int(os.getenv("MAX_BYTES", str(50 * 1024 * 1024)))        # 50MB
MOD_COOLDOWN_SEC = float(os.getenv("MOD_COOLDOWN_SEC", "2.0"))        # debounce per path
HASH_ON_MODIFY = os.getenv("HASH_ON_MODIFY", "true").lower() == "true"

# ignore patterns (simple substring / prefix checks)
IGNORE_SUBSTRINGS = [
    "/qgc-data/tmp/qipc_",     # noisy QGC IPC artifacts
    "/qgc-data/tmp/.",
    "/qgc-data/Documents/QGroundControl/tmp",
]
IGNORE_SUFFIXES = [".lock", ".tmp", ".swp", ".part"]

def now_ts() -> float:
    return time.time()

def append_event(obj: dict):
    obj.setdefault("ts", now_ts())
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def should_ignore(path: str) -> bool:
    p = path or ""
    for s in IGNORE_SUBSTRINGS:
        if s in p:
            return True
    for suf in IGNORE_SUFFIXES:
        if p.endswith(suf):
            return True
    return False

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_stat(path: str):
    try:
        st = os.stat(path)
        return st.st_size, st.st_mtime
    except Exception:
        return None, None

def copy_out(path: str, digest: str) -> str:
    # store under date directory
    day = time.strftime("%Y-%m-%d", time.gmtime(now_ts()))
    out_dir = UPLOAD_ROOT / day
    out_dir.mkdir(parents=True, exist_ok=True)
    base = os.path.basename(path) or "file"
    out_path = out_dir / f"{digest}_{base}"

    # de-dup by sha+basename; if exists, don't overwrite
    if not out_path.exists():
        shutil.copy2(path, out_path)
    return str(out_path)

class Handler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.last_handled = {}  # path -> ts

    def _debounced(self, path: str) -> bool:
        t = now_ts()
        last = self.last_handled.get(path, 0.0)
        if t - last < MOD_COOLDOWN_SEC:
            return True
        self.last_handled[path] = t
        return False

    def _handle_file_event(self, op: str, src_path: str, dest_path: str | None = None):
        if not src_path or should_ignore(src_path):
            return
        if dest_path and should_ignore(dest_path):
            return

        # record base event
        size, mtime = (None, None)
        if op != "deleted":
            size, mtime = safe_stat(dest_path or src_path)

        ev = {
            "event": "fs_event",
            "op": op,
            "path": src_path,
        }
        if dest_path:
            ev["dest_path"] = dest_path
        if size is not None:
            ev["size"] = size
        if mtime is not None:
            ev["mtime"] = mtime

        # tag root for easier analysis
        if src_path.startswith("/qgc-data/"):
            ev["root_tag"] = "qgc-data"
        elif src_path.startswith("/qgc-logs/"):
            ev["root_tag"] = "qgc-logs"
        else:
            ev["root_tag"] = "other"

        append_event(ev)

        # copy-out logic for created/modified/moved (destination)
        target = dest_path or src_path
        if op in ("created", "modified", "moved") and target and os.path.isfile(target):
            # debounce modified spam
            if op == "modified" and self._debounced(target):
                return

            if not HASH_ON_MODIFY and op == "modified":
                return

            try:
                fsize = os.path.getsize(target)
                if fsize <= 0 or fsize > MAX_BYTES:
                    return
                digest = sha256_file(target)
                stored = copy_out(target, digest)
                append_event({
                    "event": "artifact_saved",
                    "op": op,
                    "original_path": target,
                    "sha256": digest,
                    "size": fsize,
                    "stored_path": stored,
                })
            except Exception as e:
                append_event({
                    "event": "watcher_error",
                    "where": "copy_out",
                    "path": target,
                    "error": repr(e),
                })

    # watchdog callbacks
    def on_created(self, event):
        if event.is_directory:
            return
        self._handle_file_event("created", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle_file_event("modified", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._handle_file_event("deleted", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self._handle_file_event("moved", event.src_path, event.dest_path)

def main():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

    append_event({
        "event": "watcher_start",
        "watch_dirs": WATCH_DIRS,
        "max_bytes": MAX_BYTES,
        "mod_cooldown_sec": MOD_COOLDOWN_SEC,
        "hash_on_modify": HASH_ON_MODIFY,
    })

    observer = Observer()
    handler = Handler()

    for d in WATCH_DIRS:
        if not d:
            continue
        if not os.path.exists(d):
            append_event({"event": "watcher_warn", "msg": f"watch dir not found: {d}"})
            continue
        observer.schedule(handler, d, recursive=True)
        append_event({"event": "watching", "path": d})

    observer.start()
    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join(timeout=5)

if __name__ == "__main__":
    main()
