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
MIN_BYTES = int(os.getenv("MIN_BYTES", "16"))                        # skip tiny noise files
MOD_COOLDOWN_SEC = float(os.getenv("MOD_COOLDOWN_SEC", "2.0"))        # debounce per path
HASH_ON_MODIFY = os.getenv("HASH_ON_MODIFY", "true").lower() == "true"
DEDUP_TTL_SEC = float(os.getenv("DEDUP_TTL_SEC", "300"))
MAX_TRACKED_PATHS = int(os.getenv("MAX_TRACKED_PATHS", "20000"))
SUMMARY_INTERVAL_SEC = float(os.getenv("SUMMARY_INTERVAL_SEC", "60"))

# ignore patterns (simple substring / prefix checks)
IGNORE_SUBSTRINGS = [
    "/qgc-data/tmp/qipc_",     # noisy QGC IPC artifacts
    "/qgc-data/tmp/.",
    "/qgc-data/Documents/QGroundControl/tmp",
    "/qgc-data/.cache/",
    "/qgc-data/.config/QGroundControl.org/QGroundControl/Cache",
]
IGNORE_SUFFIXES = [
    ".lock", ".tmp", ".swp", ".part",
    ".wal", ".shm", ".journal", ".db-wal", ".db-shm",
    ".png~", ".autosave",
    ".DS_Store", ".crdownload",
]

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
    day = time.strftime("%Y-%m-%d", time.gmtime(now_ts()))
    out_dir = UPLOAD_ROOT / day
    out_dir.mkdir(parents=True, exist_ok=True)
    base = os.path.basename(path) or "file"
    out_path = out_dir / f"{digest}_{base}"
    if not out_path.exists():
        shutil.copy2(path, out_path)
    return str(out_path)

class Handler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.last_handled = {}  # path -> ts
        self.last_saved = {}    # (path, mtime, size) -> ts
        self.last_digest = {}   # path -> digest
        self.stats = {"events": 0, "ignored": 0, "saved": 0, "errors": 0, "deduped": 0}
        self.last_summary = now_ts()

    def _debounced(self, path: str) -> bool:
        t = now_ts()
        last = self.last_handled.get(path, 0.0)
        if t - last < MOD_COOLDOWN_SEC:
            return True
        self.last_handled[path] = t
        if len(self.last_handled) > MAX_TRACKED_PATHS:
            cutoff = t - max(MOD_COOLDOWN_SEC * 10, 60.0)
            self.last_handled = {k: v for k, v in self.last_handled.items() if v >= cutoff}
        return False

    def _already_saved_recently(self, path: str, mtime: float, size: int) -> bool:
        key = (path, float(mtime), int(size))
        t = now_ts()
        last = self.last_saved.get(key, 0.0)
        self.last_saved[key] = t
        if len(self.last_saved) > MAX_TRACKED_PATHS:
            cutoff = t - DEDUP_TTL_SEC
            self.last_saved = {k: v for k, v in self.last_saved.items() if v >= cutoff}
        return (t - last) < DEDUP_TTL_SEC

    def _emit_summary_if_due(self):
        t = now_ts()
        if t - self.last_summary < SUMMARY_INTERVAL_SEC:
            return
        self.last_summary = t
        append_event({
            "event": "watcher_summary",
            "events": self.stats["events"],
            "ignored": self.stats["ignored"],
            "saved": self.stats["saved"],
            "errors": self.stats["errors"],
            "deduped": self.stats["deduped"],
            "tracked_recent": len(self.last_saved),
        })

    def _handle_file_event(self, op: str, src_path: str, dest_path: str | None = None):
        self.stats["events"] += 1
        if not src_path or should_ignore(src_path):
            self.stats["ignored"] += 1
            self._emit_summary_if_due()
            return
        if dest_path and should_ignore(dest_path):
            self.stats["ignored"] += 1
            self._emit_summary_if_due()
            return

        size, mtime = (None, None)
        if op != "deleted":
            size, mtime = safe_stat(dest_path or src_path)

        ev = {"event": "fs_event", "op": op, "path": src_path}
        if dest_path:
            ev["dest_path"] = dest_path
        if size is not None:
            ev["size"] = size
        if mtime is not None:
            ev["mtime"] = mtime

        if src_path.startswith("/qgc-data/"):
            ev["root_tag"] = "qgc-data"
        elif src_path.startswith("/qgc-logs/"):
            ev["root_tag"] = "qgc-logs"
        else:
            ev["root_tag"] = "other"

        append_event(ev)

        target = dest_path or src_path
        if op in ("created", "modified", "moved") and target and os.path.isfile(target):
            if op == "modified" and self._debounced(target):
                self.stats["deduped"] += 1
                self._emit_summary_if_due()
                return
            if not HASH_ON_MODIFY and op == "modified":
                self._emit_summary_if_due()
                return

            try:
                fsize = os.path.getsize(target)
                if fsize < MIN_BYTES or fsize > MAX_BYTES:
                    self.stats["ignored"] += 1
                    self._emit_summary_if_due()
                    return
                mtime = os.path.getmtime(target)
                if self._already_saved_recently(target, mtime, fsize):
                    self.stats["deduped"] += 1
                    self._emit_summary_if_due()
                    return
                mtime = os.path.getmtime(target)
                if self._already_saved_recently(target, mtime, fsize):
                    return
                digest = sha256_file(target)
                if self.last_digest.get(target) == digest:
                    self.stats["deduped"] += 1
                    self._emit_summary_if_due()
                    return
                self.last_digest[target] = digest
                if len(self.last_digest) > MAX_TRACKED_PATHS:
                    self.last_digest = dict(list(self.last_digest.items())[-MAX_TRACKED_PATHS:])

                stored = copy_out(target, digest)
                self.stats["saved"] += 1
                append_event({
                    "event": "artifact_saved",
                    "op": op,
                    "original_path": target,
                    "sha256": digest,
                    "size": fsize,
                    "stored_path": stored,
                })
            except Exception as e:
                self.stats["errors"] += 1
                append_event({"event": "watcher_error", "where": "copy_out", "path": target, "error": repr(e)})

        self._emit_summary_if_due()

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
        "min_bytes": MIN_BYTES,
        "max_bytes": MAX_BYTES,
        "mod_cooldown_sec": MOD_COOLDOWN_SEC,
        "hash_on_modify": HASH_ON_MODIFY,
        "dedup_ttl_sec": DEDUP_TTL_SEC,
        "max_tracked_paths": MAX_TRACKED_PATHS,
        "summary_interval_sec": SUMMARY_INTERVAL_SEC,
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
