import re
import subprocess
import sys
from pathlib import Path

NOISE_PATTERNS = [
    re.compile(r"^no script honeypot/mavinit\.scr$", re.IGNORECASE),
    re.compile(r"^waiting for heartbeat from 0\.0\.0\.0:\d+$", re.IGNORECASE),
    re.compile(r"^link \d+ down$", re.IGNORECASE),
    re.compile(r"^link \d+ no link$", re.IGNORECASE),
]


def is_noise(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return any(pattern.match(stripped) for pattern in NOISE_PATTERNS)


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: run_logged.py <logfile> <command> [args...]", file=sys.stderr)
        return 2

    log_path = Path(sys.argv[1])
    cmd = sys.argv[2:]
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as log_file:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        assert proc.stdout is not None
        for line in proc.stdout:
            if is_noise(line):
                continue
            log_file.write(line)
            log_file.flush()

        return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
