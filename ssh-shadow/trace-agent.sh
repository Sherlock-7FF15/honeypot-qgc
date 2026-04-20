#!/usr/bin/env bash
set -euo pipefail

SESSION_DIR="${SESSION_DIR:?}"
WORKSPACE="${WORKSPACE:?}"
BASELINE_FILE="${BASELINE_FILE:?}"
LOGIN_USER="${LOGIN_USER:-admin}"

EVENTS_FILE="${SESSION_DIR}/events.jsonl"
TERM_FILE="${SESSION_DIR}/termination_reason.txt"
EVIDENCE_DIR="${SESSION_DIR}/evidence"
PROVENANCE_FILE="${SESSION_DIR}/provenance.json"

log_event() {
  local event_name="$1"
  local detail="${2:-}"
  local extra="${3:-{}}"
  local ts
  ts="$(date -u +%s.%N)"
  python3 - <<'PY' "$EVENTS_FILE" "$ts" "$event_name" "$detail" "$extra"
import json,sys
path,ts,name,detail,extra = sys.argv[1:]
obj={"ts":float(ts),"event":name,"detail":detail}
try:
    obj.update(json.loads(extra))
except Exception:
    obj["extra_raw"]=extra
with open(path,"a",encoding="utf-8") as f:
    f.write(json.dumps(obj,ensure_ascii=False)+"\n")
PY
}

capture_evidence() {
  mkdir -p "$EVIDENCE_DIR/files"
  python3 - <<'PY' "$WORKSPACE" "$BASELINE_FILE" "$EVIDENCE_DIR"
import sys,hashlib,json,shutil
from pathlib import Path
workspace=Path(sys.argv[1])
baseline=Path(sys.argv[2])
ev=Path(sys.argv[3])
known=set()
if baseline.exists():
    for line in baseline.read_text(encoding='utf-8',errors='replace').splitlines():
        if line.strip():
            known.add(line.strip())

login_user = "${LOGIN_USER}"

def excluded(rel: str) -> bool:
    lower=rel.lower()
    if rel.startswith('var/log/'):
        return True
    if rel.startswith(f'home/{login_user}/.cache/'):
        return True
    if '/.cache/' in rel:
        return True
    if lower.endswith('.stdout') or lower.endswith('.stderr'):
        return True
    if 'ffmpeg' in lower and 'log' in lower:
        return True
    return False

rows=[]
for p in workspace.rglob('*'):
    if not p.is_file():
        continue
    rel=str(p.relative_to(workspace))
    if excluded(rel):
        continue
    st=p.stat()
    is_new=rel not in known
    is_exe=bool(st.st_mode & 0o111)
    suspicious_suffix=rel.endswith(('.sh','.py','.elf','.bin'))
    with p.open('rb') as f:
        head=f.read(4)
    is_elf=head==b'\x7fELF'
    if is_new or is_exe or suspicious_suffix or is_elf:
        h=hashlib.sha256()
        with p.open('rb') as f:
            for ch in iter(lambda:f.read(1024*1024),b''):
                h.update(ch)
        rows.append({"path":rel,"sha256":h.hexdigest(),"size":st.st_size,"is_new":is_new,"is_executable":is_exe,"is_elf":is_elf})
        out=ev/"files"/rel
        out.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(p,out)
(ev/"file_hashes.json").write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
PY
}

terminate_with_reason() {
  local reason="$1"
  log_event "payload_captured" "$reason" '{"severity":"high","action":"terminate"}'
  capture_evidence || true
  echo "$reason" > "$TERM_FILE"
  return 99
}

update_provenance_from_command() {
  local cmd="$1"
  local cwd="$2"
  python3 - <<'PY' "$PROVENANCE_FILE" "$cmd" "$cwd" "$LOGIN_USER"
import json,shlex,sys,time,re
from pathlib import PurePosixPath

prov_path,cmd,cwd,login_user = sys.argv[1:]
now=time.time()

try:
    data=json.loads(open(prov_path,'r',encoding='utf-8').read())
except Exception:
    data={"files":{}}
files=data.setdefault("files",{})

EXCLUDED_PREFIXES=("var/log/", f"home/{login_user}/.cache/")
ALLOWED_PREFIXES=("tmp/","var/tmp/",f"home/{login_user}/", "opt/")


def canonical_rel(path_token: str, base_cwd: str=None):
    if not path_token:
        return None
    p=path_token.strip().strip("'\"")
    if not p or p in {"-",">",">>","<"}:
        return None
    p=p.split("\n")[0].strip()
    if p.startswith("~"):
        p=f"/home/{login_user}/" + p[2:] if p.startswith("~/") else f"/home/{login_user}"
    if p.startswith("/"):
        abs_p=PurePosixPath(p)
    else:
        abs_p=PurePosixPath(base_cwd or cwd) / p
    rel=str(abs_p).lstrip("/")
    rel=str(PurePosixPath(rel))
    if rel=="." or rel.startswith("../"):
        return None
    if any(rel.startswith(x) for x in EXCLUDED_PREFIXES):
        return None
    if not any(rel.startswith(x) for x in ALLOWED_PREFIXES):
        return None
    return rel


def tag(rel: str, kind: str):
    if not rel:
        return
    rec=files.setdefault(rel,{"path":rel,"first_seen":now,"source":None,"downloaded":False,"created":False,"executed":False,"chmod_x":False,"commands":[]})
    rec["last_seen"]=now
    if cmd not in rec["commands"]:
        rec["commands"].append(cmd)
        rec["commands"]=rec["commands"][-8:]
    if kind=="download":
        rec["source"]="download"
        rec["downloaded"]=True
    elif kind=="create":
        if rec.get("source") is None:
            rec["source"]="shell_create"
        rec["created"]=True
    elif kind=="chmod_x":
        rec["chmod_x"]=True
    elif kind=="execute":
        rec["executed"]=True

# command-level suspicious signals (observe-only)
obs=[]
if re.search(r'(^|\s)(scp|sftp|wget|curl|tftp|nc|ncat)(\s|$)', cmd):
    obs.append("network_tool")
if re.search(r'chmod\s+\+x', cmd):
    obs.append("chmod_plus_x")
if re.search(r'(python|python3|bash|sh)\s+-c\s', cmd):
    obs.append("inline_exec")
if re.search(r'(/dev/tcp|reverse|bash\s+-i)', cmd):
    obs.append("reverse_shell_like")

def resolve_abs(path_token: str, base_cwd: str):
    p=path_token.strip().strip("'\"")
    if p.startswith("~"):
        p=f"/home/{login_user}/" + p[2:] if p.startswith("~/") else f"/home/{login_user}"
    if p.startswith("/"):
        return str(PurePosixPath(p))
    return str(PurePosixPath(base_cwd) / p)

segments=[seg.strip() for seg in re.split(r'\s*(?:&&|;|\|\|)\s*', cmd) if seg.strip()]
current_cwd=cwd

for seg in segments:
    m_cd=re.match(r'^cd\s+([^\s;&|]+)$', seg)
    if m_cd:
        try:
            current_cwd=resolve_abs(m_cd.group(1), current_cwd)
        except Exception:
            pass
        continue

    try:
        tokens=shlex.split(seg, posix=True)
    except Exception:
        tokens=seg.split()

    # download destinations
    for i,t in enumerate(tokens):
        if t in {"wget","curl"}:
            if "-O" in tokens[i+1:]:
                j=tokens.index("-O", i+1)
                if j+1 < len(tokens):
                    tag(canonical_rel(tokens[j+1].strip(), current_cwd),"download")
            if "-o" in tokens[i+1:]:
                j=tokens.index("-o", i+1)
                if j+1 < len(tokens):
                    tag(canonical_rel(tokens[j+1].strip(), current_cwd),"download")
        if t == "tftp" and "-l" in tokens[i+1:]:
            j=tokens.index("-l", i+1)
            if j+1 < len(tokens):
                tag(canonical_rel(tokens[j+1].strip(), current_cwd),"download")
        if t in {"scp","sftp"} and i+1 < len(tokens):
            tag(canonical_rel(tokens[-1].strip(), current_cwd),"download")

    # redirection / heredoc / tee creates
    for m in re.finditer(r'(?:^|\s)(?:>|>>|1>|2>|&>|\|\s*tee\s+|tee\s+)-?a?\s*([^\s;&|]+)', seg):
        tag(canonical_rel(m.group(1).strip(), current_cwd),"create")
    for m in re.finditer(r'<<\s*([A-Za-z0-9_\-]+).*?>\s*([^\s;&|]+)', seg):
        tag(canonical_rel(m.group(2).strip(), current_cwd),"create")

    # chmod +x file tracking
    for m in re.finditer(r'chmod\s+\+x\s+([^\s;&|]+)', seg):
        tag(canonical_rel(m.group(1).strip(), current_cwd),"chmod_x")

    # execution tracking (direct path execution + interpreter file)
    for i,t in enumerate(tokens):
        if t in {"bash","sh","python","python3","perl","ruby"} and i+1 < len(tokens):
            tag(canonical_rel(tokens[i+1].strip(), current_cwd),"execute")
        if t.startswith("./") or t.startswith("/"):
            tag(canonical_rel(t.strip(), current_cwd),"execute")

open(prov_path,'w',encoding='utf-8').write(json.dumps(data,ensure_ascii=False,indent=2))
print(json.dumps({"observe":obs}))
PY
}

check_sensitive_command() {
  local cmd="$1"
  local cwd="${2:-/home/${LOGIN_USER}}"
  local obs_json
  obs_json="$(update_provenance_from_command "$cmd" "$cwd")"
  python3 - <<'PY' "$obs_json" "$cmd" "$EVENTS_FILE"
import json,sys,time
obs_json,cmd,events=sys.argv[1:]
try:
    obs=json.loads(obs_json).get("observe",[])
except Exception:
    obs=[]
for marker in obs:
    obj={"ts":time.time(),"event":"suspicious","detail":f"{marker}:{cmd}","severity":"medium","action":"observe"}
    with open(events,"a",encoding="utf-8") as f:
        f.write(json.dumps(obj,ensure_ascii=False)+"\n")
PY
  return 0
}

scan_workspace_payload() {
  python3 - <<'PY' "$WORKSPACE" "$BASELINE_FILE" "$PROVENANCE_FILE" "$LOGIN_USER"
import json,sys
from pathlib import Path

ws=Path(sys.argv[1])
baseline=Path(sys.argv[2])
prov_path=Path(sys.argv[3])
login_user=sys.argv[4]
known=set()
if baseline.exists():
    known=set(x.strip() for x in baseline.read_text(encoding='utf-8',errors='replace').splitlines() if x.strip())

prov={}
if prov_path.exists():
    try:
        prov=json.loads(prov_path.read_text(encoding='utf-8',errors='replace')).get('files',{})
    except Exception:
        prov={}

EXCLUDED_PREFIXES=("var/log/",f"home/{login_user}/.cache/")
ALLOWED_PREFIXES=("tmp/","var/tmp/",f"home/{login_user}/","opt/")

def excluded(rel):
    low=rel.lower()
    if any(rel.startswith(p) for p in EXCLUDED_PREFIXES):
        return True
    if '/.cache/' in rel:
        return True
    if low.endswith('.stdout') or low.endswith('.stderr'):
        return True
    if 'ffmpeg' in low and 'log' in low:
        return True
    return False

for rel,meta in prov.items():
    if excluded(rel):
        continue
    if not any(rel.startswith(p) for p in ALLOWED_PREFIXES):
        continue
    p=ws/rel
    if not p.is_file():
        continue
    if rel in known:
        continue

    created_or_downloaded = bool(meta.get('created') or meta.get('downloaded') or meta.get('source') in {'download','shell_create'})
    prepared_or_executed = bool(meta.get('executed') or meta.get('chmod_x'))
    if not created_or_downloaded:
        continue
    if not prepared_or_executed:
        continue

    try:
        with p.open('rb') as f:
            head=f.read(256)
    except Exception:
        continue

    is_elf=head[:4]==b'\x7fELF'
    shebang=head.startswith(b'#!')
    suspicious_suffix=rel.endswith(('.sh','.py','.elf','.bin','.pl'))

    # final confidence gate: attacker provenance + prep/exec + payload-like artifact
    if is_elf or shebang or suspicious_suffix or meta.get('executed'):
        source=meta.get('source') or 'attacker_drop'
        print(f'payload_captured:{source}:{rel}')
        sys.exit(7)

sys.exit(0)
PY
}

case "${1:-}" in
  check-command)
    check_sensitive_command "${2:-}" "${3:-/home/${LOGIN_USER}}" ;;
  post-command)
    reason="$(scan_workspace_payload || true)"
    if [[ -n "$reason" ]]; then
      terminate_with_reason "$reason"
    fi
    ;;
  capture-evidence)
    capture_evidence ;;
  log-idle-timeout)
    log_event "idle_timeout" "session idle timeout reached" '{"severity":"low","action":"terminate"}'
    echo "idle_timeout" > "$TERM_FILE"
    ;;
  *)
    echo "usage: $0 {check-command|post-command|capture-evidence|log-idle-timeout}" >&2
    exit 2 ;;
esac
