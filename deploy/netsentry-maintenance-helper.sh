#!/bin/sh
# NetSentry maintenance helper: the only root code NetSentry can set off.
#
# Installed as /usr/local/lib/netsentry/maintenance-helper (root:root 0755) and
# run by netsentry-power.service whenever NetSentry drops a request file (its
# path is the first argument). NetSentry runs unprivileged and sandboxed; all it
# can do is write ONE word into that file. This script
#
#   1. refuses anything that is not a plain file (a symlink, a FIFO, ...),
#   2. opens it, deletes it (a request can never fire twice), then reads at
#      most 32 bytes, keeps the first word and only the characters a-z and -,
#   3. matches the word against a fixed list. Nothing else from the request,
#      and nothing from Telegram, ever reaches a command line.
#
# Words:
#   reboot        record running containers/units, then `systemctl reboot`
#   refresh       apt-get update + the upgrade plan (plan-upgrade.json)
#   upgrade       re-simulate; only if the plan's hash still matches,
#                 apt-get -y upgrade --with-new-pkgs (never removes anything)
#   prune         docker builder prune -af + docker image prune -af
#                 (never volumes, never containers)
#   kernels-plan  the apt-get autoremove --purge plan (plan-kernels.json)
#   kernels       re-simulate; only if the hash still matches, autoremove --purge
#   eeprom        rpi-eeprom-update -a (stages it; applied on the next restart)
#   status        what is waiting, disk, Docker, bootloader, SD errors (status.json)
#   health        after a restart: failed units, containers vs before, DNS,
#                 tunnel and key services (health.json)
#
# Output goes to a root-owned folder NetSentry can read but not write, so it can
# not forge a plan: plan-upgrade.json, plan-kernels.json, status.json,
# health.json, result.json (the last changing action), busy.json (while
# running), ignored.json (a word refused because another action was running),
# pre-reboot.json. Every file is written atomically (temp file + rename), 0644.
# Logs of each run: /var/log/netsentry-maintenance (the newest 20 are kept).
#
# The NS_MAINT_* variables exist for the offline tests only; the systemd unit
# sets none of them.
set -eu
umask 022

REQUEST="${1:-${NS_MAINT_REQUEST:-}}"
OUT="${NS_MAINT_OUT:-/var/lib/netsentry-maintenance}"
LOGDIR="${NS_MAINT_LOG:-/var/log/netsentry-maintenance}"
LOCK="${NS_MAINT_LOCK:-/run/netsentry-maintenance.lock}"
PY="${NS_MAINT_PYTHON:-/usr/bin/python3}"

say() { printf 'netsentry-maintenance: %s\n' "$*" >&2; }

if [ -z "$REQUEST" ]; then
    say "no request file given"
    exit 0
fi
if [ ! -e "$REQUEST" ] && [ ! -L "$REQUEST" ]; then
    exit 0
fi
if [ -L "$REQUEST" ] || [ ! -f "$REQUEST" ]; then
    rm -f -- "$REQUEST"
    say "ignored a request that is not a plain file"
    exit 0
fi

# Consume first: open, delete, then read from the open file.
exec 3<"$REQUEST"
rm -f -- "$REQUEST"
word=$(head -c 32 <&3 | head -n 1 | tr -cd 'a-z- ') || word=""
exec 3<&-
word=${word# }
word=${word%% *}

case "$word" in
    reboot|refresh|upgrade|prune|kernels-plan|kernels|eeprom|status|health) ;;
    *)
        # The content is never logged: it is not ours to repeat.
        say "ignored an unknown request"
        exit 0
        ;;
esac

mkdir -p -- "$OUT" "$LOGDIR"
chmod 0755 -- "$OUT" "$LOGDIR"
say "running: $word"

exec "$PY" -I - "$word" "$OUT" "$LOGDIR" "$LOCK" <<'PYEOF'
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.request

ACTION, OUT, LOGDIR, LOCK = sys.argv[1:5]
PATH = os.environ.get("PATH") or "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV = {"PATH": PATH, "LC_ALL": "C", "LANG": "C", "HOME": "/root"}
APT_ENV = dict(ENV, DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="l",
               APT_LISTCHANGES_FRONTEND="none")
# Wait (up to 5 min) instead of failing when apt-daily or unattended-upgrades
# holds the dpkg/apt lock at that moment.
APT_LOCK_WAIT = ["-o", "DPkg::Lock::Timeout=300"]
APT_KEEP_CONFIG = APT_LOCK_WAIT + ["-o", "Dpkg::Options::=--force-confdef",
                                   "-o", "Dpkg::Options::=--force-confold"]
REBOOT_FILE = "/var/run/reboot-required"
MODULES = "/lib/modules"
UNITS = ("netsentry.service", "docker.service", "cloudflared.service",
         "tailscaled.service", "hidwayd.service", "pihole-FTL.service")
HEALTH_WAIT = float(os.environ.get("NS_MAINT_HEALTH_WAIT", "240"))
HEALTH_STEP = float(os.environ.get("NS_MAINT_HEALTH_STEP", "10"))
KEEP_LOGS = 20
LOG = None
LOG_PATH = ""


def now():
    return time.time()


def write_json(name, data):
    """Write OUT/name so a reader sees the old file or the new one, never half."""
    final = os.path.join(OUT, name)
    tmp = os.path.join(OUT, ".%s.%d.tmp" % (name, os.getpid()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, final)


def read_json(name):
    try:
        with open(os.path.join(OUT, name), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def log(text):
    if LOG is not None:
        LOG.write(text.rstrip("\n") + "\n")
        LOG.flush()


def run(argv, timeout=120, env=None, quiet=False):
    """Run a fixed argv (never a shell); returns (exit code, output)."""
    if shutil.which(argv[0], path=PATH) is None:
        log("$ %s: not found" % argv[0])
        return 127, ""
    log("$ " + " ".join(argv))
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, errors="replace",
                           env=env or ENV, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as e:
        out = e.output or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        log(out)
        log("timed out after %ds" % timeout)
        return 124, out
    except OSError as e:
        log("could not run: %s" % e)
        return 126, ""
    if not quiet:
        log(r.stdout)
    log("exit %d" % r.returncode)
    return r.returncode, r.stdout


def tail(text, n=6):
    lines = [ln.strip()[:200] for ln in text.splitlines() if ln.strip()]
    return lines[-n:]


def digest(lines):
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def open_log():
    global LOG, LOG_PATH
    os.makedirs(LOGDIR, exist_ok=True)
    name = "%s-%s.log" % (time.strftime("%Y%m%d-%H%M%S"), ACTION)
    path = os.path.join(LOGDIR, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    LOG = os.fdopen(fd, "a", encoding="utf-8")
    LOG_PATH = path
    logs = sorted(f for f in os.listdir(LOGDIR) if f.endswith(".log"))
    for old in logs[:-KEEP_LOGS]:
        try:
            os.unlink(os.path.join(LOGDIR, old))
        except OSError:
            pass
    return path


# ─── apt ─────────────────────────────────────────────────────────

INST = re.compile(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+)")
REMOVE = re.compile(r"^(?:Purg|Remv) (\S+)(?: \[(\S+)\])?")


def simulate_upgrade():
    rc, out = run(["apt-get", "-s", "upgrade", "--with-new-pkgs"], 600, APT_ENV)
    packages, kept, in_kept = [], [], False
    for line in out.splitlines():
        m = INST.match(line)
        if m:
            packages.append({"name": m.group(1), "from": m.group(2) or "",
                             "to": m.group(3)})
            continue
        if line.startswith("The following packages have been kept back"):
            in_kept = True
            continue
        if in_kept:
            if line.startswith(" "):
                kept.extend(line.split())
            else:
                in_kept = False
    lines = ["%s %s %s" % (p["name"], p["from"], p["to"]) for p in packages]
    return {"ok": rc == 0, "exit": rc, "packages": packages, "kept_back": kept,
            "hash": digest(lines), "error": [] if rc == 0 else tail(out)}


def simulate_autoremove():
    rc, out = run(["apt-get", "-s", "autoremove", "--purge"], 600, APT_ENV)
    packages = []
    for line in out.splitlines():
        m = REMOVE.match(line)
        if m:
            packages.append({"name": m.group(1), "version": m.group(2) or ""})
    lines = ["%s %s" % (p["name"], p["version"]) for p in packages]
    return {"ok": rc == 0, "exit": rc, "packages": packages,
            "hash": digest(lines), "error": [] if rc == 0 else tail(out)}


def version_key(text):
    return [int(x) for x in re.findall(r"\d+", text)]


def kernel_flavour(release):
    """``6.12.25+rpt-rpi-v8`` -> ``+rpt-rpi-v8``: only the same kind of kernel compares."""
    m = re.match(r"^[0-9.]+", release)
    return release[m.end():] if m else None


def reboot_info():
    info = {"required": os.path.exists(REBOOT_FILE), "packages": [],
            "running_kernel": os.uname().release, "newest_kernel": ""}
    try:
        with open(REBOOT_FILE + ".pkgs", encoding="utf-8", errors="replace") as f:
            info["packages"] = sorted({ln.strip() for ln in f if ln.strip()})[:20]
    except OSError:
        pass
    running = info["running_kernel"]
    flavour = kernel_flavour(running)
    try:
        found = [d for d in os.listdir(MODULES) if kernel_flavour(d) == flavour]
    except OSError:
        found = []
    if found:
        newest = max(found, key=version_key)
        if newest != running:
            info["newest_kernel"] = newest
    return info


def needrestart_services():
    if shutil.which("needrestart", path=PATH) is None:
        return None
    _, out = run(["needrestart", "-b", "-r", "l"], 300, APT_ENV)
    return sorted({ln.split(":", 1)[1].strip() for ln in out.splitlines()
                   if ln.startswith("NEEDRESTART-SVC:")})


# ─── the other tools ─────────────────────────────────────────────

def docker_reclaimable():
    if shutil.which("docker", path=PATH) is None:
        return None
    rc, out = run(["docker", "system", "df", "--format", "{{json .}}"], 120)
    found = {}
    for line in out.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("Type") in ("Images", "Build Cache"):
            key = "images" if row["Type"] == "Images" else "build_cache"
            found[key] = str(row.get("Reclaimable", ""))[:40]
    found["ok"] = rc == 0
    return found


def eeprom_info():
    if shutil.which("rpi-eeprom-update", path=PATH) is None:
        return None
    rc, out = run(["rpi-eeprom-update"], 120)
    info = {"exit": rc, "state": "", "current": "", "latest": ""}
    section = ""
    for line in out.splitlines():
        key, _, value = line.strip().partition(":")
        key = key.strip().upper()
        if key == "BOOTLOADER":
            section = key
            info["state"] = value.strip()[:80]
        elif key.startswith("VL805"):
            section = "VL805"       # the USB chip's own CURRENT/LATEST follow: not ours
        elif key in ("CURRENT", "LATEST") and section == "BOOTLOADER":
            info[key.lower()] = value.strip()[:80]
    text = info["state"].lower()
    info["update_available"] = "update available" in text or "update required" in text
    return info


DISK_ERROR = re.compile(r"(mmc\d+:.*(error|timeout)|I/O error|EXT4-fs error|"
                        r"blk_update_request|critical medium error|FAT-fs .*error|"
                        r"Buffer I/O error)", re.I)


def disk_errors():
    rc, out = run(["journalctl", "-k", "-b", "--no-pager", "-o", "cat"], 120, quiet=True)
    if rc == 127:
        return None
    hits = [ln.strip() for ln in out.splitlines() if DISK_ERROR.search(ln)]
    return {"count": len(hits), "last": hits[-1][:200] if hits else ""}


def disks():
    out = []
    for path in ("/", "/boot/firmware"):
        if os.path.isdir(path):
            try:
                u = shutil.disk_usage(path)
            except OSError:
                continue
            out.append({"path": path, "total": u.total, "free": u.free})
    return out


def containers():
    """Running containers: {name: status text}, or None without Docker."""
    if shutil.which("docker", path=PATH) is None:
        return None
    rc, out = run(["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"], 60, quiet=True)
    if rc != 0:
        return None
    found = {}
    for line in out.splitlines():
        name, _, status = line.partition("\t")
        if name.strip():
            found[name.strip()] = status.strip()
    return found


def unit_states(units):
    rc, out = run(["systemctl", "show", "-p", "Id", "-p", "LoadState", "-p", "ActiveState",
                   *units], 60, quiet=True)
    states, block = {}, {}
    for line in out.splitlines() + [""]:
        if not line.strip():
            if block.get("Id"):
                load = block.get("LoadState", "")
                states[block["Id"]] = ("not-found" if load in ("not-found", "")
                                       else block.get("ActiveState", "unknown"))
            block = {}
            continue
        key, _, value = line.partition("=")
        block[key.strip()] = value.strip()
    return states


def failed_units():
    _, out = run(["systemctl", "--failed", "--plain", "--no-legend", "--no-pager"], 60)
    names = []
    for line in out.splitlines():
        parts = line.replace("●", " ").split()
        if parts:
            names.append(parts[0])
    return names


def dns_check(server="127.0.0.1", name="deb.debian.org"):
    qid = secrets.randbelow(65536)
    query = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    query += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    query += struct.pack(">HH", 1, 1)
    for _ in range(2):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(query, (server, 53))
            data, _ = s.recvfrom(2048)
        except OSError:
            continue
        finally:
            s.close()
        if len(data) >= 12:
            rid, flags, _, answers = struct.unpack(">HHHH", data[:8])
            if rid == qid and flags & 0x000F == 0 and answers > 0:
                return {"ok": True, "detail": "%s answers via %s" % (name, server)}
            if rid == qid:
                return {"ok": False, "detail": "%s: no answer (code %d)" % (name, flags & 15)}
    return {"ok": False, "detail": "the DNS server on %s does not answer" % server}


def tunnel_check():
    """cloudflared's own readiness page (its metrics server, on localhost only)."""
    for port in (20241, 20242, 20243, 20244, 20245, 2000):
        url = "http://127.0.0.1:%d/ready" % port
        try:
            with urllib.request.urlopen(url, timeout=2) as r:  # nosec B310 - fixed localhost URL
                body = json.loads(r.read(4096).decode("utf-8", "replace") or "{}")
                ready = int(body.get("readyConnections", 0))
                return {"ok": ready > 0, "detail": "%d tunnel connections" % ready}
        except Exception:
            continue
    return {"ok": None, "detail": "tunnel state unknown (no metrics page)"}


# ─── actions ─────────────────────────────────────────────────────

def stamp(data, started):
    data["started"] = started
    data["finished"] = now()
    return data


def result(started, **fields):
    fields["action"] = ACTION
    fields["log"] = LOG_PATH
    write_json("result.json", stamp(fields, started))


def do_refresh(started):
    rc, out = run(["apt-get", *APT_LOCK_WAIT, "update"], 900, APT_ENV)
    plan = simulate_upgrade()
    plan["update_ok"] = rc == 0
    if rc != 0:
        plan["update_error"] = tail(out, 3)
    write_json("plan-upgrade.json", stamp(plan, started))


def do_upgrade(started):
    before = read_json("plan-upgrade.json")
    plan = simulate_upgrade()
    if not plan["ok"]:
        write_json("plan-upgrade.json", stamp(dict(plan, update_ok=True), started))
        result(started, exit=plan["exit"], error=plan["error"])
        return
    if before.get("hash") != plan["hash"]:
        write_json("plan-upgrade.json", stamp(dict(plan, update_ok=True), started))
        result(started, exit=None, changed=True, hash=plan["hash"])
        return
    if not plan["packages"]:
        result(started, exit=0, nothing=True, upgraded=[])
        return
    rc, out = run(["apt-get", "-y", *APT_KEEP_CONFIG, "upgrade", "--with-new-pkgs"],
                  3600, APT_ENV)
    services = needrestart_services()
    after = simulate_upgrade()
    write_json("plan-upgrade.json", stamp(dict(after, update_ok=True), started))
    result(started, exit=rc, upgraded=plan["packages"], reboot=reboot_info(),
           services=services, error=[] if rc == 0 else tail(out))


def do_kernels_plan(started):
    write_json("plan-kernels.json", stamp(simulate_autoremove(), started))


def do_kernels(started):
    before = read_json("plan-kernels.json")
    plan = simulate_autoremove()
    if not plan["ok"] or before.get("hash") != plan["hash"]:
        write_json("plan-kernels.json", stamp(plan, started))
        if not plan["ok"]:
            result(started, exit=plan["exit"], error=plan["error"])
        else:
            result(started, exit=None, changed=True, hash=plan["hash"])
        return
    if not plan["packages"]:
        result(started, exit=0, nothing=True, removed=[])
        return
    rc, out = run(["apt-get", "-y", *APT_KEEP_CONFIG, "autoremove", "--purge"],
                  1800, APT_ENV)
    write_json("plan-kernels.json", stamp(simulate_autoremove(), started))
    result(started, exit=rc, removed=plan["packages"],
           error=[] if rc == 0 else tail(out))


def do_prune(started):
    if shutil.which("docker", path=PATH) is None:
        result(started, exit=127, error=["docker is not installed"])
        return
    rc1, out1 = run(["docker", "builder", "prune", "-af"], 1800)
    rc2, out2 = run(["docker", "image", "prune", "-af"], 1800)
    m1 = re.search(r"Total:\s*(\S+)", out1)
    m2 = re.search(r"Total reclaimed space:\s*(\S+)", out2)
    result(started, exit=rc1 or rc2, freed_build=m1.group(1) if m1 else "0B",
           freed_images=m2.group(1) if m2 else "0B",
           error=tail(out1 + "\n" + out2) if (rc1 or rc2) else [])


def do_eeprom(started):
    rc, out = run(["rpi-eeprom-update", "-a"], 600)
    result(started, exit=rc, output=tail(out, 8))


def do_status(started):
    plan = simulate_upgrade()
    write_json("status.json", stamp({
        "pending": plan["packages"], "kept_back": plan["kept_back"],
        "apt_ok": plan["ok"], "reboot": reboot_info(), "disks": disks(),
        "docker": docker_reclaimable(), "eeprom": eeprom_info(),
        "disk_errors": disk_errors(),
        "autoremove": [p["name"] for p in simulate_autoremove()["packages"]],
    }, started))


def do_reboot(started):
    try:
        running = containers()
        units = unit_states(UNITS)
        write_json("pre-reboot.json", {
            "created": now(), "containers": sorted(running or {}),
            "units": sorted(u for u, s in units.items() if s == "active")})
    except Exception as e:  # the snapshot must never stop the restart
        log("pre-reboot snapshot failed: %s" % e)
    result(started, exit=0)
    try:
        os.unlink(os.path.join(OUT, "busy.json"))     # the shutdown may not let us finish
    except OSError:
        pass
    run(["systemctl", "reboot"], 60)


def do_health(started):
    before = read_json("pre-reboot.json")
    wanted = [str(c) for c in before.get("containers", [])]
    deadline = now() + HEALTH_WAIT
    while True:
        running = containers()
        names = running or {}
        starting = sorted(n for n, s in names.items() if "health: starting" in s)
        missing = sorted(set(wanted) - set(names))
        if running is None and shutil.which("docker", path=PATH) is not None:
            missing = list(wanted)
        if (not missing and not starting) or now() >= deadline:
            break
        time.sleep(HEALTH_STEP)
    unhealthy = sorted(n for n, s in names.items() if "(unhealthy)" in s)
    states = unit_states(UNITS)
    report = {
        "before_ts": before.get("created"),
        "containers": {"before": wanted, "running": sorted(names), "missing": missing,
                       "starting": starting, "unhealthy": unhealthy,
                       "docker": running is not None},
        "units": {u: s for u, s in states.items() if s != "not-found"},
        "units_before": before.get("units", []),
        "failed_units": failed_units(),
        "dns": dns_check(),
        "tunnel": tunnel_check() if states.get("cloudflared.service") == "active" else None,
        "waited_s": round(now() - started),
    }
    write_json("health.json", stamp(report, started))


READ_ONLY = {"refresh": "plan-upgrade.json", "kernels-plan": "plan-kernels.json",
             "status": "status.json", "health": "health.json"}
ACTIONS = {"refresh": do_refresh, "upgrade": do_upgrade, "prune": do_prune,
           "kernels-plan": do_kernels_plan, "kernels": do_kernels, "eeprom": do_eeprom,
           "status": do_status, "reboot": do_reboot, "health": do_health}


def main():
    started = now()
    lock = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        busy = read_json("busy.json")
        write_json("ignored.json", {"action": ACTION, "started": started,
                                    "finished": now(), "busy_with": busy.get("action", "")})
        print("netsentry-maintenance: busy, ignored %s" % ACTION, file=sys.stderr)
        return 0
    busy_file = os.path.join(OUT, "busy.json")
    try:
        write_json("busy.json", {"action": ACTION, "started": started, "pid": os.getpid()})
        open_log()
        log("netsentry-maintenance %s" % ACTION)
        try:
            ACTIONS[ACTION](started)
        except Exception as e:
            # Always leave an answer, so NetSentry is not left waiting.
            log("failed: %r" % e)
            error = ["the helper failed: %s" % type(e).__name__]
            if ACTION in READ_ONLY:
                write_json(READ_ONLY[ACTION], stamp({"ok": False, "error": error}, started))
            else:
                result(started, exit=1, error=error)
            raise
    finally:
        try:
            os.unlink(busy_file)
        except OSError:
            pass
        if LOG is not None:
            LOG.close()
    return 0


sys.exit(main())
PYEOF
