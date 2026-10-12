"""Background job: pcap -> Suricata + Snort -> pipeline (--once). Used by the dashboard's Upload & Run panel.

It runs as a *separate process* (python -m idspipe.runner ...) so Streamlit reruns never kill it.
Progress goes to data/run_status.json and data/run.log.  Can also be used from the CLI:

    python -m idspipe.runner --pcap pcaps/x.pcap --home-net 192.168.10.0/24 [--no-llm]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS = os.path.join(ROOT, "data", "run_status.json")
LOG = os.path.join(ROOT, "data", "run.log")
LOG_SURI = os.path.join(ROOT, "logs", "suricata")
LOG_SNORT = os.path.join(ROOT, "logs", "snort")
SNORT_FIELDS = ("seconds timestamp action class dir dst_addr dst_port gid iface msg priority proto rev "
                "rule service sid src_addr src_port")


def read_status():
    try:
        with open(STATUS) as f:
            return json.load(f)
    except Exception:
        return {"state": "idle"}


def _set(**kw):
    st = read_status()
    st.update(kw)
    os.makedirs(os.path.dirname(STATUS), exist_ok=True)
    with open(STATUS + ".tmp", "w") as f:
        json.dump(st, f)
    os.replace(STATUS + ".tmp", STATUS)


def is_running():
    st = read_status()
    if st.get("state") != "running":
        return False
    try:
        os.kill(int(st.get("pid", 0)), 0)
        return True
    except Exception:
        return False


def start_job(pcap, home_net, use_llm=True, max_packets=0):
    """Launch the job detached from the caller. Returns False if one is already running."""
    if is_running():
        return False
    os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
    open(LOG, "w").close()
    _set(state="running", pcap=os.path.abspath(pcap), step="starting", started=time.time(), finished=None,
         error=None, pid=0)
    cmd = [sys.executable, "-m", "idspipe.runner", "--pcap", pcap, "--home-net", home_net]
    if not use_llm:
        cmd.append("--no-llm")
    if max_packets:
        cmd += ["--max-packets", str(int(max_packets))]
    p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    _set(pid=p.pid)
    return True


def _log(msg):
    with open(LOG, "a") as f:
        f.write(msg.rstrip("\n") + "\n")


def _run(cmd, step):
    _set(step=step)
    _log(f"$ {' '.join(cmd)}")
    p = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    tail = "\n".join(p.stdout.strip().splitlines()[-40:])
    if tail:
        _log(tail)
    _log(f"[exit code {p.returncode}]")
    return p.returncode


def _sudo_prefix():
    """Run directly if we are root; otherwise try without sudo (reading a pcap does not need root)."""
    return []


def _find_snort_lua():
    for p in [os.environ.get("SNORT_LUA"), "/usr/local/etc/snort/snort.lua", "/etc/snort/snort.lua",
              "/usr/etc/snort/snort.lua", "/opt/snort3/etc/snort/snort.lua"]:
        if p and os.path.isfile(p):
            return p
    return None


def _find_snort_rules():
    p = os.environ.get("SNORT_RULES") or os.path.join(ROOT, "rules", "snort3-community-rules", "snort3-community.rules")
    return p if os.path.isfile(p) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--home-net", default="192.168.10.0/24")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--max-packets", type=int, default=0, help="analyse only the first N packets (needs tcpdump)")
    a = ap.parse_args()
    pcap = os.path.abspath(a.pcap)
    os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
    if not os.path.exists(STATUS) or read_status().get("state") != "running":
        _set(state="running", pcap=pcap, started=time.time(), finished=None, error=None)
    _set(pid=os.getpid())
    warnings = []
    try:
        if not os.path.isfile(pcap):
            raise RuntimeError(f"pcap not found: {pcap}")
        os.makedirs(LOG_SURI, exist_ok=True)
        os.makedirs(LOG_SNORT, exist_ok=True)
        size = os.path.getsize(pcap)
        free = shutil.disk_usage(ROOT).free
        _log(f"pcap {size / 1e9:.2f} GB, free disk {free / 1e9:.2f} GB")
        if a.max_packets:
            tcpdump = shutil.which("tcpdump")
            if not tcpdump:
                raise RuntimeError("tcpdump not found (needed for 'first N packets'); install it or set N to 0")
            sl = os.path.join(ROOT, "data", "slice.pcap")
            rc = _run([tcpdump, "-r", pcap, "-w", sl, "-c", str(a.max_packets)], f"Cutting first {a.max_packets} packets")
            if rc != 0 or not os.path.exists(sl):
                raise RuntimeError("tcpdump failed to cut the slice (see log)")
            pcap = sl
            size = os.path.getsize(pcap)
        if free < size * 0.5 + 500e6:
            warnings.append(f"Low disk space ({free / 1e9:.1f} GB free): Suricata/Snort logs can be large; "
                            "consider 'first N packets' or freeing space")
        for f in (os.path.join(LOG_SURI, "eve.json"), os.path.join(LOG_SNORT, "alert_json.txt")):
            if os.path.exists(f):
                os.remove(f)

        # ---- Suricata ----
        suri = shutil.which("suricata")
        if suri:
            yaml_path = os.environ.get("SURICATA_YAML", "/etc/suricata/suricata.yaml")
            rc = _run([suri, "-c", yaml_path, "-r", pcap, "-l", LOG_SURI, "-k", "none",
                       "--set", f"vars.address-groups.HOME_NET=[{a.home_net}]",
                       "--set", "vars.address-groups.EXTERNAL_NET=any"], "Suricata analysing pcap")
            if rc != 0:
                warnings.append(f"Suricata exited with code {rc} (see log)")
        else:
            warnings.append("Suricata not found in PATH - skipped")

        # ---- Snort 3 ----
        snort = shutil.which("snort")
        lua, rules = _find_snort_lua(), _find_snort_rules()
        if snort and lua:
            cmd = [snort, "-c", lua]
            if rules:
                cmd += ["-R", rules]
            else:
                warnings.append("Snort ran WITHOUT the community rules file (only the rules inside snort.lua); "
                                "run scripts/02_get_snort_rules.sh for better coverage")
            cmd += ["-r", pcap, "-k", "none", "-A", "alert_json", "-l", LOG_SNORT, "-q",
                    "--lua", f"alert_json = {{ file = true, fields = '{SNORT_FIELDS}' }}"]
            rc = _run(cmd, "Snort analysing pcap")
            if rc != 0:
                warnings.append(f"Snort exited with code {rc} - see Run log (is it Snort 3? `snort -V`)")
        else:
            missing = []
            if not snort:
                missing.append("`snort` is not in PATH")
            if not lua:
                missing.append("snort.lua not found (export SNORT_LUA=/path/to/snort.lua)")
            warnings.append("Snort skipped, so only Suricata alerts exist: " + "; ".join(missing))

        eve = os.path.join(LOG_SURI, "eve.json")
        sn = os.path.join(LOG_SNORT, "alert_json.txt")
        if not os.path.exists(eve) and not os.path.exists(sn):
            raise RuntimeError("Neither Suricata nor Snort produced a log - nothing to analyse. " + "; ".join(warnings))
        # make sure files exist so the pipeline does not fail on a missing one
        for f in (eve, sn):
            if not os.path.exists(f):
                open(f, "w").close()

        # ---- Pipeline ----
        cmd = [sys.executable, os.path.join(ROOT, "run_pipeline.py"), "run", "--once", "--reset"]
        if a.no_llm:
            cmd.append("--no-llm")
        rc = _run(cmd, "Pipeline: correlate, aggregate, LLM analysis, report")
        if rc != 0:
            raise RuntimeError(f"run_pipeline.py failed with code {rc} (see log)")
        _set(state="done", step="finished", finished=time.time(), warnings=warnings)
    except Exception as e:  # noqa: BLE001
        _log(f"ERROR: {e}")
        _set(state="error", step="failed", finished=time.time(), error=str(e), warnings=warnings)


if __name__ == "__main__":
    main()
