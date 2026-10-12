"""Output / Visualization: Notifications, Reports, Recommended actions, Stats/Charts.
Run:  streamlit run dashboard/app.py
Reads the SQLite DB the pipeline writes; auto-refreshes so you see alerts in real time."""
import json
import os
import sys

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idspipe import db  # noqa: E402
from idspipe.audit import audit  # noqa: E402
from idspipe.config import load_config  # noqa: E402
from idspipe.report import generate_report  # noqa: E402
from idspipe.util import fmt_ts  # noqa: E402
from idspipe import runner  # noqa: E402
import time  # noqa: E402

st.set_page_config(page_title="IDS + LLM Pipeline", layout="wide")
cfg = load_config(os.environ.get("IDS_CONFIG"))

st.title("Snort + Suricata -> LLM  |  IDS pipeline")
PCAP_DIR = os.path.join(cfg["_root"], "pcaps")
os.makedirs(PCAP_DIR, exist_ok=True)

@st.fragment(run_every=3)
def status_panel():
    stt = runner.read_status()
    if stt.get("state") == "running" and not runner.is_running():
        stt["state"] = "error"
        stt["error"] = "Job process died unexpectedly (see run log)"
    if stt.get("state") == "running":
        st.info(f"Running: {stt.get('step', '')} ({os.path.basename(stt.get('pcap', ''))}, "
                f"{int(time.time() - stt.get('started', time.time()))}s)")
    elif stt.get("state") == "done":
        st.success(f"Last run finished: {os.path.basename(stt.get('pcap', ''))}")
    elif stt.get("state") == "error":
        st.error(stt.get("error") or "Last run failed")
    for w in stt.get("warnings") or []:
        st.warning(w)
    if os.path.exists(runner.LOG):
        with st.expander("Run log"):
            st.code(open(runner.LOG).read()[-6000:] or "(empty)")


with st.sidebar:
    st.header("Analyse a pcap")
    up = st.file_uploader("Upload a pcap / pcapng", type=["pcap", "pcapng", "cap"])
    existing = sorted(f for f in os.listdir(PCAP_DIR) if f.lower().endswith((".pcap", ".pcapng", ".cap")))
    pick = st.selectbox("...or choose one already in pcaps/", ["(none)"] + existing)
    path_in = st.text_input("...or full path of a pcap on this machine (no copy, best for big files)", "",
                            placeholder="/home/you/Downloads/Friday-WorkingHours.pcap")
    max_pk = st.number_input("Analyse only the first N packets (0 = all)", min_value=0, value=0, step=500000,
                             help="Quick way to test a huge pcap. Needs tcpdump.")
    home_net = st.text_input("HOME_NET (your protected network)", "192.168.10.0/24",
                             help="Use your capture's internal range, e.g. 10.0.0.0/24 or 192.168.1.0/24")
    use_llm = st.checkbox("Use OpenAI LLM analysis", value=bool(os.environ.get("OPENAI_API_KEY")))
    if st.button("Run analysis", type="primary"):
        target = None
        if path_in.strip():
            target = os.path.expanduser(path_in.strip().strip('"').strip("'"))
            if not os.path.isfile(target):
                st.error(f"File not found: {target}")
                target = ""
        elif up is not None:
            target = os.path.join(PCAP_DIR, os.path.basename(up.name))
            try:
                with open(target, "wb") as f:
                    f.write(up.getbuffer())
            except OSError as e:
                st.error(f"Could not save the upload ({e}). Free disk space or use the path box instead.")
                target = ""
        elif pick != "(none)":
            target = os.path.join(PCAP_DIR, pick)
        if target is None:
            st.error("Upload a pcap, choose one, or type a path first.")
        elif target and runner.start_job(target, home_net.strip(), use_llm, int(max_pk)):
            st.rerun()
    status_panel()
    st.divider()

refresh = st.sidebar.slider("Auto-refresh (seconds, 0 = off)", 0, 60, 5)
if runner.is_running():
    refresh = max(refresh, 3) if refresh else 3
st.sidebar.caption(f"DB: {cfg['paths']['db']}")
if st.sidebar.button("Generate report now"):
    c = db.connect(cfg["paths"]["db"])
    st.sidebar.success(f"Saved {generate_report(cfg, c)}")


def q(conn, sql, *args):
    return pd.read_sql_query(sql, conn, params=args)


def render():
    conn = db.connect(cfg["paths"]["db"])
    one = lambda sql: conn.execute(sql).fetchone()[0] or 0
    c = st.columns(7)
    c[0].metric("Total alerts", one("SELECT COUNT(*) FROM events"))
    c[1].metric("Suricata", one("SELECT COUNT(*) FROM events WHERE engine='suricata'"))
    c[2].metric("Snort", one("SELECT COUNT(*) FROM events WHERE engine='snort'"))
    c[3].metric("ML anomalies", one("SELECT COUNT(*) FROM events WHERE engine='ml'"))
    c[4].metric("Incidents", one("SELECT COUNT(*) FROM incidents"))
    c[5].metric("High/Critical", one("SELECT COUNT(*) FROM incidents WHERE risk_label IN ('high','critical')"))
    c[6].metric("Assets", one("SELECT COUNT(*) FROM assets"))

    t1, t2, t3, t4, t5, t6 = st.tabs(["Notifications", "Incidents & LLM", "Stats / Charts", "Assets", "Reports", "Count audit"])

    with t1:
        n = q(conn, "SELECT datetime(wall,'unixepoch','localtime') AS time, level, incident_id, message FROM notifications ORDER BY id DESC LIMIT 100")
        if len(n):
            st.dataframe(n, hide_index=True)
        else:
            st.info("No notifications yet.")

    with t2:
        st.caption("Flow: Snort + Suricata alerts -> unified into one event table -> correlated into incidents -> "
                   "**ranked by risk score** (rank 1 = most urgent) -> LLM analyses the top-ranked incidents.")
        lc1, lc2 = st.columns([1, 3])
        top_n = lc1.number_input("LLM: analyse top N ranked incidents", 1, 500, 30, key="top_n")
        if lc2.button("Run LLM on top-ranked incidents"):
            with st.spinner("Calling the LLM on the top-ranked incidents..."):
                import subprocess
                pr = subprocess.run([sys.executable, os.path.join(cfg["_root"], "run_pipeline.py"), "llm", "--top", str(int(top_n))],
                                    capture_output=True, text=True, cwd=cfg["_root"])
            (st.success if pr.returncode == 0 and "analysed 0" not in pr.stdout else st.warning)(
                (pr.stdout.strip().splitlines() or ["done"])[-2] if pr.returncode == 0 else pr.stderr[-500:])
        inc = q(conn, "SELECT id, src_ip, dst_ip, event_count AS alerts, group_count AS groups, engines, risk_score, risk_label,"
                      " llm_risk, llm_priority, top_signature, first_ts, last_ts FROM incidents"
                      " ORDER BY risk_score DESC, event_count DESC LIMIT 300")
        if inc.empty:
            st.info("No incidents yet.")
        else:
            inc.insert(0, "rank", range(1, len(inc) + 1))
            inc["first_alert"] = inc["first_ts"].map(fmt_ts)
            st.dataframe(inc.drop(columns=["first_ts", "last_ts"]), hide_index=True)
            sel = st.selectbox("Inspect incident", inc["id"].tolist(), key="sel_inc")
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (sel,)).fetchone()
            a, b = st.columns(2)
            with a:
                st.subheader(f"Incident #{sel}: {row['src_ip']} -> {row['dst_ip']}")
                st.write(f"{row['event_count']} alerts | engines: {row['engines']} | risk {row['risk_score']} ({row['risk_label']})")
                st.dataframe(q(conn, "SELECT engine, signature, category, MAX(severity) sev, COUNT(*) alerts FROM events WHERE incident_id=? GROUP BY engine, sid ORDER BY alerts DESC", sel), hide_index=True)
            with b:
                st.subheader("LLM analysis")
                if row["llm_json"]:
                    j = json.loads(row["llm_json"])
                    st.markdown(f"**{j.get('attack_type', '')}** - risk: **{j.get('risk_class', '')}**, priority {j.get('priority', '')}, confidence {j.get('confidence', '')}")
                    st.write(j.get("summary", ""))
                    st.write(j.get("explanation", ""))
                    st.markdown("**Recommended actions**")
                    for x in j.get("recommended_actions", []):
                        st.markdown(f"- {x}")
                    if j.get("mitre_attack"):
                        st.caption("MITRE ATT&CK: " + ", ".join(j["mitre_attack"]))
                    if j.get("false_positive_notes"):
                        st.caption("False-positive notes: " + j["false_positive_notes"])
                else:
                    st.info(f"Not analysed yet (status: {row['llm_status']}). {row['llm_error'] or ''}")
            with st.expander("Raw alert rows (latest 200)"):
                st.dataframe(q(conn, "SELECT id, datetime(ts,'unixepoch') utc, engine, sid, signature, severity, src_ip, src_port, dst_ip, dst_port, proto FROM events WHERE incident_id=? ORDER BY ts DESC LIMIT 200", sel), hide_index=True)

        st.subheader("Recommended actions (top analysed incidents)")
        for r in conn.execute("SELECT id, src_ip, dst_ip, llm_json FROM incidents WHERE llm_json IS NOT NULL ORDER BY risk_score DESC LIMIT 5"):
            j = json.loads(r["llm_json"])
            st.markdown(f"**#{r['id']} {r['src_ip']} -> {r['dst_ip']}** ({j.get('attack_type', '')})")
            for x in j.get("recommended_actions", [])[:4]:
                st.markdown(f"- {x}")

    with t3:
        ts = q(conn, "SELECT CAST(ts/60 AS INT)*60 AS minute, engine, COUNT(*) alerts FROM events GROUP BY 1, 2 ORDER BY 1")
        if ts.empty:
            st.info("No alerts yet.")
        else:
            ts["time"] = pd.to_datetime(ts["minute"], unit="s")
            st.plotly_chart(px.bar(ts, x="time", y="alerts", color="engine", title="Alerts per minute (pcap time)"), use_container_width=True)
            l, r = st.columns(2)
            sev = q(conn, "SELECT engine, CASE severity WHEN 3 THEN 'high' WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE 'info' END sev, COUNT(*) n FROM events GROUP BY 1, 2")
            l.plotly_chart(px.bar(sev, x="engine", y="n", color="sev", title="Severity by engine"), use_container_width=True)
            top = q(conn, "SELECT engine, signature, COUNT(*) n FROM events GROUP BY engine, sid ORDER BY n DESC LIMIT 15")
            r.plotly_chart(px.bar(top, x="n", y="signature", color="engine", orientation="h", title="Top signatures").update_layout(yaxis={"categoryorder": "total ascending"}), use_container_width=True)
            l2, r2 = st.columns(2)
            src = q(conn, "SELECT src_ip, COUNT(*) n FROM events GROUP BY src_ip ORDER BY n DESC LIMIT 10")
            dst = q(conn, "SELECT dst_ip, COUNT(*) n FROM events GROUP BY dst_ip ORDER BY n DESC LIMIT 10")
            l2.plotly_chart(px.bar(src, x="n", y="src_ip", orientation="h", title="Top alert sources").update_layout(yaxis={"categoryorder": "total ascending"}), use_container_width=True)
            r2.plotly_chart(px.bar(dst, x="n", y="dst_ip", orientation="h", title="Top alert targets").update_layout(yaxis={"categoryorder": "total ascending"}), use_container_width=True)
            cat = q(conn, "SELECT category, COUNT(*) n FROM events GROUP BY category ORDER BY n DESC LIMIT 12")
            st.plotly_chart(px.pie(cat, names="category", values="n", title="Alert categories"), use_container_width=True)
        fl = q(conn, "SELECT minute, flows, bytes FROM flow_stats ORDER BY minute")
        if not fl.empty:
            fl["time"] = pd.to_datetime(fl["minute"], unit="s")
            st.plotly_chart(px.line(fl, x="time", y="flows", title="Flows per minute (Suricata flow records)"), use_container_width=True)

    with t4:
        a = q(conn, "SELECT ip, role, device_type, internal, hostname, ports, flows, known FROM assets ORDER BY flows DESC LIMIT 500")
        if len(a):
            st.dataframe(a, hide_index=True)
        else:
            st.info("No assets yet.")

    with t5:
        for r in conn.execute("SELECT path, datetime(wall,'unixepoch','localtime') w FROM reports ORDER BY id DESC LIMIT 10"):
            with st.expander(f"{os.path.basename(r['path'])}  ({r['w']})"):
                if os.path.exists(r["path"]):
                    st.markdown(open(r["path"]).read())

    with t6:
        st.caption("raw alert lines written by Snort/Suricata == events stored == sum of group counts == sum of incident counts")
        st.dataframe(pd.DataFrame(audit(cfg, conn)), hide_index=True)
        st.dataframe(q(conn, "SELECT * FROM ingest_stats"), hide_index=True)


if refresh:
    st.fragment(run_every=refresh)(render)()
else:
    render()
