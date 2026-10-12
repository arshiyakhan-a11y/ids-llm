# Snort + Suricata -> LLM pipeline on CICIDS2017 pcaps

A complete 8-stage pipeline (your diagram) where **every alert comes from Snort or Suricata
actually running on the CICIDS2017 pcaps**. Nothing in this project generates, simulates or
edits alerts. The OpenAI LLM only *analyses* the real alerts.

```
CICIDS2017 pcap ──tcpreplay (real time) or -r (offline)──► Suricata ─► eve.json ─┐
                                                      └──► Snort 3  ─► alert_json.txt ─┤
                                                                                         ▼
 1 Asset ident.  2 Collection  3 Pre-process  4 Detection  5 Correlation  6 Aggregation  7 Unified event  8 LLM (OpenAI)
 (idspipe/assets) (tailer+parsers) (preprocess)  (IDS + ML)  (correlation)   (aggregation)   (models+db)     (llm_engine)
                                                                                         ▼
                         Output: Notifications | Reports | Recommended actions | Stats & charts   (dashboard/app.py, reports/)
```

| Stage | What it does here | File |
|---|---|---|
| 1 Asset identification | Passive inventory from traffic (IP, internal/external, server ports -> role/device type incl. IoT/industrial port hints) + optional `assets.yaml` | `idspipe/assets.py` |
| 2 Passive traffic collection | Tails Suricata `eve.json` and Snort `alert_json.txt` in real time (restart-safe offsets) | `tailer.py`, `parsers.py` |
| 3 Pre-processing | 5-tuple flows from Suricata flow records -> duration, bytes, packets, rates | `preprocess.py` |
| 4 Detection | Rule-based = Suricata + Snort themselves. AI-based = optional IsolationForest on flows | `detection.py` |
| 5 Correlation | Links related alerts (same src/dst, within 300 s) into incidents; risk score; asset context | `correlation.py` |
| 6 Aggregation | Groups duplicate/similar alerts into counted summaries (nothing dropped) | `aggregation.py` |
| 7 Unified event | One schema: asset + threat + severity + time (SQLite) | `models.py`, `db.py` |
| 8 AI/LLM engine | OpenAI: analysis, ranking (priority 1-10), explanation, risk class, MITRE, recommended actions, report summary | `llm_engine.py`, `report.py` |
| Output | Console/log/webhook notifications, Markdown reports, Streamlit dashboard | `notifier.py`, `dashboard/app.py` |

## Honest status: what is tested and what is not

* **Tested in my sandbox:** all Python code - parsers for the three log formats, the full
  ingest -> correlation -> aggregation -> database path, restart without duplicates, the count audit,
  report generation, the ML detector, and the LLM stage (with a stubbed OpenAI response).
  Run `python -m unittest tests.test_smoke -v` yourself.
* **Not testable by me:** Snort 3 and Suricata themselves, the OpenAI call, and the Streamlit dashboard
  (no network / no IDS binaries in my environment). The scripts follow the official Snort 3 and Suricata
  command-line options, but **expect to adjust paths on your machine** (e.g. `SNORT_LUA`).
  If something fails, the Troubleshooting section lists the likely causes.

## "Same number" of alerts - what is guaranteed

* The pipeline stores **every** alert line Snort/Suricata wrote: `python run_pipeline.py audit` (and the
  dashboard's "Count audit" tab) checks that
  `raw alert lines in file == events in DB == sum of group counts == sum of incident counts`.
* Snort and Suricata will **not** report identical numbers to each other: they use different rulesets
  (Snort community rules vs. Emerging Threats Open) and different detection engines. That is expected and
  is exactly what the pipeline correlates and shows side by side.
* ML anomalies (if enabled) are stored with `engine = ml` and counted separately; they never inflate the
  Snort/Suricata numbers.

---

## 00. One command (Kali/Ubuntu): setup + ask for OpenAI key + open dashboard

```bash
cd ids-llm-pipeline && chmod +x scripts/*.sh && ./scripts/kali_start.sh
```

## 0. Quickest way: upload a pcap in the dashboard

```bash
./scripts/run_dashboard.sh          # http://localhost:8501  (run as your normal user, not sudo)
```
In the sidebar: **upload a .pcap/.pcapng** (or pick one already in `pcaps/`, or type the **full path** of a pcap anywhere on the machine - no copy is made, best for multi-GB files; "first N packets" analyses just a slice), set **HOME_NET** to your capture's
internal network, tick/untick the LLM option, press **Run analysis**. The dashboard launches Suricata and Snort on the
file, then the pipeline, and fills the tabs (notifications, incidents + LLM analysis, charts, assets, reports, count audit)
when it finishes. Each run replaces the previous results. Progress and the command log show in the sidebar.
If Snort is not installed/configured, only Suricata runs and a warning is shown (and vice versa).
Reading a pcap needs no root. If Snort 3's `snort.lua` is not in a standard place: `export SNORT_LUA=/path/snort.lua`
before starting the dashboard. CLI equivalent: `python -m idspipe.runner --pcap pcaps/x.pcap --home-net 10.0.0.0/24`.

### How alerts are unified, ranked and analysed

1. Snort and Suricata alerts go into **one event table** (same schema, `engine` column says which tool).
2. Events are **correlated into incidents** (same src/dst, close in time). An incident seen by both engines gets a bonus.
3. Every incident gets a **risk score and a rank** (rank 1 = most urgent). Suricata housekeeping events
   (`SURICATA ... invalid checksum`, bad ethertype, ...) are kept and counted but can never score above "low".
4. The **LLM analyses the top-ranked incidents** (`llm.max_incidents_once`, default 30). In the dashboard's
   *Incidents & LLM* tab, "Run LLM on top-ranked incidents" analyses more (CLI: `python run_pipeline.py llm --top 50`).
If Snort is not installed/configured, only Suricata alerts exist - the dashboard shows a warning, and `engines` will never show `snort`.

## 1. Requirements

* Linux (Ubuntu 22.04/24.04 tested layout), sudo, Python 3.10+
* **Suricata 6/7** (the install script uses the OISF PPA)
* **Snort 3** (install from https://www.snort.org/downloads - follow their Snort 3 guide; check `snort -V` shows 3.x)
* `tcpreplay` (live mode), `editcap`/`capinfos` from Wireshark (optional, to cut pcaps)
* OpenAI API key (platform.openai.com). Default model `gpt-4o-mini` (cheap); change in `config.yaml`.
* Disk: CICIDS2017 pcaps are 8-13 GB each. Start with a time slice (section 3).

Snort 2.9 instead of 3? Set `snort.format: fast` in `config.yaml` and write alerts with `-A fast`
to `logs/snort/alert_fast.txt` (set `paths.snort_alerts` accordingly). Snort 3 JSON is strongly preferred (exact epoch times).

## 2. Setup

```bash
cd ids-llm-pipeline
./scripts/01_install_ubuntu.sh          # Suricata, tcpreplay, venv + python deps, ET Open rules
./scripts/02_get_snort_rules.sh         # Snort 3 community rules into ./rules
cp .env.example .env && nano .env       # put your OPENAI_API_KEY
python -m venv .venv 2>/dev/null; source .venv/bin/activate
python -m unittest tests.test_smoke -v  # sanity check (should say OK)
```

Edit `assets.yaml` / `config.yaml` only if your network differs from CICIDS2017.

## 3. Get the CICIDS2017 pcaps

Download the PCAPs from the Canadian Institute for Cybersecurity page
https://www.unb.ca/cic/datasets/ids-2017.html (files `Monday-WorkingHours.pcap` ... `Friday-WorkingHours.pcap`)
and put them in `pcaps/`.

Reference attack schedule (as published for the dataset; times are the dataset's local time - pcap
timestamps may be offset by the timezone, check with `capinfos`):

| Day | Attacks |
|---|---|
| Mon | Benign only (good for training the optional ML detector) |
| Tue | FTP-Patator ~09:20-10:20, SSH-Patator ~14:00-15:00 |
| Wed | DoS slowloris/Slowhttptest/Hulk/GoldenEye ~09:47-11:23, Heartbleed ~15:12-15:32 |
| Thu | Web attacks (brute force, XSS, SQLi) ~09:20-10:42, Infiltration ~14:19-15:45 |
| Fri | Botnet ~10:02-11:02, PortScan ~13:55-14:35, DDoS ~15:56-16:16 |

**Important CICIDS2017 detail:** attacker traffic to the web server is NAT-ed, so in the pcaps it
often appears to come from `172.16.0.1` (the firewall), not from `205.174.165.73`. The scripts set
Suricata `HOME_NET=192.168.10.0/24` and `EXTERNAL_NET=any` so these alerts are not filtered out.

**Cut a manageable slice for a first run** (e.g. the Friday DDoS window, ~20 minutes):

```bash
capinfos pcaps/Friday-WorkingHours.pcap | grep -i -E "start|end"
editcap -A "2017-07-07 15:50:00" -B "2017-07-07 16:25:00" pcaps/Friday-WorkingHours.pcap pcaps/friday_ddos.pcap
```
(`editcap` interprets times in your local timezone; adjust, or use `tcpdump -r in.pcap -w out.pcap -c 3000000` to take the first 3M packets.)

## 4. Mode A - offline (simplest, deterministic)

```bash
./scripts/run_offline.sh pcaps/friday_ddos.pcap
```
This runs Suricata (`-r`), Snort (`-r`), then `python run_pipeline.py run --once --reset`, which ingests,
correlates, calls the LLM on the incidents, writes `reports/report_*.md` and prints the count audit.
Then open the dashboard:

```bash
./scripts/run_dashboard.sh          # http://localhost:8501
```

## 5. Mode B - real time (alerts appear while the pcap is replayed)

One command (needs sudo; replays at original speed; use `SPEED=10` for 10x):

```bash
SPEED=10 ./scripts/live_all.sh pcaps/friday_ddos.pcap
# second terminal:
./scripts/run_dashboard.sh
```

Or manually, one terminal each:

```bash
./scripts/03_veth_up.sh                       # virtual wire veth0 -> veth1
./scripts/run_suricata_live.sh                # T1  (writes logs/suricata/eve.json)
./scripts/run_snort_live.sh                   # T2  (writes logs/snort/alert_json.txt)
python run_pipeline.py run --reset            # T3  pipeline: tails both logs, notifies, calls LLM
./scripts/run_dashboard.sh                    # T4  dashboard
SPEED=10 ./scripts/replay.sh pcaps/friday_ddos.pcap   # T5  start replay AFTER T1/T2 print that they are ready
./scripts/99_veth_down.sh                     # cleanup
```

Wait until Snort and Suricata finish loading rules (30-60 s) before starting the replay, otherwise the first packets are missed.
`SPEED=max` replays as fast as possible (may drop packets on slow machines - the numbers then differ between runs).

## 6. Useful commands

```bash
python run_pipeline.py audit                  # reconcile raw alert counts vs DB (exit code 1 on mismatch)
python run_pipeline.py report                 # Markdown report (+ LLM executive summary)
python run_pipeline.py run --once --no-llm    # no OpenAI calls
python run_pipeline.py run --once --reset --suricata /path/eve.json --snort /path/alert_json.txt   # custom logs
```

Optional AI detector (stage 4, off by default): run Suricata on the benign Monday pcap, then

```bash
python run_pipeline.py train-ml --eve logs/suricata/eve.json     # trains on Suricata flow records
# set ml.enabled: true in config.yaml, then run Mode A/B on an attack day
```

## 7. Configuration (`config.yaml`)

| Key | Meaning |
|---|---|
| `pipeline.aggregation_window_sec` | same signature+src+dst closer than this = one group |
| `pipeline.correlation_window_sec`, `correlation_key` | incident time gap; `pair`, `src` or `dst` |
| `llm.model`, `llm.min_risk_score`, `llm.max_incidents_per_cycle`, `llm.max_incidents_once` | which model; skip trivial incidents; cost caps |
| `notifications.min_risk_score`, `webhook_url` | when to notify; optional Slack/Discord webhook |
| `snort.format` | `json` (Snort 3) or `fast` |

Risk score (0-100) = 15 x max severity + log-scaled alert count + signature variety + 10 if **both** Snort and
Suricata fired + 5 if the target is a server. Labels: >=80 critical, >=60 high, >=40 medium.

**LLM cost control:** the LLM receives one compact JSON summary per incident (never raw packets or the full
alert list), so a full run is typically a few dozen small requests. Lower `max_incidents_once` to cap it.
Without `OPENAI_API_KEY` the pipeline still runs; the LLM stage is skipped.

## 8. Troubleshooting

* **No alerts at all** - check `logs/suricata/eve.json` and `logs/snort/alert_json.txt` exist and are non-empty.
  Snort 3: confirm `snort -c $SNORT_LUA -R <rules> -T` validates; set `export SNORT_LUA=/path/to/snort.lua`.
* **Suricata sees few alerts on replay** - checksum offload: the scripts already pass `-k none` and disable offloads on veth.
* **Count audit says MISMATCH while running live** - normal while logs are still being written; re-run after the replay ends.
* **Snort 3 alert time looks wrong in fast format** - fast format has no year/timezone; use JSON (default).
* **`openai` errors** - check the key in `.env`, billing, and that `llm.model` is available to your account. Failed incidents retry up to 3 times.
* **Dashboard empty** - the DB is `data/pipeline.db`; the pipeline must have run at least once.
* **Re-ingest from scratch** - `python run_pipeline.py run --once --reset`.
* Dashboard charts use *pcap time* (July 2017), not today's date. That is correct.

## 9. Project layout

```
config.yaml  assets.yaml  .env.example  requirements.txt  run_pipeline.py
idspipe/      tailer parsers assets preprocess detection correlation aggregation engine
              llm_engine notifier report audit db models util config
dashboard/app.py          Streamlit UI
scripts/                  install, rules, veth, live/offline runners, replay, dashboard
tests/                    parser/pipeline smoke tests (+ format-only fixtures, never used for results)
pcaps/ logs/ data/ reports/ models/ rules/    working folders
```

## 10. Notes on the IoT/industrial asset types in the diagram

Stage 1 labels IP cameras, MQTT sensors, printers and industrial devices from the **ports they serve**
(RTSP 554, MQTT 1883, Modbus 502, ...). CICIDS2017 contains none of those devices (it is Windows/Linux/macOS
hosts and servers), so on this dataset you will see servers/workstations/gateways. The logic is there for other datasets.
