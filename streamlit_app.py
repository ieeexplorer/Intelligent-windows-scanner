from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import streamlit as st

from ricohpulse import run_once, get_local_subnet

st.set_page_config(page_title="RicohPulse Dashboard", page_icon="R", layout="wide")

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

:root {
  --bg-1: #f7f4ea;
  --bg-2: #e3f1ec;
  --ink: #1f2a37;
  --muted: #5b6572;
  --ok: #147d64;
  --warn: #bb6d00;
  --err: #a82700;
  --card: rgba(255,255,255,0.88);
  --line: rgba(22, 43, 58, 0.12);
}

.stApp {
  background:
    radial-gradient(900px 400px at 8% -5%, #f9dcc4 0%, rgba(249, 220, 196, 0) 60%),
    radial-gradient(800px 380px at 100% 0%, #c5e8d5 0%, rgba(197, 232, 213, 0) 62%),
    linear-gradient(140deg, var(--bg-1), var(--bg-2));
}

.block-container {
  padding-top: 1.2rem;
  padding-bottom: 2rem;
  max-width: 1300px;
}

.main-title {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 2.1rem;
  font-weight: 700;
  letter-spacing: 0.01em;
  color: var(--ink);
  margin: 0;
}

.main-subtitle {
  color: var(--muted);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.92rem;
  margin-top: 0.3rem;
  margin-bottom: 1.0rem;
}

.disclaimer {
  border: 1px solid var(--line);
  background: rgba(255,255,255,0.74);
  border-radius: 16px;
  padding: 0.8rem 1rem;
  color: var(--ink);
}

.metric-card {
  border: 1px solid var(--line);
  border-radius: 16px;
  background: var(--card);
  padding: 1rem;
  min-height: 92px;
}

.metric-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.78rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.09em;
}

.metric-value {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 1.55rem;
  font-weight: 700;
  color: var(--ink);
}

.device-card {
  border: 1px solid var(--line);
  border-radius: 20px;
  background: var(--card);
  padding: 1rem;
  margin-bottom: 0.8rem;
  animation: fadeup 380ms ease both;
}

.status-chip {
  display: inline-block;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.74rem;
  padding: 0.2rem 0.48rem;
  border-radius: 999px;
  font-weight: 500;
}

.status-ok { background: rgba(20, 125, 100, 0.12); color: var(--ok); }
.status-warning { background: rgba(187, 109, 0, 0.12); color: var(--warn); }
.status-error { background: rgba(168, 39, 0, 0.13); color: var(--err); }
.status-unknown { background: rgba(88, 96, 105, 0.12); color: #4f5a66; }

.alert-box {
  border-left: 3px solid #c6ccd2;
  padding-left: 0.7rem;
  margin-bottom: 0.45rem;
}
.alert-crit { border-left-color: var(--err); }
.alert-warn { border-left-color: var(--warn); }

.footer-note {
  color: var(--muted);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.82rem;
}

@keyframes fadeup {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
""",
    unsafe_allow_html=True,
)


if "results" not in st.session_state:
    st.session_state.results = []
if "run_at" not in st.session_state:
    st.session_state.run_at = None
if "csv_path" not in st.session_state:
    st.session_state.csv_path = ""
if "html_path" not in st.session_state:
    st.session_state.html_path = ""
if "db_path" not in st.session_state:
    st.session_state.db_path = ""


st.markdown("<h1 class='main-title'>RicohPulse Dashboard</h1>", unsafe_allow_html=True)
st.markdown(
    "<p class='main-subtitle'>One-click, read-only Ricoh health scan over SNMP GET/WALK only.</p>",
    unsafe_allow_html=True,
)

st.markdown(
    """
<div class='disclaimer'>
<b>Safety:</b> This app does <b>not</b> change Ricoh settings or network config. It only reads SNMP data and writes local files on this PC.
</div>
""",
    unsafe_allow_html=True,
)

left, right = st.columns([1, 1])
with left:
    subnet = st.text_input("Subnet", value=get_local_subnet(), help="Example: 192.168.1.0/24")
    manual_ips = st.text_input("Optional fixed IPs", placeholder="192.168.1.45 192.168.1.46")
    community = st.text_input("SNMP community", value="public")

with right:
    snmp_version = st.selectbox("SNMP version", options=["2c", "1"], index=0)
    workers = st.slider("Concurrency workers", min_value=10, max_value=200, value=80, step=10)
    timeout = st.slider("SNMP timeout (seconds)", min_value=0.2, max_value=2.0, value=0.8, step=0.1)

advanced = st.expander("Advanced options")
with advanced:
    retries = st.slider("Retries", min_value=0, max_value=3, value=0)
    repeat_threshold = st.slider("Repeated alert threshold", min_value=2, max_value=10, value=3)
    repeat_window = st.slider("Repeat window (minutes)", min_value=5, max_value=240, value=30)

run_scan = st.button("Run Scan", type="primary", use_container_width=True)

if run_scan:
    with st.spinner("Scanning subnet and checking Ricoh devices..."):
        args = SimpleNamespace(
            subnet=subnet.strip() or None,
            ips=[x.strip() for x in manual_ips.split() if x.strip()] if manual_ips.strip() else None,
            community=community.strip() or "public",
            snmp_version=snmp_version,
            timeout=float(timeout),
            retries=int(retries),
            workers=int(workers),
            max_hosts=1024,
            db="ricohpulse.db",
            csv="ricohpulse_report.csv",
            html="ricohpulse_report.html",
            repeat_threshold=int(repeat_threshold),
            repeat_window=int(repeat_window),
            watch=False,
            interval=300,
        )
        results = asyncio.run(run_once(args))
        st.session_state.results = results
        st.session_state.run_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.csv_path = str(Path(args.csv).resolve())
        st.session_state.html_path = str(Path(args.html).resolve())
        st.session_state.db_path = str(Path(args.db).resolve())

results = st.session_state.results

if results:
    total = len(results)
    ok_count = len([r for r in results if r.status == "ok"])
    warn_count = len([r for r in results if r.status == "warning"])
    err_count = len([r for r in results if r.status == "error"])

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown("<div class='metric-card'><div class='metric-label'>Devices</div><div class='metric-value'>%d</div></div>" % total, unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='metric-card'><div class='metric-label'>Healthy</div><div class='metric-value'>%d</div></div>" % ok_count, unsafe_allow_html=True)
    with c3:
        st.markdown("<div class='metric-card'><div class='metric-label'>Warnings</div><div class='metric-value'>%d</div></div>" % warn_count, unsafe_allow_html=True)
    with c4:
        st.markdown("<div class='metric-card'><div class='metric-label'>Errors</div><div class='metric-value'>%d</div></div>" % err_count, unsafe_allow_html=True)

    st.caption(f"Last run: {st.session_state.run_at}")

    rows = []
    for d in results:
        rows.append(
            {
                "IP": d.ip,
                "Status": d.status,
                "Hostname": d.hostname,
                "Model": d.model,
                "Serial": d.serial,
                "Alerts": len(d.alerts),
            }
        )

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.subheader("Device Details")
    for d in results:
        status_class = f"status-{d.status}" if d.status in ("ok", "warning", "error", "unknown") else "status-unknown"
        st.markdown("<div class='device-card'>", unsafe_allow_html=True)
        st.markdown(
            f"<b>{d.ip}</b> &nbsp; <span class='status-chip {status_class}'>{d.status.upper()}</span>",
            unsafe_allow_html=True,
        )
        st.write(f"Hostname: {d.hostname or '-'}")
        st.write(f"Model: {d.model or '-'}")
        st.write(f"Serial: {d.serial or '-'}")

        if d.alerts:
            st.markdown("**Alerts**")
            for a in d.alerts:
                cls = "alert-crit" if a.severity == "critical" else "alert-warn"
                st.markdown(f"<div class='alert-box {cls}'>", unsafe_allow_html=True)
                st.write(f"{a.severity.upper()}: {a.description}")
                if a.code:
                    st.write(f"Code: {a.code}")
                st.write(f"Fix: {a.fix}")
                if a.repeated_count:
                    st.write(f"Repeated count in window: {a.repeated_count}")
                st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.success("No active critical/warning alerts.")

        for note in d.notes:
            st.info(note)

        st.markdown("</div>", unsafe_allow_html=True)

    st.subheader("Generated Local Files")
    st.write(f"CSV: {st.session_state.csv_path}")
    st.write(f"HTML: {st.session_state.html_path}")
    st.write(f"SQLite DB: {st.session_state.db_path}")

    csv_file = Path("ricohpulse_report.csv")
    if csv_file.exists():
        st.download_button(
            label="Download CSV",
            data=csv_file.read_bytes(),
            file_name=csv_file.name,
            mime="text/csv",
            use_container_width=True,
        )

    html_file = Path("ricohpulse_report.html")
    if html_file.exists():
        st.download_button(
            label="Download HTML",
            data=html_file.read_bytes(),
            file_name=html_file.name,
            mime="text/html",
            use_container_width=True,
        )

st.markdown(
    "<p class='footer-note'>SNMP may not expose every scan-to-folder/email job-level failure. For those, check Ricoh web UI job logs and destination server/email logs.</p>",
    unsafe_allow_html=True,
)
