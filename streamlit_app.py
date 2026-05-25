from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import streamlit as st

import smtplib
import socket
import ssl
import subprocess

from ricohpulse import run_once, get_local_subnet


# ── Connectivity test helpers ─────────────────────────────────────────────────

def _smb_port_open(host: str) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, 445), timeout=4):
            return True, "Port 445 is reachable."
    except OSError as exc:
        return False, f"Port 445 unreachable: {exc}"


def _smb_share(unc: str) -> str:
    parts = unc.strip("\\").split("\\")
    return f"\\\\{parts[0]}\\{parts[1]}" if len(parts) >= 2 else unc


def _smb_auth_windows(unc: str, username: str, password: str) -> tuple[bool, str]:
    share = _smb_share(unc)
    try:
        subprocess.run(["net", "use", share, "/delete", "/y"], capture_output=True, timeout=6)
        r = subprocess.run(
            ["net", "use", share, f"/user:{username}", password],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            subprocess.run(["net", "use", share, "/delete", "/y"], capture_output=True, timeout=6)
            return True, "Authentication successful — share is accessible."
        return False, (r.stderr or r.stdout).strip() or "Authentication failed (unknown error)."
    except Exception as exc:
        return False, str(exc)


def _smtp_test(server: str, port: int, username: str, password: str, use_ssl: bool) -> tuple[bool, str]:
    ctx = ssl.create_default_context()
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(server, port, context=ctx, timeout=6) as s:
                s.login(username, password)
            return True, f"SSL connection to {server}:{port} and login OK."
        else:
            with smtplib.SMTP(server, port, timeout=6) as s:
                s.ehlo()
                s.starttls(context=ctx)
                s.login(username, password)
            return True, f"STARTTLS connection to {server}:{port} and login OK."
    except smtplib.SMTPAuthenticationError:
        return False, "Authentication failed — check username / password."
    except smtplib.SMTPConnectError as exc:
        return False, f"Could not connect: {exc}"
    except Exception as exc:
        return False, str(exc)


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
<b>Safety:</b> This app is <b>read-only</b> — it sends SNMP GET/WALK only and never changes Ricoh settings.<br>
<b>SNMP limitation:</b> Device-level alerts (paper jams, toner, covers, offline) <b>are</b> visible here.
Job-level failures — wrong SMB folder password, missing share, Microsoft&nbsp;365 SMTP auth errors — <b>may not appear in SNMP</b>.
For those, use the <b>Test Scan Destinations</b> section below, or check the Ricoh web&nbsp;UI job&nbsp;log.
</div>
""",
    unsafe_allow_html=True,
)

# ── Scan mode ─────────────────────────────────────────────────────────────
use_ips_mode = st.radio(
    "Scan mode",
    ["📍 Enter scanner IPs (recommended)", "🔍 Auto-scan subnet"],
    index=0,
    horizontal=True,
    label_visibility="collapsed",
)
use_ips = use_ips_mode.startswith("📍")

if use_ips:
    st.markdown("#### Enter your Ricoh scanner IP addresses")
    st.caption(
        "Paste the IPs of your C5500 / C300 scanners — one per line or space-separated. "
        "The scanner will go straight to these addresses without needing to sweep the whole subnet."
    )
    ip_textarea = st.text_area(
        "Scanner IP addresses",
        placeholder="192.168.1.45\n192.168.1.46\n192.168.1.50",
        height=130,
        label_visibility="collapsed",
    )
    col_a, col_b = st.columns(2)
    with col_a:
        community = st.text_input("SNMP community", value="public")
    with col_b:
        snmp_version = st.selectbox("SNMP version", options=["2c", "1"], index=0)
    subnet = None
    workers = 80
    timeout = 0.8
else:
    st.markdown("#### Auto-scan subnet")
    subnet = st.text_input("Subnet", value=get_local_subnet(), help="Example: 192.168.1.0/24")
    col_c, col_d, col_e = st.columns(3)
    with col_c:
        community = st.text_input("SNMP community", value="public")
    with col_d:
        snmp_version = st.selectbox("SNMP version", options=["2c", "1"], index=0)
    with col_e:
        workers = st.slider("Workers", min_value=10, max_value=200, value=80, step=10)
    timeout = st.slider("SNMP timeout (seconds)", min_value=0.2, max_value=2.0, value=0.8, step=0.1)
    ip_textarea = ""

# ── Model filter ───────────────────────────────────────────────────────────
filter_model = st.checkbox(
    "Only show Ricoh C5500 / C300 results",
    value=True,
    help="Hides any other Ricoh models that respond. Uncheck to see all Ricoh devices.",
)

advanced = st.expander("Advanced options")
with advanced:
    retries = st.slider("Retries", min_value=0, max_value=3, value=0)
    repeat_threshold = st.slider("Repeated alert threshold", min_value=2, max_value=10, value=3)
    repeat_window = st.slider("Repeat window (minutes)", min_value=5, max_value=240, value=30)
    web_scan = st.checkbox(
        "Scrape Web Image Monitor for failed scan jobs",
        value=False,
        help=(
            "Attempts a read-only HTTP GET on each device\'s job-history page. "
            "Catches scan-to-folder / scan-to-email failures that SNMP alone misses. "
            "Adds a few seconds per device. Safe — no POST, no config changes."
        ),
    )

run_scan = st.button("Run Scan", type="primary", use_container_width=True)

if run_scan:
    parsed_ips = (
        [x.strip() for x in ip_textarea.replace("\n", " ").split() if x.strip()]
        if use_ips else None
    )
    if use_ips and not parsed_ips:
        st.error("Please enter at least one scanner IP address above.")
        st.stop()

    spinner_msg = "Checking Ricoh devices..." if use_ips else "Scanning subnet and checking Ricoh devices..."
    with st.spinner(spinner_msg):
        args = SimpleNamespace(
            subnet=subnet,
            ips=parsed_ips,
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
            web_scan=web_scan,
        )
        results = asyncio.run(run_once(args))
        st.session_state.results = results
        st.session_state.run_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.csv_path = str(Path(args.csv).resolve())
        st.session_state.html_path = str(Path(args.html).resolve())
        st.session_state.db_path = str(Path(args.db).resolve())
        st.session_state.filter_model = filter_model

results = st.session_state.results

# Apply C5500 / C300 model filter if it was active during the last scan
_filter_model = st.session_state.get("filter_model", True)
_MODEL_KW = ("c5500", "c300", "c 5500", "c 300", "im c5500", "im c300")
if _filter_model and results:
    results = [
        r for r in results
        if any(kw in (r.model + " " + r.sys_descr).lower() for kw in _MODEL_KW)
    ]
    if not results:
        st.warning(
            "No C5500 or C300 devices were found in the last scan results. "
            "Uncheck **Only show Ricoh C5500 / C300 results** and re-run to see all Ricoh devices."
        )

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
            f"<b>{d.ip}</b> &nbsp; <span class='status-chip {status_class}'>{d.status.upper()}</span>"
            f" &nbsp; <a href='http://{d.ip}/' target='_blank' style='font-size:0.82rem;color:#1a73e8;text-decoration:none;'>Open Ricoh web UI ↗</a>",
            unsafe_allow_html=True,
        )
        st.write(f"Hostname: {d.hostname or '-'}")
        st.write(f"Model: {d.model or '-'}")
        st.write(f"Serial: {d.serial or '-'}")

        if d.alerts:
            # Show a scan-job failure banner if any alert came from job logs
            scan_job_alerts = [
                a for a in d.alerts
                if "job" in a.source.lower() or a.code == "SCAN_JOB_FAIL"
                or "scan job" in a.description.lower()
            ]
            if scan_job_alerts:
                st.warning(
                    f"⚠️ {len(scan_job_alerts)} scan-job failure(s) detected — "
                    "likely a credentials, path, or SMTP problem not visible in SNMP."
                )

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

# ── Scan destination tests ───────────────────────────────────────────────────
st.divider()
with st.expander("🔧 Test scan destinations (scan-to-folder & scan-to-email)", expanded=False):
    st.caption(
        "Use these tests when a Ricoh device shows no SNMP alert but users still cannot scan. "
        "These tests check the actual destination — independent of the SNMP scan above."
    )

    st.markdown("##### Scan-to-Folder (SMB / Windows share)")
    smb_col1, smb_col2 = st.columns([2, 1])
    with smb_col1:
        smb_unc = st.text_input(
            "UNC path",
            placeholder=r"\\server\ScanFolder  or  \\192.168.1.10\scans",
            key="smb_unc",
        )
    with smb_col2:
        smb_host_override = st.text_input("Server IP (for port test)", placeholder="auto", key="smb_host")

    smb_user = st.text_input("Username", placeholder="DOMAIN\\user  or  user@domain.com", key="smb_user")
    smb_pass = st.text_input("Password", type="password", key="smb_pass")

    if st.button("Test SMB connection", key="btn_smb"):
        if not smb_unc.strip():
            st.error("Enter a UNC path first.")
        else:
            host = smb_host_override.strip() or smb_unc.strip("\\").split("\\")[0]
            with st.spinner(f"Testing port 445 on {host}..."):
                ok, msg = _smb_port_open(host)
            if ok:
                st.success(f"Port check: {msg}")
                if smb_user.strip():
                    with st.spinner("Testing SMB authentication..."):
                        ok2, msg2 = _smb_auth_windows(smb_unc.strip(), smb_user.strip(), smb_pass)
                    if ok2:
                        st.success(f"Auth check: {msg2}")
                    else:
                        st.error(f"Auth check failed: {msg2}")
                        st.info(
                            "Fix: Check the UNC path, username (try DOMAIN\\\\user or user@domain.com), "
                            "password, share permissions, and NTFS permissions on the destination folder."
                        )
                else:
                    st.info("Enter a username + password above to also test SMB authentication.")
            else:
                st.error(f"Port check failed: {msg}")
                st.info("Fix: Ensure the file server is reachable and Windows file sharing (port 445) is not blocked by a firewall.")

    st.markdown("---")
    st.markdown("##### Scan-to-Email (SMTP)")
    mail_col1, mail_col2, mail_col3 = st.columns([2, 1, 1])
    with mail_col1:
        smtp_server = st.text_input("SMTP server", placeholder="smtp.office365.com", key="smtp_srv")
    with mail_col2:
        smtp_port = st.number_input("Port", min_value=1, max_value=65535, value=587, key="smtp_port")
    with mail_col3:
        smtp_ssl = st.checkbox("Use SSL (port 465)", value=False, key="smtp_ssl")

    smtp_user = st.text_input("SMTP username / email", key="smtp_user")
    smtp_pass = st.text_input("SMTP password", type="password", key="smtp_pass")

    if st.button("Test SMTP connection", key="btn_smtp"):
        if not smtp_server.strip():
            st.error("Enter an SMTP server first.")
        else:
            with st.spinner(f"Connecting to {smtp_server}:{smtp_port}..."):
                ok, msg = _smtp_test(
                    smtp_server.strip(), int(smtp_port),
                    smtp_user.strip(), smtp_pass, smtp_ssl,
                )
            if ok:
                st.success(msg)
            else:
                st.error(msg)
                st.info(
                    "Fix: Check SMTP server address, port (587=STARTTLS, 465=SSL), "
                    "username/password, and whether the account requires an app password "
                    "(Microsoft 365 / Gmail with MFA enabled)."
                )

st.markdown(
    "<p class='footer-note'>Device-level SNMP alerts are shown in the scan above. "
    "Job-level failures (wrong SMB credentials, SMTP auth) may not appear in SNMP — use the test section above.</p>",
    unsafe_allow_html=True,
)
