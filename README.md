# RicohPulse Dashboard

A read-only Ricoh discovery and health monitor with a modern local web UI.

## Read-only guarantee

This app does not modify Ricoh devices or network settings.

- Scans local subnet IPs: no device changes
- Sends SNMP GET/WALK only: no device changes
- Reads model, serial, alerts: no device changes
- Writes local files on this computer only:
  - `ricohpulse.db`
  - `ricohpulse_report.csv`
  - `ricohpulse_report.html`

It does not send SNMP SET and cannot change Ricoh configuration.

## Quick start (UI)

1. Double-click `run_ui.bat`
2. Browser opens Streamlit dashboard.
3. Click **Run Scan**.

## Console mode

Double-click `run_console.bat`.

## Manual commands

```powershell
py -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
streamlit run streamlit_app.py
```

## Core script

- `ricohpulse.py` contains scanner logic and report exporters.
- `streamlit_app.py` provides dashboard UI.

## Limitation

SNMP catches many device-level errors, but some scan-to-folder/scan-to-email job failures may only appear in Ricoh job logs or destination service logs.
