#!/usr/bin/env python3
"""
RicohPulse v1 - Auto Discovery and Health Monitor for Ricoh MFPs

This scanner is read-only for network devices:
- Uses SNMP GET/WALK only.
- Does not send SNMP SET.
- Does not modify Ricoh configuration.

Local side effects only:
- Creates SQLite/CSV/HTML files on the local machine.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import html
import ipaddress
import json
import os
import socket
import sqlite3
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from pysnmp.hlapi.v1arch.asyncio import (
        CommunityData,
        ObjectIdentity,
        ObjectType,
        SnmpDispatcher,
        UdpTransportTarget,
        get_cmd,
        walk_cmd,
    )
except Exception as exc:  # pragma: no cover - gives user-friendly install error
    print("ERROR: PySNMP is not installed or is incompatible.")
    print("Fix: pip install -r requirements.txt")
    print(f"Original error: {exc}")
    sys.exit(1)

# Standard OIDs
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

OID_PRT_GENERAL_PRINTER_NAME = "1.3.6.1.2.1.43.5.1.1.16.1"
OID_PRT_GENERAL_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"

OID_PRT_ALERT_SEVERITY = "1.3.6.1.2.1.43.18.1.1.2"
OID_PRT_ALERT_CODE = "1.3.6.1.2.1.43.18.1.1.7"
OID_PRT_ALERT_DESCR = "1.3.6.1.2.1.43.18.1.1.8"
OID_PRT_ALERT_TIME = "1.3.6.1.2.1.43.18.1.1.9"

OID_HR_DEVICE_DESCR = "1.3.6.1.2.1.25.3.2.1.3"
OID_HR_DEVICE_STATUS = "1.3.6.1.2.1.25.3.2.1.5"

RICOH_ENTERPRISE_PREFIX = "1.3.6.1.4.1.367"

HR_STATUS = {
    "1": "unknown",
    "2": "running",
    "3": "warning",
    "4": "testing",
    "5": "down",
}

ALERT_SEVERITY = {
    "1": "other",
    "3": "critical",
    "4": "warning",
}

FIX_TIPS: List[Tuple[Tuple[str, ...], str]] = [
    (("jam", "misfeed"), "Open the paper path, trays and side covers. Remove jammed/misfed paper, then close covers firmly."),
    (("toner", "marker supply", "ink", "cartridge"), "Check toner/ink level and replace the cartridge if it is low, empty, or missing."),
    (("paper empty", "paper out", "out of paper", "tray empty", "input tray"), "Refill the correct paper tray and check paper size/type settings."),
    (("tray", "cassette"), "Check the named tray/cassette: make sure it is inserted, loaded, and set to the correct paper size."),
    (("cover", "door", "interlock"), "Close all doors/covers firmly. Open and close them again if the device still reports the error."),
    (("offline", "off-line", "not ready"), "Check power/network cable, then restart the Ricoh. Confirm it is online on the device screen."),
    (("scanner", "scan"), "Restart the Ricoh scanner function. Then test scan-to-folder/email from the device panel."),
    (("smtp", "email", "mail"), "Check scan-to-email SMTP server, username/password, port, TLS, and Microsoft 365 connector/settings."),
    (("smb", "folder", "login", "authentication", "auth", "access denied", "password"), "Check scan-to-folder path, username, password, share permissions, and NTFS permissions on the destination folder."),
    (("service", "fuser", "drum", "motor", "temperature", "thermistor"), "This may need engineer/service support. Power-cycle once; if it returns, raise a Ricoh service call."),
    (("waste", "full"), "Empty/replace the waste toner or full output/waste container mentioned by the device."),
]


@dataclass
class Alert:
    source: str
    severity: str
    code: str
    description: str
    index: str = ""
    repeated_count: int = 1
    fix: str = ""

    @property
    def key(self) -> str:
        raw = f"{self.source}|{self.code}|{self.description}".strip().lower()
        raw = " ".join(raw.split())
        return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


@dataclass
class DeviceResult:
    ip: str
    status: str
    is_ricoh: bool
    sys_descr: str = ""
    sys_object_id: str = ""
    hostname: str = ""
    model: str = ""
    serial: str = ""
    alerts: List[Alert] = None
    notes: List[str] = None

    def __post_init__(self) -> None:
        if self.alerts is None:
            self.alerts = []
        if self.notes is None:
            self.notes = []


class RicohPulseDB:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                hostname TEXT,
                model TEXT,
                serial TEXT,
                sys_descr TEXT,
                sys_object_id TEXT,
                last_status TEXT
            );

            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checked_at TEXT NOT NULL,
                ip TEXT NOT NULL,
                status TEXT NOT NULL,
                alert_count INTEGER NOT NULL,
                alerts_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS error_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                ip TEXT NOT NULL,
                alert_key TEXT NOT NULL,
                source TEXT,
                severity TEXT,
                code TEXT,
                description TEXT,
                fix TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_error_events_lookup
            ON error_events(ip, alert_key, event_time);
            """
        )
        self.conn.commit()

    def save_result(self, result: DeviceResult) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        self.conn.execute(
            """
            INSERT INTO devices(ip, first_seen, last_seen, hostname, model, serial, sys_descr, sys_object_id, last_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen=excluded.last_seen,
                hostname=excluded.hostname,
                model=excluded.model,
                serial=excluded.serial,
                sys_descr=excluded.sys_descr,
                sys_object_id=excluded.sys_object_id,
                last_status=excluded.last_status
            """,
            (
                result.ip,
                now,
                now,
                result.hostname,
                result.model,
                result.serial,
                result.sys_descr,
                result.sys_object_id,
                result.status,
            ),
        )
        alerts_payload = [asdict(alert) | {"key": alert.key} for alert in result.alerts]
        self.conn.execute(
            """
            INSERT INTO checks(checked_at, ip, status, alert_count, alerts_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (now, result.ip, result.status, len(result.alerts), json.dumps(alerts_payload)),
        )
        for alert in result.alerts:
            self.conn.execute(
                """
                INSERT INTO error_events(event_time, ip, alert_key, source, severity, code, description, fix)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (now, result.ip, alert.key, alert.source, alert.severity, alert.code, alert.description, alert.fix),
            )
        self.conn.commit()

    def repeated_count(self, ip: str, alert_key: str, window_minutes: int) -> int:
        since = (datetime.now() - timedelta(minutes=window_minutes)).isoformat(timespec="seconds")
        row = self.conn.execute(
            """
            SELECT COUNT(*) FROM error_events
            WHERE ip = ? AND alert_key = ? AND event_time >= ?
            """,
            (ip, alert_key, since),
        ).fetchone()
        return int(row[0] or 0)

    def close(self) -> None:
        self.conn.close()


class SnmpClient:
    def __init__(self, community: str, snmp_version: str, timeout: float, retries: int) -> None:
        self.dispatcher = SnmpDispatcher()
        mp_model = 0 if snmp_version == "1" else 1
        self.auth = CommunityData(community, mpModel=mp_model)
        self.timeout = timeout
        self.retries = retries

    async def target(self, ip: str):
        return await UdpTransportTarget.create((ip, 161), timeout=self.timeout, retries=self.retries)

    async def get(self, ip: str, oid: str) -> Optional[str]:
        try:
            err_ind, err_status, err_index, var_binds = await get_cmd(
                self.dispatcher,
                self.auth,
                await self.target(ip),
                ObjectType(ObjectIdentity(oid)),
                lookupMib=False,
            )
            if err_ind or err_status:
                return None
            if not var_binds:
                return None
            value = var_binds[0][1]
            return str(value.prettyPrint() if hasattr(value, "prettyPrint") else value).strip()
        except Exception:
            return None

    async def walk(self, ip: str, base_oid: str, max_rows: int = 200) -> Dict[str, str]:
        rows: Dict[str, str] = {}
        try:
            iterator = walk_cmd(
                self.dispatcher,
                self.auth,
                await self.target(ip),
                ObjectType(ObjectIdentity(base_oid)),
                lookupMib=False,
                lexicographicMode=False,
                maxRows=max_rows,
            )
            async for err_ind, err_status, err_index, var_binds in iterator:
                if err_ind or err_status:
                    break
                for oid_obj, value_obj in var_binds:
                    oid = str(oid_obj.prettyPrint() if hasattr(oid_obj, "prettyPrint") else oid_obj)
                    value = str(value_obj.prettyPrint() if hasattr(value_obj, "prettyPrint") else value_obj).strip()
                    suffix = suffix_after_base(oid, base_oid)
                    if suffix:
                        rows[suffix] = value
        except Exception:
            pass
        return rows

    def close(self) -> None:
        try:
            self.dispatcher.closeDispatcher()
        except Exception:
            try:
                self.dispatcher.close_dispatcher()
            except Exception:
                pass


def suffix_after_base(full_oid: str, base_oid: str) -> str:
    full_oid = full_oid.strip(".")
    base_oid = base_oid.strip(".")
    if full_oid == base_oid:
        return ""
    prefix = base_oid + "."
    if full_oid.startswith(prefix):
        return full_oid[len(prefix):]
    return ""


def get_local_subnet() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        sock.close()
    return str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))


def safe_network(subnet: str, max_hosts: int = 1024) -> ipaddress.IPv4Network:
    network = ipaddress.IPv4Network(subnet, strict=False)
    if network.num_addresses - 2 > max_hosts:
        raise ValueError(
            f"Subnet {network} is too large for a quick office scan. "
            f"Use a smaller range like 192.168.1.0/24."
        )
    return network


def is_probably_ricoh(sys_descr: str, sys_object_id: str) -> bool:
    haystack = f"{sys_descr} {sys_object_id}".lower()
    if sys_object_id.startswith(RICOH_ENTERPRISE_PREFIX):
        return True
    return any(token in haystack for token in ("ricoh", "nrg", "nr-g", "aficio", "imagio"))


def guess_model(sys_descr: str, printer_name: str) -> str:
    if printer_name and "no such" not in printer_name.lower():
        return printer_name.strip()
    if not sys_descr:
        return ""
    cleaned = sys_descr.replace("NRG", "").replace("NR-G", "")
    cleaned = " ".join(cleaned.split())
    return cleaned[:120]


def find_fix(alert_text: str) -> str:
    lower = alert_text.lower()
    for keywords, fix in FIX_TIPS:
        if any(keyword in lower for keyword in keywords):
            return fix
    return "Check the Ricoh device panel/web page for exact details, then clear the active alert and re-test scanning/printing."


def status_from_alerts(alerts: List[Alert]) -> str:
    if any(a.severity == "critical" for a in alerts):
        return "error"
    if any(a.severity in ("warning", "down") for a in alerts):
        return "warning"
    return "ok"


async def probe_is_ricoh(ip: str, snmp: SnmpClient) -> Optional[Tuple[str, str, str]]:
    sys_descr, sys_object_id = await asyncio.gather(
        snmp.get(ip, OID_SYS_DESCR),
        snmp.get(ip, OID_SYS_OBJECT_ID),
    )
    if not sys_descr and not sys_object_id:
        return None
    sys_descr = sys_descr or ""
    sys_object_id = sys_object_id or ""
    if is_probably_ricoh(sys_descr, sys_object_id):
        return ip, sys_descr, sys_object_id
    return None


async def discover_ricoh_devices(network: ipaddress.IPv4Network, snmp: SnmpClient, workers: int) -> List[Tuple[str, str, str]]:
    ips = [str(ip) for ip in network.hosts()]
    semaphore = asyncio.Semaphore(workers)
    found: List[Tuple[str, str, str]] = []

    async def task(ip: str):
        async with semaphore:
            result = await probe_is_ricoh(ip, snmp)
            if result:
                found.append(result)

    await asyncio.gather(*(task(ip) for ip in ips))
    found.sort(key=lambda row: ipaddress.IPv4Address(row[0]))
    return found


async def check_device(ip: str, snmp: SnmpClient, db: RicohPulseDB, repeat_window: int) -> DeviceResult:
    sys_descr, sys_object_id, hostname, printer_name, serial = await asyncio.gather(
        snmp.get(ip, OID_SYS_DESCR),
        snmp.get(ip, OID_SYS_OBJECT_ID),
        snmp.get(ip, OID_SYS_NAME),
        snmp.get(ip, OID_PRT_GENERAL_PRINTER_NAME),
        snmp.get(ip, OID_PRT_GENERAL_SERIAL),
    )

    if not sys_descr and not sys_object_id:
        alert = Alert(
            source="SNMP",
            severity="critical",
            code="NO_RESPONSE",
            description="No SNMP response during health check",
            fix="Check power/network cable and confirm SNMP is enabled on the Ricoh web interface.",
        )
        alert.repeated_count = db.repeated_count(ip, alert.key, repeat_window)
        return DeviceResult(ip=ip, status="error", is_ricoh=False, alerts=[alert], notes=["Device was discovered earlier but did not respond now."])

    sys_descr = sys_descr or ""
    sys_object_id = sys_object_id or ""
    result = DeviceResult(
        ip=ip,
        status="unknown",
        is_ricoh=is_probably_ricoh(sys_descr, sys_object_id),
        sys_descr=sys_descr,
        sys_object_id=sys_object_id,
        hostname=hostname or "",
        model=guess_model(sys_descr, printer_name or ""),
        serial=serial or "",
    )

    severities, codes, descriptions, times = await asyncio.gather(
        snmp.walk(ip, OID_PRT_ALERT_SEVERITY),
        snmp.walk(ip, OID_PRT_ALERT_CODE),
        snmp.walk(ip, OID_PRT_ALERT_DESCR),
        snmp.walk(ip, OID_PRT_ALERT_TIME),
    )

    for idx, sev_value in sorted(severities.items()):
        severity = ALERT_SEVERITY.get(sev_value, f"other({sev_value})")
        if severity not in ("critical", "warning"):
            continue
        code = codes.get(idx, "")
        descr = descriptions.get(idx, "").strip()
        if not descr or "no such" in descr.lower():
            descr = f"Printer alert code {code or 'unknown'}"
        text_for_fix = f"{severity} {code} {descr} {times.get(idx, '')}"
        alert = Alert(
            source="Printer-MIB prtAlertTable",
            severity=severity,
            code=code,
            description=descr,
            index=idx,
            fix=find_fix(text_for_fix),
        )
        alert.repeated_count = db.repeated_count(ip, alert.key, repeat_window) + 1
        result.alerts.append(alert)

    hr_descrs, hr_statuses = await asyncio.gather(
        snmp.walk(ip, OID_HR_DEVICE_DESCR, max_rows=300),
        snmp.walk(ip, OID_HR_DEVICE_STATUS, max_rows=300),
    )
    for idx, status_value in sorted(hr_statuses.items()):
        status_text = HR_STATUS.get(status_value, f"unknown({status_value})")
        descr = hr_descrs.get(idx, "Host resource device")
        descr_lower = descr.lower()
        relevant = any(word in descr_lower for word in ("printer", "scanner", "mfp", "ricoh", "print")) or status_text in ("warning", "down")
        if not relevant:
            continue
        if status_text in ("warning", "down"):
            severity = "critical" if status_text == "down" else "warning"
            alert = Alert(
                source="HOST-RESOURCES-MIB hrDeviceStatus",
                severity=severity,
                code=status_value,
                description=f"{descr}: {status_text}",
                index=idx,
                fix=find_fix(f"{descr} {status_text}"),
            )
            alert.repeated_count = db.repeated_count(ip, alert.key, repeat_window) + 1
            result.alerts.append(alert)

    result.status = status_from_alerts(result.alerts)
    if not result.is_ricoh:
        result.notes.append("SNMP responded, but the Ricoh identity check was uncertain.")
    if not result.alerts:
        result.notes.append("No active critical/warning SNMP alerts were found.")
    return result


def update_repeated_labels(results: List[DeviceResult], threshold: int) -> None:
    for result in results:
        for alert in result.alerts:
            if alert.repeated_count >= threshold and result.status != "error":
                result.status = "warning"


def print_report(results: List[DeviceResult], repeat_threshold: int, repeat_window: int) -> None:
    if not results:
        print("No Ricoh devices found/responding on this subnet.")
        return

    print("\n" + "=" * 78)
    print("RicohPulse Report")
    print("=" * 78)
    for r in results:
        symbol = {"ok": "GREEN", "warning": "YELLOW", "error": "RED", "unknown": "GREY"}.get(r.status, "GREY")
        print(f"\n[{symbol}] {r.ip}  {r.status.upper()}")
        if r.hostname:
            print(f"  Hostname: {r.hostname}")
        if r.model:
            print(f"  Model:    {r.model}")
        if r.serial:
            print(f"  Serial:   {r.serial}")

        if r.alerts:
            print("  Alerts:")
            for a in r.alerts:
                repeated = ""
                if a.repeated_count >= repeat_threshold:
                    repeated = f"  [REPEATED {a.repeated_count} times in {repeat_window} min]"
                print(f"    - {a.severity.upper()}: {a.description}{repeated}")
                if a.code:
                    print(f"      Code/source: {a.code} / {a.source}")
                print(f"      Fix: {a.fix}")
        else:
            print("  OK: No active critical/warning SNMP alerts.")
        for note in r.notes:
            print(f"  Note: {note}")

    print("\n" + "=" * 78)
    print("Important: SNMP may not show every scan-to-folder or scan-to-email job error.")
    print("If users still cannot scan, check the Ricoh web UI job logs and the destination server/email logs.")
    print("=" * 78)


def write_csv(results: List[DeviceResult], path: str | Path) -> None:
    path = Path(path)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["time", "ip", "status", "hostname", "model", "serial", "severity", "alert", "code", "repeated_count", "fix"])
        now = datetime.now().isoformat(timespec="seconds")
        for r in results:
            if not r.alerts:
                writer.writerow([now, r.ip, r.status, r.hostname, r.model, r.serial, "", "No active alerts", "", "", ""])
            for a in r.alerts:
                writer.writerow([now, r.ip, r.status, r.hostname, r.model, r.serial, a.severity, a.description, a.code, a.repeated_count, a.fix])


def write_html(results: List[DeviceResult], path: str | Path, repeat_threshold: int, repeat_window: int) -> None:
    path = Path(path)
    cards = []
    for r in results:
        status_class = html.escape(r.status)
        alerts_html = ""
        if r.alerts:
            items = []
            for a in r.alerts:
                repeated = ""
                if a.repeated_count >= repeat_threshold:
                    repeated = f" <strong class='repeat'>Repeated {a.repeated_count} times in {repeat_window} min</strong>"
                items.append(
                    f"<li><strong>{html.escape(a.severity.upper())}</strong>: {html.escape(a.description)}{repeated}"
                    f"<br><small>{html.escape(a.source)} | Code: {html.escape(a.code)}</small>"
                    f"<br><em>Fix:</em> {html.escape(a.fix)}</li>"
                )
            alerts_html = "<ul>" + "\n".join(items) + "</ul>"
        else:
            alerts_html = "<p>No active critical/warning SNMP alerts.</p>"
        notes_html = "".join(f"<p class='note'>{html.escape(n)}</p>" for n in r.notes)
        cards.append(
            f"""
            <section class=\"card {status_class}\">
                <h2>{html.escape(r.ip)} <span>{html.escape(r.status.upper())}</span></h2>
                <p><b>Hostname:</b> {html.escape(r.hostname or '-')}</p>
                <p><b>Model:</b> {html.escape(r.model or '-')}</p>
                <p><b>Serial:</b> {html.escape(r.serial or '-')}</p>
                {alerts_html}
                {notes_html}
            </section>
            """
        )

    content = f"""
<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>RicohPulse Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; background: #f6f7f9; color: #202124; }}
h1 {{ margin-bottom: 4px; }}
.meta {{ color: #555; margin-bottom: 20px; }}
.card {{ background: white; border-left: 10px solid #999; border-radius: 10px; padding: 16px; margin: 14px 0; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
.card.ok {{ border-left-color: #0b8043; }}
.card.warning {{ border-left-color: #f9ab00; }}
.card.error {{ border-left-color: #c5221f; }}
.card h2 {{ margin: 0 0 8px; }}
.card h2 span {{ font-size: 0.75em; color: #555; margin-left: 10px; }}
li {{ margin-bottom: 12px; }}
.repeat {{ color: #c5221f; }}
.note {{ color: #555; }}
</style>
</head>
<body>
<h1>RicohPulse Report</h1>
<p class=\"meta\">Generated {html.escape(datetime.now().isoformat(timespec='seconds'))}</p>
{''.join(cards) if cards else '<p>No Ricoh devices found.</p>'}
</body>
</html>
"""
    path.write_text(content, encoding="utf-8")


async def run_once(args) -> List[DeviceResult]:
    subnet = args.subnet or get_local_subnet()
    network = safe_network(subnet, max_hosts=args.max_hosts)
    print(f"Scanning subnet: {network}")
    print(f"SNMP: v{args.snmp_version}, community='{args.community}', timeout={args.timeout}s, retries={args.retries}")

    db = RicohPulseDB(args.db)
    snmp = SnmpClient(args.community, args.snmp_version, args.timeout, args.retries)
    try:
        if args.ips:
            initial_devices = []
            for ip in args.ips:
                sys_descr = await snmp.get(ip, OID_SYS_DESCR) or ""
                sys_object_id = await snmp.get(ip, OID_SYS_OBJECT_ID) or ""
                if sys_descr or sys_object_id:
                    initial_devices.append((ip, sys_descr, sys_object_id))
                else:
                    print(f"  No SNMP response from manually supplied IP: {ip}")
        else:
            initial_devices = await discover_ricoh_devices(network, snmp, args.workers)

        results: List[DeviceResult] = []
        for ip, _sys_descr, _sys_object_id in initial_devices:
            result = await check_device(ip, snmp, db, args.repeat_window)
            db.save_result(result)
            results.append(result)

        update_repeated_labels(results, args.repeat_threshold)
        print_report(results, args.repeat_threshold, args.repeat_window)
        write_csv(results, args.csv)
        write_html(results, args.html, args.repeat_threshold, args.repeat_window)
        print(f"\nSaved CSV report:  {Path(args.csv).resolve()}")
        print(f"Saved HTML report: {Path(args.html).resolve()}")
        print(f"Saved history DB:  {Path(args.db).resolve()}")
        return results
    finally:
        snmp.close()
        db.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RicohPulse - Ricoh MFP auto-discovery and health monitor")
    parser.add_argument("--subnet", help="Subnet to scan, e.g. 192.168.1.0/24. Default: auto-detect local /24.")
    parser.add_argument("--ips", nargs="*", help="Optional fixed IPs to check instead of scanning, e.g. --ips 192.168.1.20 192.168.1.21")
    parser.add_argument("--community", default=os.environ.get("SNMP_COMMUNITY", "public"), help="SNMP v1/v2c community. Default: public or SNMP_COMMUNITY env var.")
    parser.add_argument("--snmp-version", choices=["1", "2c"], default="2c", help="SNMP version. Default: 2c.")
    parser.add_argument("--timeout", type=float, default=0.8, help="SNMP timeout seconds. Default: 0.8")
    parser.add_argument("--retries", type=int, default=0, help="SNMP retries. Default: 0 for fast discovery.")
    parser.add_argument("--workers", type=int, default=80, help="Concurrent probes. Default: 80")
    parser.add_argument("--max-hosts", type=int, default=1024, help="Safety limit for subnet size. Default: 1024 hosts")
    parser.add_argument("--db", default="ricohpulse.db", help="SQLite history database path. Default: ricohpulse.db")
    parser.add_argument("--csv", default="ricohpulse_report.csv", help="CSV report output path. Default: ricohpulse_report.csv")
    parser.add_argument("--html", default="ricohpulse_report.html", help="HTML report output path. Default: ricohpulse_report.html")
    parser.add_argument("--repeat-threshold", type=int, default=3, help="Repeated error threshold. Default: 3")
    parser.add_argument("--repeat-window", type=int, default=30, help="Repeated error window in minutes. Default: 30")
    parser.add_argument("--watch", action="store_true", help="Keep monitoring instead of running once.")
    parser.add_argument("--interval", type=int, default=300, help="Seconds between checks in watch mode. Default: 300")
    return parser


async def main_async() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.watch:
        print("RicohPulse watch mode started. Press Ctrl+C to stop.")
        while True:
            try:
                await run_once(args)
                print(f"\nNext check in {args.interval} seconds...\n")
                await asyncio.sleep(args.interval)
            except KeyboardInterrupt:
                print("\nStopped by user.")
                return
            except Exception as exc:
                print(f"\nERROR during monitoring cycle: {exc}")
                print(f"Retrying in {args.interval} seconds...\n")
                await asyncio.sleep(args.interval)
    else:
        await run_once(args)


def main() -> None:
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nStopped by user.")


if __name__ == "__main__":
    main()
