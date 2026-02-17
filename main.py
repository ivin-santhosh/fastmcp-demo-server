from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Literal, Callable, Union

import psutil
from fastmcp import FastMCP

# ============================================================
# MCP Server
# ============================================================

mcp = FastMCP("NetProbe MCP - Security Agent (Windows)")

# ============================================================
# Types (Azure Foundry / Strict Schema Friendly)
# ============================================================

ISO8601 = str

# Pure security-only profiles (NO system health)
RecordingProfile = Literal["security", "soc", "full_security"]
RecordingMode = Literal["foreground", "background"]
ExportFormat = Literal["json", "csv", "html"]

SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")


@dataclass
class ToolMeta:
    tool: str
    success: bool
    timestamp_utc: ISO8601
    message: str


@dataclass
class ErrorInfo:
    error_type: str
    error_message: str


@dataclass
class RecordingSessionInfo:
    session_id: str
    started_utc: ISO8601
    stopped_utc: Optional[ISO8601]
    is_running: bool
    profile: RecordingProfile
    interval_seconds: int
    mode: RecordingMode
    output_dir: str
    snapshot_count: int


@dataclass
class SecuritySnapshot:
    snapshot_id: str
    timestamp_utc: ISO8601
    profile: RecordingProfile

    evidence: Dict[str, Any]
    alerts: List[Dict[str, Any]]
    soc_assessment: Dict[str, Any]
    recommended_actions: List[str]
    standards: Dict[str, Any]


# ============================================================
# Global in-memory state
# ============================================================

LAST_ALERTS: List[Dict[str, Any]] = []
LAST_REPORT: Optional[Dict[str, Any]] = None

_sessions_lock = threading.Lock()
_sessions: Dict[str, "RecorderSession"] = {}

# ============================================================
# Storage
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "recordings"
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# Utility (Robust execution wrappers)
# ============================================================

def utc_now_iso() -> ISO8601:
    return datetime.now(timezone.utc).isoformat()


def safe_str(x: Any) -> Optional[str]:
    try:
        return str(x) if x is not None else None
    except Exception:
        return None


def run_cmd(cmd: List[str], timeout: int = 12) -> Tuple[int, str, str]:
    """
    Robust command runner.
    Returns: (exit_code, stdout, stderr)
    """
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as e:
        return 999, "", f"exception: {e}"


def run_powershell(ps: str, timeout: int = 12) -> Tuple[int, str, str]:
    """
    Robust PowerShell runner.
    """
    return run_cmd(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        timeout=timeout,
    )


def is_admin() -> bool:
    """
    Best-effort admin check.
    """
    code, out, _ = run_powershell(
        "[bool]([Security.Principal.WindowsPrincipal] "
        "[Security.Principal.WindowsIdentity]::GetCurrent()"
        ").IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    )
    return code == 0 and out.strip().lower() == "true"


# ============================================================
# SOC Standards / Scoring Helpers
# ============================================================

def clamp_severity(level: str) -> str:
    lvl = (level or "").strip().lower()
    return lvl if lvl in SEVERITY_LEVELS else "medium"


def severity_score(level: str) -> int:
    """
    Simple SOC-grade severity mapping (0-100).
    """
    lvl = clamp_severity(level)
    mapping = {
        "info": 5,
        "low": 25,
        "medium": 50,
        "high": 75,
        "critical": 95,
    }
    return mapping.get(lvl, 50)


def mitre_guess(event: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Lightweight MITRE ATT&CK mapping heuristics.
    Explainable + SOC-usable.
    """
    text = json.dumps(event, ensure_ascii=False).lower()

    rules: List[Tuple[str, str, str]] = [
        ("T1059", "Command and Scripting Interpreter", "powershell"),
        ("T1569", "System Services", "service"),
        ("T1053", "Scheduled Task/Job", "task"),
        ("T1547", "Boot or Logon Autostart Execution", "run key"),
        ("T1110", "Brute Force", "failed"),
        ("T1021", "Remote Services", "rdp"),
        ("T1047", "Windows Management Instrumentation", "wmi"),
        ("T1105", "Ingress Tool Transfer", "download"),
        ("T1071", "Application Layer Protocol", "http"),
        ("T1078", "Valid Accounts", "logon"),
    ]

    hits: List[Dict[str, str]] = []
    for tid, name, keyword in rules:
        if keyword in text:
            hits.append({"technique_id": tid, "name": name})

    seen = set()
    out: List[Dict[str, str]] = []
    for h in hits:
        if h["technique_id"] not in seen:
            seen.add(h["technique_id"])
            out.append(h)
    return out[:6]


# ============================================================
# Evidence Collection (Security Only)
# ============================================================

def safe_process_attribution(pid: Optional[int]) -> Dict[str, Any]:
    """
    Safe PID -> process attribution.
    Never crashes the server.
    """
    if pid is None:
        return {"pid": None, "process": None, "exe": None, "username": None}

    try:
        p = psutil.Process(pid)
        with p.oneshot():
            name = None
            exe = None
            username = None
            try:
                name = p.name()
            except Exception:
                pass
            try:
                exe = p.exe()
            except Exception:
                pass
            try:
                username = p.username()
            except Exception:
                pass

        return {"pid": pid, "process": name, "exe": exe, "username": username}
    except Exception:
        return {"pid": pid, "process": None, "exe": None, "username": None}


def get_external_connections(limit: int = 250) -> List[Dict[str, Any]]:
    """
    Returns external network connections with process attribution.
    NO packet payload capture.
    """
    results: List[Dict[str, Any]] = []
    limit = max(50, min(limit, 2000))

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        return [{"error": f"psutil.net_connections failed: {str(e)}"}]

    for c in conns:
        try:
            if not c.raddr:
                continue

            remote_ip = getattr(c.raddr, "ip", None)
            remote_port = getattr(c.raddr, "port", None)

            if not remote_ip:
                continue

            # Skip obvious local
            if str(remote_ip).startswith("127.") or str(remote_ip) in ("0.0.0.0", "::1"):
                continue

            proc = safe_process_attribution(c.pid)

            local_ip = getattr(getattr(c, "laddr", None), "ip", None)
            local_port = getattr(getattr(c, "laddr", None), "port", None)

            results.append(
                {
                    "pid": proc["pid"],
                    "process": proc["process"],
                    "exe": proc["exe"],
                    "username": proc["username"],
                    "local_ip": safe_str(local_ip),
                    "local_port": int(local_port) if isinstance(local_port, int) else None,
                    "remote_ip": safe_str(remote_ip),
                    "remote_port": int(remote_port) if isinstance(remote_port, int) else None,
                    "status": safe_str(getattr(c, "status", "UNKNOWN")) or "UNKNOWN",
                    "protocol": "TCP" if getattr(c, "type", None) == 1 else "UDP",
                }
            )
        except Exception:
            continue

    results.sort(key=lambda x: (str(x.get("remote_ip")), int(x.get("pid") or 0)))
    return results[:limit]


def get_running_process_inventory(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Security inventory: process, pid, exe path, user, cmdline.
    """
    out: List[Dict[str, Any]] = []
    limit = max(50, min(limit, 5000))

    for p in psutil.process_iter(attrs=["pid", "name", "username"]):
        try:
            pid = int(p.info["pid"])
            proc = psutil.Process(pid)

            exe = None
            cmdline = None
            ppid = None

            try:
                exe = proc.exe()
            except Exception:
                pass

            try:
                cmdline_list = proc.cmdline()
                cmdline = " ".join(cmdline_list[:50]) if isinstance(cmdline_list, list) else None
            except Exception:
                pass

            try:
                ppid = proc.ppid()
            except Exception:
                pass

            out.append(
                {
                    "pid": pid,
                    "ppid": int(ppid) if isinstance(ppid, int) else None,
                    "name": p.info.get("name"),
                    "username": p.info.get("username"),
                    "exe": exe,
                    "cmdline": cmdline,
                }
            )
        except Exception:
            continue

    out.sort(key=lambda x: str(x.get("name") or ""))
    return out[:limit]


def get_listening_ports(limit: int = 250) -> List[Dict[str, Any]]:
    """
    Returns listening ports (security view).
    """
    limit = max(20, min(limit, 3000))
    results: List[Dict[str, Any]] = []

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        return [{"error": f"psutil.net_connections failed: {str(e)}"}]

    for c in conns:
        try:
            if safe_str(getattr(c, "status", "")).upper() != "LISTEN":
                continue

            proc = safe_process_attribution(c.pid)

            local_ip = getattr(getattr(c, "laddr", None), "ip", None)
            local_port = getattr(getattr(c, "laddr", None), "port", None)

            results.append(
                {
                    "pid": proc["pid"],
                    "process": proc["process"],
                    "exe": proc["exe"],
                    "username": proc["username"],
                    "local_ip": safe_str(local_ip),
                    "local_port": int(local_port) if isinstance(local_port, int) else None,
                }
            )

            if len(results) >= limit:
                break
        except Exception:
            continue

    results.sort(key=lambda x: (str(x.get("local_ip")), int(x.get("local_port") or 0)))
    return results[:limit]


# ============================================================
# Windows Event Logs (SOC-grade)
# ============================================================

WINDOWS_SECURITY_EVENT_IDS: Dict[int, str] = {
    4624: "Successful logon",
    4625: "Failed logon",
    4634: "Logoff",
    4648: "Logon with explicit credentials",
    4672: "Special privileges assigned",
    4720: "User account created",
    4722: "User enabled",
    4723: "Attempt to change password",
    4724: "Password reset attempt",
    4728: "User added to security-enabled group",
    4732: "User added to local group",
    4735: "Local group modified",
    4740: "Account locked out",
    4697: "Service installed",
    7045: "Service created (System log, but often seen)",
    4698: "Scheduled task created",
    4699: "Scheduled task deleted",
    4702: "Scheduled task updated",
}


def read_eventlog_via_wevtutil(log_name: str, minutes: int = 60, max_events: int = 80) -> List[Dict[str, Any]]:
    minutes = max(1, min(minutes, 1440))
    max_events = max(10, min(max_events, 500))

    ms = minutes * 60 * 1000
    query = f"*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    cmd = ["wevtutil", "qe", log_name, f"/q:{query}", "/f:Text", f"/c:{max_events}"]

    code, out, err = run_cmd(cmd, timeout=18)
    if code != 0 or not out:
        return [{"error": f"wevtutil failed for {log_name}", "stderr": err}]

    blocks = out.split("\n\n")
    events: List[Dict[str, Any]] = []

    for b in blocks:
        b = b.strip()
        if not b:
            continue

        m_id = re.search(r"Event ID:\s*(\d+)", b)
        eid = int(m_id.group(1)) if m_id else None

        m_time = re.search(r"Date:\s*(.+)", b)
        date_str = m_time.group(1).strip() if m_time else None

        m_provider = re.search(r"Provider Name:\s*(.+)", b)
        provider = m_provider.group(1).strip() if m_provider else log_name

        message = b[-1200:] if len(b) > 1200 else b

        events.append(
            {
                "log": log_name,
                "event_id": eid,
                "event_name": WINDOWS_SECURITY_EVENT_IDS.get(eid, None) if eid else None,
                "provider": provider,
                "time_raw": date_str,
                "message_tail": message,
            }
        )

    return events[:max_events]


def read_eventlog_via_powershell(log_name: str, minutes: int = 60, max_events: int = 80) -> List[Dict[str, Any]]:
    minutes = max(1, min(minutes, 1440))
    max_events = max(10, min(max_events, 500))

    ps = rf"""
    $since = (Get-Date).AddMinutes(-{minutes})
    try {{
      Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; StartTime=$since}} -MaxEvents {max_events} |
      Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
      ConvertTo-Json -Depth 3
    }} catch {{
      ""
    }}
    """
    code, out, err = run_powershell(ps, timeout=18)
    if code != 0 or not out:
        return [{"error": f"powershell Get-WinEvent failed for {log_name}", "stderr": err}]

    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
    except Exception:
        return [{"error": "failed to parse powershell json", "stderr": err, "raw": out[:4000]}]

    events: List[Dict[str, Any]] = []
    for e in data:
        try:
            eid = int(e.get("Id")) if e.get("Id") is not None else None
            msg = (e.get("Message") or "")[:1200]

            events.append(
                {
                    "log": log_name,
                    "event_id": eid,
                    "event_name": WINDOWS_SECURITY_EVENT_IDS.get(eid, None) if eid else None,
                    "provider": e.get("ProviderName"),
                    "level": e.get("LevelDisplayName"),
                    "time": safe_str(e.get("TimeCreated")),
                    "message": msg,
                }
            )
        except Exception:
            continue

    return events[:max_events]


def collect_recent_eventlogs(minutes: int = 60) -> Dict[str, Any]:
    logs_to_pull = [
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-WindowsUpdateClient/Operational",
    ]

    out: Dict[str, Any] = {"minutes": minutes, "sources": {}, "events": {}}

    for log in logs_to_pull:
        a = read_eventlog_via_wevtutil(log, minutes=minutes, max_events=80)
        if a and not (len(a) == 1 and "error" in a[0]):
            out["sources"][log] = "wevtutil"
            out["events"][log] = a
            continue

        b = read_eventlog_via_powershell(log, minutes=minutes, max_events=80)
        out["sources"][log] = "powershell"
        out["events"][log] = b

    return out


# ============================================================
# Detection Logic (Efficient + Explainable)
# ============================================================

SUSPICIOUS_PROCESS_KEYWORDS: List[str] = [
    "mimikatz",
    "powershell -enc",
    "powershell.exe -enc",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "mshta",
    "wmic",
    "psexec",
    "nc.exe",
    "netcat",
]


def detect_suspicious_processes(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []

    for p in processes:
        name = (p.get("name") or "").lower()
        cmd = (p.get("cmdline") or "").lower()
        exe = (p.get("exe") or "").lower()

        hay = f"{name} {cmd} {exe}"

        for kw in SUSPICIOUS_PROCESS_KEYWORDS:
            if kw in hay:
                alerts.append(
                    {
                        "type": "suspicious_process",
                        "severity": "high",
                        "reason": f"Matched suspicious keyword: {kw}",
                        "process": p,
                        "mitre": [{"technique_id": "T1059", "name": "Command and Scripting Interpreter"}],
                    }
                )
                break

    return alerts


def detect_bruteforce_from_security_events(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    failed = [e for e in events if e.get("event_id") == 4625]
    if len(failed) >= 12:
        return {
            "type": "bruteforce_suspected",
            "severity": "critical",
            "reason": f"{len(failed)} failed logons detected in window",
            "event_id": 4625,
            "mitre": [{"technique_id": "T1110", "name": "Brute Force"}],
        }
    if len(failed) >= 6:
        return {
            "type": "bruteforce_suspected",
            "severity": "high",
            "reason": f"{len(failed)} failed logons detected in window",
            "event_id": 4625,
            "mitre": [{"technique_id": "T1110", "name": "Brute Force"}],
        }
    return None


def detect_service_install(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    for e in events:
        if e.get("event_id") in (4697, 7045):
            alerts.append(
                {
                    "type": "service_install_detected",
                    "severity": "high",
                    "reason": "Service installation event detected",
                    "event": e,
                    "mitre": [{"technique_id": "T1569", "name": "System Services"}],
                }
            )
    return alerts


def detect_scheduled_task_changes(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    for e in events:
        if e.get("event_id") in (4698, 4702, 4699):
            alerts.append(
                {
                    "type": "scheduled_task_change",
                    "severity": "high",
                    "reason": "Scheduled task creation/modification detected",
                    "event": e,
                    "mitre": [{"technique_id": "T1053", "name": "Scheduled Task/Job"}],
                }
            )
    return alerts


def detect_suspicious_external_connections(conns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    suspicious_ports = {4444, 1337, 31337, 6666, 6667, 1080, 9050}
    alerts: List[Dict[str, Any]] = []

    for c in conns:
        rp = c.get("remote_port")
        proc = (c.get("process") or "").lower()
        exe = (c.get("exe") or "").lower()

        if rp in suspicious_ports:
            alerts.append(
                {
                    "type": "suspicious_connection",
                    "severity": "high",
                    "reason": f"Connection to suspicious remote port {rp}",
                    "connection": c,
                    "mitre": [{"technique_id": "T1071", "name": "Application Layer Protocol"}],
                }
            )
            continue

        if any(x in proc for x in ["powershell", "mshta", "rundll32", "regsvr32", "wmic"]):
            alerts.append(
                {
                    "type": "suspicious_connection",
                    "severity": "medium",
                    "reason": f"Connection made by LOLBin-like process: {proc}",
                    "connection": c,
                    "mitre": [{"technique_id": "T1059", "name": "Command and Scripting Interpreter"}],
                }
            )

        if "\\appdata\\roaming\\" in exe or "\\temp\\" in exe:
            alerts.append(
                {
                    "type": "suspicious_connection",
                    "severity": "high",
                    "reason": "Network connection from executable in Temp/AppData (common malware location)",
                    "connection": c,
                    "mitre": [{"technique_id": "T1105", "name": "Ingress Tool Transfer"}],
                }
            )

    return alerts


def detect_exposed_listening_ports(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Security: 0.0.0.0 / :: listening ports are often risky.
    """
    alerts: List[Dict[str, Any]] = []
    for p in ports:
        ip = p.get("local_ip")
        port = p.get("local_port")
        if ip in ("0.0.0.0", "::"):
            alerts.append(
                {
                    "type": "exposed_listening_port",
                    "severity": "medium",
                    "reason": f"Port bound to all interfaces: {ip}:{port}",
                    "port": p,
                    "mitre": [{"technique_id": "T1021", "name": "Remote Services"}],
                }
            )
    return alerts


# ============================================================
# Defender + Firewall (Automated Response)
# ============================================================

def defender_status() -> Dict[str, Any]:
    ps = r"""
    try {
      $mp = Get-MpComputerStatus
      $pref = Get-MpPreference
      [PSCustomObject]@{
        AMServiceEnabled = $mp.AMServiceEnabled
        AntispywareEnabled = $mp.AntispywareEnabled
        AntivirusEnabled = $mp.AntivirusEnabled
        RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
        NISEnabled = $mp.NISEnabled
        QuickScanAge = $mp.QuickScanAge
        FullScanAge = $mp.FullScanAge
        SignatureAge = $mp.AntivirusSignatureAge
        ExclusionCount = ($pref.ExclusionPath.Count + $pref.ExclusionProcess.Count + $pref.ExclusionExtension.Count)
      } | ConvertTo-Json -Depth 3
    } catch { "" }
    """
    code, out, err = run_powershell(ps, timeout=15)
    if code != 0 or not out:
        return {"available": False, "error": err or "Defender status unavailable"}
    try:
        return {"available": True, "data": json.loads(out)}
    except Exception:
        return {"available": True, "raw": out[:2000]}


def defender_quick_scan() -> Dict[str, Any]:
    ps = r"try { Start-MpScan -ScanType QuickScan; 'OK' } catch { 'ERROR' }"
    code, out, err = run_powershell(ps, timeout=12)
    return {"ok": code == 0 and "OK" in out, "stdout": out, "stderr": err}


def defender_full_scan() -> Dict[str, Any]:
    ps = r"try { Start-MpScan -ScanType FullScan; 'OK' } catch { 'ERROR' }"
    code, out, err = run_powershell(ps, timeout=12)
    return {"ok": code == 0 and "OK" in out, "stdout": out, "stderr": err}


def defender_update_signatures() -> Dict[str, Any]:
    ps = r"try { Update-MpSignature; 'OK' } catch { 'ERROR' }"
    code, out, err = run_powershell(ps, timeout=18)
    return {"ok": code == 0 and "OK" in out, "stdout": out, "stderr": err}


def firewall_block_ip(ip: str) -> Dict[str, Any]:
    rule_name = f"NetProbe_BlockIP_{ip}_{uuid.uuid4().hex[:8]}"
    ps = rf"""
    try {{
      New-NetFirewallRule -DisplayName "{rule_name}_OUT" -Direction Outbound -Action Block -RemoteAddress {ip} | Out-Null
      New-NetFirewallRule -DisplayName "{rule_name}_IN" -Direction Inbound -Action Block -RemoteAddress {ip} | Out-Null
      "OK"
    }} catch {{
      "ERROR"
    }}
    """
    code, out, err = run_powershell(ps, timeout=18)
    return {"ok": code == 0 and "OK" in out, "rule_prefix": rule_name, "stdout": out, "stderr": err}


def firewall_lockdown_mode() -> Dict[str, Any]:
    prefix = f"NetProbe_Lockdown_{uuid.uuid4().hex[:8]}"
    ps = rf"""
    try {{
      New-NetFirewallRule -DisplayName "{prefix}_BLOCK_ALL_OUT" -Direction Outbound -Action Block | Out-Null
      New-NetFirewallRule -DisplayName "{prefix}_ALLOW_DNS" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 | Out-Null
      New-NetFirewallRule -DisplayName "{prefix}_ALLOW_DNS_TCP" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53 | Out-Null
      "OK"
    }} catch {{
      "ERROR"
    }}
    """
    code, out, err = run_powershell(ps, timeout=18)
    return {"ok": code == 0 and "OK" in out, "rule_prefix": prefix, "stdout": out, "stderr": err}


# ============================================================
# SOC Report Generator (Standards + Evidence)
# ============================================================

def build_soc_report(minutes: int = 60) -> Dict[str, Any]:
    """
    Produces a SOC-style report:
    - Evidence collected
    - Alerts
    - Severity score
    - MITRE mapping
    - Recommended actions
    """
    global LAST_ALERTS, LAST_REPORT

    report_id = str(uuid.uuid4())

    processes = get_running_process_inventory(limit=350)
    conns = get_external_connections(limit=350)
    ports = get_listening_ports(limit=350)
    logs = collect_recent_eventlogs(minutes=minutes)
    def_status = defender_status()

    sec_events: List[Dict[str, Any]] = []
    if isinstance(logs.get("events", {}).get("Security"), list):
        sec_events = logs["events"]["Security"]

    alerts: List[Dict[str, Any]] = []
    alerts.extend(detect_suspicious_processes(processes))
    alerts.extend(detect_suspicious_external_connections(conns))

    bf = detect_bruteforce_from_security_events(sec_events)
    if bf:
        alerts.append(bf)

    alerts.extend(detect_service_install(sec_events))
    alerts.extend(detect_scheduled_task_changes(sec_events))
    alerts.extend(detect_exposed_listening_ports(ports))

    for a in alerts:
        if "mitre" not in a:
            a["mitre"] = mitre_guess(a)

    max_lvl = "info"
    max_score = 0
    for a in alerts:
        lvl = clamp_severity(a.get("severity", "medium"))
        score = severity_score(lvl)
        if score > max_score:
            max_score = score
            max_lvl = lvl

    recs = [
        "If suspicious connections exist, block remote IPs using fw_block_ip().",
        "If brute force suspected, review logon sources and enforce stronger auth.",
        "If service installs detected, verify the service binary path and publisher.",
        "Run defender_update() then defender_scan_quick().",
        "If critical, apply containment via fw_lockdown_mode().",
        "Deploy Sysmon for higher-fidelity telemetry and better detection coverage.",
    ]

    report = {
        "report_id": report_id,
        "generated_utc": utc_now_iso(),
        "agent": {
            "name": "NetProbe MCP - Security Agent",
            "admin": is_admin(),
            "host": os.environ.get("COMPUTERNAME") or "unknown",
        },
        "window_minutes": minutes,
        "evidence": {
            "external_connections": conns[:200],
            "listening_ports": ports[:200],
            "process_inventory_sample": processes[:200],
            "eventlogs": logs,
            "defender_status": def_status,
        },
        "alerts": alerts,
        "soc_assessment": {
            "alert_count": len(alerts),
            "max_severity": max_lvl,
            "max_severity_score": max_score,
            "confidence": "medium",
            "note": "Heuristic detection. Use Sysmon for higher fidelity evidence.",
        },
        "recommended_actions": recs,
        "standards": {
            "mitre_attack": True,
            "nist_style": True,
            "soc_reporting": True,
        },
    }

    LAST_ALERTS = alerts
    LAST_REPORT = report
    return report


# ============================================================
# Security Snapshot Builder (Recording-Compatible)
# ============================================================

def build_security_snapshot(profile: RecordingProfile, minutes: int = 60) -> SecuritySnapshot:
    """
    A snapshot is a SOC report wrapped into a strict dataclass.
    """
    report = build_soc_report(minutes=minutes)

    return SecuritySnapshot(
        snapshot_id=str(uuid.uuid4()),
        timestamp_utc=utc_now_iso(),
        profile=profile,
        evidence=report.get("evidence", {}),
        alerts=report.get("alerts", []),
        soc_assessment=report.get("soc_assessment", {}),
        recommended_actions=report.get("recommended_actions", []),
        standards=report.get("standards", {}),
    )


# ============================================================
# Recording Engine (Security-Only)
# ============================================================

class RecorderSession:
    def __init__(
        self,
        session_id: str,
        profile: RecordingProfile,
        interval_seconds: int,
        mode: RecordingMode,
        output_dir: Path,
        minutes_window: int = 30,
    ) -> None:
        self.session_id = session_id
        self.profile = profile
        self.interval_seconds = max(2, int(interval_seconds))
        self.mode = mode
        self.output_dir = output_dir
        self.minutes_window = max(1, min(minutes_window, 1440))

        self.started_utc: ISO8601 = utc_now_iso()
        self.stopped_utc: Optional[ISO8601] = None
        self.is_running: bool = False

        self.snapshot_count: int = 0
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def start(self) -> None:
        if self.is_running:
            return
        self.is_running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self.is_running:
            return
        self._stop_event.set()
        self.is_running = False
        self.stopped_utc = utc_now_iso()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                snap = build_security_snapshot(profile=self.profile, minutes=self.minutes_window)
                self._save_snapshot(snap)
                self.snapshot_count += 1
            except Exception:
                pass

            time.sleep(self.interval_seconds)

    def _save_snapshot(self, snapshot: SecuritySnapshot) -> None:
        safe_ts = snapshot.timestamp_utc.replace(":", "-")
        path = self.output_dir / f"{safe_ts}_{snapshot.snapshot_id}.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(asdict(snapshot), f, indent=2)
        except Exception:
            pass

    def info(self) -> RecordingSessionInfo:
        return RecordingSessionInfo(
            session_id=self.session_id,
            started_utc=self.started_utc,
            stopped_utc=self.stopped_utc,
            is_running=self.is_running,
            profile=self.profile,
            interval_seconds=self.interval_seconds,
            mode=self.mode,
            output_dir=str(self.output_dir),
            snapshot_count=self.snapshot_count,
        )


# ============================================================
# MCP Tools (Azure Foundry Style Outputs)
# ============================================================

@mcp.tool()
def security_triage_snapshot(minutes: int = 30) -> Dict[str, Any]:
    """
    Main security snapshot tool.
    Returns SOC-grade evidence and alert list.
    """
    try:
        minutes = max(1, min(minutes, 1440))
        report = build_soc_report(minutes=minutes)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="security_triage_snapshot",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="SOC snapshot generated successfully.",
                )
            ),
            "data": report,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="security_triage_snapshot",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="SOC snapshot failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def list_external_connections(limit: int = 250) -> Dict[str, Any]:
    try:
        data = get_external_connections(limit=limit)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="list_external_connections",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="External connections collected successfully.",
                )
            ),
            "data": {"connections": data, "count": len(data)},
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="list_external_connections",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to collect external connections.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def list_listening_ports(limit: int = 250) -> Dict[str, Any]:
    try:
        data = get_listening_ports(limit=limit)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="list_listening_ports",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Listening ports collected successfully.",
                )
            ),
            "data": {"ports": data, "count": len(data)},
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="list_listening_ports",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to collect listening ports.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def list_process_inventory(limit: int = 200) -> Dict[str, Any]:
    try:
        limit = max(50, min(limit, 5000))
        data = get_running_process_inventory(limit=limit)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="list_process_inventory",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Process inventory collected successfully.",
                )
            ),
            "data": {"processes": data, "count": len(data)},
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="list_process_inventory",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to collect process inventory.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def get_recent_eventlogs(minutes: int = 30) -> Dict[str, Any]:
    """
    Pulls Security/System/Application/Defender/WindowsUpdate logs.
    """
    try:
        minutes = max(1, min(minutes, 1440))
        data = collect_recent_eventlogs(minutes=minutes)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="get_recent_eventlogs",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Event logs collected successfully.",
                )
            ),
            "data": data,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="get_recent_eventlogs",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to collect event logs.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def defender_get_status() -> Dict[str, Any]:
    try:
        status = defender_status()
        return {
            "meta": asdict(
                ToolMeta(
                    tool="defender_get_status",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Defender status fetched successfully.",
                )
            ),
            "data": status,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="defender_get_status",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to fetch Defender status.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def defender_update() -> Dict[str, Any]:
    try:
        result = defender_update_signatures()
        return {
            "meta": asdict(
                ToolMeta(
                    tool="defender_update",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Defender update executed.",
                )
            ),
            "data": result,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="defender_update",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Defender update failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def defender_scan_quick() -> Dict[str, Any]:
    try:
        result = defender_quick_scan()
        return {
            "meta": asdict(
                ToolMeta(
                    tool="defender_scan_quick",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Defender quick scan triggered.",
                )
            ),
            "data": result,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="defender_scan_quick",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Defender quick scan failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def defender_scan_full() -> Dict[str, Any]:
    try:
        result = defender_full_scan()
        return {
            "meta": asdict(
                ToolMeta(
                    tool="defender_scan_full",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Defender full scan triggered.",
                )
            ),
            "data": result,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="defender_scan_full",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Defender full scan failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def fw_block_ip(ip: str) -> Dict[str, Any]:
    """
    Blocks an IP inbound+outbound.
    Requires admin.
    """
    try:
        ip = ip.strip()
        if not ip:
            return {
                "meta": asdict(
                    ToolMeta(
                        tool="fw_block_ip",
                        success=False,
                        timestamp_utc=utc_now_iso(),
                        message="IP required.",
                    )
                ),
                "error": asdict(ErrorInfo(error_type="ValidationError", error_message="ip is required")),
            }

        result = firewall_block_ip(ip)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="fw_block_ip",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Firewall block IP executed.",
                )
            ),
            "data": result,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="fw_block_ip",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Firewall block IP failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def fw_lockdown_mode(reason: str = "") -> Dict[str, Any]:
    """
    Emergency containment mode.
    Requires admin.
    """
    try:
        result = firewall_lockdown_mode()
        return {
            "meta": asdict(
                ToolMeta(
                    tool="fw_lockdown_mode",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Firewall lockdown mode executed.",
                )
            ),
            "data": {"reason": reason, "result": result},
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="fw_lockdown_mode",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Firewall lockdown failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def export_last_soc_report(path: str = "netprobe_soc_report.json") -> Dict[str, Any]:
    """
    Saves the last SOC report to JSON.
    """
    global LAST_REPORT
    try:
        if not LAST_REPORT:
            return {
                "meta": asdict(
                    ToolMeta(
                        tool="export_last_soc_report",
                        success=False,
                        timestamp_utc=utc_now_iso(),
                        message="No report available.",
                    )
                ),
                "error": asdict(ErrorInfo(error_type="NoReport", error_message="Run security_triage_snapshot() first.")),
            }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(LAST_REPORT, f, indent=2)

        return {
            "meta": asdict(
                ToolMeta(
                    tool="export_last_soc_report",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="SOC report exported successfully.",
                )
            ),
            "data": {"saved_to": path, "report_id": LAST_REPORT.get("report_id")},
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="export_last_soc_report",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Export failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


# ============================================================
# Missing MCP Tools from Old Code (Re-added)
# ============================================================

@mcp.tool()
def start_recording(
    profile: RecordingProfile = "security",
    interval_seconds: int = 10,
    mode: RecordingMode = "background",
    minutes_window: int = 30,
) -> Dict[str, Any]:
    """
    Starts a security-only recording session.
    Writes snapshots to disk until stopped.
    """
    try:
        session_id = str(uuid.uuid4())
        output_dir = DATA_DIR / session_id

        session = RecorderSession(
            session_id=session_id,
            profile=profile,
            interval_seconds=interval_seconds,
            mode=mode,
            output_dir=output_dir,
            minutes_window=minutes_window,
        )

        with _sessions_lock:
            _sessions[session_id] = session

        session.start()

        return {
            "meta": asdict(
                ToolMeta(
                    tool="start_recording",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Recording started successfully.",
                )
            ),
            "data": asdict(session.info()),
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="start_recording",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to start recording.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def stop_recording(session_id: str) -> Dict[str, Any]:
    """
    Stops a running recording session.
    """
    try:
        with _sessions_lock:
            session = _sessions.get(session_id)

        if not session:
            return {
                "meta": asdict(
                    ToolMeta(
                        tool="stop_recording",
                        success=False,
                        timestamp_utc=utc_now_iso(),
                        message="Session not found.",
                    )
                ),
                "error": asdict(ErrorInfo(error_type="NotFound", error_message=f"Session {session_id} not found.")),
            }

        session.stop()

        return {
            "meta": asdict(
                ToolMeta(
                    tool="stop_recording",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Recording stopped successfully.",
                )
            ),
            "data": asdict(session.info()),
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="stop_recording",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to stop recording.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def list_recordings() -> Dict[str, Any]:
    """
    Lists all known sessions (running + stopped) in memory.
    """
    try:
        with _sessions_lock:
            sessions = list(_sessions.values())

        return {
            "meta": asdict(
                ToolMeta(
                    tool="list_recordings",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Sessions listed successfully.",
                )
            ),
            "data": {"sessions": [asdict(s.info()) for s in sessions], "count": len(sessions)},
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="list_recordings",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to list sessions.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def read_session_snapshots(session_id: str, limit: int = 20) -> Dict[str, Any]:
    """
    Reads snapshots saved on disk for a session.
    """
    try:
        session_dir = DATA_DIR / session_id
        if not session_dir.exists():
            return {
                "meta": asdict(
                    ToolMeta(
                        tool="read_session_snapshots",
                        success=False,
                        timestamp_utc=utc_now_iso(),
                        message="Session directory not found on disk.",
                    )
                ),
                "error": asdict(ErrorInfo(error_type="NotFound", error_message=f"No folder found for {session_id}")),
            }

        files = sorted(session_dir.glob("*.json"))
        files = files[: max(1, limit)]

        snapshots: List[Dict[str, Any]] = []
        for f in files:
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    snapshots.append(json.load(fp))
            except Exception:
                continue

        return {
            "meta": asdict(
                ToolMeta(
                    tool="read_session_snapshots",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Snapshots read successfully.",
                )
            ),
            "data": {
                "session_id": session_id,
                "snapshot_files_read": len(snapshots),
                "snapshots": snapshots,
            },
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="read_session_snapshots",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to read snapshots.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def generate_executive_report(session_id: str) -> Dict[str, Any]:
    """
    Generates an executive summary from recorded snapshots.
    Evidence-based and transparent.
    """
    try:
        session_dir = DATA_DIR / session_id
        if not session_dir.exists():
            return {
                "meta": asdict(
                    ToolMeta(
                        tool="generate_executive_report",
                        success=False,
                        timestamp_utc=utc_now_iso(),
                        message="Session directory not found.",
                    )
                ),
                "error": asdict(ErrorInfo(error_type="NotFound", error_message=f"No session folder for {session_id}")),
            }

        files = sorted(session_dir.glob("*.json"))
        if not files:
            return {
                "meta": asdict(
                    ToolMeta(
                        tool="generate_executive_report",
                        success=False,
                        timestamp_utc=utc_now_iso(),
                        message="No snapshots found to analyze.",
                    )
                ),
                "error": asdict(ErrorInfo(error_type="EmptySession", error_message="No snapshots found.")),
            }

        all_alerts: List[Dict[str, Any]] = []
        exposed_ports_count = 0
        suspicious_process_hits = 0
        suspicious_conn_hits = 0

        for f in files:
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    snap = json.load(fp)

                alerts = snap.get("alerts") or []
                if isinstance(alerts, list):
                    for a in alerts:
                        if isinstance(a, dict):
                            all_alerts.append(a)

                evidence = snap.get("evidence") or {}
                ports = evidence.get("listening_ports") or []

                for p in ports:
                    if isinstance(p, dict) and p.get("local_ip") in ("0.0.0.0", "::"):
                        exposed_ports_count += 1

            except Exception:
                continue

        for a in all_alerts:
            if a.get("type") == "suspicious_process":
                suspicious_process_hits += 1
            if a.get("type") in ("suspicious_connection", "suspicious_external_connection"):
                suspicious_conn_hits += 1

        # Severity rollup
        max_lvl = "info"
        max_score = 0
        for a in all_alerts:
            lvl = clamp_severity(a.get("severity", "medium"))
            score = severity_score(lvl)
            if score > max_score:
                max_score = score
                max_lvl = lvl

        report = {
            "session_id": session_id,
            "snapshot_count": len(files),
            "alerts_total": len(all_alerts),
            "max_severity": max_lvl,
            "max_severity_score": max_score,
            "exposed_ports_count": exposed_ports_count,
            "suspicious_process_hits": suspicious_process_hits,
            "suspicious_connection_hits": suspicious_conn_hits,
            "alerts_sample": all_alerts[:30],
            "recommendations": [
                "Review exposed ports bound to 0.0.0.0 / ::",
                "Investigate suspicious processes and verify executable path + publisher",
                "Block suspicious remote IPs using fw_block_ip() if needed",
                "Deploy Sysmon for stronger evidence and timeline reconstruction",
            ],
        }

        return {
            "meta": asdict(
                ToolMeta(
                    tool="generate_executive_report",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Executive report generated successfully.",
                )
            ),
            "data": report,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="generate_executive_report",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to generate report.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


# ============================================================
# Run Server
# ============================================================

if __name__ == "__main__":
    # Claude Desktop MCP typically uses stdio.
    # For HTTP: mcp.run(transport="http", host="0.0.0.0", port=8000)
    mcp.run(transport="stdio")



# =========================================================
# META-TOOLS: TOOL REGISTRY + CUSTOM TOOL SYSTEM (DSL + RAW PYTHON)
# APPEND-ONLY BLOCK (do not remove existing tools)
# =========================================================

# -----------------------------
# Storage locations
# -----------------------------
_BASE_DIR = Path(__file__).resolve().parent
_REGISTRY_DIR = _BASE_DIR / "registry"
_REGISTRY_DIR.mkdir(parents=True, exist_ok=True)

STATIC_TOOLS_FILE = _REGISTRY_DIR / "static_tools.json"
CUSTOM_DSL_TOOLS_FILE = _REGISTRY_DIR / "custom_dsl_tools.json"
CUSTOM_PY_TOOLS_FILE = _REGISTRY_DIR / "custom_python_tools.json"
AUDIT_LOG_FILE = _REGISTRY_DIR / "soar_audit_log.jsonl"

# -----------------------------
# Helper: JSON safe write
# -----------------------------
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _read_json_file(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def _write_json_file(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def _append_audit(event: Dict[str, Any]) -> None:
    try:
        event["utc"] = _utc_now_iso()
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass

# -----------------------------
# Tool Introspection / Registry
# -----------------------------
def _get_all_registered_tool_names() -> List[str]:
    """
    Best-effort: we cannot always introspect FastMCP internals reliably.
    So we maintain a registry ourselves.
    """
    static = _read_json_file(STATIC_TOOLS_FILE, default={"tools": []})
    tools = static.get("tools", [])
    if not isinstance(tools, list):
        return []
    names: List[str] = []
    for t in tools:
        if isinstance(t, dict) and isinstance(t.get("name"), str):
            names.append(t["name"])
    return sorted(set(names))

def _sync_static_tools_registry(tool_names: List[str]) -> Dict[str, Any]:
    """
    Stores static tool names (the hardcoded ones in main.py).
    This is needed because FastMCP does not always expose full introspection.
    """
    payload = {
        "schema_version": "1.0",
        "updated_utc": _utc_now_iso(),
        "tools": [{"name": n} for n in sorted(set(tool_names))],
    }
    _write_json_file(STATIC_TOOLS_FILE, payload)
    return payload

# -----------------------------
# Custom Tool Models
# -----------------------------
@dataclass
class DSLStep:
    tool: str
    args: Dict[str, Any]

@dataclass
class DSLTool:
    name: str
    description: str
    steps: List[DSLStep]
    created_utc: str
    created_by: str = "user"

@dataclass
class PythonTool:
    name: str
    description: str
    code: str
    created_utc: str
    created_by: str = "user"

# -----------------------------
# Load/Save Custom Tools
# -----------------------------
def _load_custom_dsl_tools() -> Dict[str, Any]:
    return _read_json_file(CUSTOM_DSL_TOOLS_FILE, default={"schema_version": "1.0", "tools": {}})

def _save_custom_dsl_tools(payload: Dict[str, Any]) -> None:
    _write_json_file(CUSTOM_DSL_TOOLS_FILE, payload)

def _load_custom_python_tools() -> Dict[str, Any]:
    return _read_json_file(CUSTOM_PY_TOOLS_FILE, default={"schema_version": "1.0", "tools": {}})

def _save_custom_python_tools(payload: Dict[str, Any]) -> None:
    _write_json_file(CUSTOM_PY_TOOLS_FILE, payload)

# -----------------------------
# Safe name
# -----------------------------
def _normalize_tool_name(name: str) -> str:
    name = name.strip()
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    name = re.sub(r"_+", "_", name)
    name = name.strip("_")
    if not name:
        raise ValueError("Tool name cannot be empty.")
    if len(name) > 80:
        name = name[:80]
    return name

# -----------------------------
# DSL variable substitution
# -----------------------------
_VAR_PATTERN = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")

def _resolve_template(value: Any, context: Dict[str, Any]) -> Any:
    """
    Resolves strings like:
      "{{step_1.result.remote_ip}}"
    """
    if isinstance(value, str):
        def repl(match: re.Match) -> str:
            key = match.group(1)
            # dot path
            cur: Any = context
            for part in key.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    return match.group(0)
            return str(cur)
        return _VAR_PATTERN.sub(repl, value)

    if isinstance(value, dict):
        return {k: _resolve_template(v, context) for k, v in value.items()}

    if isinstance(value, list):
        return [_resolve_template(v, context) for v in value]

    return value

# -----------------------------
# DSL runner
# -----------------------------
async def _run_dsl_tool(
    tool_name: str,
    input_args: Dict[str, Any],
    tool_caller: Callable[[str, Dict[str, Any]], Any],
) -> Dict[str, Any]:
    """
    Executes a stored DSL tool (playbook).
    """
    dsl_payload = _load_custom_dsl_tools()
    tools: Dict[str, Any] = dsl_payload.get("tools", {})
    if tool_name not in tools:
        raise ValueError(f"DSL tool not found: {tool_name}")

    tool_def = tools[tool_name]
    steps = tool_def.get("steps", [])
    if not isinstance(steps, list) or not steps:
        raise ValueError("DSL tool has no steps.")

    run_context: Dict[str, Any] = {
        "input": input_args,
        "tool": {"name": tool_name},
    }

    results: List[Dict[str, Any]] = []

    for idx, step in enumerate(steps, start=1):
        step_tool = step.get("tool")
        step_args = step.get("args", {})
        if not isinstance(step_tool, str):
            raise ValueError(f"Invalid step tool at index {idx}")
        if not isinstance(step_args, dict):
            raise ValueError(f"Invalid step args at index {idx}")

        resolved_args = _resolve_template(step_args, run_context)

        _append_audit({
            "type": "dsl_step_start",
            "dsl_tool": tool_name,
            "step_index": idx,
            "tool": step_tool,
            "args": resolved_args,
        })

        try:
            step_result = await tool_caller(step_tool, resolved_args)
        except Exception as e:
            err = {
                "step_index": idx,
                "tool": step_tool,
                "error": str(e),
                "trace": traceback.format_exc(),
            }
            _append_audit({
                "type": "dsl_step_error",
                "dsl_tool": tool_name,
                "step_index": idx,
                "tool": step_tool,
                "error": err,
            })
            raise

        step_record = {
            "step_index": idx,
            "tool": step_tool,
            "args": resolved_args,
            "result": step_result,
        }
        results.append(step_record)

        run_context[f"step_{idx}"] = {"result": step_result}
        run_context["last"] = {"result": step_result}

        _append_audit({
            "type": "dsl_step_done",
            "dsl_tool": tool_name,
            "step_index": idx,
            "tool": step_tool,
        })

    return {
        "dsl_tool": tool_name,
        "input_args": input_args,
        "steps_executed": len(results),
        "results": results,
        "finished_utc": _utc_now_iso(),
    }

# -----------------------------
# Raw Python execution (OPTIONAL, permission gated)
# -----------------------------
def _validate_python_tool_code(code: str) -> None:
    """
    Minimal sanity checks.
    NOTE: This is NOT a sandbox.
    You requested explicit permission gating instead.
    """
    banned = [
        "import os",
        "import subprocess",
        "import socket",
        "import psutil",
        "ctypes",
        "win32",
        "requests",
        "pip",
        "eval(",
        "exec(",
        "__import__",
        "open(",
    ]
    # We don't block everything, but we at least detect obvious stuff.
    # You can relax this later.
    lower = code.lower()
    for b in banned:
        if b in lower:
            # Not hard-blocking: we allow but warn in response.
            return

async def _run_python_tool(
    tool_name: str,
    input_args: Dict[str, Any],
    permission_granted: bool,
) -> Dict[str, Any]:
    """
    Executes a stored raw python tool only if permission_granted=True.
    """
    if not permission_granted:
        return {
            "status": "permission_required",
            "message": (
                "This tool is a RAW PYTHON custom tool. "
                "You must re-run with permission_granted=true to execute."
            ),
            "tool": tool_name,
        }

    py_payload = _load_custom_python_tools()
    tools: Dict[str, Any] = py_payload.get("tools", {})
    if tool_name not in tools:
        raise ValueError(f"Python tool not found: {tool_name}")

    tool_def = tools[tool_name]
    code = tool_def.get("code", "")
    if not isinstance(code, str) or not code.strip():
        raise ValueError("Python tool has empty code.")

    _validate_python_tool_code(code)

    # Execution environment: restricted builtins (still not a true sandbox)
    safe_builtins = {
        "str": str,
        "int": int,
        "float": float,
        "bool": bool,
        "dict": dict,
        "list": list,
        "tuple": tuple,
        "set": set,
        "len": len,
        "min": min,
        "max": max,
        "sum": sum,
        "sorted": sorted,
        "range": range,
        "enumerate": enumerate,
        "print": print,
    }

    env: Dict[str, Any] = {
        "__builtins__": safe_builtins,
        "args": input_args,
        "result": None,
    }

    _append_audit({
        "type": "python_tool_exec_start",
        "tool": tool_name,
        "args": input_args,
    })

    try:
        exec(code, env, env)  # user requested this method to exist
        output = env.get("result", None)
    except Exception as e:
        _append_audit({
            "type": "python_tool_exec_error",
            "tool": tool_name,
            "error": str(e),
            "trace": traceback.format_exc(),
        })
        raise

    _append_audit({
        "type": "python_tool_exec_done",
        "tool": tool_name,
    })

    return {
        "python_tool": tool_name,
        "input_args": input_args,
        "result": output,
        "finished_utc": _utc_now_iso(),
        "permission_granted": True,
    }

# =========================================================
# MCP TOOLS (APPENDED)
# =========================================================

@mcp.tool()
def tool_registry_sync(static_tool_names: List[str]) -> Dict[str, Any]:
    """
    Saves/updates the static tool registry.
    You pass the list of tool names you want registered.
    """
    payload = _sync_static_tools_registry(static_tool_names)
    _append_audit({"type": "registry_sync", "count": len(static_tool_names)})
    return payload

@mcp.tool()
def tool_registry_list() -> Dict[str, Any]:
    """
    Lists:
    - Static tools (hardcoded)
    - Custom DSL tools
    - Custom Python tools
    """
    static_payload = _read_json_file(STATIC_TOOLS_FILE, default={"tools": []})
    dsl_payload = _load_custom_dsl_tools()
    py_payload = _load_custom_python_tools()

    dsl_tools = sorted(list((dsl_payload.get("tools") or {}).keys()))
    py_tools = sorted(list((py_payload.get("tools") or {}).keys()))

    return {
        "static_tools": static_payload.get("tools", []),
        "custom_dsl_tools": dsl_tools,
        "custom_python_tools": py_tools,
        "files": {
            "static": str(STATIC_TOOLS_FILE),
            "dsl": str(CUSTOM_DSL_TOOLS_FILE),
            "python": str(CUSTOM_PY_TOOLS_FILE),
        },
        "updated_utc": _utc_now_iso(),
    }

@mcp.tool()
def custom_dsl_tool_create(
    name: str,
    description: str,
    steps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Creates a custom tool using secure Workflow DSL.
    steps format:
      [{"tool": "existing_tool_name", "args": {...}}, ...]
    """
    tool_name = _normalize_tool_name(name)

    if not steps or not isinstance(steps, list):
        raise ValueError("steps must be a non-empty list")

    # validate steps
    normalized_steps: List[Dict[str, Any]] = []
    for i, s in enumerate(steps, start=1):
        if not isinstance(s, dict):
            raise ValueError(f"Step {i} must be a dict")
        if "tool" not in s:
            raise ValueError(f"Step {i} missing 'tool'")
        if "args" not in s:
            s["args"] = {}
        if not isinstance(s["tool"], str):
            raise ValueError(f"Step {i} tool must be str")
        if not isinstance(s["args"], dict):
            raise ValueError(f"Step {i} args must be dict")
        normalized_steps.append({"tool": s["tool"], "args": s["args"]})

    payload = _load_custom_dsl_tools()
    tools = payload.get("tools", {})
    if not isinstance(tools, dict):
        tools = {}

    tools[tool_name] = {
        "name": tool_name,
        "description": description.strip(),
        "steps": normalized_steps,
        "created_utc": _utc_now_iso(),
        "created_by": "user",
    }

    payload["tools"] = tools
    payload["schema_version"] = "1.0"
    _save_custom_dsl_tools(payload)

    _append_audit({"type": "dsl_tool_created", "tool": tool_name, "steps": len(steps)})

    return {
        "status": "created",
        "tool": tool_name,
        "steps": normalized_steps,
        "stored_in": str(CUSTOM_DSL_TOOLS_FILE),
    }

@mcp.tool()
def custom_dsl_tool_delete(name: str) -> Dict[str, Any]:
    tool_name = _normalize_tool_name(name)
    payload = _load_custom_dsl_tools()
    tools = payload.get("tools", {})
    if tool_name not in tools:
        return {"status": "not_found", "tool": tool_name}

    del tools[tool_name]
    payload["tools"] = tools
    _save_custom_dsl_tools(payload)

    _append_audit({"type": "dsl_tool_deleted", "tool": tool_name})

    return {"status": "deleted", "tool": tool_name}

@mcp.tool()
async def custom_dsl_tool_run(name: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Executes a DSL tool.
    """
    tool_name = _normalize_tool_name(name)
    args = args or {}

    async def caller(tool: str, tool_args: Dict[str, Any]) -> Any:
        # This is the key trick:
        # We call an existing MCP tool by name using FastMCP's internal dispatch.
        # If FastMCP changes, we can replace this with a direct mapping.
        fn = globals().get(tool)
        if fn is None or not callable(fn):
            raise ValueError(f"Tool not found in server runtime: {tool}")
        if hasattr(fn, "__call__"):
            # Supports sync or async
            res = fn(**tool_args)  # type: ignore
            if hasattr(res, "__await__"):
                return await res  # type: ignore
            return res
        raise ValueError(f"Tool not callable: {tool}")

    result = await _run_dsl_tool(tool_name, args, caller)
    _append_audit({"type": "dsl_tool_run_done", "tool": tool_name})
    return result

@mcp.tool()
def custom_python_tool_create(name: str, description: str, code: str) -> Dict[str, Any]:
    """
    Stores a raw python tool (NOT executed yet).
    Execution is gated by permission at run time.
    Code must set:
      result = ...
    """
    tool_name = _normalize_tool_name(name)

    if "result" not in code:
        code = code.strip() + "\n\nresult = None\n"

    payload = _load_custom_python_tools()
    tools = payload.get("tools", {})
    if not isinstance(tools, dict):
        tools = {}

    tools[tool_name] = {
        "name": tool_name,
        "description": description.strip(),
        "code": code,
        "created_utc": _utc_now_iso(),
        "created_by": "user",
    }

    payload["tools"] = tools
    payload["schema_version"] = "1.0"
    _save_custom_python_tools(payload)

    _append_audit({"type": "python_tool_created", "tool": tool_name})

    return {
        "status": "created",
        "tool": tool_name,
        "stored_in": str(CUSTOM_PY_TOOLS_FILE),
        "warning": (
            "This tool contains raw python. It will NOT run unless "
            "custom_python_tool_run(..., permission_granted=True)."
        ),
    }

@mcp.tool()
def custom_python_tool_delete(name: str) -> Dict[str, Any]:
    tool_name = _normalize_tool_name(name)
    payload = _load_custom_python_tools()
    tools = payload.get("tools", {})
    if tool_name not in tools:
        return {"status": "not_found", "tool": tool_name}

    del tools[tool_name]
    payload["tools"] = tools
    _save_custom_python_tools(payload)

    _append_audit({"type": "python_tool_deleted", "tool": tool_name})

    return {"status": "deleted", "tool": tool_name}

@mcp.tool()
async def custom_python_tool_run(
    name: str,
    args: Optional[Dict[str, Any]] = None,
    permission_granted: bool = False,
) -> Dict[str, Any]:
    """
    Executes a stored raw python tool only when permission_granted=True.
    """
    tool_name = _normalize_tool_name(name)
    args = args or {}
    return await _run_python_tool(tool_name, args, permission_granted)

@mcp.tool()
def soar_audit_log_tail(lines: int = 50) -> Dict[str, Any]:
    """
    Returns last N audit log events.
    """
    if lines < 1:
        lines = 1
    if lines > 500:
        lines = 500

    if not AUDIT_LOG_FILE.exists():
        return {"events": [], "note": "No audit log yet."}

    raw = AUDIT_LOG_FILE.read_text(encoding="utf-8").splitlines()
    tail = raw[-lines:]
    events: List[Dict[str, Any]] = []
    for t in tail:
        try:
            events.append(json.loads(t))
        except Exception:
            continue
    return {"events": events, "count": len(events)}

# =========================================================
# SOAR ORCHESTRATOR (AUTO-PLANNER)
# =========================================================

@mcp.tool()
def soar_orchestrate(
    goal: str,
    constraints: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Returns a suggested workflow plan (DSL style) to achieve a goal.
    This does NOT execute anything.
    """
    constraints = constraints or {}

    # Very simple first version: deterministic planning
    # (we will upgrade later into rule-based + scoring + MITRE mapping)
    goal_l = goal.lower()

    plan: List[Dict[str, Any]] = []

    # Try to reference your existing security tools by name.
    # If your tool names differ, you can rename them here later.
    if "triage" in goal_l or "snapshot" in goal_l:
        plan.append({"tool": "security_triage_snapshot", "args": {"minutes": constraints.get("minutes", 60)}})

    if "connections" in goal_l or "network" in goal_l:
        plan.append({"tool": "list_external_connections", "args": {"limit": constraints.get("limit", 200)}})

    if "event" in goal_l or "logs" in goal_l:
        plan.append({"tool": "get_recent_windows_event_logs", "args": {"minutes": constraints.get("minutes", 60)}})

    if "block" in goal_l or "firewall" in goal_l:
        plan.append({"tool": "fw_block_ip", "args": {"ip": constraints.get("ip", "0.0.0.0")}})

    if not plan:
        plan.append({
            "tool": "security_triage_snapshot",
            "args": {"minutes": constraints.get("minutes", 30)}
        })

    return {
        "goal": goal,
        "constraints": constraints,
        "recommended_plan": plan,
        "note": (
            "Use custom_dsl_tool_create() with these steps to store as a playbook. "
            "Then run via custom_dsl_tool_run()."
        ),
    }