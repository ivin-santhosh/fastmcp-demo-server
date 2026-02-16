from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Literal

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

EVIDENCE_DIR = BASE_DIR / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


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


def sha256_file(path: str) -> Optional[str]:
    """
    Computes SHA256 for evidence integrity.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
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
        return {"pid": None, "process": None, "exe": None, "username": None, "signed": None}

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

        signed = None
        if exe:
            signed = verify_file_signature(exe).get("is_signed")

        return {"pid": pid, "process": name, "exe": exe, "username": username, "signed": signed}
    except Exception:
        return {"pid": pid, "process": None, "exe": None, "username": None, "signed": None}


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
                    "signed": proc.get("signed"),
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
                cmdline = " ".join(cmdline_list[:60]) if isinstance(cmdline_list, list) else None
            except Exception:
                pass

            try:
                ppid = proc.ppid()
            except Exception:
                pass

            signed = None
            if exe:
                signed = verify_file_signature(exe).get("is_signed")

            out.append(
                {
                    "pid": pid,
                    "ppid": int(ppid) if isinstance(ppid, int) else None,
                    "name": p.info.get("name"),
                    "username": p.info.get("username"),
                    "exe": exe,
                    "cmdline": cmdline,
                    "signed": signed,
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
                    "signed": proc.get("signed"),
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
# Critical Reliability: Dual-Path Evidence Fetching
# (wevtutil + powershell already done for event logs)
# ============================================================

def verify_file_signature(path: str) -> Dict[str, Any]:
    """
    Uses PowerShell Get-AuthenticodeSignature.
    """
    ps = rf"""
    try {{
      $sig = Get-AuthenticodeSignature -FilePath "{path}"
      [PSCustomObject]@{{
        Status = $sig.Status.ToString()
        SignerCertificate = $sig.SignerCertificate.Subject
        TimeStamperCertificate = $sig.TimeStamperCertificate.Subject
      }} | ConvertTo-Json -Depth 3
    }} catch {{
      ""
    }}
    """
    code, out, err = run_powershell(ps, timeout=12)
    if code != 0 or not out:
        return {"available": False, "error": err or "signature check failed", "is_signed": None}

    try:
        data = json.loads(out)
        status = str(data.get("Status") or "")
        return {
            "available": True,
            "data": data,
            "is_signed": status.lower() == "valid",
        }
    except Exception:
        return {"available": True, "raw": out[:2000], "is_signed": None}


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
# Persistence + Hardening Evidence (NEW)
# ============================================================

def get_startup_persistence() -> Dict[str, Any]:
    """
    Checks Run keys + Startup folders.
    """
    ps = r"""
    try {
      $paths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
      )

      $runKeys = foreach ($p in $paths) {
        try {
          Get-ItemProperty -Path $p | Select-Object * -ExcludeProperty PS* |
          ForEach-Object {
            $_.PSObject.Properties |
            Where-Object { $_.Name -ne "" -and $_.Value -ne $null } |
            ForEach-Object {
              [PSCustomObject]@{
                Location = $p
                Name = $_.Name
                Value = $_.Value
              }
            }
          }
        } catch {}
      }

      $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
      )

      $startupItems = foreach ($sf in $startupFolders) {
        try {
          Get-ChildItem -Path $sf -ErrorAction SilentlyContinue |
          Select-Object FullName, Name, LastWriteTime
        } catch {}
      }

      [PSCustomObject]@{
        RunKeys = $runKeys
        StartupItems = $startupItems
      } | ConvertTo-Json -Depth 5
    } catch { "" }
    """
    code, out, err = run_powershell(ps, timeout=20)
    if code != 0 or not out:
        return {"available": False, "error": err or "persistence scan failed"}
    try:
        return {"available": True, "data": json.loads(out)}
    except Exception:
        return {"available": True, "raw": out[:4000]}


def get_scheduled_tasks_inventory(limit: int = 250) -> Dict[str, Any]:
    """
    Enumerates scheduled tasks (not only event logs).
    """
    limit = max(10, min(limit, 2000))
    ps = rf"""
    try {{
      Get-ScheduledTask |
      Select-Object -First {limit} TaskName, TaskPath, State, Author, Description |
      ConvertTo-Json -Depth 4
    }} catch {{
      ""
    }}
    """
    code, out, err = run_powershell(ps, timeout=18)
    if code != 0 or not out:
        return {"available": False, "error": err or "scheduled tasks unavailable"}
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return {"available": True, "tasks": data, "count": len(data)}
    except Exception:
        return {"available": True, "raw": out[:4000]}


def get_services_inventory(limit: int = 250) -> Dict[str, Any]:
    """
    Enumerates services and their binary paths.
    """
    limit = max(10, min(limit, 4000))
    ps = rf"""
    try {{
      Get-CimInstance Win32_Service |
      Select-Object -First {limit} Name, DisplayName, State, StartMode, PathName, StartName |
      ConvertTo-Json -Depth 4
    }} catch {{
      ""
    }}
    """
    code, out, err = run_powershell(ps, timeout=20)
    if code != 0 or not out:
        return {"available": False, "error": err or "services unavailable"}
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return {"available": True, "services": data, "count": len(data)}
    except Exception:
        return {"available": True, "raw": out[:4000]}


def get_defender_exclusions() -> Dict[str, Any]:
    ps = r"""
    try {
      $pref = Get-MpPreference
      [PSCustomObject]@{
        ExclusionPath = $pref.ExclusionPath
        ExclusionProcess = $pref.ExclusionProcess
        ExclusionExtension = $pref.ExclusionExtension
      } | ConvertTo-Json -Depth 4
    } catch { "" }
    """
    code, out, err = run_powershell(ps, timeout=15)
    if code != 0 or not out:
        return {"available": False, "error": err or "Defender exclusions unavailable"}
    try:
        return {"available": True, "data": json.loads(out)}
    except Exception:
        return {"available": True, "raw": out[:2000]}


def get_hosts_file_status() -> Dict[str, Any]:
    """
    Hosts file tampering is a common persistence trick.
    """
    hosts = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        if not os.path.exists(hosts):
            return {"exists": False}

        with open(hosts, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        suspicious_lines = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "microsoft" in line.lower() or "windowsupdate" in line.lower():
                suspicious_lines.append(line)

        return {
            "exists": True,
            "path": hosts,
            "sha256": sha256_file(hosts),
            "suspicious_lines": suspicious_lines[:50],
        }
    except Exception as e:
        return {"exists": None, "error": str(e)}


def get_dns_cache(limit: int = 200) -> Dict[str, Any]:
    """
    DNS cache is evidence for C2 domains.
    """
    limit = max(20, min(limit, 2000))
    ps = rf"""
    try {{
      Get-DnsClientCache |
      Select-Object -First {limit} Entry, Data, Type, Status |
      ConvertTo-Json -Depth 3
    }} catch {{
      ""
    }}
    """
    code, out, err = run_powershell(ps, timeout=18)
    if code != 0 or not out:
        return {"available": False, "error": err or "DNS cache unavailable"}
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return {"available": True, "entries": data, "count": len(data)}
    except Exception:
        return {"available": True, "raw": out[:4000]}


def get_local_admins() -> Dict[str, Any]:
    """
    Lists local Administrators group membership.
    """
    ps = r"""
    try {
      Get-LocalGroupMember -Group "Administrators" |
      Select-Object Name, ObjectClass, PrincipalSource |
      ConvertTo-Json -Depth 3
    } catch { "" }
    """
    code, out, err = run_powershell(ps, timeout=15)
    if code != 0 or not out:
        return {"available": False, "error": err or "local admins unavailable"}
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return {"available": True, "members": data, "count": len(data)}
    except Exception:
        return {"available": True, "raw": out[:3000]}


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
        signed = p.get("signed")

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

        if exe and ("\\temp\\" in exe or "\\appdata\\roaming\\" in exe):
            alerts.append(
                {
                    "type": "process_from_suspicious_path",
                    "severity": "high",
                    "reason": "Process executable located in Temp/AppData (common malware location)",
                    "process": p,
                    "mitre": [{"technique_id": "T1105", "name": "Ingress Tool Transfer"}],
                }
            )

        if signed is False:
            alerts.append(
                {
                    "type": "unsigned_running_binary",
                    "severity": "medium",
                    "reason": "Running executable is not Authenticode-signed (may be suspicious)",
                    "process": p,
                    "mitre": [{"technique_id": "T1036", "name": "Masquerading"}],
                }
            )

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
                    "type": "lolbin_network_activity",
                    "severity": "medium",
                    "reason": f"Connection made by LOLBin-like process: {proc}",
                    "connection": c,
                    "mitre": [{"technique_id": "T1059", "name": "Command and Scripting Interpreter"}],
                }
            )

        if "\\appdata\\roaming\\" in exe or "\\temp\\" in exe:
            alerts.append(
                {
                    "type": "network_from_suspicious_path",
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


def firewall_remove_rules(prefix: str) -> Dict[str, Any]:
    """
    Reliability tool: rollback containment rules.
    """
    ps = rf"""
    try {{
      Get-NetFirewallRule | Where-Object {{$_.DisplayName -like "{prefix}*"}} | Remove-NetFirewallRule
      "OK"
    }} catch {{
      "ERROR"
    }}
    """
    code, out, err = run_powershell(ps, timeout=18)
    return {"ok": code == 0 and "OK" in out, "stdout": out, "stderr": err}


# ============================================================
# SOC Report Generator (Standards + Evidence)
# ============================================================

def extract_iocs(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts IPs/domains/paths for SOC workflows.
    """
    ips = set()
    paths = set()

    evidence = report.get("evidence") or {}
    conns = evidence.get("external_connections") or []
    procs = evidence.get("process_inventory_sample") or []

    for c in conns:
        if isinstance(c, dict):
            ip = c.get("remote_ip")
            if ip:
                ips.add(str(ip))
            exe = c.get("exe")
            if exe:
                paths.add(str(exe))

    for p in procs:
        if isinstance(p, dict):
            exe = p.get("exe")
            if exe:
                paths.add(str(exe))

    return {
        "remote_ips": sorted(list(ips))[:500],
        "exe_paths": sorted(list(paths))[:500],
    }


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
    def_exclusions = get_defender_exclusions()
    persistence = get_startup_persistence()
    tasks = get_scheduled_tasks_inventory(limit=250)
    services = get_services_inventory(limit=250)
    admins = get_local_admins()
    hosts = get_hosts_file_status()
    dns_cache = get_dns_cache(limit=250)

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
        "If service installs detected, verify service binary path and publisher.",
        "Audit persistence (Run keys + Startup folders) and remove unknown entries.",
        "Review Defender exclusions; malicious actors often add exclusions.",
        "Run defender_update() then defender_scan_quick().",
        "If critical, apply containment via fw_lockdown_mode().",
        "Deploy Sysmon for higher-fidelity evidence and timeline reconstruction.",
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
            "defender_exclusions": def_exclusions,
            "persistence": persistence,
            "scheduled_tasks_inventory": tasks,
            "services_inventory": services,
            "local_admins": admins,
            "hosts_file": hosts,
            "dns_cache": dns_cache,
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
            "chain_of_custody_ready": True,
        },
    }

    report["iocs"] = extract_iocs(report)

    LAST_ALERTS = alerts
    LAST_REPORT = report
    return report


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
                report = build_soc_report(minutes=self.minutes_window)
                self._save_report(report)
                self.snapshot_count += 1
            except Exception:
                pass
            time.sleep(self.interval_seconds)

    def _save_report(self, report: Dict[str, Any]) -> None:
        safe_ts = utc_now_iso().replace(":", "-")
        path = self.output_dir / f"{safe_ts}_{report.get('report_id')}.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
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
def persistence_scan() -> Dict[str, Any]:
    """
    Run keys + Startup folder evidence.
    """
    try:
        data = get_startup_persistence()
        return {
            "meta": asdict(
                ToolMeta(
                    tool="persistence_scan",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Persistence scan completed.",
                )
            ),
            "data": data,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="persistence_scan",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Persistence scan failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def scheduled_tasks_inventory(limit: int = 250) -> Dict[str, Any]:
    try:
        data = get_scheduled_tasks_inventory(limit=limit)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="scheduled_tasks_inventory",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Scheduled tasks collected.",
                )
            ),
            "data": data,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="scheduled_tasks_inventory",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to collect scheduled tasks.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def services_inventory(limit: int = 250) -> Dict[str, Any]:
    try:
        data = get_services_inventory(limit=limit)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="services_inventory",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Services collected.",
                )
            ),
            "data": data,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="services_inventory",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to collect services.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def defender_get_exclusions() -> Dict[str, Any]:
    try:
        data = get_defender_exclusions()
        return {
            "meta": asdict(
                ToolMeta(
                    tool="defender_get_exclusions",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Defender exclusions fetched.",
                )
            ),
            "data": data,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="defender_get_exclusions",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to fetch exclusions.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def hosts_file_check() -> Dict[str, Any]:
    try:
        data = get_hosts_file_status()
        return {
            "meta": asdict(
                ToolMeta(
                    tool="hosts_file_check",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Hosts file checked.",
                )
            ),
            "data": data,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="hosts_file_check",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Hosts file check failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def dns_cache_dump(limit: int = 200) -> Dict[str, Any]:
    try:
        data = get_dns_cache(limit=limit)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="dns_cache_dump",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="DNS cache fetched.",
                )
            ),
            "data": data,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="dns_cache_dump",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="DNS cache fetch failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def list_local_admins() -> Dict[str, Any]:
    try:
        data = get_local_admins()
        return {
            "meta": asdict(
                ToolMeta(
                    tool="list_local_admins",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Local admins fetched.",
                )
            ),
            "data": data,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="list_local_admins",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Failed to fetch local admins.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


@mcp.tool()
def fw_remove_rules(prefix: str) -> Dict[str, Any]:
    """
    Rollback firewall rules created by lockdown/block tools.
    Requires admin.
    """
    try:
        prefix = prefix.strip()
        if not prefix:
            return {
                "meta": asdict(
                    ToolMeta(
                        tool="fw_remove_rules",
                        success=False,
                        timestamp_utc=utc_now_iso(),
                        message="Prefix required.",
                    )
                ),
                "error": asdict(ErrorInfo(error_type="ValidationError", error_message="prefix is required")),
            }

        result = firewall_remove_rules(prefix)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="fw_remove_rules",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Firewall rules removal executed.",
                )
            ),
            "data": result,
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="fw_remove_rules",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Firewall rule removal failed.",
                )
            ),
            "error": asdict(ErrorInfo(error_type=type(e).__name__, error_message=str(e))),
        }


# ============================================================
# Run Server
# ============================================================

if __name__ == "__main__":
    mcp.run(transport="stdio")
