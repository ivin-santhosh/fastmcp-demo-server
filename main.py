from fastmcp import FastMCP
import psutil
import platform
import socket
import datetime
import time
import uuid
import json
import subprocess
from typing import Any, Dict, List, Optional, Tuple


mcp = FastMCP("NetProbe MCP - Fan Spike Watch (Windows + Event Logs)")


# -----------------------------
# In-memory session storage
# -----------------------------
LAST_WATCH_SESSION: Optional[Dict[str, Any]] = None


# -----------------------------
# Helpers
# -----------------------------
def utc_now() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


def utc_dt_now() -> datetime.datetime:
    return datetime.datetime.utcnow()


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def run_powershell(cmd: str, timeout_sec: int = 10) -> str:
    """
    Safe wrapper for reading system info via PowerShell.
    """
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout_sec
        )
        return (completed.stdout or "").strip()
    except Exception:
        return ""


def get_basic_machine_info() -> Dict[str, Any]:
    return {
        "hostname": platform.node(),
        "os": platform.platform(),
        "local_ip": get_local_ip(),
        "boot_time_utc": datetime.datetime.utcfromtimestamp(psutil.boot_time()).isoformat(timespec="seconds") + "Z"
    }


def safe_process_info(limit: int = 12) -> List[Dict[str, Any]]:
    procs = []
    for p in psutil.process_iter(attrs=["pid", "name", "username"]):
        try:
            mem = p.memory_info().rss
            cpu = p.cpu_percent(interval=0.0)
            procs.append({
                "pid": p.info["pid"],
                "name": p.info["name"],
                "username": p.info.get("username"),
                "cpu_percent": cpu,
                "memory_rss_bytes": mem,
            })
        except Exception:
            continue

    procs = sorted(procs, key=lambda x: (x["cpu_percent"], x["memory_rss_bytes"]), reverse=True)
    return procs[:limit]


def get_system_snapshot() -> Dict[str, Any]:
    cpu = psutil.cpu_percent(interval=0.25)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("C://")

    return {
        "timestamp_utc": utc_now(),
        "machine": get_basic_machine_info(),
        "cpu": {"percent": cpu},
        "ram": {
            "percent": ram.percent,
            "used_bytes": ram.used,
            "available_bytes": ram.available,
            "total_bytes": ram.total,
        },
        "disk_c": {
            "percent": disk.percent,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
            "total_bytes": disk.total,
        }
    }


def get_network_summary() -> Dict[str, Any]:
    io = psutil.net_io_counters(pernic=True)
    interfaces = {}

    for nic, c in io.items():
        interfaces[nic] = {
            "bytes_sent": c.bytes_sent,
            "bytes_recv": c.bytes_recv,
            "packets_sent": c.packets_sent,
            "packets_recv": c.packets_recv,
            "errin": c.errin,
            "errout": c.errout,
            "dropin": c.dropin,
            "dropout": c.dropout,
        }

    conns = []
    try:
        for c in psutil.net_connections(kind="inet")[:60]:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None
            conns.append({
                "pid": c.pid,
                "status": c.status,
                "local": laddr,
                "remote": raddr,
            })
    except Exception as e:
        conns = [{"error": str(e)}]

    return {
        "interfaces": interfaces,
        "connections_sample": conns
    }


def get_gpu_snapshot_windows() -> Dict[str, Any]:
    """
    Best-effort GPU telemetry via Windows perf counters.
    """
    ps_cmd = r"""
    $counters = Get-Counter '\GPU Engine(*)\Utilization Percentage' -ErrorAction SilentlyContinue
    if ($counters -and $counters.CounterSamples) {
      $top = $counters.CounterSamples |
        Sort-Object CookedValue -Descending |
        Select-Object -First 10 |
        ForEach-Object { "$($_.InstanceName)=$([math]::Round($_.CookedValue,2))" }
      $top -join "`n"
    }
    """
    out = run_powershell(ps_cmd, timeout_sec=8)

    if not out:
        return {"available": False, "note": "GPU perf counters not available on this system."}

    lines = [x.strip() for x in out.splitlines() if x.strip()]
    return {
        "available": True,
        "top_gpu_engines": lines
    }


# -----------------------------
# Windows Event Logs (Sampling)
# -----------------------------
def _win_event_query(log_name: str, minutes: int, max_events: int) -> str:
    """
    Returns a PowerShell script that fetches last N minutes of events.
    We keep fields small so it stays fast.
    """
    return rf"""
    $start=(Get-Date).AddMinutes(-{minutes})
    Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; StartTime=$start}} -ErrorAction SilentlyContinue |
      Select-Object -First {max_events} |
      ForEach-Object {{
        [PSCustomObject]@{{
          TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o")
          Id = $_.Id
          LevelDisplayName = $_.LevelDisplayName
          ProviderName = $_.ProviderName
          Message = ($_.Message -replace "\r"," " -replace "\n"," ") 
        }}
      }} | ConvertTo-Json -Depth 4
    """


def get_recent_event_logs(minutes: int = 3, max_events_per_log: int = 12) -> Dict[str, Any]:
    """
    Collects a small batch of event logs from multiple sources.
    """
    minutes = max(1, min(minutes, 30))
    max_events_per_log = max(3, min(max_events_per_log, 50))

    logs = {
        "System": [],
        "Application": [],
        "Security": [],
        # Defender Operational log
        "Defender": [],
        # Windows Update client operational log
        "WindowsUpdate": [],
    }

    # Standard logs
    for log_name in ["System", "Application", "Security"]:
        out = run_powershell(_win_event_query(log_name, minutes, max_events_per_log), timeout_sec=12)
        if out:
            try:
                logs[log_name] = json.loads(out)
            except Exception:
                logs[log_name] = [{"raw": out[:2000]}]

    # Defender log
    defender_cmd = rf"""
    $start=(Get-Date).AddMinutes(-{minutes})
    Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$start}} -ErrorAction SilentlyContinue |
      Select-Object -First {max_events_per_log} |
      ForEach-Object {{
        [PSCustomObject]@{{
          TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o")
          Id = $_.Id
          LevelDisplayName = $_.LevelDisplayName
          ProviderName = $_.ProviderName
          Message = ($_.Message -replace "\r"," " -replace "\n"," ")
        }}
      }} | ConvertTo-Json -Depth 4
    """
    out = run_powershell(defender_cmd, timeout_sec=12)
    if out:
        try:
            logs["Defender"] = json.loads(out)
        except Exception:
            logs["Defender"] = [{"raw": out[:2000]}]

    # Windows Update log
    wu_cmd = rf"""
    $start=(Get-Date).AddMinutes(-{minutes})
    Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-WindowsUpdateClient/Operational'; StartTime=$start}} -ErrorAction SilentlyContinue |
      Select-Object -First {max_events_per_log} |
      ForEach-Object {{
        [PSCustomObject]@{{
          TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o")
          Id = $_.Id
          LevelDisplayName = $_.LevelDisplayName
          ProviderName = $_.ProviderName
          Message = ($_.Message -replace "\r"," " -replace "\n"," ")
        }}
      }} | ConvertTo-Json -Depth 4
    """
    out = run_powershell(wu_cmd, timeout_sec=12)
    if out:
        try:
            logs["WindowsUpdate"] = json.loads(out)
        except Exception:
            logs["WindowsUpdate"] = [{"raw": out[:2000]}]

    return logs


# -----------------------------
# Correlation Engine
# -----------------------------
FAN_SPIKE_EVENT_KEYWORDS = [
    # Defender / scanning
    "scan",
    "Windows Defender",
    "MpCmdRun",
    "antimalware",
    "threat",
    # Updates
    "Windows Update",
    "install",
    "servicing",
    "cumulative update",
    "download",
    # GPU / driver
    "display driver",
    "nvlddmkm",
    "graphics",
    "GPU",
    # System load
    "thermal",
    "power",
    "ACPI",
    "Kernel-Power",
    "WMI",
]


def extract_relevant_events(event_logs: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Filters event logs down to a small list that likely correlates with fan spikes.
    """
    relevant: List[Dict[str, Any]] = []

    def norm(x: str) -> str:
        return (x or "").lower()

    for log_name, events in event_logs.items():
        if not isinstance(events, list):
            continue

        for e in events:
            msg = norm(str(e.get("Message", "")))
            provider = norm(str(e.get("ProviderName", "")))
            lvl = norm(str(e.get("LevelDisplayName", "")))

            hit = False
            for kw in FAN_SPIKE_EVENT_KEYWORDS:
                if kw.lower() in msg or kw.lower() in provider:
                    hit = True
                    break

            # Always keep critical errors
            if "critical" in lvl or "error" in lvl:
                hit = True

            if hit:
                relevant.append({
                    "log": log_name,
                    "time_utc": e.get("TimeCreated"),
                    "id": e.get("Id"),
                    "level": e.get("LevelDisplayName"),
                    "provider": e.get("ProviderName"),
                    "message": (e.get("Message") or "")[:300]
                })

    return relevant[:25]


def compute_network_peak_delta(samples: List[Dict[str, Any]]) -> int:
    deltas = []
    for i in range(1, len(samples)):
        prev = samples[i - 1]["network"]["interfaces"]
        cur = samples[i]["network"]["interfaces"]
        total_prev = sum(v["bytes_recv"] + v["bytes_sent"] for v in prev.values())
        total_cur = sum(v["bytes_recv"] + v["bytes_sent"] for v in cur.values())
        deltas.append(total_cur - total_prev)
    return max(deltas) if deltas else 0


def summarize_meaning(cpu_peak: float, net_peak_delta: int, gpu_available: bool, relevant_events: List[Dict[str, Any]]) -> List[str]:
    meaning: List[str] = []

    # CPU
    if cpu_peak >= 75:
        meaning.append("CPU spike detected (strong fan trigger candidate).")
    elif cpu_peak >= 35:
        meaning.append("Moderate CPU activity detected (possible brief fan ramp).")
    else:
        meaning.append("CPU stayed low (fan spikes likely not CPU-driven).")

    # GPU
    if gpu_available:
        meaning.append("GPU perf counters are available (GPU boost may contribute).")
    else:
        meaning.append("GPU telemetry not available via perf counters (GPU could still be the cause).")

    # Network
    if net_peak_delta > 10_000_000:
        meaning.append("High network throughput spike detected (downloads/updates possible).")
    elif net_peak_delta > 1_000_000:
        meaning.append("Moderate network throughput detected.")
    else:
        meaning.append("Network activity appears normal.")

    # Event logs
    if relevant_events:
        meaning.append(f"Event Logs: {len(relevant_events)} relevant events detected during the window.")
        top_providers = {}
        for e in relevant_events:
            prov = e.get("provider") or "Unknown"
            top_providers[prov] = top_providers.get(prov, 0) + 1
        top_sorted = sorted(top_providers.items(), key=lambda x: x[1], reverse=True)[:5]
        meaning.append("Top event providers correlated: " + ", ".join([f"{p} ({c})" for p, c in top_sorted]))
    else:
        meaning.append("Event Logs: No relevant system/update/defender/driver events detected in the window.")

    return meaning


# -----------------------------
# MCP Tools
# -----------------------------
@mcp.tool()
def get_full_snapshot() -> Dict[str, Any]:
    """
    One-call snapshot: system + network + processes + GPU + event logs.
    """
    return {
        "system": get_system_snapshot(),
        "network": get_network_summary(),
        "processes": safe_process_info(limit=12),
        "gpu": get_gpu_snapshot_windows(),
        "event_logs": get_recent_event_logs(minutes=3, max_events_per_log=10),
    }


@mcp.tool()
def start_live_fan_speed_spike_watch(duration_sec: int = 30, interval_ms: int = 500) -> Dict[str, Any]:
    """
    High-resolution monitoring session.
    Captures snapshots repeatedly and correlates spikes + event logs.
    """
    global LAST_WATCH_SESSION

    duration_sec = max(5, min(duration_sec, 180))
    interval_ms = max(250, min(interval_ms, 3000))

    session_id = str(uuid.uuid4())
    start = time.time()
    samples: List[Dict[str, Any]] = []

    # Prime CPU percent
    psutil.cpu_percent(interval=0.1)

    # Collect event logs at the beginning (baseline)
    baseline_events = get_recent_event_logs(minutes=3, max_events_per_log=15)

    while True:
        now = time.time()
        if now - start > duration_sec:
            break

        snap = {
            "system": get_system_snapshot(),
            "network": get_network_summary(),
            "processes": safe_process_info(limit=12),
            "gpu": get_gpu_snapshot_windows(),
        }
        snap["snapshot_id"] = str(uuid.uuid4())
        samples.append(snap)

        time.sleep(interval_ms / 1000.0)

    # Collect event logs again at the end
    end_events = get_recent_event_logs(minutes=3, max_events_per_log=25)

    # Merge events (simple: keep both sets)
    merged_events = {
        "baseline": baseline_events,
        "end": end_events
    }

    relevant_events = extract_relevant_events(baseline_events) + extract_relevant_events(end_events)
    relevant_events = relevant_events[:30]

    # Analyze spikes
    cpu_values = [s["system"]["cpu"]["percent"] for s in samples]
    ram_values = [s["system"]["ram"]["percent"] for s in samples]

    cpu_peak = max(cpu_values) if cpu_values else 0
    cpu_avg = round(sum(cpu_values) / len(cpu_values), 2) if cpu_values else 0

    ram_peak = max(ram_values) if ram_values else 0
    ram_avg = round(sum(ram_values) / len(ram_values), 2) if ram_values else 0

    net_peak_delta = 0
    try:
        net_peak_delta = compute_network_peak_delta(samples)
    except Exception:
        net_peak_delta = 0

    gpu_available = samples[-1]["gpu"].get("available", False) if samples else False

    meaning = summarize_meaning(cpu_peak, net_peak_delta, gpu_available, relevant_events)

    # Store session
    LAST_WATCH_SESSION = {
        "session_id": session_id,
        "started_utc": samples[0]["system"]["timestamp_utc"] if samples else utc_now(),
        "ended_utc": samples[-1]["system"]["timestamp_utc"] if samples else utc_now(),
        "duration_sec": duration_sec,
        "interval_ms": interval_ms,
        "stats": {
            "cpu_avg": cpu_avg,
            "cpu_peak": cpu_peak,
            "ram_avg": ram_avg,
            "ram_peak": ram_peak,
            "net_peak_bytes_delta": net_peak_delta,
            "sample_count": len(samples),
        },
        "meaning": meaning,
        "relevant_events": relevant_events,
        "event_logs_raw": merged_events,
        "samples": samples
    }

    # Prompter-style output
    return {
        "title": "🔎 Live High-Resolution Monitoring — Fan Spike Watch",
        "time_utc": utc_now(),
        "session_id": session_id,
        "snapshot_count": len(samples),
        "cpu_avg": cpu_avg,
        "cpu_peak": cpu_peak,
        "ram_avg": ram_avg,
        "ram_peak": ram_peak,
        "net_peak_bytes_delta": net_peak_delta,
        "event_log_hits": len(relevant_events),
        "meaning": meaning,
        "next_step": "Run export_last_watch_to_json() to save the full raw dataset."
    }


@mcp.tool()
def export_last_watch_to_json(output_path: str = "netprobe_last_watch.json") -> Dict[str, Any]:
    """
    Saves the last monitoring session to a JSON file locally.
    """
    global LAST_WATCH_SESSION

    if not LAST_WATCH_SESSION:
        return {"ok": False, "error": "No watch session found. Run start_live_fan_speed_spike_watch() first."}

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(LAST_WATCH_SESSION, f, indent=2)

        return {
            "ok": True,
            "saved_to": output_path,
            "session_id": LAST_WATCH_SESSION["session_id"],
            "sample_count": LAST_WATCH_SESSION["stats"]["sample_count"],
            "event_log_hits": len(LAST_WATCH_SESSION.get("relevant_events", []))
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


if __name__ == "__main__":
    mcp.run()
