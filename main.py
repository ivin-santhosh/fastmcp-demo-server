from __future__ import annotations

import json
import os
import time
import uuid
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Literal, Tuple

import psutil
from fastmcp import FastMCP

# ============================================================
# MCP Server
# ============================================================

mcp = FastMCP("AI System Recorder MCP Server")

# ============================================================
# Types (Azure Foundry / Strict Schema Friendly)
# ============================================================

ISO8601 = str
RecordingProfile = Literal["basic", "security", "full"]
RecordingMode = Literal["foreground", "background"]
ExportFormat = Literal["json", "csv", "html"]


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
class NetworkSummary:
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errin: int
    errout: int
    dropin: int
    dropout: int


@dataclass
class ProcessInfo:
    pid: int
    name: Optional[str]
    exe: Optional[str]
    username: Optional[str]
    status: Optional[str]
    create_time_utc: Optional[ISO8601]
    cpu_percent: Optional[float]
    memory_rss: Optional[int]
    memory_vms: Optional[int]
    ppid: Optional[int]
    cmdline: Optional[List[str]]


@dataclass
class ConnectionInfo:
    pid: Optional[int]
    process_name: Optional[str]
    exe: Optional[str]
    username: Optional[str]
    status: str
    local_ip: Optional[str]
    local_port: Optional[int]
    remote_ip: Optional[str]
    remote_port: Optional[int]


@dataclass
class ListeningPortInfo:
    pid: Optional[int]
    process_name: Optional[str]
    exe: Optional[str]
    username: Optional[str]
    local_ip: Optional[str]
    local_port: Optional[int]


@dataclass
class SystemSnapshot:
    snapshot_id: str
    timestamp_utc: ISO8601
    profile: RecordingProfile

    cpu_percent: Optional[float]
    ram_percent: Optional[float]
    ram_used: Optional[int]
    ram_total: Optional[int]

    network: Optional[NetworkSummary]

    top_processes: Optional[List[ProcessInfo]]
    active_connections: Optional[List[ConnectionInfo]]
    listening_ports: Optional[List[ListeningPortInfo]]

    alerts: List[str]


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


# ============================================================
# Helpers (Safe + Robust)
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "recordings"
DATA_DIR.mkdir(parents=True, exist_ok=True)

_sessions_lock = threading.Lock()
_sessions: Dict[str, "RecorderSession"] = {}


def utc_now_iso() -> ISO8601:
    return datetime.now(timezone.utc).isoformat()


def safe_str(x: Any) -> Optional[str]:
    try:
        return str(x) if x is not None else None
    except Exception:
        return None


def safe_psutil_call(fn, default):
    try:
        return fn()
    except Exception:
        return default


def safe_process_info(pid: Optional[int]) -> ProcessInfo:
    """
    Safe process fetch.
    Never crashes the server.
    """
    if pid is None:
        return ProcessInfo(
            pid=-1,
            name=None,
            exe=None,
            username=None,
            status=None,
            create_time_utc=None,
            cpu_percent=None,
            memory_rss=None,
            memory_vms=None,
            ppid=None,
            cmdline=None,
        )

    try:
        p = psutil.Process(pid)

        with p.oneshot():
            name = safe_psutil_call(p.name, None)
            exe = safe_psutil_call(p.exe, None)
            username = safe_psutil_call(p.username, None)
            status = safe_psutil_call(p.status, None)

            create_time = safe_psutil_call(p.create_time, None)
            create_time_utc = (
                datetime.fromtimestamp(create_time, tz=timezone.utc).isoformat()
                if isinstance(create_time, (int, float))
                else None
            )

            cpu_percent = safe_psutil_call(p.cpu_percent, None)
            mem = safe_psutil_call(p.memory_info, None)

            memory_rss = getattr(mem, "rss", None) if mem else None
            memory_vms = getattr(mem, "vms", None) if mem else None

            ppid = safe_psutil_call(p.ppid, None)
            cmdline = safe_psutil_call(p.cmdline, None)

        return ProcessInfo(
            pid=pid,
            name=name,
            exe=exe,
            username=username,
            status=safe_str(status),
            create_time_utc=create_time_utc,
            cpu_percent=float(cpu_percent) if cpu_percent is not None else None,
            memory_rss=int(memory_rss) if memory_rss is not None else None,
            memory_vms=int(memory_vms) if memory_vms is not None else None,
            ppid=int(ppid) if ppid is not None else None,
            cmdline=list(cmdline) if isinstance(cmdline, list) else None,
        )

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ProcessInfo(
            pid=pid,
            name=None,
            exe=None,
            username=None,
            status=None,
            create_time_utc=None,
            cpu_percent=None,
            memory_rss=None,
            memory_vms=None,
            ppid=None,
            cmdline=None,
        )
    except Exception:
        return ProcessInfo(
            pid=pid,
            name=None,
            exe=None,
            username=None,
            status=None,
            create_time_utc=None,
            cpu_percent=None,
            memory_rss=None,
            memory_vms=None,
            ppid=None,
            cmdline=None,
        )


def safe_net_connections(kind: str = "inet") -> List[Any]:
    """
    psutil.net_connections is the #1 crash point.
    This wrapper prevents the server from dying.
    """
    try:
        return psutil.net_connections(kind=kind)
    except psutil.AccessDenied:
        return []
    except Exception:
        return []


def safe_net_io() -> Optional[NetworkSummary]:
    try:
        stats = psutil.net_io_counters()
        return NetworkSummary(
            bytes_sent=int(stats.bytes_sent),
            bytes_recv=int(stats.bytes_recv),
            packets_sent=int(stats.packets_sent),
            packets_recv=int(stats.packets_recv),
            errin=int(stats.errin),
            errout=int(stats.errout),
            dropin=int(stats.dropin),
            dropout=int(stats.dropout),
        )
    except Exception:
        return None


def safe_memory() -> Tuple[Optional[float], Optional[int], Optional[int]]:
    try:
        vm = psutil.virtual_memory()
        return float(vm.percent), int(vm.used), int(vm.total)
    except Exception:
        return None, None, None


def safe_cpu_percent() -> Optional[float]:
    try:
        return float(psutil.cpu_percent(interval=0.2))
    except Exception:
        return None


def detect_basic_alerts(snapshot: SystemSnapshot) -> List[str]:
    """
    Very safe lightweight alert engine.
    No "malware detection" claims. Just anomaly indicators.
    """
    alerts: List[str] = []

    if snapshot.cpu_percent is not None and snapshot.cpu_percent >= 85:
        alerts.append(f"High CPU usage detected: {snapshot.cpu_percent:.2f}%")

    if snapshot.ram_percent is not None and snapshot.ram_percent >= 90:
        alerts.append(f"High RAM usage detected: {snapshot.ram_percent:.2f}%")

    # Port 0.0.0.0 warnings
    if snapshot.listening_ports:
        for p in snapshot.listening_ports:
            if p.local_ip in ("0.0.0.0", "::"):
                alerts.append(
                    f"Port exposed on all interfaces: {p.local_ip}:{p.local_port} (PID={p.pid}, Process={p.process_name})"
                )

    return alerts


# ============================================================
# Snapshot Generator
# ============================================================

def build_snapshot(profile: RecordingProfile, limit: int = 30) -> SystemSnapshot:
    snapshot_id = str(uuid.uuid4())
    timestamp = utc_now_iso()

    cpu = safe_cpu_percent()
    ram_percent, ram_used, ram_total = safe_memory()
    net = safe_net_io()

    top_processes: Optional[List[ProcessInfo]] = None
    active_connections: Optional[List[ConnectionInfo]] = None
    listening_ports: Optional[List[ListeningPortInfo]] = None

    # BASIC profile only captures system stats
    if profile in ("security", "full"):
        # Processes
        procs: List[ProcessInfo] = []
        try:
            for p in psutil.process_iter(attrs=[]):
                if len(procs) >= max(1, limit):
                    break
                procs.append(safe_process_info(p.pid))
        except Exception:
            pass
        top_processes = procs

        # Connections
        conns = safe_net_connections(kind="inet")
        conn_results: List[ConnectionInfo] = []

        for c in conns[: max(1, limit)]:
            proc = safe_process_info(c.pid)

            local_ip = getattr(getattr(c, "laddr", None), "ip", None)
            local_port = getattr(getattr(c, "laddr", None), "port", None)

            remote_ip = getattr(getattr(c, "raddr", None), "ip", None)
            remote_port = getattr(getattr(c, "raddr", None), "port", None)

            conn_results.append(
                ConnectionInfo(
                    pid=proc.pid if proc.pid != -1 else None,
                    process_name=proc.name,
                    exe=proc.exe,
                    username=proc.username,
                    status=safe_str(getattr(c, "status", "UNKNOWN")) or "UNKNOWN",
                    local_ip=safe_str(local_ip),
                    local_port=int(local_port) if isinstance(local_port, int) else None,
                    remote_ip=safe_str(remote_ip),
                    remote_port=int(remote_port) if isinstance(remote_port, int) else None,
                )
            )

        active_connections = conn_results

        # Listening ports
        listening: List[ListeningPortInfo] = []
        for c in conns:
            try:
                if safe_str(getattr(c, "status", "")).upper() == "LISTEN":
                    proc = safe_process_info(c.pid)

                    local_ip = getattr(getattr(c, "laddr", None), "ip", None)
                    local_port = getattr(getattr(c, "laddr", None), "port", None)

                    listening.append(
                        ListeningPortInfo(
                            pid=proc.pid if proc.pid != -1 else None,
                            process_name=proc.name,
                            exe=proc.exe,
                            username=proc.username,
                            local_ip=safe_str(local_ip),
                            local_port=int(local_port) if isinstance(local_port, int) else None,
                        )
                    )
                    if len(listening) >= max(1, limit):
                        break
            except Exception:
                continue

        listening_ports = listening

    snapshot = SystemSnapshot(
        snapshot_id=snapshot_id,
        timestamp_utc=timestamp,
        profile=profile,
        cpu_percent=cpu,
        ram_percent=ram_percent,
        ram_used=ram_used,
        ram_total=ram_total,
        network=net,
        top_processes=top_processes,
        active_connections=active_connections,
        listening_ports=listening_ports,
        alerts=[],
    )

    snapshot.alerts = detect_basic_alerts(snapshot)
    return snapshot


# ============================================================
# Recording Engine
# ============================================================

class RecorderSession:
    def __init__(
        self,
        session_id: str,
        profile: RecordingProfile,
        interval_seconds: int,
        mode: RecordingMode,
        output_dir: Path,
    ) -> None:
        self.session_id = session_id
        self.profile = profile
        self.interval_seconds = max(1, int(interval_seconds))
        self.mode = mode
        self.output_dir = output_dir

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
                snapshot = build_snapshot(profile=self.profile, limit=50)
                self._save_snapshot(snapshot)
                self.snapshot_count += 1
            except Exception:
                pass

            time.sleep(self.interval_seconds)

    def _save_snapshot(self, snapshot: SystemSnapshot) -> None:
        path = self.output_dir / f"{snapshot.timestamp_utc.replace(':', '-')}_{snapshot.snapshot_id}.json"
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
# MCP Tools (Claude can call these)
# ============================================================

@mcp.tool()
def hello(name: str = "World") -> Dict[str, Any]:
    """
    Sanity test tool.
    """
    return {
        "meta": asdict(
            ToolMeta(
                tool="hello",
                success=True,
                timestamp_utc=utc_now_iso(),
                message="Hello tool executed successfully.",
            )
        ),
        "data": {"greeting": f"Timestamp : {utc_now_iso()} - Hello, {name}!"},
    }


@mcp.tool()
def system_snapshot(profile: RecordingProfile = "basic", limit: int = 30) -> Dict[str, Any]:
    """
    Takes ONE snapshot instantly.
    Useful for testing and quick analysis.
    """
    try:
        snap = build_snapshot(profile=profile, limit=limit)
        return {
            "meta": asdict(
                ToolMeta(
                    tool="system_snapshot",
                    success=True,
                    timestamp_utc=utc_now_iso(),
                    message="Snapshot collected successfully.",
                )
            ),
            "data": asdict(snap),
        }
    except Exception as e:
        return {
            "meta": asdict(
                ToolMeta(
                    tool="system_snapshot",
                    success=False,
                    timestamp_utc=utc_now_iso(),
                    message="Snapshot failed.",
                )
            ),
            "error": {"error_type": type(e).__name__, "error_message": str(e)},
        }


@mcp.tool()
def start_recording(
    profile: RecordingProfile = "security",
    interval_seconds: int = 5,
    mode: RecordingMode = "background",
) -> Dict[str, Any]:
    """
    Starts a background recorder session.
    Saves snapshots to disk until stopped.
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
            "error": {"error_type": type(e).__name__, "error_message": str(e)},
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
                "error": {"error_type": "NotFound", "error_message": f"Session {session_id} not found."},
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
            "error": {"error_type": type(e).__name__, "error_message": str(e)},
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
            "data": {
                "sessions": [asdict(s.info()) for s in sessions],
                "count": len(sessions),
            },
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
            "error": {"error_type": type(e).__name__, "error_message": str(e)},
        }


@mcp.tool()
def read_session_snapshots(session_id: str, limit: int = 20) -> Dict[str, Any]:
    """
    Reads snapshots saved on disk for a session.
    Useful for "incident replay".
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
                "error": {"error_type": "NotFound", "error_message": f"No folder found for {session_id}"},
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
            "error": {"error_type": type(e).__name__, "error_message": str(e)},
        }


@mcp.tool()
def generate_executive_report(session_id: str) -> Dict[str, Any]:
    """
    Generates a simple executive report from saved snapshots.
    Transparent + evidence-based.
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
                "error": {"error_type": "NotFound", "error_message": f"No session folder for {session_id}"},
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
                "error": {"error_type": "EmptySession", "error_message": "No snapshots found."},
            }

        cpu_values: List[float] = []
        ram_values: List[float] = []
        all_alerts: List[str] = []
        total_ports_exposed = 0

        for f in files:
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    snap = json.load(fp)

                cpu = snap.get("cpu_percent")
                ram = snap.get("ram_percent")
                alerts = snap.get("alerts") or []
                ports = snap.get("listening_ports") or []

                if isinstance(cpu, (int, float)):
                    cpu_values.append(float(cpu))
                if isinstance(ram, (int, float)):
                    ram_values.append(float(ram))

                for a in alerts:
                    if isinstance(a, str):
                        all_alerts.append(a)

                for p in ports:
                    if isinstance(p, dict) and p.get("local_ip") in ("0.0.0.0", "::"):
                        total_ports_exposed += 1

            except Exception:
                continue

        def safe_avg(nums: List[float]) -> Optional[float]:
            if not nums:
                return None
            return sum(nums) / len(nums)

        report = {
            "session_id": session_id,
            "snapshot_count": len(files),
            "cpu_avg": safe_avg(cpu_values),
            "cpu_max": max(cpu_values) if cpu_values else None,
            "ram_avg": safe_avg(ram_values),
            "ram_max": max(ram_values) if ram_values else None,
            "alert_count": len(all_alerts),
            "alerts_sample": all_alerts[:25],
            "ports_exposed_count": total_ports_exposed,
            "recommendations": [
                "Review exposed ports bound to 0.0.0.0 / ::",
                "Investigate spikes in CPU/RAM if present",
                "Use a longer recording interval for day-long monitoring (e.g., 30s)",
                "Export session to JSON for deeper analysis",
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
            "error": {"error_type": type(e).__name__, "error_message": str(e)},
        }


# ============================================================
# Run Server
# ============================================================

if __name__ == "__main__":
    # For Claude Desktop MCP: use stdio
    # For local HTTP testing: use transport="http"
    mcp.run(transport="stdio")
