from fastmcp import FastMCP
import psutil
 
mcp = FastMCP("Demo MCP Server")
 
 
@mcp.tool()
def hello(name: str = "World") -> str:
    return f"Hello, {name}!"
 
 
@mcp.tool()
def network_summary() -> dict:
    """
    Returns system-wide network I/O counters.
    """
    try:
        stats = psutil.net_io_counters()
        return {
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv,
            "errin": stats.errin,
            "errout": stats.errout,
            "dropin": stats.dropin,
            "dropout": stats.dropout,
        }
    except Exception as e:
        return {"error": f"Failed to read net_io_counters: {str(e)}"}
 
 
def safe_process_info(pid) -> dict:
    """
    Safely fetch process details without crashing.
    """
    if not pid:
        return {"pid": None, "name": None, "exe": None, "username": None}
 
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
 
        return {
            "pid": pid,
            "name": name,
            "exe": exe,
            "username": username,
        }
 
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"pid": pid, "name": None, "exe": None, "username": None}
    except Exception:
        return {"pid": pid, "name": None, "exe": None, "username": None}
 
 
def safe_net_connections(kind="inet"):
    """
    net_connections is the #1 crash point.
    This wrapper prevents the server from dying.
    """
    try:
        return psutil.net_connections(kind=kind)
    except psutil.AccessDenied:
        return []
    except Exception:
        return []
 
 
@mcp.tool()
def active_connections(limit: int = 30) -> list:
    """
    Returns active network connections with process info.
    """
    conns = safe_net_connections(kind="inet")
 
    results = []
    for c in conns[: max(1, limit)]:
        proc = safe_process_info(c.pid)
 
        results.append(
            {
                "pid": proc["pid"],
                "process_name": proc["name"],
                "exe": proc["exe"],
                "username": proc["username"],
                "status": str(c.status),
                "local_ip": c.laddr.ip if c.laddr else None,
                "local_port": c.laddr.port if c.laddr else None,
                "remote_ip": c.raddr.ip if c.raddr else None,
                "remote_port": c.raddr.port if c.raddr else None,
            }
        )
 
    return results
 
 
@mcp.tool()
def listening_ports(limit: int = 50) -> list:
    """
    Returns LISTENING ports (most useful for security).
    """
    conns = safe_net_connections(kind="inet")
 
    listening = [c for c in conns if str(c.status).upper() == "LISTEN"]
    listening = listening[: max(1, limit)]
 
    results = []
    for c in listening:
        proc = safe_process_info(c.pid)
 
        results.append(
            {
                "pid": proc["pid"],
                "process_name": proc["name"],
                "exe": proc["exe"],
                "username": proc["username"],
                "local_ip": c.laddr.ip if c.laddr else None,
                "local_port": c.laddr.port if c.laddr else None,
            }
        )
 
    return results
 
 
if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000)