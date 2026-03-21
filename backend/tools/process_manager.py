import psutil
from typing import Optional


class ProcessManager:
    """List and manage running processes."""

    @staticmethod
    def list_processes(name_filter: Optional[str] = None) -> dict:
        processes = []
        for proc in psutil.process_iter(["pid", "name", "exe", "username", "memory_info", "cpu_percent", "create_time"]):
            try:
                info = proc.info
                if name_filter and name_filter.lower() not in (info["name"] or "").lower():
                    continue
                processes.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "exe": info["exe"],
                    "username": info["username"],
                    "memory_mb": round(info["memory_info"].rss / (1024 * 1024), 2) if info["memory_info"] else 0,
                    "cpu_percent": info["cpu_percent"],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        processes.sort(key=lambda x: x["memory_mb"], reverse=True)
        return {"processes": processes, "total": len(processes)}

    @staticmethod
    def get_process_info(pid: int) -> dict:
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                children = [{"pid": c.pid, "name": c.name()} for c in proc.children()]
                connections = []
                try:
                    for conn in proc.net_connections():
                        connections.append({
                            "fd": conn.fd,
                            "family": str(conn.family),
                            "type": str(conn.type),
                            "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                            "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                            "status": conn.status,
                        })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    connections = [{"error": "access denied"}]

                return {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "exe": proc.exe(),
                    "cwd": proc.cwd() if proc.cwd else "",
                    "cmdline": proc.cmdline(),
                    "username": proc.username(),
                    "status": proc.status(),
                    "create_time": proc.create_time(),
                    "memory_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
                    "cpu_percent": proc.cpu_percent(),
                    "num_threads": proc.num_threads(),
                    "children": children,
                    "connections": connections,
                    "open_files_count": len(proc.open_files()) if proc.open_files else 0,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {"error": str(e)}
