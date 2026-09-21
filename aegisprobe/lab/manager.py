"""
Lab Manager for AegisProbe AI.
Provides start, stop, status, and reset controls for the local training lab.
Supports both in-memory threads (for test suites) and persistent daemon processes (for CLI commands).
"""

import os
import sys
import time
import signal
import subprocess
from pathlib import Path
from typing import Dict, Any
from aegisprobe.lab.vulnerable_apps import LabServer, LAB_HOST, LAB_PORT, LAB_CANARY

PID_FILE = Path("/tmp/aegisprobe_lab.pid")


class LabManager:
    @staticmethod
    def _is_pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    @classmethod
    def start(cls, daemon: bool = False) -> Dict[str, Any]:
        # 1. Check if already active
        if cls.status()["running"]:
            return {
                "status": "ONLINE",
                "running": True,
                "url": f"http://{LAB_HOST}:{LAB_PORT}",
                "canary": LAB_CANARY,
                "message": f"AegisProbe AI Vulnerable Lab active at http://{LAB_HOST}:{LAB_PORT}"
            }

        if daemon:
            # Spawn detached background process
            try:
                cmd = [
                    sys.executable,
                    "-c",
                    f"from http.server import HTTPServer; from aegisprobe.lab.vulnerable_apps import VulnerableLabHandler; s = HTTPServer(('{LAB_HOST}', {LAB_PORT}), VulnerableLabHandler); s.serve_forever()"
                ]
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True
                )
                PID_FILE.write_text(str(proc.pid))
                for _ in range(15):
                    if LabServer.is_port_open(LAB_HOST, LAB_PORT):
                        break
                    time.sleep(0.1)
            except Exception:
                pass
            running = LabServer.is_port_open(LAB_HOST, LAB_PORT)
        else:
            in_proc_success = LabServer.start()
            running = in_proc_success and LabServer.is_running()

        return {
            "status": "ONLINE" if running else "FAILED",
            "running": running,
            "url": f"http://{LAB_HOST}:{LAB_PORT}",
            "canary": LAB_CANARY,
            "message": f"AegisProbe AI Vulnerable Lab active at http://{LAB_HOST}:{LAB_PORT}" if running else "Failed starting lab server."
        }

    @classmethod
    def stop(cls) -> Dict[str, Any]:
        LabServer.stop()

        # Kill background daemon if present
        if PID_FILE.exists():
            try:
                pid = int(PID_FILE.read_text().strip())
                if cls._is_pid_alive(pid):
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.2)
                    if cls._is_pid_alive(pid):
                        os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
            try:
                PID_FILE.unlink(missing_ok=True)
            except Exception:
                pass

        # Give 0.2s for socket release
        time.sleep(0.2)
        return {
            "status": "STOPPED",
            "running": False,
            "message": "AegisProbe AI Vulnerable Lab stopped."
        }

    @classmethod
    def status(cls) -> Dict[str, Any]:
        running = LabServer.is_running() or LabServer.is_port_open(LAB_HOST, LAB_PORT)
        return {
            "running": running,
            "status": "ONLINE" if running else "OFFLINE",
            "url": f"http://{LAB_HOST}:{LAB_PORT}" if running else None,
            "canary": LAB_CANARY if running else None
        }

    @classmethod
    def reset(cls, daemon: bool = False) -> Dict[str, Any]:
        cls.stop()
        res = cls.start(daemon=daemon)
        return {
            "status": "RESET_COMPLETE",
            "running": res.get("running", False),
            "message": "AegisProbe AI Vulnerable Lab state reset to default."
        }
