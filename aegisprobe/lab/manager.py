"""
Lab Manager for AegisProbe AI.
Provides start, stop, status, and reset controls for the local training lab.
"""

from typing import Dict, Any
from aegisprobe.lab.vulnerable_apps import LabServer, LAB_HOST, LAB_PORT, LAB_CANARY


class LabManager:
    @staticmethod
    def start() -> Dict[str, Any]:
        success = LabServer.start()
        return {
            "status": "ONLINE" if success else "FAILED",
            "url": f"http://{LAB_HOST}:{LAB_PORT}",
            "canary": LAB_CANARY,
            "message": f"AegisProbe AI Vulnerable Lab active at http://{LAB_HOST}:{LAB_PORT}" if success else "Failed starting lab server."
        }

    @staticmethod
    def stop() -> Dict[str, Any]:
        LabServer.stop()
        return {
            "status": "STOPPED",
            "message": "AegisProbe AI Vulnerable Lab stopped."
        }

    @staticmethod
    def status() -> Dict[str, Any]:
        running = LabServer.is_running()
        return {
            "running": running,
            "status": "ONLINE" if running else "OFFLINE",
            "url": f"http://{LAB_HOST}:{LAB_PORT}" if running else None,
            "canary": LAB_CANARY if running else None
        }

    @staticmethod
    def reset() -> Dict[str, Any]:
        LabServer.stop()
        success = LabServer.start()
        return {
            "status": "RESET_COMPLETE",
            "running": success,
            "message": "AegisProbe AI Vulnerable Lab state reset to default."
        }
