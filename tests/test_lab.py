"""
Tests for Training Lab Lifecycle in AegisProbe AI.
"""

from aegisprobe.lab.manager import LabManager
from aegisprobe.lab.vulnerable_apps import LabServer, LAB_HOST, LAB_PORT


def test_lab_lifecycle():
    # Start lab
    start_res = LabManager.start()
    assert start_res["status"] == "ONLINE"
    assert LabServer.is_running() is True

    # Status check
    status_res = LabManager.status()
    assert status_res["running"] is True
    assert status_res["status"] == "ONLINE"
    assert f"{LAB_PORT}" in status_res["url"]

    # Reset
    reset_res = LabManager.reset()
    assert reset_res["status"] == "RESET_COMPLETE"

    # Stop lab
    stop_res = LabManager.stop()
    assert stop_res["status"] == "STOPPED"
    assert LabServer.is_running() is False
