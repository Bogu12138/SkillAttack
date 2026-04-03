import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.append(str(Path(__file__).parent.parent))

from core.run_guard import (
    SingleInstanceLock,
    SingleInstanceLockError,
    SimulatorPreflightError,
    ensure_simulator_preflight,
)
from stages.simulator.openclaw import OpenClawSimulator


class _FakeSimulator:
    def __init__(self, result):
        self._result = result

    def preflight(self):
        return self._result


class TestRunGuardAndPreflight(unittest.TestCase):
    def test_single_instance_lock_blocks_reentry(self):
        root = Path(tempfile.mkdtemp(prefix="skillrt-lock-tests-"))
        try:
            lock1 = SingleInstanceLock("skillrt_batch_test", root=root)
            lock1.acquire()
            lock2 = SingleInstanceLock("skillrt_batch_test", root=root)
            with self.assertRaises(SingleInstanceLockError):
                lock2.acquire()
            lock1.release()

            lock3 = SingleInstanceLock("skillrt_batch_test", root=root)
            lock3.acquire()
            lock3.release()
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_preflight_helper_raises_structured_error(self):
        simulator = _FakeSimulator(
            {
                "ok": False,
                "code": "docker_permission_denied",
                "message": "permission denied",
                "diagnostics": {"step": "docker_version"},
            }
        )
        with self.assertRaises(SimulatorPreflightError) as ctx:
            ensure_simulator_preflight(simulator)
        self.assertEqual(ctx.exception.code, "docker_permission_denied")
        self.assertEqual(ctx.exception.diagnostics.get("step"), "docker_version")

    def test_openclaw_preflight_reports_docker_permission_denied(self):
        simulator = OpenClawSimulator({"container_name": "skillrt-openclaw-host"})
        denied = subprocess.CompletedProcess(
            args=["docker", "version"],
            returncode=1,
            stdout="",
            stderr="Got permission denied while trying to connect to the Docker daemon socket",
        )
        with patch.object(simulator, "_run_cmd", return_value=denied):
            result = simulator.preflight()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "docker_permission_denied")

    def test_openclaw_preflight_reports_missing_api_key(self):
        simulator = OpenClawSimulator({"container_name": "skillrt-openclaw-host"})
        docker_ok = [
            subprocess.CompletedProcess(args=["docker", "version"], returncode=0, stdout="27.0.1", stderr=""),
            subprocess.CompletedProcess(args=["docker", "inspect"], returncode=0, stdout="true", stderr=""),
        ]
        with patch.object(simulator, "_run_cmd", side_effect=docker_ok):
            with patch.object(
                simulator,
                "_resolve_target_model",
                side_effect=RuntimeError("API key not found for model profile 'sim'. Expected env 'X'."),
            ):
                result = simulator.preflight()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "api_key_missing")

    def test_openclaw_preflight_reports_unreachable_endpoint(self):
        simulator = OpenClawSimulator({"container_name": "skillrt-openclaw-host"})
        docker_ok = [
            subprocess.CompletedProcess(args=["docker", "version"], returncode=0, stdout="27.0.1", stderr=""),
            subprocess.CompletedProcess(args=["docker", "inspect"], returncode=0, stdout="true", stderr=""),
        ]
        with patch.object(simulator, "_run_cmd", side_effect=docker_ok):
            with patch.object(
                simulator,
                "_resolve_target_model",
                return_value={
                    "profile_name": "sim",
                    "provider_name": "dashscope",
                    "base_url": "https://example.invalid/v1",
                    "container_base_url": "https://example.invalid/v1",
                    "model_name": "demo-model",
                    "api_key": "x",
                },
            ):
                with patch.object(
                    simulator,
                    "_probe_http_endpoint",
                    return_value={"ok": False, "message": "<urlopen error [Errno -2] Name or service not known>"},
                ):
                    result = simulator.preflight()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "model_endpoint_unreachable")

    def test_openclaw_preflight_auto_starts_stopped_container(self):
        simulator = OpenClawSimulator({"container_name": "skillrt-openclaw-host"})
        docker_ok = [
            subprocess.CompletedProcess(args=["docker", "version"], returncode=0, stdout="27.0.1", stderr=""),
            subprocess.CompletedProcess(args=["docker", "inspect"], returncode=0, stdout="false", stderr=""),
            subprocess.CompletedProcess(args=["docker", "start"], returncode=0, stdout="skillrt-openclaw-host", stderr=""),
            subprocess.CompletedProcess(args=["docker", "inspect"], returncode=0, stdout="true", stderr=""),
        ]
        with patch.object(simulator, "_run_cmd", side_effect=docker_ok):
            with patch.object(
                simulator,
                "_resolve_target_model",
                return_value={
                    "profile_name": "sim",
                    "provider_name": "dashscope",
                    "base_url": "https://example.invalid/v1",
                    "container_base_url": "https://example.invalid/v1",
                    "model_name": "demo-model",
                    "api_key": "x",
                },
            ):
                with patch.object(
                    simulator,
                    "_probe_http_endpoint",
                    return_value={"ok": True, "http_status": 200},
                ):
                    result = simulator.preflight()
        self.assertTrue(result["ok"])
        self.assertTrue(result["diagnostics"].get("container_auto_started"))


if __name__ == "__main__":
    unittest.main()
