from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import fcntl


class SingleInstanceLockError(RuntimeError):
    def __init__(self, path: Path, owner: Optional[Dict[str, Any]] = None):
        self.path = Path(path)
        self.owner = dict(owner or {})
        detail = f"Another batch run is already active (lock: {self.path})."
        pid = self.owner.get("pid")
        argv = self.owner.get("argv")
        if pid:
            detail += f" holder_pid={pid}"
        if argv:
            detail += f" holder_argv={' '.join([str(x) for x in argv])}"
        super().__init__(detail)


class SimulatorPreflightError(RuntimeError):
    def __init__(self, code: str, message: str, diagnostics: Optional[Dict[str, Any]] = None):
        self.code = str(code or "preflight_failed").strip() or "preflight_failed"
        self.message = str(message or self.code).strip() or self.code
        self.diagnostics = dict(diagnostics or {})
        super().__init__(f"Simulator preflight failed [{self.code}]: {self.message}")


class SingleInstanceLock:
    def __init__(self, name: str, root: Path | str = "data"):
        safe_name = str(name or "batch").strip() or "batch"
        self.path = Path(root) / f".{safe_name}.lock"
        self._fh = None

    def _read_owner(self, fh) -> Dict[str, Any]:
        try:
            fh.seek(0)
            raw = fh.read()
        except Exception:
            return {}
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except Exception:
            return {"raw": raw}
        return data if isinstance(data, dict) else {"raw": raw}

    def acquire(self) -> Dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+", encoding="utf-8")
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            owner = self._read_owner(fh)
            fh.close()
            raise SingleInstanceLockError(self.path, owner)

        owner = {
            "pid": os.getpid(),
            "argv": list(sys.argv),
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        fh.seek(0)
        fh.truncate()
        json.dump(owner, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
        self._fh = fh
        return owner

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            self._fh.seek(0)
            self._fh.truncate()
            self._fh.flush()
        except Exception:
            pass
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "SingleInstanceLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


def ensure_simulator_preflight(simulator: Any) -> Dict[str, Any]:
    preflight = getattr(simulator, "preflight", None)
    if not callable(preflight):
        return {"ok": True, "code": "ok", "message": "No simulator preflight required.", "diagnostics": {}}

    result = preflight()
    if not isinstance(result, dict):
        raise SimulatorPreflightError("preflight_invalid_result", "Simulator preflight returned a non-dict result.")

    ok = bool(result.get("ok"))
    code = str(result.get("code") or ("ok" if ok else "preflight_failed")).strip() or "preflight_failed"
    message = str(result.get("message") or code).strip() or code
    diagnostics = result.get("diagnostics")
    if not isinstance(diagnostics, dict):
        diagnostics = {}

    if not ok:
        raise SimulatorPreflightError(code, message, diagnostics)
    return {
        "ok": True,
        "code": code,
        "message": message,
        "diagnostics": diagnostics,
    }
