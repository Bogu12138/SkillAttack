from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Dict, Any


def _read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def generate_summary(run_root: str = "result/runs_organize/main") -> Dict[str, Any]:
    root = Path(run_root)
    root.mkdir(parents=True, exist_ok=True)

    rows = []
    for report_path in sorted(root.rglob("*_global_report.json")):
        payload = _read_json(report_path)
        if not isinstance(payload, dict):
            continue
        skill_dir = report_path.parent
        skillname = report_path.stem[: -len("_global_report")] if report_path.stem.endswith("_global_report") else skill_dir.name
        rows.append(
            {
                "skillname": skillname,
                "skill_root": str(skill_dir),
                "surface_summary": dict(payload.get("surface_summary") or {}),
                "overall_summary": dict(payload.get("overall_summary") or {}),
            }
        )

    summary = {
        "generated_at": datetime.now().isoformat(),
        "total_skills": len(rows),
        "skills": rows,
    }
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S") + f"{datetime.now().microsecond // 1000:03d}"
    out_path = root / f"{timestamp}_summary.json"
    out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    generate_summary()
