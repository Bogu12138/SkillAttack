from __future__ import annotations

import hashlib
import io
import json
import os
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from core.schemas import AnalysisResult, AttackCase, FeedbackResult, JudgeResult, SimulationResult, SurfaceResult


def slugify(text: Any, max_len: int = 80) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(text or "").strip().lower()).strip("-")
    if not slug:
        slug = "untitled"
    return slug[:max_len]


def surface_label(text: Any, max_len: int = 80) -> str:
    label = str(text or "").strip()
    label = re.sub(r'[\x00-\x1f\x7f<>:"/\\|?*]+', "_", label)
    label = re.sub(r"\s+", " ", label).strip()
    if not label:
        label = "untitled"
    return label[:max_len]


def surface_id(index: int, title: Any) -> str:
    return f"surface_{int(index):02d}_{surface_label(title)}"


def build_skill_hash(skill_path: Optional[Path], skill_content: str = "") -> str:
    """Compute a stable SHA-1 hash of the skill source.

    If skill_path is a directory, creates a deterministic in-memory zip archive
    of all files (sorted by relative path) and hashes the archive bytes.
    Otherwise falls back to hashing skill_content text.
    """
    if skill_path is not None and Path(skill_path).is_dir():
        root = Path(skill_path)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                arcname = str(path.relative_to(root)).replace(os.sep, "/")
                zf.write(path, arcname=arcname)
        archive_bytes = buf.getvalue()
        return hashlib.sha1(archive_bytes).hexdigest()

    return hashlib.sha1(str(skill_content or "").encode("utf-8", errors="ignore")).hexdigest()


def ensure_surface_ids(results: Iterable[SurfaceResult]) -> List[SurfaceResult]:
    normalized: List[SurfaceResult] = []
    for index, item in enumerate(list(results or []), start=1):
        if isinstance(item, SurfaceResult):
            payload = item.model_dump()
        else:
            payload = dict(item or {})
        payload["title"] = str(payload.get("title") or "").strip()
        payload["description"] = str(payload.get("description") or "").strip()
        payload["risk_type"] = str(payload.get("risk_type") or "").strip()
        payload["level"] = str(payload.get("level") or "").strip()
        payload["id"] = surface_id(index, payload.get("title") or "untitled")
        normalized.append(SurfaceResult(**payload))
    return normalized


def analysis_public_payload(analysis: AnalysisResult) -> Dict[str, Any]:
    return {
        "skillname": str(analysis.skillname or ""),
        "skillhash": str(analysis.skillhash or ""),
        "readme": str(analysis.readme or ""),
        "results": [
            {
                "id": str(item.id or ""),
                "title": str(item.title or ""),
                "description": str(item.description or ""),
                "risk_type": str(item.risk_type or ""),
                "level": str(item.level or ""),
            }
            for item in list(analysis.results or [])
        ],
    }


def attack_public_payload(attack: AttackCase) -> Dict[str, Any]:
    return {
        "attack_prompt": str(attack.attack_prompt or ""),
        "target": {
            "risk_type": str(attack.target.risk_type or ""),
            "surface": str(attack.target.surface or ""),
            "success_condition": str(attack.target.success_condition or ""),
        },
        "expected_path": [str(item) for item in list(attack.expected_path or [])],
        "metadata": dict(attack.metadata or {}),
    }


def attack_feedback_payload(attack: AttackCase) -> Dict[str, Any]:
    """Lightweight version for feedback — keep attack_prompt/target/expected_path,
    drop metadata (round_id/phase/session_id/skillname/surface_* are all redundant)."""
    return {
        "attack_prompt": str(attack.attack_prompt or ""),
        "target": {
            "risk_type": str(attack.target.risk_type or ""),
            "surface": str(attack.target.surface or ""),
            "success_condition": str(attack.target.success_condition or ""),
        },
        "expected_path": [str(item) for item in list(attack.expected_path or [])],
    }


def simulation_public_payload(simulation: SimulationResult) -> Dict[str, Any]:
    return {
        "steps": list(simulation.steps or []),
        "logs": str(simulation.logs or ""),
        "errors": [str(item) for item in list(simulation.errors or [])],
        "execution_time": float(simulation.execution_time or 0.0),
    }


def simulation_feedback_payload(simulation: SimulationResult) -> Dict[str, Any]:
    """Lightweight version for feedback — omits logs to save attacker model tokens."""
    return {
        "steps": list(simulation.steps or []),
        "errors": [str(item) for item in list(simulation.errors or [])],
        "execution_time": float(simulation.execution_time or 0.0),
    }


def judge_public_payload(judge_result: JudgeResult) -> Dict[str, Any]:
    payload = {
        "result": str(judge_result.result or ""),
        "reason": str(judge_result.reason or ""),
    }
    suggestion = str(judge_result.actionable_suggestion or "").strip()
    if suggestion:
        payload["actionable_suggestion"] = suggestion
    return payload


def feedback_public_payload(feedback: FeedbackResult) -> Dict[str, Any]:
    return {
        "round_id": int(feedback.round_id or 0),
        "attacks": list(feedback.attacks or []),
        "simulations": list(feedback.simulations or []),
        "judges": list(feedback.judges or []),
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def build_feedback_history(
    previous_feedback: Optional[FeedbackResult],
    attack: AttackCase,
    simulation: SimulationResult,
    judge_result: JudgeResult,
    round_id: int,
) -> FeedbackResult:
    attacks = list(previous_feedback.attacks or []) if previous_feedback is not None else []
    simulations = list(previous_feedback.simulations or []) if previous_feedback is not None else []
    judges = list(previous_feedback.judges or []) if previous_feedback is not None else []
    attacks.append(attack_feedback_payload(attack))
    simulations.append(simulation_feedback_payload(simulation))
    judges.append(judge_public_payload(judge_result))
    return FeedbackResult(
        round_id=int(round_id),
        attacks=attacks,
        simulations=simulations,
        judges=judges,
    )


def native_cache_path(cache_root: Path, skillname: str, skillhash: str) -> Path:
    return cache_root / f"{slugify(skillname)}_{skillhash}_native.json"


def analyze_output_path(skill_root: Path, skillname: str) -> Path:
    return skill_root / f"{skillname}_analyze.json"


def global_report_output_path(skill_root: Path, skillname: str) -> Path:
    return skill_root / f"{skillname}_global_report.json"


def round_output_path(skill_root: Path, surface_name: str, round_id: int) -> Path:
    return skill_root / surface_name / f"round_{int(round_id):02d}.json"


def find_surface(analysis: AnalysisResult, surface_name: str) -> Optional[SurfaceResult]:
    for item in list(analysis.results or []):
        if str(item.id or "").strip() == str(surface_name or "").strip():
            return item
    return None


def build_round_payload(
    surface_name: str,
    round_id: int,
    attack: AttackCase,
    simulation: SimulationResult,
    judge_result: JudgeResult,
    feedback: FeedbackResult,
) -> Dict[str, Any]:
    return {
        "surface": str(surface_name or ""),
        "round_id": int(round_id),
        "attack": attack_public_payload(attack),
        "simulation": simulation_public_payload(simulation),
        "judge": judge_public_payload(judge_result),
        "feedback": feedback_public_payload(feedback),
    }


def build_global_report(
    analysis: AnalysisResult,
    surface_rounds: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    surface_summary: Dict[str, Dict[str, Any]] = {}
    success_count = 0
    ignore_count = 0
    technical_count = 0

    for surface in list(analysis.results or []):
        records = list(surface_rounds.get(surface.id) or [])
        final_status = "ignore"
        for record in records:
            if str(((record.get("judge") or {}).get("result") or "")).strip() == "success":
                final_status = "success"
                break
        if final_status != "success" and records:
            final_status = str(((records[-1].get("judge") or {}).get("result") or "ignore")).strip() or "ignore"

        if final_status == "success":
            success_count += 1
        elif final_status == "technical":
            technical_count += 1
        else:
            ignore_count += 1

        surface_summary[surface.id] = {
            "rounds": len(records),
            "status": final_status,
            "final_risk_type": str(surface.risk_type or ""),
        }

    return {
        "surface_summary": surface_summary,
        "overall_summary": {
            "success_count": success_count,
            "ignore_count": ignore_count,
            "technical_count": technical_count,
        },
    }
