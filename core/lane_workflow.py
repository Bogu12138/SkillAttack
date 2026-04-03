from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.config_loader import ConfigLoader
from core.schemas import AnalysisResult, JudgeResult, SimulationResult, SurfaceResult
from core.surface_protocol import (
    build_feedback_history,
    build_skill_hash,
    analysis_public_payload,
    analyze_output_path,
    build_global_report,
    build_round_payload,
    find_surface,
    global_report_output_path,
    round_output_path,
    write_json,
)


def _build_model_manifest(stages_cfg: Dict[str, Any], loader: ConfigLoader) -> Dict[str, Any]:
    stage_profile_keys = {
        "analyzer": "model_profile",
        "attacker": "model_profile",
        "simulator": "target_agent_model_profile",
        "judge": "model_profile",
        "feedback": "model_profile",
    }
    manifest: Dict[str, Any] = {}
    for stage, profile_key in stage_profile_keys.items():
        stage_cfg = dict(stages_cfg.get(stage) or {})
        profile_name = str(stage_cfg.get(profile_key) or "").strip()
        profile = loader.get_model_profile(profile_name) if profile_name else {}
        manifest[stage] = {
            "model_profile": profile_name,
            "model": str(profile.get("model") or ""),
        }
    remap_profile_name = str((stages_cfg.get("analyzer") or {}).get("risk_type_remap_model_profile") or "").strip()
    if remap_profile_name:
        remap_profile = loader.get_model_profile(remap_profile_name)
        manifest["analyzer_risk_type_remap"] = {
            "model_profile": remap_profile_name,
            "model": str(remap_profile.get("model") or ""),
        }
    return manifest


def _archive_skill_source(skill_path: Path, skill_root: Path) -> str:
    """Compress the original skill directory into skill_root and return SHA-1 of the archive.

    Uses the same hash logic as build_skill_hash() for consistency with the
    analyzer cache key.
    """
    archive_base = skill_root / "skill_source"
    shutil.make_archive(str(archive_base), "zip", root_dir=str(skill_path.parent), base_dir=skill_path.name)
    return build_skill_hash(skill_path)


def _emit_progress(progress_cb: Optional[Callable[[str], None]], message: str) -> None:
    if callable(progress_cb):
        progress_cb(str(message or ""))


def judge_success(judge_result: Any) -> bool:
    return str(getattr(judge_result, "result", "")).strip() == "success"


def resolve_surface_parallelism(value: Any, default: int = 1) -> Tuple[int, str]:
    def _fallback() -> Tuple[int, str]:
        try:
            fallback_limit = int(default)
        except Exception:
            fallback_limit = 1
        if fallback_limit < 0:
            fallback_limit = 1
        if fallback_limit == 0:
            return 0, "max"
        return fallback_limit, str(fallback_limit)

    if value is None:
        return _fallback()

    text = str(value).strip()
    if not text:
        return _fallback()
    if text.lower() == "max":
        return 0, "max"

    try:
        limit = int(text)
    except Exception:
        return _fallback()

    if limit < 0:
        return _fallback()
    if limit == 0:
        return 0, "max"
    return limit, str(limit)


def derive_attack_surfaces(analysis: AnalysisResult, limit: int) -> List[str]:
    surfaces = [str(item.id or "").strip() for item in list(analysis.results or []) if str(item.id or "").strip()]
    if limit <= 0:
        return surfaces
    return surfaces[:limit]


def clone_analysis_for_surface(analysis: AnalysisResult, skill_id: str, surface: str) -> Dict[str, Any]:
    surface_obj = find_surface(analysis, surface)
    if surface_obj is None:
        raise ValueError(f"Surface `{surface}` not found in analyze results for `{skill_id}`.")
    return {
        "skillname": str(getattr(analysis, "skillname", "") or skill_id),
        "skillhash": str(getattr(analysis, "skillhash", "") or ""),
        "readme": str(getattr(analysis, "readme", "") or ""),
        **surface_obj.model_dump(),
    }


def all_lanes_done(lane_states: List[Dict[str, Any]], max_iterations: int) -> bool:
    return all(bool(lane["terminated"] or lane["surface_round"] >= max_iterations) for lane in lane_states)


def default_fallback_attack(analysis: Dict[str, Any], skill_id: str, surface: str) -> AttackCase:
    raise RuntimeError("fallback attack builder must be provided by the caller in the new surface workflow")


def run_lane_workflow(
    *,
    skill_id: str,
    skill_content: str,
    analyzer: Any,
    attacker: Any,
    simulator: Any,
    judge: Any,
    feedback: Any,
    max_iterations: int,
    surface_parallelism: Any,
    run_root: Path,
    analyzer_context: Optional[Dict[str, Any]] = None,
    workspace_files: Optional[List[str]] = None,
    collect_all_surfaces: bool = False,
    progress_cb: Optional[Callable[[str], None]] = None,
    simulator_model_name: Optional[str] = None,
) -> Dict[str, Any]:
    if simulator_model_name:
        skill_root = Path(run_root) / simulator_model_name / skill_id
    else:
        skill_root = Path(run_root) / skill_id
    skill_root.mkdir(parents=True, exist_ok=True)

    context = dict(analyzer_context or {})
    skill_path_str = str(context.get("skill_path") or "").strip()
    skill_path = Path(skill_path_str) if skill_path_str else None
    skill_source_hash = ""
    if skill_path and skill_path.is_dir():
        skill_source_hash = _archive_skill_source(skill_path, skill_root)

    analyzer_config = getattr(analyzer, "config", None)
    fail_open = True
    if isinstance(analyzer_config, dict):
        fail_open = bool(analyzer_config.get("fail_open", True))

    _emit_progress(progress_cb, f"skill={skill_id} analyzer=start")
    try:
        analysis = analyzer.analyze(skill_content, context or {"skill_id": skill_id})
        if not str(getattr(analysis, "skillname", "") or "").strip():
            analysis.skillname = skill_id
    except Exception:
        if not fail_open:
            raise
        analysis = AnalysisResult(
            skillname=skill_id,
            skillhash="",
            readme=f"# Security Audit Report: {skill_id}",
            results=[],
        )

    if skill_source_hash:
        analysis.skillhash = skill_source_hash

    analyze_path = analyze_output_path(skill_root, analysis.skillname)
    write_json(analyze_path, analysis_public_payload(analysis))

    loader = ConfigLoader()
    model_manifest = _build_model_manifest(loader.stages, loader)
    write_json(skill_root / "model.json", model_manifest)

    lane_limit, lane_limit_label = resolve_surface_parallelism(surface_parallelism, 1)
    lane_surfaces = derive_attack_surfaces(analysis, lane_limit)
    _emit_progress(
        progress_cb,
        f"skill={skill_id} analyzer=done surfaces={len(lane_surfaces)} analyze_path={analyze_path}",
    )
    lane_states: List[Dict[str, Any]] = []
    surface_rounds: Dict[str, List[Dict[str, Any]]] = {}
    for lane_idx, surface_name in enumerate(lane_surfaces, start=1):
        lane_states.append(
            {
                "lane_index": lane_idx,
                "lane_id": f"lane{lane_idx:02d}-{surface_name}",
                "surface": surface_name,
                "analysis": clone_analysis_for_surface(analysis, skill_id, surface_name),
                "feedback": None,
                "surface_round": 0,
                "terminated": False,
                "success": False,
                "last_result": "",
                "last_reason": "",
            }
        )
        surface_rounds[surface_name] = []

    iter_records: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    success = False
    winning_surface = ""
    winning_lane_id = ""
    winning_global_iteration = 0
    global_iteration = 0

    if lane_surfaces:
        final_result = "technical"
        final_reason = "workflow_not_started"
    else:
        final_result = "ignore"
        final_reason = "no_attack_surfaces"
        _emit_progress(progress_cb, f"skill={skill_id} no_attack_surfaces")

    for _round in range(1, max_iterations + 1):
        any_active_lane = False
        for lane in lane_states:
            if lane["terminated"] or lane["surface_round"] >= max_iterations:
                continue
            any_active_lane = True
            lane["surface_round"] += 1
            global_iteration += 1
            _emit_progress(
                progress_cb,
                (
                    f"skill={skill_id} surface={lane['surface']} "
                    f"round={lane['surface_round']}/{max_iterations} start"
                ),
            )

            lane_feedback = lane.get("feedback")
            analysis_input = dict(lane["analysis"])
            try:
                attack = attacker.generate_attack(
                    analysis_input,
                    lane_feedback,
                    skill_content=skill_content,
                    workspace_files=workspace_files,
                )
            except Exception as exc:
                print(f"[lane] attacker failed for surface={lane['surface']} round={lane['surface_round']}: {exc}")
                judge_result = JudgeResult(
                    result="technical",
                    reason=f"Attacker LLM unavailable: {exc}",
                    actionable_suggestion="Retry when the attacker model API is available.",
                )
                lane["last_result"] = "technical"
                lane["last_reason"] = judge_result.reason
                _emit_progress(
                    progress_cb,
                    f"skill={skill_id} surface={lane['surface']} round={lane['surface_round']}/{max_iterations} result=technical (attacker failed)",
                )
                iter_records.append(
                    {
                        "iteration": global_iteration,
                        "surface_round": lane["surface_round"],
                        "surface_lane_id": lane["lane_id"],
                        "surface_name": lane["surface"],
                        "judge_result": "technical",
                        "judge_reason": judge_result.reason,
                        "success": False,
                    }
                )
                if not success:
                    final_result = "technical"
                    final_reason = judge_result.reason
                continue

            simulation = simulator.simulate(attack, skill_content)
            judge_result = judge.judge(attack, simulation)
            feedback_result = feedback.generate_feedback(
                lane_feedback,
                attack,
                simulation,
                judge_result,
                lane["surface_round"],
            )
            lane["feedback"] = feedback_result

            round_payload = build_round_payload(
                lane["surface"],
                lane["surface_round"],
                attack,
                simulation,
                judge_result,
                feedback_result,
            )
            write_json(round_output_path(skill_root, lane["surface"], lane["surface_round"]), round_payload)
            surface_rounds[lane["surface"]].append(round_payload)

            lane["last_result"] = str(judge_result.result or "")
            lane["last_reason"] = str(judge_result.reason or "")
            _emit_progress(
                progress_cb,
                (
                    f"skill={skill_id} surface={lane['surface']} "
                    f"round={lane['surface_round']}/{max_iterations} result={lane['last_result']}"
                ),
            )
            iter_records.append(
                {
                    "iteration": global_iteration,
                    "surface_round": lane["surface_round"],
                    "surface_lane_id": lane["lane_id"],
                    "surface_name": lane["surface"],
                    "judge_result": lane["last_result"],
                    "judge_reason": lane["last_reason"],
                    "success": judge_success(judge_result),
                }
            )

            if judge_success(judge_result):
                lane["success"] = True
                lane["terminated"] = True
                success = True
                findings.append(dict(round_payload))
                if not winning_surface:
                    winning_surface = lane["surface"]
                    winning_lane_id = lane["lane_id"]
                    winning_global_iteration = global_iteration
                    final_result = "success"
                    final_reason = lane["last_reason"]
                if not collect_all_surfaces:
                    break
            elif lane["surface_round"] >= max_iterations:
                lane["terminated"] = True
                if not success:
                    final_result = str(judge_result.result or final_result)
                    final_reason = str(judge_result.reason or final_reason)
            else:
                if not success:
                    final_result = str(judge_result.result or final_result)
                    final_reason = str(judge_result.reason or final_reason)

        if success and not collect_all_surfaces:
            break
        if not any_active_lane:
            break
        if all_lanes_done(lane_states, max_iterations):
            break

    global_report = build_global_report(analysis, surface_rounds)
    global_report_path = global_report_output_path(skill_root, analysis.skillname)
    write_json(global_report_path, global_report)
    _emit_progress(
        progress_cb,
        (
            f"skill={skill_id} complete verdict={final_result} "
            f"winning_surface={winning_surface or '-'} global_report={global_report_path}"
        ),
    )

    surface_results: List[Dict[str, Any]] = []
    for lane in lane_states:
        surface_results.append(
            {
                "surface_name": lane["surface"],
                "lane_id": lane["lane_id"],
                "rounds_used": int(lane["surface_round"] or 0),
                "terminated": bool(lane["terminated"]),
                "success": bool(lane["success"]),
                "final_result": str(lane["last_result"] or ""),
                "final_reason": str(lane["last_reason"] or ""),
            }
        )

    return {
        "analysis": analysis,
        "lane_limit": len(lane_surfaces),
        "lane_limit_requested": lane_limit_label,
        "lane_states": lane_states,
        "iter_records": iter_records,
        "findings": findings,
        "surface_results": surface_results,
        "surface_rounds": surface_rounds,
        "success": success,
        "winning_surface": winning_surface,
        "winning_lane_id": winning_lane_id,
        "winning_iteration": winning_global_iteration,
        "final_verdict": final_result,
        "final_reason_code": final_reason,
        "final_confidence": 1.0 if final_result == "success" else 0.0,
        "final_smoking": final_reason,
        "final_run_id": "",
        "skill_root": str(skill_root),
    }
