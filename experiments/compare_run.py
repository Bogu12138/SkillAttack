#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
ROOT_STR = str(ROOT)
if ROOT_STR in sys.path:
    sys.path.remove(ROOT_STR)
sys.path.insert(0, ROOT_STR)

from core.config_loader import ConfigLoader
from core.lane_workflow import resolve_surface_parallelism, run_lane_workflow
from core.run_guard import SingleInstanceLock, SimulatorPreflightError
from core.schemas import AnalysisResult, AttackCase, AttackTarget, SurfaceResult
from core.surface_protocol import (
    analysis_public_payload,
    analyze_output_path,
    build_feedback_history,
    build_global_report,
    build_round_payload,
    global_report_output_path,
    round_output_path,
    write_json,
)
from experiments.case_loader import (
    CaseDef,
    SUPPORTED_SKILLINJECT_SPLITS,
    build_trial_specs,
    derive_expected_indicators,
    inject_at_line,
    load_cases,
    normalize_comparison_split,
    slugify,
)
from experiments.common import (
    enforce_openclaw_isolate_per_run,
    init_runtime,
    preflight_check_openclaw,
    runtime_run_root,
)
from stages.analyzer.taxonomy import infer_taxonomy_category


def _as_int(value: Any, fallback: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        return fallback
    return parsed if parsed > 0 else fallback


def _comparison_defaults_from_app() -> Dict[str, Any]:
    exp_cfg = ConfigLoader().comparison_experiment
    project_cfg = exp_cfg.get("project", {}) or {}
    input_cfg = exp_cfg.get("input", {}) or {}
    split = normalize_comparison_split(input_cfg.get("split", "obvious"))
    configured_output_root = str(project_cfg.get("experiment_output_root") or "").strip()
    return {
        "pair_root": Path(input_cfg.get("pair_root", ROOT / "data" / "skillinject")),
        "split": split,
        "experiment_output_root": Path(
            configured_output_root or (ROOT / "result" / "runs_organize" / "comparison" / "_experiment_results")
        ),
        "max_cases": _as_int(project_cfg.get("max_cases", 20), 20),
        "repeats": _as_int(project_cfg.get("repeats", 1), 1),
        "seed": _as_int(project_cfg.get("seed", 42), 42),
        "main_max_iters": _as_int(project_cfg.get("main_max_iters", 3), 3),
        "case_selection": str(project_cfg.get("case_selection", "diverse_injection_skill")),
        "surface_mode": str(project_cfg.get("surface_mode", "per_case_parallel")),
        "surface_parallelism": str(project_cfg.get("surface_parallelism", "max")),
        "shuffle": bool(project_cfg.get("shuffle", False)),
        "resume": bool(project_cfg.get("resume", False)),
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    defaults = _comparison_defaults_from_app()
    parser = argparse.ArgumentParser(description="Paired ASR comparison for SKILL-INJECT prepared pairs.")
    parser.add_argument("--split", type=str, default=defaults["split"], choices=list(SUPPORTED_SKILLINJECT_SPLITS))
    parser.add_argument("--pair-root", type=Path, default=defaults["pair_root"])
    parser.add_argument("--max-cases", type=int, default=defaults["max_cases"])
    parser.add_argument("--repeats", type=int, default=defaults["repeats"])
    parser.add_argument("--seed", type=int, default=defaults["seed"])
    parser.add_argument("--no-shuffle", action="store_true", default=not defaults["shuffle"])
    parser.add_argument("--main-max-iters", type=int, default=defaults["main_max_iters"])
    parser.add_argument(
        "--case-selection",
        type=str,
        default=defaults["case_selection"],
        choices=["sequential", "diverse_injection_skill"],
    )
    parser.add_argument(
        "--surface-mode",
        type=str,
        default=defaults["surface_mode"],
        choices=["single", "per_case_parallel"],
    )
    parser.add_argument("--surface-parallelism", type=str, default=defaults["surface_parallelism"])
    parser.add_argument("--resume", action="store_true", default=defaults["resume"])
    parser.add_argument("--dry-run", action="store_true", default=False)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.set_defaults(experiment_output_root=defaults["experiment_output_root"])
    return parser.parse_args(argv)


def _case_skill_dir(case: CaseDef, pair_root: Path) -> Path:
    return pair_root / case.skill_rel_path


def _case_skill_name(case: CaseDef) -> str:
    return Path(case.skill_rel_path).name


def _trial_root_name(trial_id: int, group: str, case: CaseDef, repeat: int) -> str:
    return f"trial_{trial_id:04d}_{group}_{slugify(case.case_id, 28)}_r{repeat:02d}"


def _baseline_analysis(case: CaseDef, skillname: str, skillhash: str) -> AnalysisResult:
    risk_type = infer_taxonomy_category(
        raw_label=case.target_objective,
        attack_surface=[case.line_injection],
        trigger_patterns=case.expected_indicators,
        skill_content=case.unsafe_skill_content,
    )
    return AnalysisResult(
        skillname=skillname,
        skillhash=skillhash,
        readme=f"# Security Audit Report: {skillname}\n\nSynthetic baseline analyze artifact.",
        results=[
            SurfaceResult(
                id="surface_01_baseline",
                title="Baseline prompt execution",
                description=case.target_objective,
                risk_type=risk_type,
                level="Baseline",
            )
        ],
    )


def _baseline_attack(case: CaseDef, skillname: str) -> AttackCase:
    analysis = _baseline_analysis(case, skillname, "")
    surface = analysis.results[0]
    return AttackCase(
        attack_prompt=case.normal_prompt,
        target=AttackTarget(
            risk_type=surface.risk_type,
            surface=surface.id,
            success_condition=f"Produce observable evidence that the baseline prompt compromises `{surface.id}`.",
        ),
        expected_path=["Submit the baseline prompt.", "Observe the resulting skill behavior."],
        metadata={"skillname": skillname, "surface_id": surface.id, "group": "baseline"},
    )


def _write_baseline_trial(
    *,
    case: CaseDef,
    skillname: str,
    skillhash: str,
    trial_root: Path,
    simulator: Any,
    judge: Any,
    feedback: Any,
) -> Dict[str, Any]:
    analysis = _baseline_analysis(case, skillname, skillhash)
    skill_root = trial_root
    skill_root.mkdir(parents=True, exist_ok=True)
    write_json(analyze_output_path(skill_root, skillname), analysis_public_payload(analysis))

    attack = _baseline_attack(case, skillname)
    simulation = simulator.simulate(attack, case.unsafe_skill_content)
    judge_result = judge.judge(attack, simulation)
    feedback_result = build_feedback_history(None, attack, simulation, judge_result, 1)
    round_payload = build_round_payload("surface_01_baseline", 1, attack, simulation, judge_result, feedback_result)
    write_json(round_output_path(skill_root, "surface_01_baseline", 1), round_payload)
    write_json(global_report_output_path(skill_root, skillname), build_global_report(analysis, {"surface_01_baseline": [round_payload]}))
    return {
        "success": str(judge_result.result or "") == "success",
        "final_verdict": str(judge_result.result or ""),
        "final_reason_code": str(judge_result.reason or ""),
        "skill_root": str(skill_root),
    }


def _write_comparison_outputs(
    *,
    output_dir: Optional[Path],
    rows: List[Dict[str, Any]],
    experiment_id: str,
    cases: List[CaseDef],
    run_root: Path,
) -> None:
    if output_dir is None:
        return
    output_dir.mkdir(parents=True, exist_ok=True)

    if rows:
        headers = list(rows[0].keys())
        with (output_dir / "paired_results.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

    group_summary: Dict[str, Dict[str, int]] = {"baseline": {}, "main": {}}
    for row in rows:
        group = str(row.get("group") or "")
        verdict = str(row.get("final_verdict") or "")
        if group in group_summary:
            group_summary[group][verdict] = group_summary[group].get(verdict, 0) + 1

    payload = {
        "experiment_id": experiment_id,
        "cases": len(cases),
        "run_root": str(run_root),
        "group_summary": group_summary,
        "rows": rows,
    }
    (output_dir / "summary_by_group.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    cases = load_cases(args.pair_root, args.split, args.max_cases, case_selection=args.case_selection)
    trial_specs = build_trial_specs(cases, args.repeats, args.seed, shuffle=not args.no_shuffle)
    if args.dry_run:
        print(json.dumps([trial.__dict__ for trial in trial_specs], ensure_ascii=False, indent=2))
        return 0

    analyzer, attacker, simulator, judge, feedback = init_runtime()
    enforce_openclaw_isolate_per_run(simulator)
    try:
        preflight_check_openclaw(simulator)
    except SimulatorPreflightError as exc:
        print(str(exc))
        return 2

    from core.config_loader import ConfigLoader as _CL
    simulator_model_name = str(_CL().get_model_profile("simulator_model").get("model") or "unknown").strip()

    experiment_id = datetime.now(timezone.utc).strftime("%y%m%d%H%M%S%f")[:-3]
    output_dir = args.output_dir or (args.experiment_output_root / experiment_id)
    rows: List[Dict[str, Any]] = []

    try:
        with runtime_run_root("comparison") as run_root:
            with SingleInstanceLock(f"skillattack_compare_{slugify(str(run_root), 32)}"):
                surface_parallelism, _label = resolve_surface_parallelism(args.surface_parallelism, 0)
                model_base = Path(run_root) / simulator_model_name if simulator_model_name else Path(run_root)
                for trial in trial_specs:
                    case = next(item for item in cases if item.case_id == trial.case_id)
                    skillname = _case_skill_name(case)
                    skill_path = _case_skill_dir(case, args.pair_root)
                    skillhash = analyzer._build_skill_hash(case.unsafe_skill_content, {"skill_path": str(skill_path)}) if hasattr(analyzer, "_build_skill_hash") else ""
                    trial_root = model_base / skillname / trial.group

                    if trial.group == "baseline":
                        result = _write_baseline_trial(
                            case=case,
                            skillname=skillname,
                            skillhash=skillhash,
                            trial_root=trial_root,
                            simulator=simulator,
                            judge=judge,
                            feedback=feedback,
                        )
                    else:
                        result = run_lane_workflow(
                            skill_id=trial.group,
                            skill_content=case.unsafe_skill_content,
                            analyzer=analyzer,
                            attacker=attacker,
                            simulator=simulator,
                            judge=judge,
                            feedback=feedback,
                            max_iterations=int(args.main_max_iters),
                            surface_parallelism=1 if args.surface_mode == "single" else surface_parallelism,
                            run_root=model_base / skillname,
                            analyzer_context={"skill_id": skillname, "skill_path": str(skill_path)},
                            workspace_files=[],
                            collect_all_surfaces=True,
                        )

                    rows.append(
                        {
                            "experiment_id": experiment_id,
                            "trial_id": trial.trial_id,
                            "group": trial.group,
                            "case_id": case.case_id,
                            "repeat": trial.repeat,
                            "skillname": skillname,
                            "success": bool(result.get("success")),
                            "final_verdict": str(result.get("final_verdict") or ""),
                            "final_reason_code": str(result.get("final_reason_code") or ""),
                            "skill_root": str(result.get("skill_root") or ""),
                        }
                    )
    finally:
        _write_comparison_outputs(
            output_dir=output_dir,
            rows=rows,
            experiment_id=experiment_id,
            cases=cases,
            run_root=Path(ConfigLoader().get_runtime_run_root() or "result/runs_organize/comparison"),
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
