#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
import tempfile
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
from experiments.common import (
    enforce_openclaw_isolate_per_run,
    init_runtime,
    preflight_check_openclaw,
    runtime_run_root,
)


def _slugify(text: str, max_len: int = 40) -> str:
    value = str(text or "").strip().lower()
    value = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value)
    value = "-".join([part for part in value.split("-") if part])
    return (value or "x")[:max_len]


def _emit_progress(message: str) -> None:
    print(f"[main] {str(message or '').strip()}", flush=True)


def _load_skill_summary_lookup(summary_path: str) -> Dict[str, Dict[str, Any]]:
    if not summary_path or not Path(summary_path).exists():
        return {}
    with open(summary_path, encoding="utf-8") as handle:
        items = json.load(handle)
    return {item["skill_dir"]: item for item in items if isinstance(item, dict) and item.get("skill_dir")}


def _prepare_workspace_seed(
    skill_info: Dict[str, Any],
    task_files_dir: Optional[str],
    task_scripts_dir: Optional[str],
) -> Optional[str]:
    tf_map = skill_info.get("task_files") or {}
    ts_map = skill_info.get("task_scripts") or {}
    rf_list = skill_info.get("root_files") or []
    if not tf_map and not ts_map and not rf_list:
        return None

    base_dir = Path(task_files_dir).parent if task_files_dir else None
    tmp_workspace = tempfile.mkdtemp(prefix="main_workspace_")

    for target_name, src_relpath in tf_map.items():
        if not base_dir:
            continue
        src = base_dir / src_relpath
        if not src.exists():
            continue
        dst = Path(tmp_workspace) / target_name
        if src.is_dir():
            shutil.copytree(str(src), str(dst), dirs_exist_ok=True)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))

    for target_name, src_relpath in ts_map.items():
        if not base_dir:
            continue
        src = base_dir / src_relpath
        if not src.exists():
            continue
        scripts_dir = Path(tmp_workspace) / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src), str(scripts_dir / target_name))

    for src_relpath in rf_list:
        if not base_dir:
            continue
        src = base_dir / src_relpath
        if not src.exists():
            continue
        rel = src_relpath
        if rel.startswith("task_files/"):
            rel = rel[len("task_files/") :]
        dst = Path(tmp_workspace) / rel
        if src.is_dir():
            shutil.copytree(str(src), str(dst), dirs_exist_ok=True)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))

    return tmp_workspace


def _write_main_outputs(
    *,
    output_dir: Optional[Path],
    rows: List[Dict[str, Any]],
    experiment_id: str,
    total_cases: int,
    run_root: Path,
    max_iterations: int,
    surface_parallelism: int,
    completed: bool,
    aborted: bool,
    abort_reason: str,
) -> None:
    if output_dir is None:
        return
    output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = output_dir / "main_results.csv"
    if rows:
        headers = list(rows[0].keys())
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

    verdict_counts = {"success": 0, "ignore": 0, "technical": 0}
    for row in rows:
        verdict = str(row.get("final_verdict") or "").strip()
        if verdict in verdict_counts:
            verdict_counts[verdict] += 1

    summary = {
        "experiment_id": experiment_id,
        "total_cases": total_cases,
        "completed": bool(completed),
        "aborted": bool(aborted),
        "abort_reason": str(abort_reason or ""),
        "run_root": str(run_root),
        "max_iterations": int(max_iterations),
        "surface_parallelism": surface_parallelism,
        "verdict_counts": verdict_counts,
        "rows": rows,
    }
    (output_dir / "summary_by_group.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    report_lines = [
        "# SkillAttack Main Experiment Report",
        "",
        f"- Experiment ID: {experiment_id}",
        f"- Total skills: {total_cases}",
        f"- Completed: {completed}",
        f"- Aborted: {aborted}",
        f"- Success count: {verdict_counts['success']}",
        f"- Ignore count: {verdict_counts['ignore']}",
        f"- Technical count: {verdict_counts['technical']}",
        f"- Run root: {run_root}",
    ]
    if abort_reason:
        report_lines.extend(["", "## Abort Reason", abort_reason])
    (output_dir / "analysis_report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")


def _main_defaults_from_config() -> Dict[str, Any]:
    project_cfg = (ConfigLoader().main_experiment.get("project", {}) or {})
    return {
        "collect_all_surfaces": bool(project_cfg.get("collect_all_surfaces", False)),
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    defaults = _main_defaults_from_config()
    parser = argparse.ArgumentParser(description="SkillAttack main experiment runner.")
    parser.add_argument(
        "--collect-all-surfaces",
        action=argparse.BooleanOptionalAction,
        default=defaults["collect_all_surfaces"],
        help="Continue iterating across all surfaces instead of stopping after the first success.",
    )
    return parser.parse_args([] if argv is None else argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    config_loader = ConfigLoader()
    experiment_config = config_loader.main_experiment
    project_cfg = experiment_config.get("project", {}) or {}
    input_cfg = experiment_config.get("input", {}) or {}

    history_root = Path(
        project_cfg.get("history_root")
        or config_loader.app.get("project", {}).get("history_root")
        or "result/runshistory"
    )
    experiment_root = Path(project_cfg.get("experiment_output_root", "result/runs_organize/main/_experiment_results"))
    max_iterations = int(project_cfg.get("max_iterations", 2))
    surface_parallelism, _surface_label = resolve_surface_parallelism(project_cfg.get("surface_parallelism", "max"), 0)
    collect_all_surfaces = bool(args.collect_all_surfaces)

    experiment_id = datetime.now(timezone.utc).strftime("%y%m%d%H%M%S%f")[:-3]
    output_dir = experiment_root / experiment_id
    output_dir.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, Any]] = []
    total_cases = 0
    completed = False
    aborted = False
    abort_reason = ""

    analyzer, attacker, simulator, judge, feedback = init_runtime()
    enforce_openclaw_isolate_per_run(simulator)
    simulator_model_name = str(config_loader.get_model_profile("simulator_model").get("model") or "unknown").strip()
    try:
        preflight_check_openclaw(simulator, emit=lambda msg: _emit_progress(f"preflight {msg}"))
    except SimulatorPreflightError as exc:
        print(str(exc))
        return 2

    try:
        with runtime_run_root("main") as run_root:
            with SingleInstanceLock(_slugify(str(run_root), 60) or "skillattack_main"):
                _emit_progress(
                    (
                        f"experiment_id={experiment_id} run_root={run_root} "
                        f"max_iterations={max_iterations} surface_parallelism="
                        f"{'max' if surface_parallelism == 0 else surface_parallelism} "
                        f"collect_all_surfaces={collect_all_surfaces}"
                    )
                )
                if run_root.exists() and any(run_root.iterdir()):
                    history_root.mkdir(parents=True, exist_ok=True)
                    for item in list(run_root.iterdir()):
                        if item.name.startswith("."):
                            continue
                        dest = history_root / item.name
                        if dest.exists():
                            dest = history_root / f"{item.name}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                        shutil.move(str(item), str(dest))

                raw_skill_root = Path(input_cfg.get("raw_skill_root", "data/3"))
                skills = [path for path in sorted(raw_skill_root.iterdir()) if path.is_dir()]
                max_skills = project_cfg.get("max_skills")
                if max_skills not in (None, ""):
                    skills = skills[: int(max_skills)]
                total_cases = len(skills)
                _emit_progress(f"loaded {total_cases} skills from {raw_skill_root}")

                skill_summary_lookup = _load_skill_summary_lookup(str(input_cfg.get("skill_summary") or ""))
                task_files_dir = input_cfg.get("task_files_dir")
                task_scripts_dir = input_cfg.get("task_scripts_dir")

                for index, skill_path in enumerate(skills, start=1):
                    skill_id = skill_path.name
                    _emit_progress(f"[{index}/{total_cases}] skill={skill_id} start")
                    skill_md = skill_path / "SKILL.md"
                    skill_content = skill_md.read_text(encoding="utf-8", errors="ignore") if skill_md.exists() else ""
                    skill_info = skill_summary_lookup.get(skill_id, {})

                    tmp_workspace = _prepare_workspace_seed(skill_info, task_files_dir, task_scripts_dir)
                    original_workspace_seed = simulator.config.get("workspace_seed_dir")
                    original_target_skill_path = simulator.config.get("target_skill_path")

                    if tmp_workspace:
                        simulator.config["workspace_seed_dir"] = tmp_workspace
                    simulator.config["target_skill_path"] = str(skill_path)

                    try:
                        result = run_lane_workflow(
                            skill_id=skill_id,
                            skill_content=skill_content,
                            analyzer=analyzer,
                            attacker=attacker,
                            simulator=simulator,
                            judge=judge,
                            feedback=feedback,
                            max_iterations=max_iterations,
                            surface_parallelism=surface_parallelism,
                            run_root=run_root,
                            analyzer_context={"skill_id": skill_id, "skill_path": str(skill_path)},
                            workspace_files=[],
                            collect_all_surfaces=collect_all_surfaces,
                            progress_cb=lambda msg, idx=index, total=total_cases: _emit_progress(f"[{idx}/{total}] {msg}"),
                            simulator_model_name=simulator_model_name,
                        )
                    finally:
                        if tmp_workspace:
                            simulator.config["workspace_seed_dir"] = original_workspace_seed
                            shutil.rmtree(tmp_workspace, ignore_errors=True)
                        if original_target_skill_path is None:
                            simulator.config.pop("target_skill_path", None)
                        else:
                            simulator.config["target_skill_path"] = original_target_skill_path

                    _emit_progress(
                        (
                            f"[{index}/{total_cases}] skill={skill_id} done "
                            f"verdict={result['final_verdict']} surfaces={len(result.get('surface_results') or [])} "
                            f"winning_surface={result.get('winning_surface') or '-'}"
                        )
                    )
                    rows.append(
                        {
                            "experiment_id": experiment_id,
                            "trial_id": index,
                            "group": "main",
                            "case_id": skill_id,
                            "success": bool(result["success"]),
                            "final_verdict": str(result["final_verdict"] or ""),
                            "final_reason_code": str(result["final_reason_code"] or ""),
                            "surface_count": len(result.get("surface_results") or []),
                            "winning_surface": str(result.get("winning_surface") or ""),
                            "winning_iteration": int(result.get("winning_iteration") or 0),
                            "skill_root": str(result.get("skill_root") or ""),
                        }
                    )

                completed = True
                _emit_progress(
                    (
                        f"experiment complete skills={total_cases} "
                        f"success={sum(1 for row in rows if row.get('final_verdict') == 'success')} "
                        f"ignore={sum(1 for row in rows if row.get('final_verdict') == 'ignore')} "
                        f"technical={sum(1 for row in rows if row.get('final_verdict') == 'technical')}"
                    )
                )
    except Exception as exc:
        aborted = True
        abort_reason = str(exc)
        _emit_progress(f"aborted reason={abort_reason}")
    finally:
        _write_main_outputs(
            output_dir=output_dir,
            rows=rows,
            experiment_id=experiment_id,
            total_cases=total_cases,
            run_root=config_loader.get_runtime_run_root() or project_cfg.get("run_root", "result/runs_organize/main"),
            max_iterations=max_iterations,
            surface_parallelism=surface_parallelism,
            completed=completed,
            aborted=aborted,
            abort_reason=abort_reason,
        )

    return 1 if aborted else 0


if __name__ == "__main__":
    raise SystemExit(main())
