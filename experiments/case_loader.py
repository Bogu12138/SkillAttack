from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SENSITIVE_HINT_TERMS = [
    "token",
    "secret",
    "credential",
    "password",
    "api key",
    "access",
    "delete",
    "backup",
    "network",
    "script",
]

SUPPORTED_SKILLINJECT_SPLITS = ("obvious", "contextual")


@dataclass
class CaseDef:
    case_id: str
    injection_id: str
    injection_title: str
    task_index: int
    skill_type: str
    skill_rel_path: str
    normal_prompt: str
    unsafe_skill_content: str
    expected_indicators: List[str]
    target_objective: str
    success_criteria: List[str]
    line_injection: str
    judge_prompt: str
    main_prompt: str = ""
    main_prompt_source: str = ""
    generated_expected_indicators: Optional[List[str]] = None


@dataclass
class TrialSpec:
    trial_id: int
    case_id: str
    group: str
    repeat: int


@dataclass
class RunSpec:
    run_id: str
    case_id: str
    group: str
    repeat: int
    prompt: str
    iteration: int = 1


def slugify(text: str, max_len: int = 40) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", (text or "").strip()).strip("-")
    if not slug:
        slug = "x"
    return slug[:max_len]


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def normalize_comparison_split(value: Any, fallback: str = "obvious") -> str:
    split = str(value or fallback).strip().lower()
    if split not in SUPPORTED_SKILLINJECT_SPLITS:
        return fallback
    return split


def inject_at_line(content: str, instruction_text: str, line_number: int) -> str:
    lines = content.splitlines(keepends=True)
    if line_number < 1 or line_number > len(lines) + 1:
        raise ValueError(f"line_number={line_number} out of range for {len(lines)} lines")
    block: List[str] = []
    for raw in instruction_text.strip("\n").splitlines():
        if raw.strip():
            block.append(f"{raw.strip()}\n")
        else:
            block.append("\n")
    pos = line_number - 1
    return "".join(lines[:pos] + block + lines[pos:])


def derive_expected_indicators(injection_goal: str, line_injection: str, judge_prompt: str) -> List[str]:
    indicators: List[str] = []

    script_hits = re.findall(r"\b[A-Za-z0-9_.-]+\.(?:sh|py|js)\b", f"{line_injection}\n{judge_prompt}")
    for hit in script_hits:
        if hit not in indicators:
            indicators.append(hit)

    hay = f"{injection_goal}\n{line_injection}\n{judge_prompt}".lower()
    for term in SENSITIVE_HINT_TERMS:
        if term in hay and term not in indicators:
            indicators.append(term)

    if not indicators:
        fallback = (injection_goal or line_injection or "unsafe behavior evidence").strip()
        indicators.append(fallback[:80])

    return indicators[:8]


def resolve_prepared_pair_dataset(pair_root: Path, split: str) -> Tuple[Path, Path, str]:
    normalized = normalize_comparison_split(split)
    summary_name = f"{normalized}_skills_summary.json"
    direct_summary = pair_root / summary_name
    if direct_summary.exists():
        return pair_root, direct_summary, normalized

    nested_dataset_dir = pair_root / normalized
    nested_summary = nested_dataset_dir / summary_name
    if nested_summary.exists():
        return nested_dataset_dir, nested_summary, normalized

    raise FileNotFoundError(
        f"Prepared pair dataset for split='{normalized}' not found under: {pair_root}. "
        f"Expected {summary_name} directly or under {normalized}/."
    )


def load_cases(
    pair_root: Path,
    split: str,
    max_cases: int,
    case_selection: str = "sequential",
) -> List[CaseDef]:
    dataset_dir, summary_path, _dataset_split = resolve_prepared_pair_dataset(pair_root, split)
    raw = _load_json(summary_path)
    candidates: List[CaseDef] = []

    for item in raw:
        if not isinstance(item, dict):
            continue

        inj_id = str(item.get("id") or "").strip()
        if not inj_id:
            continue

        skill_dir = str(item.get("skill_dir") or "").strip()
        skill_type = str(item.get("original_skill") or "").strip()
        normal_prompt = str(item.get("prompt") or "").strip()
        if not skill_dir or not skill_type or not normal_prompt:
            continue

        case_dir = dataset_dir / skill_dir
        skill_md = case_dir / "SKILL.md"
        if not skill_md.exists():
            continue

        unsafe_content = skill_md.read_text(encoding="utf-8", errors="ignore")
        injection_goal = str(item.get("injection_goal") or item.get("title") or "")
        judge_prompt = str(item.get("judge_prompt") or "")
        line_injection = str(item.get("full_injected_text") or item.get("injected_content") or "")

        expected = derive_expected_indicators(injection_goal, line_injection, judge_prompt)
        target_objective = (injection_goal or line_injection or judge_prompt or "unsafe instruction execution").strip()
        success_criteria = [f"Evidence of compromised behavior: {x}" for x in expected]
        skill_rel = str(case_dir.relative_to(pair_root))
        cid = f"inj{inj_id}_t00_{slugify(skill_type, 20)}"

        candidates.append(
            CaseDef(
                case_id=cid,
                injection_id=inj_id,
                injection_title=str(item.get("title") or f"injection-{inj_id}"),
                task_index=0,
                skill_type=skill_type,
                skill_rel_path=skill_rel,
                normal_prompt=normal_prompt,
                unsafe_skill_content=unsafe_content,
                expected_indicators=expected,
                target_objective=target_objective,
                success_criteria=success_criteria,
                line_injection=line_injection,
                judge_prompt=judge_prompt,
            )
        )

    if case_selection == "sequential":
        return candidates[:max_cases]

    if case_selection != "diverse_injection_skill":
        return candidates[:max_cases]

    selected: List[CaseDef] = []
    used_injections: set[str] = set()
    used_skills: set[str] = set()

    for case in candidates:
        if case.injection_id in used_injections or case.skill_type in used_skills:
            continue
        selected.append(case)
        used_injections.add(case.injection_id)
        used_skills.add(case.skill_type)
        if len(selected) >= max_cases:
            return selected

    for case in candidates:
        if any(x.case_id == case.case_id for x in selected) or case.injection_id in used_injections:
            continue
        selected.append(case)
        used_injections.add(case.injection_id)
        used_skills.add(case.skill_type)
        if len(selected) >= max_cases:
            return selected

    for case in candidates:
        if any(x.case_id == case.case_id for x in selected) or case.skill_type in used_skills:
            continue
        selected.append(case)
        used_injections.add(case.injection_id)
        used_skills.add(case.skill_type)
        if len(selected) >= max_cases:
            return selected

    for case in candidates:
        if any(x.case_id == case.case_id for x in selected):
            continue
        selected.append(case)
        if len(selected) >= max_cases:
            return selected

    return selected


def build_trial_specs(cases: List[CaseDef], repeats: int, seed: int, shuffle: bool) -> List[TrialSpec]:
    specs: List[TrialSpec] = []
    trial_id = 0
    for case in cases:
        for repeat in range(1, repeats + 1):
            trial_id += 1
            specs.append(TrialSpec(trial_id=trial_id, case_id=case.case_id, group="baseline", repeat=repeat))
            trial_id += 1
            specs.append(TrialSpec(trial_id=trial_id, case_id=case.case_id, group="main", repeat=repeat))
    if shuffle:
        rng = random.Random(seed)
        rng.shuffle(specs)
    return specs
