import json
import shutil
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.append(str(Path(__file__).parent.parent))

from core.lane_workflow import resolve_surface_parallelism, run_lane_workflow
from core.schemas import AnalysisResult, AttackCase, AttackTarget, FeedbackResult, JudgeResult, SimulationResult, SurfaceResult


class FakeAnalyzer:
    def __init__(self, surfaces):
        self.surfaces = list(surfaces)
        self.config = {}

    def analyze(self, skill_content, scan_results=None):
        return AnalysisResult(
            skillname=str((scan_results or {}).get("skill_id") or "demo-skill"),
            skillhash="hash-1",
            readme="# Security Audit Report: demo-skill",
            results=[
                SurfaceResult(
                    id=f"surface_{idx:02d}_{name}",
                    title=name,
                    description=f"description for {name}",
                    risk_type="Data Exfiltration",
                    level="High",
                )
                for idx, name in enumerate(self.surfaces, start=1)
            ],
        )


class FakeAttacker:
    def generate_attack(self, analysis, feedback=None, skill_content=None, workspace_files=None):
        surface_id = str(analysis.get("id") or "")
        round_id = 1 if feedback is None else int(feedback.round_id or 0) + 1
        return AttackCase(
            attack_prompt=f"attack {surface_id} round {round_id}",
            target=AttackTarget(
                risk_type=str(analysis.get("risk_type") or "Data Exfiltration"),
                surface=surface_id,
                success_condition="observe evidence",
            ),
            expected_path=["step1", "step2"],
            metadata={"skillname": str(analysis.get("skillname") or ""), "round_id": round_id},
        )


class FakeSimulator:
    def __init__(self):
        self.config = {}

    def simulate(self, attack, skill_content):
        return SimulationResult(
            steps=[{"type": "assistant_message", "text": attack.attack_prompt}],
            logs=attack.attack_prompt,
            errors=[],
            execution_time=1.0,
        )


class FakeJudge:
    def __init__(self, verdict_map=None):
        self.verdict_map = verdict_map or {}

    def judge(self, attack, simulation):
        del simulation
        result = self.verdict_map.get(attack.target.surface, "ignore")
        return JudgeResult(
            result=result,
            reason=f"{attack.target.surface}:{result}",
            actionable_suggestion="retry later" if result != "success" else "",
        )


class FakeFeedback:
    def generate_feedback(self, previous_feedback, attack, simulation, judge_result, round_id):
        attacks = list(previous_feedback.attacks or []) if previous_feedback else []
        simulations = list(previous_feedback.simulations or []) if previous_feedback else []
        judges = list(previous_feedback.judges or []) if previous_feedback else []
        attacks.append({"attack_prompt": attack.attack_prompt})
        simulations.append({"logs": simulation.logs})
        judges.append({"result": judge_result.result})
        return FeedbackResult(round_id=round_id, attacks=attacks, simulations=simulations, judges=judges)


class TestPipelineLaneScheduler(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="lane-main-tests-"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_resolve_surface_parallelism(self):
        self.assertEqual(resolve_surface_parallelism("max", 1), (0, "max"))
        self.assertEqual(resolve_surface_parallelism("2", 1), (2, "2"))

    def test_run_lane_workflow_writes_surface_directories(self):
        result = run_lane_workflow(
            skill_id="demo-skill",
            skill_content="demo",
            analyzer=FakeAnalyzer(["alpha", "beta"]),
            attacker=FakeAttacker(),
            simulator=FakeSimulator(),
            judge=FakeJudge({"surface_01_alpha": "success", "surface_02_beta": "ignore"}),
            feedback=FakeFeedback(),
            max_iterations=2,
            surface_parallelism="max",
            run_root=self.tmpdir,
            collect_all_surfaces=True,
        )

        skill_root = self.tmpdir / "demo-skill"
        self.assertTrue((skill_root / "demo-skill_analyze.json").exists())
        self.assertTrue((skill_root / "surface_01_alpha" / "round_01.json").exists())
        self.assertTrue((skill_root / "surface_02_beta" / "round_01.json").exists())
        self.assertTrue((skill_root / "surface_02_beta" / "round_02.json").exists())
        self.assertTrue((skill_root / "demo-skill_global_report.json").exists())
        self.assertTrue(result["success"])
        self.assertEqual(result["final_verdict"], "success")
        self.assertEqual(result["winning_surface"], "surface_01_alpha")
        self.assertEqual(result["final_reason_code"], "surface_01_alpha:success")

        report_payload = json.loads((skill_root / "demo-skill_global_report.json").read_text(encoding="utf-8"))
        self.assertEqual(report_payload["surface_summary"]["surface_01_alpha"]["status"], "success")
        self.assertEqual(report_payload["surface_summary"]["surface_02_beta"]["rounds"], 2)

    def test_run_lane_workflow_skips_rounds_when_analyzer_returns_no_surfaces(self):
        result = run_lane_workflow(
            skill_id="demo-skill",
            skill_content="demo",
            analyzer=FakeAnalyzer([]),
            attacker=FakeAttacker(),
            simulator=FakeSimulator(),
            judge=FakeJudge(),
            feedback=FakeFeedback(),
            max_iterations=2,
            surface_parallelism="max",
            run_root=self.tmpdir,
            collect_all_surfaces=True,
        )

        skill_root = self.tmpdir / "demo-skill"
        self.assertTrue((skill_root / "demo-skill_analyze.json").exists())
        self.assertTrue((skill_root / "demo-skill_global_report.json").exists())
        self.assertFalse((skill_root / "surface_01_untitled").exists())
        self.assertEqual(result["surface_results"], [])
        self.assertFalse(result["success"])
        self.assertEqual(result["final_verdict"], "ignore")
        self.assertEqual(result["final_reason_code"], "no_attack_surfaces")

        analyze_payload = json.loads((skill_root / "demo-skill_analyze.json").read_text(encoding="utf-8"))
        self.assertEqual(analyze_payload["results"], [])

        report_payload = json.loads((skill_root / "demo-skill_global_report.json").read_text(encoding="utf-8"))
        self.assertEqual(report_payload["surface_summary"], {})
        self.assertEqual(report_payload["overall_summary"]["success_count"], 0)
        self.assertEqual(report_payload["overall_summary"]["ignore_count"], 0)
        self.assertEqual(report_payload["overall_summary"]["technical_count"], 0)

    def test_run_lane_workflow_emits_progress_messages(self):
        progress_messages = []

        run_lane_workflow(
            skill_id="demo-skill",
            skill_content="demo",
            analyzer=FakeAnalyzer(["alpha"]),
            attacker=FakeAttacker(),
            simulator=FakeSimulator(),
            judge=FakeJudge({"surface_01_alpha": "success"}),
            feedback=FakeFeedback(),
            max_iterations=2,
            surface_parallelism="max",
            run_root=self.tmpdir,
            collect_all_surfaces=True,
            progress_cb=progress_messages.append,
        )

        joined = "\n".join(progress_messages)
        self.assertIn("skill=demo-skill analyzer=start", joined)
        self.assertIn("skill=demo-skill analyzer=done surfaces=1", joined)
        self.assertIn("skill=demo-skill surface=surface_01_alpha round=1/2 start", joined)
        self.assertIn("skill=demo-skill surface=surface_01_alpha round=1/2 result=success", joined)
        self.assertIn("skill=demo-skill complete verdict=success", joined)


if __name__ == "__main__":
    unittest.main()
