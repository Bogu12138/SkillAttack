import unittest
from pathlib import Path

import sys

sys.path.append(str(Path(__file__).parent.parent))

from core.config_loader import ConfigLoader
from experiments.common import init_runtime
from stages.analyzer.aig_native_api import AIGNativeAPIAnalyzer
from stages.attacker.upgraded import UpgradedAttacker
from stages.feedback.basic import BasicFeedback
from stages.judge.basic import BasicJudge
from stages.simulator.openclaw import OpenClawSimulator


class TestPipelineSmoke(unittest.TestCase):
    def test_config_loader_exposes_minimal_runtime_sections(self):
        loader = ConfigLoader()
        self.assertIn("project", loader.app)
        self.assertIn("profiles", loader.models)
        self.assertIn("analyzer", loader.stages)
        self.assertIn("attacker", loader.stages)
        self.assertIn("simulator", loader.stages)

    def test_init_runtime_returns_only_active_stage_implementations(self):
        analyzer, attacker, simulator, judge, feedback = init_runtime()
        self.assertIsInstance(analyzer, AIGNativeAPIAnalyzer)
        self.assertIsInstance(attacker, UpgradedAttacker)
        self.assertIsInstance(simulator, OpenClawSimulator)
        self.assertIsInstance(judge, BasicJudge)
        self.assertIsInstance(feedback, BasicFeedback)


if __name__ == "__main__":
    unittest.main()
