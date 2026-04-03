import os
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.append(str(Path(__file__).parent.parent))

from core.config_loader import ConfigLoader
from core.llm_router import LLMRouter
from stages.analyzer.aig_native_api import AIGNativeAPIAnalyzer
from stages.simulator.openclaw import OpenClawSimulator


class DummyOpenAI:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class TestModelProfileEnvResolution(unittest.TestCase):
    def setUp(self):
        self.loader = ConfigLoader()
        self.original_profiles = dict(self.loader.models.get("profiles", {}))
        self.loader._config["models"]["profiles"]["test_env_model"] = {
            "provider": "openai_compatible",
            "model": "qwen3.5-flash",
            "api_key_env": "TEST_QWEN_API_KEY",
            "base_url_env": "TEST_QWEN_BASE_URL",
            "thinking": False,
        }
        os.environ["TEST_QWEN_API_KEY"] = "test-key"
        os.environ["TEST_QWEN_BASE_URL"] = "https://qwen.example/v1"

    def tearDown(self):
        self.loader._config["models"]["profiles"] = self.original_profiles
        os.environ.pop("TEST_QWEN_API_KEY", None)
        os.environ.pop("TEST_QWEN_BASE_URL", None)

    def test_llm_router_reads_api_key_and_base_url_from_env(self):
        router = LLMRouter()
        with patch("core.llm_router.OpenAI", DummyOpenAI):
            client, profile = router._get_client("test_env_model")

        self.assertEqual(profile["model"], "qwen3.5-flash")
        self.assertEqual(client.kwargs["api_key"], "test-key")
        self.assertEqual(client.kwargs["base_url"], "https://qwen.example/v1")

    def test_openclaw_simulator_reads_base_url_from_env(self):
        simulator = OpenClawSimulator({"target_agent_model_profile": "test_env_model"})
        model_cfg = simulator._resolve_target_model()

        self.assertEqual(model_cfg["model_name"], "qwen3.5-flash")
        self.assertEqual(model_cfg["api_key"], "test-key")
        self.assertEqual(model_cfg["base_url"], "https://qwen.example/v1")

    def test_aig_native_analyzer_reads_base_url_from_env(self):
        payload = AIGNativeAPIAnalyzer._extract_model_credentials("test_env_model")

        self.assertEqual(payload["model"], "qwen3.5-flash")
        self.assertEqual(payload["token"], "test-key")
        self.assertEqual(payload["base_url"], "https://qwen.example/v1")


if __name__ == "__main__":
    unittest.main()
