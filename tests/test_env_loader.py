import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.append(str(Path(__file__).parent.parent))

from core import env_loader
from core.config_loader import ConfigLoader


class TestEnvLoader(unittest.TestCase):
    def test_load_dotenv_reads_project_root_env_file(self):
        with tempfile.TemporaryDirectory(prefix="env-loader-") as tmpdir:
            project_root = Path(tmpdir)
            env_path = project_root / ".env"
            env_path.write_text(
                'QWEN_API_KEY=test-from-dotenv\nQWEN_BASE_URL="https://qwen.example/v1"\n',
                encoding="utf-8",
            )

            os.environ.pop("QWEN_API_KEY", None)
            os.environ.pop("QWEN_BASE_URL", None)

            loaded = env_loader.load_dotenv_if_present(project_root=project_root, cwd=project_root)

            self.assertEqual(loaded, [env_path.resolve()])
            self.assertEqual(os.environ.get("QWEN_API_KEY"), "test-from-dotenv")
            self.assertEqual(os.environ.get("QWEN_BASE_URL"), "https://qwen.example/v1")

    def test_load_dotenv_overrides_existing_env_by_default(self):
        with tempfile.TemporaryDirectory(prefix="env-loader-") as tmpdir:
            project_root = Path(tmpdir)
            env_path = project_root / ".env"
            env_path.write_text("QWEN_API_KEY=from-file\n", encoding="utf-8")

            os.environ["QWEN_API_KEY"] = "from-shell"
            loaded = env_loader.load_dotenv_if_present(project_root=project_root, cwd=project_root)

            self.assertEqual(loaded, [env_path.resolve()])
            self.assertEqual(os.environ.get("QWEN_API_KEY"), "from-file")

    def test_config_loader_triggers_dotenv_loading(self):
        original_instance = ConfigLoader._instance
        original_config = dict(ConfigLoader._config)
        try:
            ConfigLoader._instance = None
            ConfigLoader._config = {}
            with patch("core.config_loader.load_dotenv_if_present") as mocked:
                ConfigLoader()
            mocked.assert_called_once()
        finally:
            ConfigLoader._instance = original_instance
            ConfigLoader._config = original_config


if __name__ == "__main__":
    unittest.main()
