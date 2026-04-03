import json
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

import sys

sys.path.append(str(Path(__file__).parent.parent))

from core.config_loader import ConfigLoader
from stages.analyzer.aig_native_api import AIGNativeAPIAnalyzer


class StubAIGNativeAPIAnalyzer(AIGNativeAPIAnalyzer):
    def __init__(self, config):
        super().__init__(config)
        self.uploaded_archives = []
        self.created_tasks = []

    def _upload_archive(self, *, archive_path, base_url, headers=None, timeout=None):
        self.uploaded_archives.append(Path(archive_path))
        return "https://aig.local/files/skill_source.zip"

    def _create_scan_task(self, *, base_url, model_payload, file_url, prompt, headers=None, timeout=None):
        self.created_tasks.append(
            {
                "base_url": base_url,
                "model_payload": dict(model_payload),
                "file_url": file_url,
                "prompt": prompt,
            }
        )
        return "session-123"

    def _poll_task_result(
        self,
        *,
        base_url,
        session_id,
        headers=None,
        timeout_seconds=600.0,
        poll_interval_seconds=5.0,
    ):
        return {
            "status_payload": {"data": {"status": "done"}},
            "result_payload": {
                "data": {
                    "event": {
                        "result": {
                            "readme": "# Security Audit Report: demo-skill",
                            "results": [
                                {
                                    "title": "Hard-coded secret exfiltration",
                                    "risk_type": "Data Exfiltration",
                                    "level": "High",
                                    "description": "**File Location**: scripts/skill.py:12\nSecret is uploaded to a remote host.",
                                },
                                {
                                    "title": "Overbroad deletion helper",
                                    "risk_type": "Data Destruction",
                                    "level": "Medium",
                                    "description": "**File Location**: scripts/cleanup.py:5\nDeletes user data.",
                                },
                            ],
                        }
                    }
                }
            },
        }


class TestAIGNativeAPIAnalyzer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="aig-native-tests-"))
        self.loader = ConfigLoader()
        self.original_profiles = dict(self.loader.models.get("profiles", {}))
        self.loader._config["models"]["profiles"]["test_native_aig"] = {
            "provider": "openai",
            "model": "openai/gpt-4.1-mini",
            "base_url": "https://openrouter.example/api/v1",
            "api_key_env": "TEST_NATIVE_AIG_API_KEY",
        }
        os.environ["TEST_NATIVE_AIG_API_KEY"] = "test-token"

    def tearDown(self):
        self.loader._config["models"]["profiles"] = self.original_profiles
        os.environ.pop("TEST_NATIVE_AIG_API_KEY", None)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_build_archive_prefers_skill_directory(self):
        skill_dir = self.tmpdir / "demo-skill"
        scripts_dir = skill_dir / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
        (scripts_dir / "run.py").write_text("print('ok')\n", encoding="utf-8")

        analyzer = StubAIGNativeAPIAnalyzer({"model_profile": "test_native_aig"})
        archive_path = analyzer._build_archive_for_scan("fallback content", {"skill_path": str(skill_dir)})

        with zipfile.ZipFile(archive_path, "r") as zf:
            names = sorted(zf.namelist())

        self.assertEqual(names, ["SKILL.md", "scripts/run.py"])

    def test_analyze_returns_surface_protocol_shape(self):
        skill_dir = self.tmpdir / "demo-skill"
        skill_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
        cache_root = self.tmpdir / "cache"

        analyzer = StubAIGNativeAPIAnalyzer(
            {
                "model_profile": "test_native_aig",
                "api_base_url": "http://localhost:8088",
                "prompt": "scan this skill",
                "analysis_cache_root": str(cache_root),
            }
        )

        result = analyzer.analyze(
            "# Demo\n",
            context={"skill_id": "demo-skill", "skill_path": str(skill_dir)},
        )

        self.assertEqual(result.skillname, "demo-skill")
        self.assertTrue(result.skillhash)
        self.assertEqual([item.id for item in result.results], [
            "surface_01_Hard-coded secret exfiltration",
            "surface_02_Overbroad deletion helper",
        ])
        self.assertEqual(result.results[0].risk_type, "Data Exfiltration")
        self.assertEqual(result.results[1].risk_type, "Data Destruction")

        cache_files = sorted(cache_root.glob("demo-skill_*_native.json"))
        self.assertEqual(len(cache_files), 1)
        payload = json.loads(cache_files[0].read_text(encoding="utf-8"))
        self.assertEqual(payload["skillname"], "demo-skill")
        self.assertIn("analyze_result", payload)
        self.assertIn("native_result", payload)
        self.assertIn("native_findings", payload)
        self.assertIn("risk_type_remap", payload)

    def test_analyze_reuses_native_cache(self):
        skill_dir = self.tmpdir / "demo-skill"
        skill_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
        cache_root = self.tmpdir / "cache"

        analyzer = StubAIGNativeAPIAnalyzer(
            {
                "model_profile": "test_native_aig",
                "api_base_url": "http://localhost:8088",
                "use_analysis_cache": True,
                "analysis_cache_root": str(cache_root),
            }
        )

        first = analyzer.analyze("# Demo\n", context={"skill_id": "demo-skill", "skill_path": str(skill_dir)})
        second = analyzer.analyze("# Demo\n", context={"skill_id": "demo-skill", "skill_path": str(skill_dir)})

        self.assertEqual(first.results[0].id, second.results[0].id)
        self.assertEqual(len(analyzer.uploaded_archives), 1)
        self.assertEqual(len(analyzer.created_tasks), 1)

    def test_status_log_fallback_returns_empty_results_when_aig_never_finishes(self):
        analyzer = AIGNativeAPIAnalyzer({"model_profile": "test_native_aig"})

        status_payload = {
            "data": {
                "status": "doing",
                "log": """
```# API Gateway Agent Skill 信息收集报告

## 审计结论
- 暂未发现需要单独报告的高危漏洞。
```

<thought>
结论：所有问题均为规范性关注点，不符合 Skill 项目漏洞报告标准。无需生成漏洞条目。
</thought>
""",
            }
        }

        native_result = analyzer._native_result_from_status_log(status_payload)

        self.assertEqual(native_result, {"readme": "# API Gateway Agent Skill 信息收集报告\n\n## 审计结论\n- 暂未发现需要单独报告的高危漏洞。", "results": []})


if __name__ == "__main__":
    unittest.main()
