from __future__ import annotations

import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from core.env_loader import load_dotenv_if_present

class ConfigLoader:
    _instance = None
    _config: Dict[str, Any] = {}
    _runtime_run_root: Optional[str] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigLoader, cls).__new__(cls)
            cls._instance._load_configs()
        return cls._instance

    def _load_configs(self):
        load_dotenv_if_present()
        config_dir = Path(__file__).parent.parent / "configs"
        experiment_cfg = self._load_yaml(config_dir / "experiment.yaml")

        self._config["models"] = self._load_yaml(config_dir / "models.yaml")
        self._config["stages"] = self._load_yaml(config_dir / "stages.yaml")
        self._config["experiment"] = experiment_cfg
        self._config["app"] = dict(experiment_cfg.get("common", {}) or {})
        self._config["main_experiment"] = dict(experiment_cfg.get("main", {}) or {})
        self._config["comparison_experiment"] = dict(experiment_cfg.get("comparison", {}) or {})

    def _load_yaml(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    @property
    def app(self) -> Dict[str, Any]:
        return self._config.get("app", {})

    @property
    def experiment(self) -> Dict[str, Any]:
        return self._config.get("experiment", {})

    @property
    def models(self) -> Dict[str, Any]:
        return self._config.get("models", {})

    @property
    def stages(self) -> Dict[str, Any]:
        return self._config.get("stages", {})

    @property
    def main_experiment(self) -> Dict[str, Any]:
        return self._config.get("main_experiment", {})

    @property
    def comparison_experiment(self) -> Dict[str, Any]:
        return self._config.get("comparison_experiment", {})

    def get_model_profile(self, profile_name: str) -> Dict[str, Any]:
        profile = dict(self.models.get("profiles", {}).get(profile_name, {}) or {})
        if not profile:
            return {}
        return profile

    def set_runtime_run_root(self, run_root: Optional[str | Path]) -> None:
        if run_root in (None, ""):
            self._runtime_run_root = None
            return
        self._runtime_run_root = str(run_root)

    def get_runtime_run_root(self) -> Optional[str]:
        if self._runtime_run_root:
            return self._runtime_run_root
        return None
