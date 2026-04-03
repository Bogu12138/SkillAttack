from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from core.schemas import AnalysisResult, AttackCase, FeedbackResult, JudgeResult, SimulationResult


class BaseStage(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config


class AnalyzerBase(BaseStage):
    @abstractmethod
    def analyze(self, skill_content: str, context: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        raise NotImplementedError


class AttackerBase(BaseStage):
    @abstractmethod
    def generate_attack(
        self,
        analysis: Any,
        feedback: Optional[FeedbackResult] = None,
        skill_content: Optional[str] = None,
        workspace_files: Optional[list] = None,
    ) -> AttackCase:
        raise NotImplementedError


class SimulatorBase(BaseStage):
    @abstractmethod
    def simulate(self, attack: AttackCase, skill_content: str) -> SimulationResult:
        raise NotImplementedError


class JudgeBase(BaseStage):
    @abstractmethod
    def judge(self, attack: AttackCase, simulation: SimulationResult) -> JudgeResult:
        raise NotImplementedError


class FeedbackBase(BaseStage):
    @abstractmethod
    def generate_feedback(
        self,
        previous_feedback: Optional[FeedbackResult],
        attack: AttackCase,
        simulation: SimulationResult,
        judge_result: JudgeResult,
        round_id: int,
    ) -> FeedbackResult:
        raise NotImplementedError
