from core.base import FeedbackBase
from core.schemas import AttackCase, FeedbackResult, JudgeResult, SimulationResult
from core.surface_protocol import build_feedback_history


class BasicFeedback(FeedbackBase):
    def generate_feedback(
        self,
        previous_feedback: FeedbackResult,
        attack: AttackCase,
        simulation: SimulationResult,
        judge_result: JudgeResult,
        round_id: int,
    ) -> FeedbackResult:
        return build_feedback_history(previous_feedback, attack, simulation, judge_result, round_id)
