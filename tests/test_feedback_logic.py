from core.schemas import AttackCase, AttackTarget, FeedbackResult, JudgeResult, SimulationResult
from stages.feedback.basic import BasicFeedback


def _attack() -> AttackCase:
    return AttackCase(
        attack_prompt="demo attack",
        target=AttackTarget(
            risk_type="Data Exfiltration",
            surface="surface_01_demo",
            success_condition="observe exploit evidence",
        ),
        expected_path=["step1", "step2"],
        metadata={"skillname": "demo-skill"},
    )


def _simulation() -> SimulationResult:
    return SimulationResult(
        steps=[{"type": "assistant_message", "text": "done"}],
        logs="demo logs",
        errors=[],
        execution_time=1.2,
    )


def test_feedback_accumulates_full_history():
    feedback_stage = BasicFeedback({})
    first = feedback_stage.generate_feedback(
        None,
        _attack(),
        _simulation(),
        JudgeResult(result="ignore", reason="blocked", actionable_suggestion="be subtler"),
        1,
    )
    second = feedback_stage.generate_feedback(
        first,
        _attack(),
        _simulation(),
        JudgeResult(result="technical", reason="timeout", actionable_suggestion="simplify"),
        2,
    )

    assert first.round_id == 1
    assert len(first.attacks) == 1
    assert second.round_id == 2
    assert len(second.attacks) == 2
    assert len(second.simulations) == 2
    assert len(second.judges) == 2
