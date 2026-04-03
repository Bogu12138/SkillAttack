from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict, Field


class SurfaceResult(BaseModel):
    id: str
    title: str
    description: str
    risk_type: str
    level: str

    model_config = ConfigDict(extra="forbid")


class AnalysisResult(BaseModel):
    skillname: str
    skillhash: str
    readme: str
    results: List[SurfaceResult] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class AttackTarget(BaseModel):
    risk_type: str
    surface: str
    success_condition: str

    model_config = ConfigDict(extra="forbid")


class AttackCase(BaseModel):
    attack_prompt: str
    target: AttackTarget
    expected_path: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class SimulationResult(BaseModel):
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    logs: str = ""
    errors: List[str] = Field(default_factory=list)
    execution_time: float = 0.0

    model_config = ConfigDict(extra="forbid")


class JudgeResult(BaseModel):
    result: str
    reason: str
    actionable_suggestion: str = ""

    model_config = ConfigDict(extra="forbid")


class FeedbackResult(BaseModel):
    round_id: int
    attacks: List[Dict[str, Any]] = Field(default_factory=list)
    simulations: List[Dict[str, Any]] = Field(default_factory=list)
    judges: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
