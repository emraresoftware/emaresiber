from pydantic import BaseModel, Field
from typing import List, Dict, Optional


class PentestState(BaseModel):
    request_id: str
    scope: Dict
    raw_input: str
    normalized_findings: List[Dict] = Field(default_factory=list)
    attack_graph: Dict = Field(default_factory=dict)
    evidence_bundle: Dict = Field(default_factory=dict)
    report_draft: str = ""
    review_score: float = 0.0
    compliance_status: bool = False
    human_intervention_needed: bool = False
    current_stage: str = "START"
    history: List[Dict] = Field(default_factory=list)
    review_feedback: Optional[str] = None
    self_critique_iterations: int = 0
    max_iterations: int = 3
