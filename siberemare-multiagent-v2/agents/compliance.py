"""Compliance Agent — KVKK/GDPR + PentestX guardrail + Scope/LOA kontrolü (Paralel)"""
import json
from config.llm_switch import get_llm
from state import PentestState
from prompts import get_system_prompt

llm = get_llm()


async def compliance_agent(state: PentestState) -> PentestState:
    system_prompt = get_system_prompt("compliance")

    context = json.dumps(
        {
            "request_id": state.request_id,
            "scope": state.scope,
            "findings_count": len(state.normalized_findings),
            "evidence_redaction_status": state.evidence_bundle.get(
                "redaction_status", "UNKNOWN"
            ),
            "report_draft_excerpt": state.report_draft[:500],
        },
        ensure_ascii=False,
    )

    response = await llm.ainvoke(
        [system_prompt, {"role": "user", "content": context}]
    )
    content = response.content if hasattr(response, "content") else str(response)

    try:
        result = json.loads(content)
        is_compliant = result.get("compliance_status", False)
        red_flags = result.get("red_flags", [])
    except (json.JSONDecodeError, ValueError):
        # Heuristic fallback
        is_compliant = "true" in content.lower() or "pass" in content.lower()
        red_flags = []

    state.compliance_status = is_compliant
    if not is_compliant:
        state.human_intervention_needed = True

    state.current_stage = "COMPLIANCE_DONE"
    state.history.append(
        {
            "agent": "compliance",
            "compliant": is_compliant,
            "red_flags": red_flags,
        }
    )
    return state
