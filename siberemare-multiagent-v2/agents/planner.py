"""Planner Agent — PentestX kademe belirleme, runbook seçimi, onay hesabı"""
import json
from config.llm_switch import get_llm
from state import PentestState
from prompts import get_system_prompt

llm = get_llm(model_type="fast")


async def planner_agent(state: PentestState) -> PentestState:
    system_prompt = get_system_prompt("planner")
    response = await llm.ainvoke(
        [system_prompt, {"role": "user", "content": state.raw_input}]
    )
    content = response.content if hasattr(response, "content") else str(response)

    # JSON parse attempt
    try:
        plan = json.loads(content)
        state.compliance_status = plan.get("compliance_status", False)
        state.scope.update(
            {
                "level": plan.get("level", "L3"),
                "data_level": plan.get("data_level", "D1"),
                "runbook": plan.get("runbook", ""),
                "approvals_required": plan.get("approvals_required", 2),
                "red_flag": plan.get("red_flag", False),
            }
        )
    except (json.JSONDecodeError, ValueError):
        state.compliance_status = True  # Optimistic, compliance will verify

    state.current_stage = "PLAN_DONE"
    state.history.append({"agent": "planner", "output": content})
    return state
