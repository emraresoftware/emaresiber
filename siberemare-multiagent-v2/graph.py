from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from agents import (
    planner_agent,
    discovery_agent,
    evidence_processor_agent,
    writer_agent,
    reviewer_agent,
    compliance_agent,
)
from state import PentestState
from integrations.slack_jira import send_slack_approval, create_jira_ticket
import asyncio
import structlog
import os
from contextlib import asynccontextmanager

logger = structlog.get_logger()


# ------------------------------------------------------------------ #
# Router node + edge (LangGraph 1.x pattern)
# ------------------------------------------------------------------ #

def router_node(state: PentestState) -> dict:
    """State güncelleme — self-critique iterasyon ve human-in-loop bayrakları."""
    logger.info(
        "router_node",
        request_id=state.request_id,
        stage=state.current_stage,
        score=state.review_score,
        iterations=state.self_critique_iterations,
    )
    updates: dict = {}

    # Self-critique loop: review başarısız → iterasyonu artır
    if (
        state.report_draft
        and state.review_score < 0.95
        and state.self_critique_iterations < state.max_iterations
    ):
        updates["self_critique_iterations"] = state.self_critique_iterations + 1
        updates["current_stage"] = "SELF_CRITIQUE_RETRY"

    # Maks tur aşıldıysa human-in-loop
    elif (
        state.report_draft
        and state.review_score < 0.95
        and state.self_critique_iterations >= state.max_iterations
    ):
        updates["human_intervention_needed"] = True

    return updates


def router_edge(state: PentestState) -> str:
    """Saf routing fonksiyonu — bir sonraki node adını döndürür."""
    if state.current_stage == "START":
        return "planner"
    if not state.compliance_status:
        return "compliance"
    if len(state.normalized_findings) == 0:
        return "discovery"
    if not state.evidence_bundle.get("processed"):
        return "evidence_processor"
    if not state.attack_graph:
        return "discovery"
    if not state.report_draft:
        return "writer"
    if state.review_score < 0.95 and state.self_critique_iterations <= state.max_iterations:
        return "writer"
    if state.human_intervention_needed:
        return "human_in_loop"
    return "final_report"


# ------------------------------------------------------------------ #
# Human-in-loop + Final Report nodes
# ------------------------------------------------------------------ #

def human_in_loop_node(state: PentestState) -> dict:
    try:
        asyncio.run(send_slack_approval(state))
    except RuntimeError:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            pool.submit(asyncio.run, send_slack_approval(state)).result()
    return {"human_intervention_needed": False}


def final_report_node(state: PentestState) -> dict:
    updates: dict = {}
    if state.compliance_status and state.review_score >= 0.95:
        ticket_key = create_jira_ticket(state)
        history = list(state.history) + [{"agent": "jira", "ticket": ticket_key}]
        updates["history"] = history
        os.makedirs("reports", exist_ok=True)
        with open(f"reports/{state.request_id}.md", "w", encoding="utf-8") as f:
            f.write(
                state.report_draft
                + f"\n\n---\nAI Self-Critique: {state.self_critique_iterations} tur, skor {state.review_score:.3f}"
            )
    return updates


# ------------------------------------------------------------------ #
# Build workflow
# ------------------------------------------------------------------ #

workflow = StateGraph(PentestState)

workflow.add_node("_router", router_node)
workflow.add_node("planner", planner_agent)
workflow.add_node("discovery", discovery_agent)
workflow.add_node("evidence_processor", evidence_processor_agent)
workflow.add_node("writer", writer_agent)
workflow.add_node("reviewer", reviewer_agent)
workflow.add_node("compliance", compliance_agent)
workflow.add_node("human_in_loop", human_in_loop_node)
workflow.add_node("final_report", final_report_node)

# Entry point → router
workflow.set_entry_point("_router")
workflow.add_conditional_edges("_router", router_edge)

# Writer → Reviewer → back to router
workflow.add_edge("writer", "reviewer")
workflow.add_edge("reviewer", "_router")

# Final
workflow.add_edge("compliance", "_router")
workflow.add_edge("human_in_loop", "_router")
workflow.add_edge("final_report", END)

# All other agents → back to router
for _node in ["planner", "discovery", "evidence_processor"]:
    workflow.add_edge(_node, "_router")

# ------------------------------------------------------------------ #
# Compiled app (MemorySaver — development & test)
# Production: async with async_app_with_sqlite() as production_app
# ------------------------------------------------------------------ #

app = workflow.compile(checkpointer=MemorySaver())


@asynccontextmanager
async def async_app_with_sqlite(db_path: str = "checkpoints/checkpoints.db"):
    """Production: async context manager ile SQLite checkpointer."""
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
    os.makedirs("checkpoints", exist_ok=True)
    async with AsyncSqliteSaver.from_conn_string(db_path) as checkpointer:
        production_app = workflow.compile(checkpointer=checkpointer)
        yield production_app
