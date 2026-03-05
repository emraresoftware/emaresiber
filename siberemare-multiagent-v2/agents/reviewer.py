"""Reviewer Agent — LLM-as-a-Judge + Self-Critique + GraphRAG gold-standard zenginleştirme"""
import json
from config.llm_switch import get_llm
from state import PentestState
from prompts import get_system_prompt

llm = get_llm()


async def _enrich_with_gold_standard(state: PentestState) -> str:
    """GraphRAG gold_standard koleksiyonundan en benzer 3 örneği çek"""
    try:
        from graph_rag.optimized_graphrag import OptimizedGraphRAG
        rag = OptimizedGraphRAG()
        docs = await rag.hybrid_retrieve(state.report_draft[:500], k=3)
        if docs:
            enriched = "EN İYİ GOLD-STANDARD ÖRNEKLER (GraphRAG):\n"
            for i, doc in enumerate(docs, 1):
                enriched += f"{i}. {str(doc)[:300]}\n"
            return enriched
    except Exception:
        pass
    return ""


async def reviewer_agent(state: PentestState) -> PentestState:
    system_prompt = get_system_prompt("reviewer")
    gold_context = await _enrich_with_gold_standard(state)

    user_msg = state.report_draft
    if state.review_feedback:
        user_msg += f"\n\nÖNCEKİ FEEDBACK:\n{state.review_feedback}"
    if gold_context:
        user_msg += f"\n\n{gold_context}"

    response = await llm.ainvoke(
        [system_prompt, {"role": "user", "content": user_msg}]
    )
    content = response.content if hasattr(response, "content") else str(response)

    # Parse review result
    try:
        review = json.loads(content)
        state.review_score = float(review.get("overall_score", 0.0))
        approved = review.get("approved", False)
        state.review_feedback = review.get("feedback") if not approved else None
    except (json.JSONDecodeError, ValueError):
        # Heuristic fallback
        state.review_score = 0.96 if "APPROVED" in content.upper() else 0.80
        state.review_feedback = content if state.review_score < 0.95 else None

    state.current_stage = "REVIEW_DONE"
    state.history.append(
        {
            "agent": "reviewer",
            "iteration": state.self_critique_iterations,
            "score": state.review_score,
            "approved": state.review_score >= 0.95,
            "gold_context_used": bool(gold_context),
        }
    )
    return state
