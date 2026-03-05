"""Discovery & Root-Cause Agent — GraphRAG ile kök neden + saldırı yolu grafiği"""
import json
from config.llm_switch import get_llm
from state import PentestState
from prompts import get_system_prompt

llm = get_llm()


async def discovery_agent(state: PentestState) -> PentestState:
    # Optionally enrich with GraphRAG context
    graph_context = ""
    try:
        from graph_rag.optimized_graphrag import OptimizedGraphRAG
        rag = OptimizedGraphRAG()
        results = await rag.hybrid_retrieve(state.raw_input)
        if results:
            graph_context = "\n\nGRAPH CONTEXT:\n" + "\n".join(
                str(r) for r in results[:3]
            )
    except Exception:
        pass

    system_prompt = get_system_prompt("discovery")
    user_msg = state.raw_input + graph_context
    response = await llm.ainvoke(
        [system_prompt, {"role": "user", "content": user_msg}]
    )
    content = response.content if hasattr(response, "content") else str(response)

    try:
        data = json.loads(content)
        state.normalized_findings = data.get("normalized_findings", [])
        state.attack_graph = data.get("attack_graph", {"nodes": [], "edges": []})
    except (json.JSONDecodeError, ValueError):
        state.normalized_findings = []
        state.attack_graph = {"nodes": [], "edges": []}

    # Fallback: JSON parselandı ama beklenen alanlar yoksa ham çıktıdan bulgu oluştur
    if not state.normalized_findings:
        state.normalized_findings = [
            {
                "title": "Keşfedilen Bulgu",
                "raw": content[:500],
                "root_cause": "Otomatik analiz edildi",
                "remediation_level": "Orta",
            }
        ]
    if not state.attack_graph:
        state.attack_graph = {"nodes": [], "edges": []}

    state.current_stage = "DISCOVERY_DONE"
    state.history.append(
        {
            "agent": "discovery",
            "findings_count": len(state.normalized_findings),
            "graph_context_used": bool(graph_context),
        }
    )
    return state
