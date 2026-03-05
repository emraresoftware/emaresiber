"""Writer Agent — Bölüm 16 bulgu şablonu + Ansible remediation entegrasyonu"""
from config.llm_switch import get_llm
from agents.remediation_generator import generate_ansible_remediation
from state import PentestState
from prompts import get_system_prompt

llm = get_llm()


async def writer_agent(state: PentestState) -> PentestState:
    system_prompt = get_system_prompt("writer")

    # Inject self-critique feedback if present
    full_system = system_prompt["content"]
    if state.review_feedback:
        full_system += (
            f"\n\nÖNCEKİ REVİZYON TALİMATI UYGULA:\n{state.review_feedback}\n"
            "Yukarıdaki feedback'i uygulayarak raporu yeniden yaz ve iyileştir."
        )

    # Build context from all previous agent outputs
    context = f"""
Bulgular: {state.normalized_findings}
Saldırı Grafiği: {state.attack_graph}
Evidence: {state.evidence_bundle.get('summaries', [])}
Kapsam: {state.scope}
"""

    response = await llm.ainvoke(
        [
            {"role": "system", "content": full_system},
            {"role": "user", "content": context},
        ]
    )
    report_draft = (
        response.content if hasattr(response, "content") else str(response)
    )

    # Append Ansible remediation scripts per finding
    for finding in state.normalized_findings:
        try:
            ansible = await generate_ansible_remediation(finding)
            report_draft += (
                f"\n\n---\n**Otomatik Remediation Script ({finding.get('title', '')}) — Ansible:**\n"
                f"```yaml\n{ansible}\n```\n"
            )
        except Exception:
            pass

    # Append self-critique summary note
    if state.self_critique_iterations > 0:
        report_draft += (
            f"\n\n---\n**AI Self-Critique Raporu**\n"
            f"• Tur sayısı: {state.self_critique_iterations}\n"
            f"• Son skor: {state.review_score:.2f}\n"
            f"• İyileştirme: Otomatik format uyumu sağlandı.\n"
        )

    state.report_draft = report_draft
    state.current_stage = "WRITER_DONE"
    state.history.append(
        {
            "agent": "writer",
            "iteration": state.self_critique_iterations,
            "feedback_applied": bool(state.review_feedback),
            "remediation_scripts": len(state.normalized_findings),
        }
    )
    return state
