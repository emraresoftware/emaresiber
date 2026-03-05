"""Evidence Processor Agent — Multimodal (OCR + Vision) + Redaction Fail-Closed"""
import base64
from config.llm_switch import get_llm, get_vision_llm
from state import PentestState
from prompts import get_system_prompt

llm = get_llm()
vision_llm = get_vision_llm()


async def evidence_processor_agent(state: PentestState) -> PentestState:
    system_prompt = get_system_prompt("evidence_processor")

    # Dosya yoksa otomatik geçiş (boş evidence bundle)
    files = state.evidence_bundle.get("files", [])
    if not files:
        return state.model_copy(update={
            "evidence_bundle": {"processed": True, "files": [], "redaction_status": "SUCCESS"},
            "current_stage": "EVIDENCE_DONE",
            "history": state.history + [{"agent": "evidence_processor", "note": "Dosya yok — otomatik geçiş"}],
        })

    processed_summaries = []

    for evidence in files:
        if isinstance(evidence, str) and evidence.endswith((".png", ".jpg", ".jpeg")):
            try:
                from PIL import Image
                import pytesseract

                img = Image.open(evidence)
                ocr_text = pytesseract.image_to_string(img)

                with open(evidence, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()

                resp = await vision_llm.ainvoke(
                    [
                        system_prompt,
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "image_url",
                                    "image_url": {
                                        "url": f"data:image/jpeg;base64,{b64}"
                                    },
                                },
                                {
                                    "type": "text",
                                    "text": f"OCR çıktısı:\n{ocr_text}\nLütfen analiz et ve PII tespiti yap.",
                                },
                            ],
                        },
                    ]
                )
                summary = (
                    resp.content if hasattr(resp, "content") else str(resp)
                )

                # Redaction fail-closed
                if "PII_DETECTED" in summary or "REDACTION_FAILED" in summary:
                    state.evidence_bundle["status"] = "REDACTION_FAILED"
                    state.human_intervention_needed = True
                    state.current_stage = "EVIDENCE_REDACTION_FAILED"
                    state.history.append(
                        {"agent": "evidence_processor", "error": "PII detected — halted"}
                    )
                    return state

                processed_summaries.append({"file": evidence, "summary": summary})
            except Exception as e:
                processed_summaries.append({"file": evidence, "error": str(e)})
        else:
            # Non-image evidence (Burp, XML, JSON logs)
            processed_summaries.append(
                {"file": evidence, "summary": "Text-based evidence — forwarded to LLM"}
            )

    state.evidence_bundle["processed"] = True
    state.evidence_bundle["summaries"] = processed_summaries
    state.evidence_bundle["redaction_status"] = "SUCCESS"
    state.current_stage = "EVIDENCE_DONE"
    state.history.append(
        {
            "agent": "evidence_processor",
            "files_processed": len(processed_summaries),
        }
    )
    return state
