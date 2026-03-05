"""
API Leak Scanner Agent — Multi-Agent Pipeline'a entegre tarayıcı ajan.
======================================================================
Bu agent, mevcut PentestState içindeki hedef bilgilerini kullanarak
internet ortamında deşifre olmuş API anahtarlarını tarar ve sonuçları
state'e yazar.
"""

import json
import asyncio
from typing import Dict, List

from config.llm_switch import get_llm
from state import PentestState
from prompts import get_system_prompt
import structlog

logger = structlog.get_logger()


async def api_leak_scanner_agent(state: PentestState) -> PentestState:
    """
    API Leak Scanner Agent:
    1. State'teki hedefi (scope.target) alır
    2. Internet kaynaklarını paralel tarar (GitHub, Shodan, Google, Paste, URLScan, IntelX)
    3. Yerel proje dosyalarını tarar (opsiyonel)
    4. Sonuçları LLM ile analiz edip raporlaştırır
    5. State'i günceller
    """
    from tools.api_leak_scanner import APILeakScanner, scan_local_files
    from tools.leak_report_generator import (
        generate_markdown_report,
        generate_json_report,
        generate_html_report,
    )

    target = state.scope.get("target", "")
    if not target or target == "auto":
        logger.warning("api_leak_scanner: hedef belirtilmemiş, atlanıyor")
        state.current_stage = "LEAK_SCAN_SKIPPED"
        return state

    logger.info("api_leak_scanner_start", target=target)

    # ---- Internet Taraması ----
    scanner = APILeakScanner(target=target)
    scan_result = await scanner.run()

    # ---- Yerel Dosya Taraması (opsiyonel — scope'ta belirtilmişse) ----
    local_scan_dir = state.scope.get("local_scan_dir")
    if local_scan_dir:
        local_findings = scan_local_files(local_scan_dir)
        scan_result.credentials.extend(local_findings)
        scan_result.total_findings += len(local_findings)
        scan_result.critical_count += sum(1 for f in local_findings if f.severity == "CRITICAL")
        scan_result.high_count += sum(1 for f in local_findings if f.severity == "HIGH")
        scan_result.medium_count += sum(1 for f in local_findings if f.severity == "MEDIUM")
        scan_result.low_count += sum(1 for f in local_findings if f.severity == "LOW")

    # ---- LLM Analiz (opsiyonel — bulgu varsa AI ile özetleme) ----
    ai_summary = ""
    if scan_result.total_findings > 0:
        try:
            llm = get_llm("fast")
            findings_summary = json.dumps(
                [
                    {
                        "type": c.credential_type,
                        "severity": c.severity,
                        "source": c.source,
                        "masked_value": c.matched_value,
                    }
                    for c in scan_result.credentials[:20]  # İlk 20 bulgu
                ],
                ensure_ascii=False,
            )
            system_msg = get_system_prompt("api_leak_scanner")
            user_msg = (
                f"Hedef: {target}\n"
                f"Toplam bulgu: {scan_result.total_findings}\n"
                f"Critical: {scan_result.critical_count}, High: {scan_result.high_count}\n\n"
                f"Bulgular:\n{findings_summary}"
            )
            response = await llm.ainvoke(
                [system_msg, {"role": "user", "content": user_msg}]
            )
            ai_summary = response.content if hasattr(response, "content") else str(response)
        except Exception as e:
            logger.warning("ai_summary_failed", error=str(e))
            ai_summary = ""

    # ---- Rapor Üretimi ----
    md_path = generate_markdown_report(scan_result)
    json_path = generate_json_report(scan_result)
    html_path = generate_html_report(scan_result)

    logger.info(
        "api_leak_scanner_reports_generated",
        markdown=md_path,
        json=json_path,
        html=html_path,
    )

    # ---- State Güncelleme ----
    leak_scan_result = {
        "scan_id": scan_result.scan_id,
        "target": target,
        "total_findings": scan_result.total_findings,
        "critical_count": scan_result.critical_count,
        "high_count": scan_result.high_count,
        "medium_count": scan_result.medium_count,
        "low_count": scan_result.low_count,
        "sources_scanned": scan_result.sources_scanned,
        "reports": {
            "markdown": md_path,
            "json": json_path,
            "html": html_path,
        },
        "ai_summary": ai_summary,
        "errors": scan_result.errors,
    }

    # Evidence bundle'a ekle
    evidence = dict(state.evidence_bundle) if state.evidence_bundle else {}
    evidence["leak_scan"] = leak_scan_result
    state.evidence_bundle = evidence

    # History'ye ekle
    state.history.append({
        "agent": "api_leak_scanner",
        "target": target,
        "total_findings": scan_result.total_findings,
        "critical": scan_result.critical_count,
        "high": scan_result.high_count,
    })

    state.current_stage = "LEAK_SCAN_DONE"

    # Critical bulgu varsa human intervention tetikle
    if scan_result.critical_count > 0:
        state.human_intervention_needed = True
        logger.warning(
            "critical_leaks_found",
            count=scan_result.critical_count,
            msg="KRİTİK sızıntı tespit edildi — insan müdahalesi gerekli!",
        )

    logger.info(
        "api_leak_scanner_complete",
        target=target,
        total=scan_result.total_findings,
        critical=scan_result.critical_count,
    )

    return state
