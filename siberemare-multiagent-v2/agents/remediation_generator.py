"""Remediation Script Generator — Bulgu → Ansible Playbook"""
from config.llm_switch import get_llm
from state import PentestState

llm = get_llm()


async def generate_ansible_remediation(finding: dict) -> str:
    """Bulgu → Ansible YAML playbook üret (idempotent, dry-run uyumlu)"""
    prompt = f"""Sen SiberEmare Remediation Script Generator'sun.
Bulgu: {finding.get('title', 'Bilinmeyen Bulgu')}
Kök neden: {finding.get('root_cause', 'N/A')}
Düzeltme seviyesi: {finding.get('remediation_level', 'Orta')}

ZORUNLU: Ansible YAML playbook üret (idempotent, dry-run uyumlu).
- Hemen: play 1
- Orta vade: play 2
- Uzun vade: play 3 + comment
- Değişkenler: {{ target_host }}, {{ service_name }}

Çıktı: Sadece YAML (başlangıç --- ile)"""

    response = await llm.ainvoke([{"role": "system", "content": prompt}])
    content = response.content if hasattr(response, "content") else str(response)
    return content.strip()
