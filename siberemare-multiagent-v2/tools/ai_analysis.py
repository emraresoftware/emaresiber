"""
SiberEmare AI-Powered Vulnerability Analysis Engine
=====================================================
Tarama bulgularını yapay zekâ ile derinlemesine analiz eder.

Desteklenen LLM'ler:
  • Cloud:  Anthropic Claude 3.5 Sonnet (varsayılan)
  • Local:  Ollama (Llama 3.3 70B, Mistral, vb.)
  • Hybrid: Groq (hızlı) + Claude (kritik analiz)
  • OpenAI: GPT-4o (fallback)

Modüller:
  1. Saldırı Zinciri Analizi (Attack Chain)
  2. Business Impact Değerlendirmesi
  3. Executive Summary (Yönetici Özeti)
  4. Detaylı Remediation Plan
  5. Risk Skoru Hesaplama
  6. KVKK / GDPR Veri Sızıntısı Değerlendirmesi
  7. Müşteri Sunumu İçin Profesyonel Rapor
"""

import os
import json
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict

import structlog

logger = structlog.get_logger()

# ------------------------------------------------------------------ #
# LLM Provider Management
# ------------------------------------------------------------------ #

class LLMProvider:
    """Birden fazla LLM backend'ini yöneten sınıf."""
    
    def __init__(self):
        self.mode = os.getenv("LLM_MODE", "cloud").lower()
        self._provider = None
        self._provider_name = "none"
    
    async def invoke(self, system_prompt: str, user_message: str, temperature: float = 0.1) -> str:
        """LLM'e mesaj gönderir — provider'a göre otomatik yönlendirir."""
        
        # 1. Anthropic Claude (cloud default)
        if self.mode in ("cloud", "hybrid"):
            result = await self._try_anthropic(system_prompt, user_message, temperature)
            if result:
                return result
        
        # 2. Ollama (onprem)
        if self.mode in ("onprem", "hybrid"):
            result = await self._try_ollama(system_prompt, user_message, temperature)
            if result:
                return result
        
        # 3. OpenAI fallback
        result = await self._try_openai(system_prompt, user_message, temperature)
        if result:
            return result
        
        # 4. Groq fallback
        result = await self._try_groq(system_prompt, user_message, temperature)
        if result:
            return result
        
        # 5. Hiç LLM yoksa — rule-based fallback
        logger.warning("no_llm_available", mode=self.mode)
        return ""
    
    async def _try_anthropic(self, system: str, user: str, temp: float) -> Optional[str]:
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key or api_key.startswith("sk-ant-..."):
            return None
        try:
            import httpx
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-3-5-sonnet-20241022",
                        "max_tokens": 4096,
                        "temperature": temp,
                        "system": system,
                        "messages": [{"role": "user", "content": user}],
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self._provider_name = "anthropic"
                    return data["content"][0]["text"]
                else:
                    logger.warning("anthropic_error", status=resp.status_code, body=resp.text[:200])
                    return None
        except ImportError:
            # httpx yoksa aiohttp ile dene
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": api_key,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json={
                            "model": "claude-3-5-sonnet-20241022",
                            "max_tokens": 4096,
                            "temperature": temp,
                            "system": system,
                            "messages": [{"role": "user", "content": user}],
                        },
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            self._provider_name = "anthropic"
                            return data["content"][0]["text"]
                        return None
            except Exception as e:
                logger.warning("anthropic_aiohttp_error", error=str(e))
                return None
        except Exception as e:
            logger.warning("anthropic_error", error=str(e))
            return None
    
    async def _try_ollama(self, system: str, user: str, temp: float) -> Optional[str]:
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "llama3.3:70b")
        try:
            import aiohttp
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=300)) as session:
                async with session.post(
                    f"{ollama_url}/api/chat",
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "stream": False,
                        "options": {"temperature": temp},
                    },
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._provider_name = f"ollama/{model}"
                        return data.get("message", {}).get("content", "")
                    return None
        except Exception as e:
            logger.debug("ollama_not_available", error=str(e))
            return None
    
    async def _try_openai(self, system: str, user: str, temp: float) -> Optional[str]:
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key or api_key.startswith("sk-..."):
            return None
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "gpt-4o",
                        "temperature": temp,
                        "max_tokens": 4096,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                    },
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._provider_name = "openai/gpt-4o"
                        return data["choices"][0]["message"]["content"]
                    return None
        except Exception as e:
            logger.warning("openai_error", error=str(e))
            return None
    
    async def _try_groq(self, system: str, user: str, temp: float) -> Optional[str]:
        api_key = os.getenv("GROQ_API_KEY", "")
        if not api_key or api_key.startswith("gsk_..."):
            return None
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "llama-3.3-70b-versatile",
                        "temperature": temp,
                        "max_tokens": 4096,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                    },
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._provider_name = "groq/llama-3.3-70b"
                        return data["choices"][0]["message"]["content"]
                    return None
        except Exception as e:
            logger.warning("groq_error", error=str(e))
            return None
    
    @property
    def provider_name(self) -> str:
        return self._provider_name


# ------------------------------------------------------------------ #
# AI Analysis Prompts
# ------------------------------------------------------------------ #

ATTACK_CHAIN_PROMPT = """Sen uzman bir siber güvenlik analisti ve penetrasyon testcisisin.

Aşağıdaki tarama bulgularını analiz ederek olası SALDIRI ZİNCİRLERİNİ tespit et.

Her saldırı zinciri için:
1. Zincir adı ve kısa açıklaması
2. Adım adım saldırı senaryosu (gerçekçi, uygulanabilir)
3. Etkilenen varlıklar
4. Başarı olasılığı (LOW/MEDIUM/HIGH)
5. Potansiyel hasar

Bulgular arasındaki İLİŞKİLERİ bul:
- Bir açık .env dosyası + açık veritabanı portu = veritabanına tam erişim zinciri
- Eksik güvenlik header'ları + açık admin paneli = session hijacking zinciri
- SSL sorunu + açık portlar = MITM zinciri
- Subdomain keşfi + açık endpoint'ler = lateral movement

ÇIKTI JSON FORMATINDA OLSUN:
{
  "attack_chains": [
    {
      "name": "...",
      "severity": "CRITICAL|HIGH|MEDIUM",
      "steps": ["Adım 1: ...", "Adım 2: ...", ...],
      "affected_assets": ["..."],
      "success_probability": "HIGH",
      "potential_damage": "...",
      "prerequisites": "...",
      "mitigations": ["..."]
    }
  ],
  "cross_correlations": [
    {"finding_a": "...", "finding_b": "...", "combined_risk": "...", "explanation": "..."}
  ]
}"""

EXECUTIVE_SUMMARY_PROMPT = """Sen profesyonel bir siber güvenlik danışmanısın. Müşteriye sunum yapacak düzeyde yönetici özeti hazırla.

KURALLAR:
- Teknik jargonu minimumda tut, iş etkisine odaklan
- Her bulgu için İŞ ETKİSİ belirt (maddi kayıp, itibar, yasal yaptırım)
- Acil aksiyon önerilerini öncelik sırasına göre listele
- Profesyonel ve kurumsal dilde yaz
- Türkçe yazOluştur:
1. **Yönetici Özeti** (2-3 paragraf — genel durum)
2. **Risk Matrisi** (her kategori için risk seviyesi)
3. **Kritik Bulgular** (en acil 5 bulgu açıklaması)
4. **Saldırı Yüzeyi Değerlendirmesi** (toplam risk skoru 1-100)
5. **Acil Aksiyon Planı** (öncelik sıralı adımlar)
6. **30-60-90 Günlük Yol Haritası**
7. **Sonuç ve Değerlendirme**

ÇIKTI: Düz Markdown formatında profesyonel rapor."""

REMEDIATION_PROMPT = """Sen kıdemli bir DevSecOps mühendisisin. Her bulgu için DETAYLI ve UYGULANABİLİR remediation planı hazırla.

Her bulgu için:
1. **Acil Müdahale** (0-24 saat) — hemen yapılması gereken
2. **Kısa Vadeli** (1-7 gün) — konfigürasyon değişiklikleri
3. **Orta Vadeli** (1-4 hafta) — mimari iyileştirmeler
4. **Uzun Vadeli** (1-3 ay) — kapsamlı güvenlik programı

Her remediation için:
- Tam komut/konfigürasyon örneği (nginx, apache, AWS, Docker vb.)
- Doğrulama adımı (nasıl test edilir)
- Olası yan etkiler

ÇIKTI JSON:
{
  "remediations": [
    {
      "finding": "...",
      "severity": "...",
      "immediate": {"action": "...", "command": "...", "verify": "..."},
      "short_term": {"action": "...", "config": "..."},
      "medium_term": {"action": "..."},
      "long_term": {"action": "..."},
      "effort_hours": 0,
      "priority": 1
    }
  ],
  "total_effort_hours": 0,
  "recommended_order": ["..."]
}"""

KVKK_GDPR_PROMPT = """Sen KVKK ve GDPR uzmanı bir veri koruma danışmanısın.

Tarama bulgularını KİŞİSEL VERİ SIZINTISI açısından değerlendir:
1. Tespit edilen her bulgu kişisel veri içerebilir mi?
2. KVKK Madde 12 kapsamında veri ihlali bildirimi gerekli mi?
3. GDPR Article 33 kapsamında 72 saat kuralı tetikleniyor mu?
4. Etkilenen veri öznesi sayısı tahmini
5. Veri sınıflandırması (kişisel/özel nitelikli/anonim)

ÇIKTI JSON:
{
  "kvkk_assessment": {
    "breach_notification_required": true/false,
    "notification_deadline": "...",
    "affected_data_subjects_estimate": "...",
    "data_categories": ["kişisel", "özel nitelikli", ...],
    "legal_obligations": ["..."],
    "recommended_actions": ["..."]
  },
  "gdpr_assessment": {
    "article_33_triggered": true/false,
    "dpia_required": true/false,
    "supervisory_authority_notification": true/false
  },
  "risk_to_individuals": "LOW|MEDIUM|HIGH|CRITICAL"
}"""

RISK_SCORE_PROMPT = """Sen risk analisti ve aktueryasın. Güvenlik bulgularını analiz ederek SAYISAL RİSK SKORU hesapla.

CVSS v3.1 benzeri metrikleri kullan:
- Attack Vector (Network/Adjacent/Local/Physical)
- Attack Complexity (Low/High)
- Privileges Required (None/Low/High)
- User Interaction (None/Required)
- Scope (Changed/Unchanged)
- Impact: Confidentiality/Integrity/Availability (High/Low/None)

TOPLAM SKOR HESAPLA:
1. Her bulguya ayrı CVSS skoru ver
2. Sistem geneli risk skoru (1-100) hesapla
3. Risk kategorisini belirle (A-E)

ÇIKTI JSON:
{
  "overall_risk_score": 0-100,
  "risk_category": "A(Critical)|B(High)|C(Medium)|D(Low)|E(Minimal)",
  "risk_trend": "INCREASING|STABLE|DECREASING",
  "findings_scored": [
    {"finding": "...", "cvss_score": 0.0, "cvss_vector": "...", "business_impact": "..."}
  ],
  "risk_breakdown": {
    "confidentiality": 0-10,
    "integrity": 0-10,
    "availability": 0-10,
    "authentication": 0-10,
    "encryption": 0-10
  }
}"""


# ------------------------------------------------------------------ #
# AI Analysis Data Classes
# ------------------------------------------------------------------ #

@dataclass
class AIAnalysisResult:
    """Tüm AI analizlerinin birleşik sonucu."""
    analysis_id: str
    target: str
    provider_used: str
    timestamp: str
    
    # Ana analizler
    executive_summary: str = ""
    attack_chains: Dict = field(default_factory=dict)
    risk_assessment: Dict = field(default_factory=dict)
    remediation_plan: Dict = field(default_factory=dict)
    kvkk_gdpr: Dict = field(default_factory=dict)
    
    # Metadata
    total_findings_analyzed: int = 0
    analysis_duration_seconds: float = 0
    llm_calls_made: int = 0
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


# ------------------------------------------------------------------ #
# Rule-Based Fallback Analysis (LLM olmadan çalışır)
# ------------------------------------------------------------------ #

def rule_based_analysis(findings: List[Dict], active_findings: List[Dict], target: str) -> AIAnalysisResult:
    """LLM yoksa kural tabanlı analiz yapar — her zaman sonuç üretir."""
    
    result = AIAnalysisResult(
        analysis_id=f"AI-{target}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        target=target,
        provider_used="rule_engine",
        timestamp=datetime.now(timezone.utc).isoformat(),
        total_findings_analyzed=len(findings) + len(active_findings),
    )
    
    # Severity sayıları
    all_findings = findings + active_findings
    critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    high = [f for f in all_findings if f.get("severity") == "HIGH"]
    medium = [f for f in all_findings if f.get("severity") == "MEDIUM"]
    low = [f for f in all_findings if f.get("severity") == "LOW"]
    info = [f for f in all_findings if f.get("severity") == "INFO"]
    
    # Risk skoru hesaplama
    risk_score = min(100, len(critical) * 25 + len(high) * 15 + len(medium) * 8 + len(low) * 3 + len(info) * 1)
    
    if risk_score >= 80:
        risk_cat = "A (Kritik)"
    elif risk_score >= 60:
        risk_cat = "B (Yüksek)"
    elif risk_score >= 40:
        risk_cat = "C (Orta)"
    elif risk_score >= 20:
        risk_cat = "D (Düşük)"
    else:
        risk_cat = "E (Minimal)"
    
    # Attack chains (rule-based)
    chains = []
    
    # Env file + DB port chain
    env_findings = [f for f in all_findings if "env" in f.get("finding_type", "").lower() or ".env" in f.get("title", "").lower()]
    db_findings = [f for f in all_findings if any(db in f.get("title", "").lower() for db in ["mysql", "postgres", "mongo", "redis", "database"])]
    if env_findings and db_findings:
        chains.append({
            "name": "Veritabanı Erişim Zinciri",
            "severity": "CRITICAL",
            "steps": [
                "1. .env dosyasına erişerek veritabanı credential'larını oku",
                "2. Açık veritabanı portuna bağlan",
                "3. Tüm verileri dump et / manipüle et",
            ],
            "success_probability": "HIGH",
            "potential_damage": "Tam veritabanı erişimi, veri sızıntısı, veri manipülasyonu",
        })
    
    # Git exposure chain
    git_findings = [f for f in all_findings if ".git" in f.get("title", "").lower()]
    if git_findings:
        chains.append({
            "name": "Kaynak Kod Sızıntısı Zinciri",
            "severity": "CRITICAL",
            "steps": [
                "1. .git dizinine erişerek tüm commit geçmişini indir",
                "2. Geçmiş commit'lerde hardcoded credential ara",
                "3. Uygulama mantığını analiz ederek güvenlik açıklarını tespit et",
                "4. Bulunan credential'lar ile sisteme erişim sağla",
            ],
            "success_probability": "HIGH",
            "potential_damage": "Kaynak kod ifşası, tüm geçmiş credential'ların ele geçirilmesi",
        })
    
    # SSL + Header chain
    ssl_findings = [f for f in all_findings if "ssl" in f.get("finding_type", "").lower() or "ssl" in f.get("title", "").lower()]
    header_findings = [f for f in all_findings if "header" in f.get("finding_type", "").lower()]
    if ssl_findings and header_findings:
        chains.append({
            "name": "MITM / Session Hijacking Zinciri",
            "severity": "HIGH",
            "steps": [
                "1. SSL/TLS zafiyetini exploit ederek MITM pozisyonu al",
                "2. Eksik güvenlik header'ları nedeniyle session cookie'leri çal",
                "3. Çalınan session ile kullanıcı hesabına erişim sağla",
            ],
            "success_probability": "MEDIUM",
            "potential_damage": "Kullanıcı hesap ele geçirme, veri hırsızlığı",
        })
    
    # Subdomain + Exposed files chain
    sub_findings = [f for f in all_findings if "subdomain" in f.get("finding_type", "").lower()]
    exposed_findings = [f for f in all_findings if "exposed" in f.get("finding_type", "").lower()]
    if sub_findings and exposed_findings:
        chains.append({
            "name": "Subdomain Lateral Movement Zinciri",
            "severity": "HIGH",
            "steps": [
                "1. Keşfedilen subdomain'lerde hassas dosya tara",
                "2. Güvenliği düşük subdomain üzerinden credential topla",
                "3. Ana domain'e lateral movement ile erişim sağla",
            ],
            "success_probability": "MEDIUM",
            "potential_damage": "Yan sistemler üzerinden ana sisteme erişim",
        })
    
    # Open port chain
    port_findings = [f for f in all_findings if "port" in f.get("finding_type", "").lower()]
    critical_ports = [f for f in port_findings if f.get("severity") in ("CRITICAL", "HIGH")]
    if critical_ports:
        chains.append({
            "name": "Açık Servis Exploitation Zinciri",
            "severity": "HIGH",
            "steps": [
                "1. Açık kritik portlara bağlan (DB, cache, admin)",
                "2. Default credential veya exploit dene",
                "3. Servis üzerinden veri erişimi / kod çalıştırma",
            ],
            "success_probability": "MEDIUM",
            "potential_damage": "Yetkisiz servis erişimi, veri sızıntısı",
        })
    
    result.attack_chains = {"attack_chains": chains, "total_chains": len(chains)}
    
    # Risk assessment
    result.risk_assessment = {
        "overall_risk_score": risk_score,
        "risk_category": risk_cat,
        "risk_breakdown": {
            "critical_findings": len(critical),
            "high_findings": len(high),
            "medium_findings": len(medium),
            "low_findings": len(low),
            "info_findings": len(info),
        },
    }
    
    # Remediation plan (rule-based)
    remediations = []
    priority = 1
    
    for f in critical + high:
        title = f.get("title", f.get("credential_type", "Bilinmeyen"))
        remediation = f.get("remediation", "")
        remediations.append({
            "finding": title,
            "severity": f.get("severity", "HIGH"),
            "priority": priority,
            "immediate": remediation or "Hemen erişimi engelleyin",
            "short_term": "Güvenlik yapılandırmasını güncelleyin",
            "medium_term": "Güvenlik politikalarını gözden geçirin",
        })
        priority += 1
    
    result.remediation_plan = {
        "remediations": remediations[:15],
        "total_items": len(remediations),
    }
    
    # Executive summary (rule-based)
    summary_parts = [
        f"# {target} — Güvenlik Tarama Raporu\n",
        f"**Tarih:** {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}",
        f"**Risk Skoru:** {risk_score}/100 ({risk_cat})\n",
        f"## Yönetici Özeti\n",
        f"{target} domain'i üzerinde yapılan kapsamlı güvenlik taramasında "
        f"toplam **{len(all_findings)} bulgu** tespit edilmiştir. "
        f"Bunların **{len(critical)} tanesi kritik**, **{len(high)} tanesi yüksek**, "
        f"**{len(medium)} tanesi orta** seviyedir.\n",
    ]
    
    if chains:
        summary_parts.append(f"\n## Tespit Edilen Saldırı Zincirleri ({len(chains)} adet)\n")
        for i, chain in enumerate(chains, 1):
            summary_parts.append(f"\n### {i}. {chain['name']} (Severity: {chain['severity']})")
            summary_parts.append(f"**Başarı Olasılığı:** {chain['success_probability']}")
            summary_parts.append(f"**Potansiyel Hasar:** {chain['potential_damage']}")
            for step in chain['steps']:
                summary_parts.append(f"  - {step}")
    
    if remediations:
        summary_parts.append(f"\n## Acil Aksiyon Planı\n")
        for r in remediations[:10]:
            summary_parts.append(f"**{r['priority']}.** [{r['severity']}] {r['finding']}")
            summary_parts.append(f"   → {r['immediate']}")
    
    summary_parts.append(f"\n## 30-60-90 Gün Yol Haritası\n")
    summary_parts.append("**0-30 Gün:** Kritik ve yüksek seviye bulguları düzeltin. Credential rotation yapın.")
    summary_parts.append("**30-60 Gün:** Orta seviye konuları çözün. Güvenlik header'larını yapılandırın.")
    summary_parts.append("**60-90 Gün:** Sürekli izleme sistemi kurun. Düzenli tarama döngüsü başlatın.")
    
    result.executive_summary = "\n".join(summary_parts)
    
    # KVKK/GDPR (rule-based)
    data_leak_risk = len(critical) > 0 or any(
        kw in str(all_findings).lower() 
        for kw in ["database", "credential", "password", "email", "user"]
    )
    
    result.kvkk_gdpr = {
        "kvkk_assessment": {
            "breach_notification_required": len(critical) > 2,
            "data_categories": ["kişisel veri" if data_leak_risk else "teknik veri"],
            "recommended_actions": [
                "Veri sızıntısı kapsamını belirleyin",
                "Etkilenen veri öznelerini tespit edin",
                "72 saat içinde KVKK kurumuna bildirim değerlendirmesi yapın",
            ] if data_leak_risk else ["Rutin güvenlik iyileştirmesi"],
        },
        "risk_to_individuals": "HIGH" if len(critical) > 2 else "MEDIUM" if len(critical) > 0 else "LOW",
    }
    
    return result


# ------------------------------------------------------------------ #
# AI-Powered Analysis Engine
# ------------------------------------------------------------------ #

class AIAnalysisEngine:
    """
    Yapay zekâ destekli güvenlik analiz motoru.
    
    LLM varsa derin analiz yapar, yoksa rule-based fallback kullanır.
    Her iki durumda da sonuç üretir.
    """
    
    def __init__(self):
        self.llm = LLMProvider()
        self.llm_calls = 0
    
    async def analyze(
        self,
        target: str,
        credentials: List[Dict],
        active_findings: List[Dict],
        osint_data: Dict = None,
    ) -> AIAnalysisResult:
        """Tam AI analizi çalıştırır."""
        
        start_time = datetime.now(timezone.utc)
        
        # Önce rule-based baseline oluştur
        result = rule_based_analysis(credentials, active_findings, target)
        
        # Findings özeti hazırla (LLM'e gönderilecek)
        findings_summary = self._prepare_findings_summary(target, credentials, active_findings, osint_data)
        
        if not findings_summary.strip():
            logger.info("no_findings_to_analyze", target=target)
            return result
        
        # LLM ile derin analiz dene
        llm_analyses = await asyncio.gather(
            self._analyze_attack_chains(findings_summary),
            self._generate_executive_summary(findings_summary),
            self._generate_remediation_plan(findings_summary),
            self._assess_risk(findings_summary),
            self._assess_kvkk_gdpr(findings_summary),
            return_exceptions=True,
        )
        
        # Sonuçları birleştir
        analysis_names = ["attack_chains", "executive_summary", "remediation_plan", "risk_assessment", "kvkk_gdpr"]
        
        for name, llm_result in zip(analysis_names, llm_analyses):
            if isinstance(llm_result, Exception):
                result.errors.append(f"{name}: {str(llm_result)}")
                continue
            
            if not llm_result:
                continue  # Rule-based fallback zaten var
            
            if name == "executive_summary":
                result.executive_summary = llm_result
            elif name == "attack_chains":
                parsed = self._safe_parse_json(llm_result)
                if parsed:
                    result.attack_chains = parsed
            elif name == "remediation_plan":
                parsed = self._safe_parse_json(llm_result)
                if parsed:
                    result.remediation_plan = parsed
            elif name == "risk_assessment":
                parsed = self._safe_parse_json(llm_result)
                if parsed:
                    result.risk_assessment = parsed
            elif name == "kvkk_gdpr":
                parsed = self._safe_parse_json(llm_result)
                if parsed:
                    result.kvkk_gdpr = parsed
        
        # Metadata güncelle
        result.provider_used = self.llm.provider_name
        result.llm_calls_made = self.llm_calls
        result.analysis_duration_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        logger.info(
            "ai_analysis_complete",
            target=target,
            provider=result.provider_used,
            llm_calls=result.llm_calls_made,
            duration=result.analysis_duration_seconds,
        )
        
        return result
    
    def _prepare_findings_summary(
        self, target: str, credentials: List[Dict], 
        active_findings: List[Dict], osint_data: Dict = None
    ) -> str:
        """LLM'e gönderilecek findings özetini hazırlar."""
        parts = [f"HEDEF: {target}\n"]
        
        if active_findings:
            parts.append(f"\n== AKTİF WEB TARAMA BULGULARI ({len(active_findings)} adet) ==")
            for f in active_findings:
                parts.append(
                    f"[{f.get('severity', '?')}] {f.get('title', 'N/A')}"
                    f"\n  Tip: {f.get('finding_type', 'N/A')}"
                    f"\n  URL: {f.get('url', 'N/A')}"
                    f"\n  Açıklama: {f.get('description', 'N/A')[:200]}"
                    f"\n  Kanıt: {f.get('evidence', 'N/A')[:150]}"
                )
        
        if credentials:
            parts.append(f"\n== CREDENTIAL SIZINTILARI ({len(credentials)} adet) ==")
            for c in credentials:
                parts.append(
                    f"[{c.get('severity', '?')}] {c.get('credential_type', 'N/A')}"
                    f"\n  Kaynak: {c.get('source', 'N/A')}"
                    f"\n  URL: {c.get('source_url', 'N/A')}"
                    f"\n  Confidence: {c.get('confidence', 'N/A')}"
                )
        
        if osint_data:
            parts.append(f"\n== OSINT VERİLERİ ==")
            for key, values in osint_data.items():
                if values:
                    parts.append(f"  {key}: {json.dumps(values, default=str)[:300]}")
        
        return "\n".join(parts)
    
    async def _analyze_attack_chains(self, findings_summary: str) -> Optional[str]:
        """Saldırı zincirlerini analiz eder."""
        result = await self.llm.invoke(
            ATTACK_CHAIN_PROMPT,
            f"Aşağıdaki bulguları analiz et:\n\n{findings_summary}",
        )
        self.llm_calls += 1
        return result if result else None
    
    async def _generate_executive_summary(self, findings_summary: str) -> Optional[str]:
        """Yönetici özeti oluşturur."""
        result = await self.llm.invoke(
            EXECUTIVE_SUMMARY_PROMPT,
            f"Aşağıdaki güvenlik tarama bulgularından yönetici özeti hazırla:\n\n{findings_summary}",
        )
        self.llm_calls += 1
        return result if result else None
    
    async def _generate_remediation_plan(self, findings_summary: str) -> Optional[str]:
        """Detaylı remediation planı oluşturur."""
        result = await self.llm.invoke(
            REMEDIATION_PROMPT,
            f"Aşağıdaki bulgular için detaylı remediation planı hazırla:\n\n{findings_summary}",
        )
        self.llm_calls += 1
        return result if result else None
    
    async def _assess_risk(self, findings_summary: str) -> Optional[str]:
        """Risk değerlendirmesi yapar."""
        result = await self.llm.invoke(
            RISK_SCORE_PROMPT,
            f"Aşağıdaki bulgular için risk analizi yap:\n\n{findings_summary}",
        )
        self.llm_calls += 1
        return result if result else None
    
    async def _assess_kvkk_gdpr(self, findings_summary: str) -> Optional[str]:
        """KVKK/GDPR değerlendirmesi yapar."""
        result = await self.llm.invoke(
            KVKK_GDPR_PROMPT,
            f"Aşağıdaki bulguları KVKK ve GDPR açısından değerlendir:\n\n{findings_summary}",
        )
        self.llm_calls += 1
        return result if result else None
    
    def _safe_parse_json(self, text: str) -> Optional[Dict]:
        """LLM çıktısından JSON parse etmeye çalışır."""
        if not text:
            return None
        
        # Direkt JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # ```json ... ``` bloğu
        import re
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # İlk { ... } bloğunu bul
        brace_start = text.find('{')
        if brace_start >= 0:
            depth = 0
            for i in range(brace_start, len(text)):
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[brace_start:i+1])
                        except json.JSONDecodeError:
                            break
        
        return None
