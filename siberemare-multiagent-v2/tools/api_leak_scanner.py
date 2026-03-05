"""
SiberEmare API Leak Scanner — Deşifre Olmuş API Keyleri İnternet Ortamından Tarar
================================================================================
Desteklenen Kaynaklar:
  • GitHub Code Search API
  • Shodan Search API
  • Google Custom Search (Dorking)
  • Paste Siteleri (Pastebin, Ghostbin, Rentry)
  • URLScan.io
  • IntelX (Intelligence X)
  • Have I Been Pwned Paste API

30+ API key regex pattern ile tespit:
  AWS, GCP, Azure, Stripe, Slack, GitHub, GitLab, Twilio, SendGrid,
  Mailgun, OpenAI, Anthropic, Firebase, JWT, SSH Private Key, vb.
"""

import re
import json
import asyncio
import hashlib
import os
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from urllib.parse import quote_plus

import structlog

logger = structlog.get_logger()

# ------------------------------------------------------------------ #
# API Key Regex Patterns — 30+ servis
# ------------------------------------------------------------------ #

API_KEY_PATTERNS: Dict[str, re.Pattern] = {
    # === Cloud Providers ===
    "AWS Access Key ID": re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    "AWS Secret Access Key": re.compile(
        r"""(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""
    ),
    "AWS MWS Key": re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "GCP API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "GCP Service Account": re.compile(r'"type"\s*:\s*"service_account"'),
    "Azure Storage Key": re.compile(
        r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};EndpointSuffix="
    ),
    "Azure SAS Token": re.compile(r"[?&]sig=[A-Za-z0-9%+/=]{40,}"),

    # === Payment ===
    "Stripe Secret Key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Publishable Key": re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Restricted Key": re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),
    "PayPal Braintree Token": re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    "Square Access Token": re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"),
    "Square OAuth Secret": re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}"),

    # === Communication ===
    "Slack Bot Token": re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
    "Slack User Token": re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"),
    "Twilio API Key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "Twilio Account SID": re.compile(r"AC[0-9a-fA-F]{32}"),
    "Discord Bot Token": re.compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}"),
    "Telegram Bot Token": re.compile(r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}"),

    # === Email ===
    "SendGrid API Key": re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
    "Mailgun API Key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "Mailchimp API Key": re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),

    # === AI/ML ===
    "OpenAI API Key": re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),
    "OpenAI Project Key": re.compile(r"sk-proj-[A-Za-z0-9_-]{40,}"),
    "Anthropic API Key": re.compile(r"sk-ant-[A-Za-z0-9_-]{40,}"),
    "HuggingFace Token": re.compile(r"hf_[A-Za-z0-9]{34}"),

    # === Version Control ===
    "GitHub Token (Classic)": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "GitHub Token (Fine-grained)": re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    "GitHub OAuth": re.compile(r"gho_[A-Za-z0-9]{36}"),
    "GitLab Token": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
    "Bitbucket App Password": re.compile(r"ATBB[A-Za-z0-9]{32}"),

    # === Database ===
    "MongoDB Connection String": re.compile(
        r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+(?:/[^\s]*)?"
    ),
    "PostgreSQL Connection String": re.compile(
        r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+(?:/[^\s]*)?"
    ),
    "MySQL Connection String": re.compile(
        r"mysql://[^:]+:[^@]+@[^/]+(?:/[^\s]*)?"
    ),
    "Redis Connection String": re.compile(
        r"redis://[^:]*:[^@]+@[^/]+(?:/[^\s]*)?"
    ),

    # === Firebase ===
    "Firebase API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Firebase Database URL": re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),

    # === Crypto & Auth ===
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "SSH Private Key": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
    "PGP Private Key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    "Generic Secret": re.compile(
        r"""(?:password|passwd|pwd|secret|token|api_key|apikey|auth)\s*[=:]\s*['"]([A-Za-z0-9/+=!@#$%^&*]{8,})['"]"""
    ),

    # === CDN / Infra ===
    "Cloudflare API Key": re.compile(r"[0-9a-f]{37}"),  # Daha spesifik contextlerle kullan
    "Heroku API Key": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    "Mapbox Token": re.compile(r"pk\.[a-zA-Z0-9]{60,}"),
    "Algolia API Key": re.compile(r"[a-f0-9]{32}"),

    # === Social ===
    "Facebook Access Token": re.compile(r"EAA[0-9A-Za-z]{100,}"),
    "Twitter Bearer Token": re.compile(r"AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{20,}"),
    "Google OAuth Client ID": re.compile(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com"),
}

# Yüksek false positive riski olanları düşük güvenlik ile işaretle
LOW_CONFIDENCE_PATTERNS = {
    "Cloudflare API Key",
    "Heroku API Key",
    "Algolia API Key",
    "Generic Secret",
}


# ------------------------------------------------------------------ #
# Data Classes
# ------------------------------------------------------------------ #

@dataclass
class LeakedCredential:
    """Tespit edilen bir sızıntı kaydı."""
    credential_type: str
    matched_value: str  # Kısmen maskelenmiş
    raw_hash: str       # SHA256 hash (tam değerin)
    source: str         # github / shodan / google / paste / urlscan
    source_url: str
    context_snippet: str  # Etrafındaki 100 karakter
    confidence: str     # HIGH / MEDIUM / LOW
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW
    found_at: str       # ISO timestamp
    target_domain: str
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Tam tarama sonucu."""
    scan_id: str
    target: str
    started_at: str
    finished_at: str = ""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    sources_scanned: List[str] = field(default_factory=list)
    credentials: List[LeakedCredential] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            **{k: v for k, v in asdict(self).items() if k != "credentials"},
            "credentials": [c.to_dict() for c in self.credentials],
        }


# ------------------------------------------------------------------ #
# Utility Functions
# ------------------------------------------------------------------ #

def mask_credential(value: str) -> str:
    """Credential'ın ortasını maskeler — ilk 4 ve son 4 karakter gösterilir."""
    if len(value) <= 12:
        return value[:3] + "***" + value[-2:]
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def hash_credential(value: str) -> str:
    """SHA256 hash — kayıt deduplikasyonu için."""
    return hashlib.sha256(value.encode()).hexdigest()


def classify_severity(cred_type: str) -> str:
    """Credential tipine göre severity belirle."""
    critical_types = {
        "AWS Secret Access Key", "AWS Access Key ID", "GCP Service Account",
        "Azure Storage Key", "SSH Private Key", "PGP Private Key",
        "MongoDB Connection String", "PostgreSQL Connection String",
        "MySQL Connection String", "Redis Connection String",
        "Stripe Secret Key", "PayPal Braintree Token",
    }
    high_types = {
        "Slack Bot Token", "Slack User Token", "GitHub Token (Classic)",
        "GitHub Token (Fine-grained)", "GitLab Token", "OpenAI API Key",
        "OpenAI Project Key", "Anthropic API Key", "Discord Bot Token",
        "SendGrid API Key", "Twilio API Key", "JWT Token",
        "Facebook Access Token", "Twitter Bearer Token",
    }
    medium_types = {
        "GCP API Key", "Firebase API Key", "Slack Webhook",
        "Telegram Bot Token", "HuggingFace Token", "Mailgun API Key",
        "Stripe Publishable Key", "Mapbox Token", "Bitbucket App Password",
    }

    if cred_type in critical_types:
        return "CRITICAL"
    elif cred_type in high_types:
        return "HIGH"
    elif cred_type in medium_types:
        return "MEDIUM"
    return "LOW"


def extract_credentials_from_text(
    text: str,
    source: str,
    source_url: str,
    target_domain: str,
    metadata: Optional[Dict] = None,
) -> List[LeakedCredential]:
    """Verilen metin bloğundan tüm API key pattern'lerini tarar."""
    findings: List[LeakedCredential] = []
    seen_hashes = set()

    for cred_type, pattern in API_KEY_PATTERNS.items():
        for match in pattern.finditer(text):
            # Grup varsa grubu, yoksa tam eşleşmeyi al
            raw_value = match.group(1) if match.lastindex else match.group(0)
            value_hash = hash_credential(raw_value)

            if value_hash in seen_hashes:
                continue
            seen_hashes.add(value_hash)

            # Context snippet
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end].replace("\n", " ").strip()

            confidence = "LOW" if cred_type in LOW_CONFIDENCE_PATTERNS else "HIGH"

            findings.append(
                LeakedCredential(
                    credential_type=cred_type,
                    matched_value=mask_credential(raw_value),
                    raw_hash=value_hash,
                    source=source,
                    source_url=source_url,
                    context_snippet=mask_credential(context),
                    confidence=confidence,
                    severity=classify_severity(cred_type),
                    found_at=datetime.now(timezone.utc).isoformat(),
                    target_domain=target_domain,
                    metadata=metadata or {},
                )
            )
    return findings


# ------------------------------------------------------------------ #
# Source Scanners — Her biri async
# ------------------------------------------------------------------ #

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore


def _get_aiohttp_session(**kwargs):
    """aiohttp session factory with default timeout."""
    if aiohttp is None:
        raise ImportError("aiohttp gerekli. pip install aiohttp")
    timeout = aiohttp.ClientTimeout(total=30)
    return aiohttp.ClientSession(timeout=timeout, **kwargs)


async def scan_github(target: str, github_token: Optional[str] = None) -> List[LeakedCredential]:
    """GitHub Code Search API ile hedef domain / org'a ait sızıntıları tarar."""
    findings: List[LeakedCredential] = []
    token = github_token or os.getenv("GITHUB_TOKEN")
    if not token:
        logger.warning("GitHub token bulunamadı, GitHub taraması atlanıyor")
        return findings

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.text-match+json",
    }

    # Birden fazla sorgu ile tara
    queries = [
        f'"{target}" api_key',
        f'"{target}" apikey',
        f'"{target}" secret',
        f'"{target}" password',
        f'"{target}" token',
        f'"{target}" AWS_ACCESS_KEY',
        f'"{target}" PRIVATE KEY',
        f'"{target}" credentials',
        f'org:{target} password',
        f'org:{target} secret',
        f'org:{target} api_key',
    ]

    async with _get_aiohttp_session() as session:
        for query in queries:
            url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page=30"
            try:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 403:
                        logger.warning("GitHub rate limit aşıldı, bekleniyor...")
                        await asyncio.sleep(60)
                        continue
                    if resp.status != 200:
                        continue

                    data = await resp.json()
                    for item in data.get("items", []):
                        text_matches = item.get("text_matches", [])
                        repo_name = item.get("repository", {}).get("full_name", "?")
                        file_path = item.get("path", "?")
                        html_url = item.get("html_url", "")

                        for tm in text_matches:
                            fragment = tm.get("fragment", "")
                            creds = extract_credentials_from_text(
                                text=fragment,
                                source="github",
                                source_url=html_url,
                                target_domain=target,
                                metadata={
                                    "repo": repo_name,
                                    "file": file_path,
                                    "query": query,
                                },
                            )
                            findings.extend(creds)

                # Rate limit: GitHub 10 req/min for code search
                await asyncio.sleep(6)

            except Exception as e:
                logger.error("github_scan_error", query=query, error=str(e))

    logger.info("github_scan_complete", target=target, findings=len(findings))
    return findings


async def scan_shodan(target: str, shodan_key: Optional[str] = None) -> List[LeakedCredential]:
    """Shodan API ile açık API endpoint'lerini ve sızan credential'ları tarar."""
    findings: List[LeakedCredential] = []
    key = shodan_key or os.getenv("SHODAN_API_KEY")
    if not key:
        logger.warning("Shodan API key bulunamadı, Shodan taraması atlanıyor")
        return findings

    queries = [
        f'hostname:"{target}" http.title:"dashboard"',
        f'hostname:"{target}" "api" port:443,8080,8443',
        f'hostname:"{target}" http.html:"api_key"',
        f'hostname:"{target}" http.html:"token"',
        f'ssl.cert.subject.CN:"{target}"',
        f'org:"{target}" port:27017,5432,3306,6379',  # Açık DB
    ]

    async with _get_aiohttp_session() as session:
        for query in queries:
            url = f"https://api.shodan.io/shodan/host/search?key={key}&query={quote_plus(query)}&minify=true"
            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        continue

                    data = await resp.json()
                    for match in data.get("matches", []):
                        banner = match.get("data", "")
                        ip = match.get("ip_str", "?")
                        port = match.get("port", 0)
                        hostnames = match.get("hostnames", [])
                        source_url = f"https://www.shodan.io/host/{ip}"

                        creds = extract_credentials_from_text(
                            text=banner,
                            source="shodan",
                            source_url=source_url,
                            target_domain=target,
                            metadata={
                                "ip": ip,
                                "port": port,
                                "hostnames": hostnames,
                                "product": match.get("product", ""),
                            },
                        )
                        findings.extend(creds)

                        # Açık DB portu kendi başına bir bulgu
                        if port in (27017, 5432, 3306, 6379, 9200, 11211):
                            db_names = {
                                27017: "MongoDB",
                                5432: "PostgreSQL",
                                3306: "MySQL",
                                6379: "Redis",
                                9200: "Elasticsearch",
                                11211: "Memcached",
                            }
                            findings.append(
                                LeakedCredential(
                                    credential_type=f"Exposed {db_names.get(port, 'Database')}",
                                    matched_value=f"{ip}:{port}",
                                    raw_hash=hash_credential(f"{ip}:{port}"),
                                    source="shodan",
                                    source_url=source_url,
                                    context_snippet=f"Açık {db_names.get(port, 'DB')} portu tespit edildi: {ip}:{port}",
                                    confidence="HIGH",
                                    severity="CRITICAL",
                                    found_at=datetime.now(timezone.utc).isoformat(),
                                    target_domain=target,
                                    metadata={"ip": ip, "port": port},
                                )
                            )

                await asyncio.sleep(1)

            except Exception as e:
                logger.error("shodan_scan_error", query=query, error=str(e))

    logger.info("shodan_scan_complete", target=target, findings=len(findings))
    return findings


async def scan_google_dorks(target: str, google_api_key: Optional[str] = None,
                            google_cx: Optional[str] = None) -> List[LeakedCredential]:
    """Google Custom Search ile dork pattern'lerini kullanarak sızıntı arar."""
    findings: List[LeakedCredential] = []
    api_key = google_api_key or os.getenv("GOOGLE_API_KEY")
    cx = google_cx or os.getenv("GOOGLE_CX")

    if not api_key or not cx:
        logger.warning("Google API key/CX bulunamadı, Google Dork taraması atlanıyor")
        return findings

    # Güçlü Google Dork sorguları
    dorks = [
        f'site:pastebin.com "{target}"',
        f'site:trello.com "{target}" password',
        f'site:github.com "{target}" api_key',
        f'"{target}" filetype:env',
        f'"{target}" filetype:yml password',
        f'"{target}" filetype:json "api_key"',
        f'"{target}" filetype:sql password',
        f'"{target}" filetype:xml "apiKey"',
        f'"{target}" inurl:credentials',
        f'"{target}" inurl:config password',
        f'intitle:"index of" "{target}" .env',
        f'"{target}" "BEGIN RSA PRIVATE KEY"',
        f'"{target}" "AWS_ACCESS_KEY_ID"',
        f'"{target}" "sk_live_"',
        f'"{target}" "AKIA"',
    ]

    async with _get_aiohttp_session() as session:
        for dork in dorks:
            url = (
                f"https://www.googleapis.com/customsearch/v1"
                f"?key={api_key}&cx={cx}&q={quote_plus(dork)}&num=10"
            )
            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        continue

                    data = await resp.json()
                    for item in data.get("items", []):
                        title = item.get("title", "")
                        link = item.get("link", "")
                        snippet = item.get("snippet", "")
                        full_text = f"{title} {snippet}"

                        creds = extract_credentials_from_text(
                            text=full_text,
                            source="google_dork",
                            source_url=link,
                            target_domain=target,
                            metadata={"dork": dork, "title": title},
                        )
                        findings.extend(creds)

                        # Snippet'te direkt hassas pattern olmasa bile URL'in
                        # kendisi önemli olabilir (pastebin, trello, .env vb.)
                        suspicious_urls = [
                            "pastebin.com", "trello.com", "ghostbin.",
                            "rentry.co", "justpaste.it", "hastebin.",
                        ]
                        if any(s in link.lower() for s in suspicious_urls):
                            findings.append(
                                LeakedCredential(
                                    credential_type="Suspicious Paste/Exposure URL",
                                    matched_value=link[:60],
                                    raw_hash=hash_credential(link),
                                    source="google_dork",
                                    source_url=link,
                                    context_snippet=snippet[:150],
                                    confidence="MEDIUM",
                                    severity="MEDIUM",
                                    found_at=datetime.now(timezone.utc).isoformat(),
                                    target_domain=target,
                                    metadata={"dork": dork},
                                )
                            )

                await asyncio.sleep(1)

            except Exception as e:
                logger.error("google_dork_error", dork=dork, error=str(e))

    logger.info("google_dork_scan_complete", target=target, findings=len(findings))
    return findings


async def scan_urlscan(target: str) -> List[LeakedCredential]:
    """URLScan.io ile hedef domaine ait taramaları kontrol eder."""
    findings: List[LeakedCredential] = []

    async with _get_aiohttp_session() as session:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{target}&size=50"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return findings

                data = await resp.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    task = result.get("task", {})
                    result_url = task.get("url", "")
                    scan_url = f"https://urlscan.io/result/{result.get('_id', '')}/"

                    # Toplanan verilerin string temsilinde credential ara
                    text_block = json.dumps(result, default=str)
                    creds = extract_credentials_from_text(
                        text=text_block,
                        source="urlscan",
                        source_url=scan_url,
                        target_domain=target,
                        metadata={
                            "scanned_url": result_url,
                            "status": page.get("status", ""),
                        },
                    )
                    findings.extend(creds)

        except Exception as e:
            logger.error("urlscan_error", target=target, error=str(e))

    logger.info("urlscan_scan_complete", target=target, findings=len(findings))
    return findings


async def scan_paste_sites(target: str) -> List[LeakedCredential]:
    """Pastebin ve diğer paste sitelerini tarar (scraping, public API)."""
    findings: List[LeakedCredential] = []

    # Pastebin Google scrape approach
    async with _get_aiohttp_session() as session:
        paste_searches = [
            f"https://psbdmp.ws/api/v3/search/{quote_plus(target)}",
        ]

        for url in paste_searches:
            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        continue

                    data = await resp.json()
                    items = data if isinstance(data, list) else data.get("data", [])

                    for item in items[:20]:
                        paste_id = item.get("id", "")
                        content = item.get("content", item.get("text", ""))

                        if not content:
                            # İçerik yoksa paste'i getirmeyi dene
                            try:
                                detail_url = f"https://psbdmp.ws/api/v3/dump/{paste_id}"
                                async with session.get(detail_url) as detail_resp:
                                    if detail_resp.status == 200:
                                        detail_data = await detail_resp.json()
                                        content = detail_data.get("content", "")
                            except Exception:
                                continue

                        if content:
                            creds = extract_credentials_from_text(
                                text=content,
                                source="paste",
                                source_url=f"https://pastebin.com/{paste_id}" if paste_id else url,
                                target_domain=target,
                                metadata={"paste_id": paste_id},
                            )
                            findings.extend(creds)

                await asyncio.sleep(2)

            except Exception as e:
                logger.error("paste_scan_error", url=url, error=str(e))

    logger.info("paste_scan_complete", target=target, findings=len(findings))
    return findings


async def scan_intelx(target: str, intelx_key: Optional[str] = None) -> List[LeakedCredential]:
    """Intelligence X API ile derinlemesine sızıntı araması."""
    findings: List[LeakedCredential] = []
    key = intelx_key or os.getenv("INTELX_API_KEY")
    if not key:
        logger.warning("IntelX API key bulunamadı, atlanıyor")
        return findings

    headers = {"x-key": key, "Content-Type": "application/json"}

    async with _get_aiohttp_session() as session:
        # 1. Arama başlat
        search_url = "https://2.intelx.io/intelligent/search"
        payload = {
            "term": target,
            "maxresults": 50,
            "media": 0,
            "sort": 2,  # Relevance
            "terminate": [],
        }
        try:
            async with session.post(search_url, json=payload, headers=headers) as resp:
                if resp.status != 200:
                    return findings
                data = await resp.json()
                search_id = data.get("id", "")

            if not search_id:
                return findings

            await asyncio.sleep(3)

            # 2. Sonuçları getir
            results_url = f"https://2.intelx.io/intelligent/search/result?id={search_id}"
            async with session.get(results_url, headers=headers) as resp:
                if resp.status != 200:
                    return findings
                data = await resp.json()

                for record in data.get("records", []):
                    name = record.get("name", "")
                    media_type = record.get("mediah", "")
                    storage_id = record.get("storageid", "")
                    source_url = f"https://intelx.io/?did={storage_id}"

                    # İçeriğe erişim için view endpoint
                    try:
                        view_url = f"https://2.intelx.io/file/view?f=0&storageid={storage_id}&bucket=&k={key}"
                        async with session.get(view_url, headers=headers) as view_resp:
                            if view_resp.status == 200:
                                content = await view_resp.text()
                                creds = extract_credentials_from_text(
                                    text=content[:10000],  # İlk 10K karakter
                                    source="intelx",
                                    source_url=source_url,
                                    target_domain=target,
                                    metadata={
                                        "name": name,
                                        "media_type": media_type,
                                    },
                                )
                                findings.extend(creds)
                    except Exception:
                        pass

        except Exception as e:
            logger.error("intelx_error", target=target, error=str(e))

    logger.info("intelx_scan_complete", target=target, findings=len(findings))
    return findings


# ------------------------------------------------------------------ #
# Main Scanner Orchestrator
# ------------------------------------------------------------------ #

class APILeakScanner:
    """
    Internet ortamından deşifre olmuş API anahtarlarını tarayan ana sınıf.

    Kullanım:
        scanner = APILeakScanner(target="example.com")
        result = await scanner.run()
        print(result.total_findings)
    """

    def __init__(
        self,
        target: str,
        github_token: Optional[str] = None,
        shodan_key: Optional[str] = None,
        google_api_key: Optional[str] = None,
        google_cx: Optional[str] = None,
        intelx_key: Optional[str] = None,
        sources: Optional[List[str]] = None,
    ):
        self.target = target.strip().lower()
        self.github_token = github_token
        self.shodan_key = shodan_key
        self.google_api_key = google_api_key
        self.google_cx = google_cx
        self.intelx_key = intelx_key
        self.sources = sources or [
            "github", "shodan", "google_dorks", "urlscan", "paste", "intelx"
        ]
        self.scan_id = f"SCAN-{self.target}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    async def run(self) -> ScanResult:
        """Tüm kaynakları paralel olarak tarar ve sonuçları birleştirir."""
        start_time = datetime.now(timezone.utc)
        result = ScanResult(
            scan_id=self.scan_id,
            target=self.target,
            started_at=start_time.isoformat(),
        )

        logger.info("api_leak_scan_start", target=self.target, sources=self.sources)

        # Tarayıcı görevlerini oluştur
        tasks = []
        source_names = []

        if "github" in self.sources:
            tasks.append(scan_github(self.target, self.github_token))
            source_names.append("github")

        if "shodan" in self.sources:
            tasks.append(scan_shodan(self.target, self.shodan_key))
            source_names.append("shodan")

        if "google_dorks" in self.sources:
            tasks.append(scan_google_dorks(self.target, self.google_api_key, self.google_cx))
            source_names.append("google_dorks")

        if "urlscan" in self.sources:
            tasks.append(scan_urlscan(self.target))
            source_names.append("urlscan")

        if "paste" in self.sources:
            tasks.append(scan_paste_sites(self.target))
            source_names.append("paste")

        if "intelx" in self.sources:
            tasks.append(scan_intelx(self.target, self.intelx_key))
            source_names.append("intelx")

        # Paralel çalıştır
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: List[LeakedCredential] = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                result.errors.append(f"{source_names[i]}: {str(res)}")
                logger.error("source_scan_failed", source=source_names[i], error=str(res))
            elif isinstance(res, list):
                all_findings.extend(res)
                result.sources_scanned.append(source_names[i])

        # Deduplikasyon (hash bazlı)
        seen_hashes = set()
        unique_findings: List[LeakedCredential] = []
        for finding in all_findings:
            if finding.raw_hash not in seen_hashes:
                seen_hashes.add(finding.raw_hash)
                unique_findings.append(finding)

        result.credentials = unique_findings
        result.total_findings = len(unique_findings)
        result.critical_count = sum(1 for c in unique_findings if c.severity == "CRITICAL")
        result.high_count = sum(1 for c in unique_findings if c.severity == "HIGH")
        result.medium_count = sum(1 for c in unique_findings if c.severity == "MEDIUM")
        result.low_count = sum(1 for c in unique_findings if c.severity == "LOW")
        result.finished_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            "api_leak_scan_complete",
            target=self.target,
            total=result.total_findings,
            critical=result.critical_count,
            high=result.high_count,
            medium=result.medium_count,
            low=result.low_count,
        )

        return result


# ------------------------------------------------------------------ #
# Lokal Dosya Tarayıcı — Proje dosyalarını tara
# ------------------------------------------------------------------ #

def scan_local_files(
    root_dir: str,
    extensions: Optional[List[str]] = None,
    exclude_dirs: Optional[List[str]] = None,
) -> List[LeakedCredential]:
    """Yerel dosya sistemini tarar — hardcoded credential tespiti."""
    if extensions is None:
        extensions = [
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
            ".php", ".cs", ".env", ".yml", ".yaml", ".json", ".xml",
            ".toml", ".ini", ".cfg", ".conf", ".sh", ".bash", ".zsh",
            ".dockerfile", ".tf", ".tfvars", ".properties", ".gradle",
        ]
    if exclude_dirs is None:
        exclude_dirs = [
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            ".tox", ".mypy_cache", "dist", "build", ".next",
        ]

    findings: List[LeakedCredential] = []
    exclude_set = set(exclude_dirs)

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Exclude directories
        dirnames[:] = [d for d in dirnames if d not in exclude_set]

        for filename in filenames:
            # Uzantı kontrolü
            if not any(filename.endswith(ext) for ext in extensions):
                continue

            filepath = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(filepath, root_dir)

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(500_000)  # Max 500KB per file

                creds = extract_credentials_from_text(
                    text=content,
                    source="local_file",
                    source_url=rel_path,
                    target_domain="local",
                    metadata={"file": rel_path, "size": os.path.getsize(filepath)},
                )
                findings.extend(creds)

            except (OSError, PermissionError) as e:
                logger.warning("local_scan_skip", file=rel_path, error=str(e))

    logger.info("local_scan_complete", root_dir=root_dir, findings=len(findings))
    return findings
