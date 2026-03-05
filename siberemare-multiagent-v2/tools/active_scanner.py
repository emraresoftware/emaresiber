"""
SiberEmare Active Web Scanner — API Key Olmadan Çalışan Aktif Tarayıcı
======================================================================
Hedef web sitesini doğrudan ziyaret ederek credential sızıntısı arar.

Tarama Modülleri:
  1. Hassas Dosya/Endpoint Probing (.env, .git, wp-config, phpinfo vb.)
  2. JavaScript Analizi (tüm JS dosyalarında hardcoded credential tarama)
  3. HTML Kaynak Kodu Analizi (form action, hidden input, comment'ler)
  4. HTTP Header Güvenlik Analizi
  5. DNS Subdomain Keşfi (brute-force + crt.sh)
  6. Robots.txt / Sitemap Analizi
  7. S3/GCS Bucket Keşfi
  8. Open Directory Listing Tespiti
  9. Wayback Machine Hassas URL Taraması
  10. GitHub Code Search (web scraping, token gerektirmez)
  11. Google Dorking (ücretsiz arama)

Tümü API key gerektirmeden çalışır.
"""

import re
import json
import asyncio
import hashlib
import os
import ssl
import socket
from datetime import datetime, timezone
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, quote_plus
from dataclasses import dataclass, field, asdict

import structlog

logger = structlog.get_logger()

try:
    import aiohttp
except ImportError:
    aiohttp = None

from tools.api_leak_scanner import (
    API_KEY_PATTERNS,
    LeakedCredential,
    extract_credentials_from_text,
    hash_credential,
    mask_credential,
    classify_severity,
    LOW_CONFIDENCE_PATTERNS,
)


# ------------------------------------------------------------------ #
# Constants
# ------------------------------------------------------------------ #

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Hassas dosya/endpoint listesi — genişletilmiş
SENSITIVE_PATHS = [
    # Environment & Config
    "/.env", "/.env.local", "/.env.production", "/.env.staging", "/.env.backup",
    "/.env.old", "/.env.dev", "/.env.example", "/.env.bak", "/.env.save",
    "/config.json", "/config.yaml", "/config.yml", "/config.php", "/config.js",
    "/configuration.php", "/settings.json", "/settings.py", "/settings.yaml",
    "/application.yml", "/application.properties", "/appsettings.json",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/wp-config.php.save", "/wp-config.php.swp", "/wp-config.php~",
    "/config/database.yml", "/config/secrets.yml", "/config/master.key",
    "/config/credentials.yml.enc",
    
    # Version Control
    "/.git/config", "/.git/HEAD", "/.git/index",
    "/.gitignore", "/.gitattributes",
    "/.svn/entries", "/.svn/wc.db",
    "/.hg/hgrc",
    
    # Server Info
    "/phpinfo.php", "/info.php", "/php_info.php", "/test.php", "/i.php",
    "/server-status", "/server-info",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
    
    # Backup / Database Dumps
    "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
    "/backup.tar.gz", "/backup.zip", "/site.tar.gz",
    "/db_backup.sql", "/mysql.sql",
    
    # API Documentation
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/api/swagger", "/api/v1/docs",
    "/graphql", "/graphiql", "/_graphql",
    "/api", "/api/v1", "/api/v2", "/api/config", "/api/settings",
    "/api/debug", "/api/health", "/api/status", "/api/info",
    
    # Admin & Debug
    "/admin", "/administrator", "/admin/login",
    "/debug", "/debug/vars", "/debug/pprof",
    "/_debug", "/_profiler", "/_status",
    "/elmah.axd", "/trace.axd",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/configprops",
    "/metrics", "/prometheus",
    
    # Common CMS paths
    "/wp-admin/", "/wp-login.php", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/readme.html",
    "/administrator/manifests/files/joomla.xml",
    
    # CI/CD & Deploy
    "/.github/workflows", "/.gitlab-ci.yml", "/.circleci/config.yml",
    "/Jenkinsfile", "/Dockerfile", "/docker-compose.yml",
    "/.travis.yml", "/bitbucket-pipelines.yml",
    
    # Package files
    "/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
    "/Pipfile", "/yarn.lock", "/package-lock.json",
    
    # Cloud  
    "/.aws/credentials", "/.aws/config",
    "/firebase.json", "/.firebaserc",
    
    # Logs
    "/error.log", "/access.log", "/debug.log", "/app.log",
    "/logs/error.log", "/logs/access.log",
    "/var/log/", "/log/",
    
    # IDE
    "/.vscode/settings.json", "/.idea/workspace.xml",
    "/.DS_Store", "/Thumbs.db",
    
    # SSL/TLS
    "/server.key", "/privatekey.pem", "/server.crt",
    "/.ssh/authorized_keys", "/.ssh/id_rsa",
]

# Subdomain brute-force listesi
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "beta", "demo", "app", "portal", "blog", "shop", "store", "cdn",
    "media", "static", "assets", "img", "images", "docs", "wiki",
    "vpn", "remote", "git", "gitlab", "jenkins", "ci", "cd",
    "monitor", "grafana", "kibana", "elastic", "prometheus",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "old", "new", "legacy", "v2", "v3",
    "internal", "intranet", "extranet", "private",
    "webmail", "email", "smtp", "imap", "pop",
    "ns1", "ns2", "dns", "mx",
    "s3", "bucket", "storage", "files",
    "auth", "login", "sso", "oauth", "id", "identity",
    "dashboard", "panel", "console", "manage",
    "status", "health", "metrics", "logs",
    "sandbox", "uat", "qa", "preprod", "pre-prod",
    "mobile", "m", "wap",
    "ws", "websocket", "socket", "realtime",
    "graphql", "rest", "rpc", "grpc",
    "pay", "payment", "billing", "checkout",
    "crm", "erp", "hr", "jira", "confluence",
]


@dataclass
class ActiveFinding:
    """Aktif taramada bulunan bir finding."""
    finding_type: str       # exposed_file, js_credential, header_issue, subdomain, etc.
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    url: str
    evidence: str           # Bulunan veri/snippet
    remediation: str
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_leaked_credential(self, target: str) -> LeakedCredential:
        """LeakedCredential formatına dönüştür (uyumluluk)."""
        return LeakedCredential(
            credential_type=self.finding_type,
            matched_value=mask_credential(self.evidence[:80]) if len(self.evidence) > 12 else self.evidence,
            raw_hash=hash_credential(self.url + self.evidence[:200]),
            source="active_scan",
            source_url=self.url,
            context_snippet=self.description[:200],
            confidence="HIGH" if self.severity in ("CRITICAL", "HIGH") else "MEDIUM",
            severity=self.severity,
            found_at=datetime.now(timezone.utc).isoformat(),
            target_domain=target,
            metadata=self.metadata,
        )


# ------------------------------------------------------------------ #
# Helper Functions
# ------------------------------------------------------------------ #

def _get_session(**kwargs) -> "aiohttp.ClientSession":
    if aiohttp is None:
        raise ImportError("aiohttp gerekli: pip install aiohttp")
    timeout = aiohttp.ClientTimeout(total=15, connect=8)
    connector = aiohttp.TCPConnector(ssl=False, limit=20, ttl_dns_cache=300)
    headers = {"User-Agent": USER_AGENT}
    return aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        headers=headers,
        **kwargs,
    )


async def _safe_get(session, url: str, **kwargs) -> Optional[Tuple[int, str, dict]]:
    """GET isteği yapar, hata durumunda None döner."""
    try:
        async with session.get(url, allow_redirects=True, **kwargs) as resp:
            text = await resp.text(encoding="utf-8", errors="replace")
            headers = dict(resp.headers)
            return resp.status, text, headers
    except Exception:
        return None


async def _safe_head(session, url: str) -> Optional[Tuple[int, dict]]:
    """HEAD isteği yapar."""
    try:
        async with session.head(url, allow_redirects=True) as resp:
            return resp.status, dict(resp.headers)
    except Exception:
        return None


# ------------------------------------------------------------------ #
# 1. Hassas Dosya/Endpoint Probing
# ------------------------------------------------------------------ #

async def probe_sensitive_files(base_url: str, session) -> List[ActiveFinding]:
    """Hassas dosya ve endpoint'leri kontrol eder."""
    findings: List[ActiveFinding] = []
    
    # Paralel olarak tüm path'leri kontrol et
    sem = asyncio.Semaphore(15)
    
    async def check_path(path: str):
        async with sem:
            url = urljoin(base_url, path)
            result = await _safe_get(session, url)
            if result is None:
                return None
            
            status, body, headers = result
            content_type = headers.get("Content-Type", "").lower()
            content_length = len(body)
            
            # 404, 403 veya çok kısa body = yok
            if status in (404, 410):
                return None
            if status == 403:
                # Forbidden ama var — sadece gerçekten kritik dosyalar için raporla
                critical_forbidden = [
                    "/.env", "/.git/config", "/.git/HEAD",
                    "/wp-config.php", "/server.key", "/privatekey.pem",
                    "/.ssh/id_rsa", "/backup.sql", "/dump.sql",
                ]
                if path not in critical_forbidden:
                    return None
                return ActiveFinding(
                    finding_type="forbidden_sensitive_path",
                    severity="MEDIUM",
                    title=f"Hassas Dosya Mevcut (403): {path}",
                    description=f"{path} yolu mevcut ama erişim engelli (403). Dosyanın varlığı bile bilgi sızıntısı.",
                    url=url,
                    evidence=f"HTTP 403 - {path}",
                    remediation="Bu yolu tamamen gizleyin (404 döndürün) veya sunucudan kaldırın.",
                )
            
            if status not in (200, 301, 302):
                return None
            
            # Boş veya çok kısa body
            if content_length < 10:
                return None
            
            # custom 404 tespiti - common 404 patterns
            not_found_patterns = [
                "not found", "404", "page not found", "sayfa bulunamadı",
                "does not exist", "no such file", "cannot be found",
            ]
            body_lower = body[:500].lower()
            if any(p in body_lower for p in not_found_patterns) and content_length < 5000:
                return None
            
            # Severity belirleme
            severity = "HIGH"
            finding_type = "exposed_sensitive_file"
            
            if path in ("/.env", "/.env.local", "/.env.production", "/.env.staging",
                        "/.env.backup", "/.env.old", "/.env.dev", "/.env.bak"):
                severity = "CRITICAL"
                finding_type = "exposed_env_file"
            elif path in ("/.git/config", "/.git/HEAD", "/.git/index"):
                severity = "CRITICAL"
                finding_type = "exposed_git_repo"
            elif path in ("/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old"):
                severity = "CRITICAL"
                finding_type = "exposed_wp_config"
            elif path in ("/backup.sql", "/dump.sql", "/database.sql", "/db.sql"):
                severity = "CRITICAL"
                finding_type = "exposed_database_dump"
            elif path in ("/server.key", "/privatekey.pem", "/.ssh/id_rsa"):
                severity = "CRITICAL"
                finding_type = "exposed_private_key"
            elif path in ("/phpinfo.php", "/info.php", "/php_info.php"):
                severity = "HIGH"
                finding_type = "exposed_phpinfo"
            elif path in ("/swagger.json", "/openapi.json", "/api-docs"):
                severity = "MEDIUM"
                finding_type = "exposed_api_docs"
            elif path in ("/robots.txt", "/sitemap.xml", "/package.json"):
                severity = "INFO"
                finding_type = "information_disclosure"
            elif "/actuator" in path:
                severity = "HIGH"
                finding_type = "exposed_actuator"
            elif "/debug" in path or "/_profiler" in path:
                severity = "HIGH"
                finding_type = "debug_endpoint"
            elif "/admin" in path:
                severity = "MEDIUM"
                finding_type = "admin_interface"
            elif "/graphql" in path or "/graphiql" in path:
                severity = "MEDIUM"
                finding_type = "exposed_graphql"
            elif path.endswith((".log", ".sql", ".bak")):
                severity = "HIGH"
                finding_type = "exposed_backup_or_log"
            
            # İçerikte credential arama
            creds_in_body = extract_credentials_from_text(
                text=body[:50000],
                source="active_probe",
                source_url=url,
                target_domain=urlparse(base_url).hostname or "",
            )
            
            if creds_in_body:
                severity = "CRITICAL"
                finding_type = "credential_in_exposed_file"
            
            # Sonuç hazırla
            evidence_text = body[:500].strip()
            if "<!DOCTYPE" in evidence_text or "<html" in evidence_text.lower():
                # HTML sayfa ise daha az anlamlı
                if finding_type == "information_disclosure":
                    return None
            
            return ActiveFinding(
                finding_type=finding_type,
                severity=severity,
                title=f"Açık Dosya/Endpoint: {path}",
                description=(
                    f"{path} erişilebilir durumda (HTTP {status}). "
                    f"Content-Type: {content_type}. Boyut: {content_length} byte."
                    + (f" İçinde {len(creds_in_body)} adet credential tespit edildi!" if creds_in_body else "")
                ),
                url=url,
                evidence=evidence_text[:300],
                remediation=_get_remediation_for_path(path),
                metadata={
                    "status_code": status,
                    "content_type": content_type,
                    "content_length": content_length,
                    "credentials_found": len(creds_in_body),
                },
            )
    
    tasks = [check_path(path) for path in SENSITIVE_PATHS]
    results = await asyncio.gather(*tasks)
    findings = [r for r in results if r is not None]
    
    logger.info("sensitive_probe_complete", base_url=base_url, findings=len(findings))
    return findings


def _get_remediation_for_path(path: str) -> str:
    """Path'e göre remediation önerisi."""
    remediations = {
        ".env": "Sunucu yapılandırmasından .env dosyasına erişimi engelleyin. nginx: 'location ~ /\\.env { deny all; }'",
        ".git": "Git deposu sunucuda açık. .git dizinine erişimi engelleyin veya sunucudan kaldırın.",
        "phpinfo": "phpinfo() sayfasını production'dan kaldırın — sunucu detayları ifşa oluyor.",
        "wp-config": "WordPress config dosyası açık — DB şifreleri ve secret key'ler ifşa olabilir.",
        "swagger": "API documentation'ı public erişime kapatın veya authentication ekleyin.",
        "actuator": "Spring Boot Actuator endpoint'lerini güvenceye alın: management.endpoints.web.exposure.exclude=*",
        "backup": "Yedek/dump dosyalarını web sunucudan kaldırın.",
        "admin": "Admin paneline IP kısıtlaması ve güçlü authentication uygulayın.",
        "graphql": "GraphQL playground'u production'da kapatın. Introspection'ı disable edin.",
        "debug": "Debug endpoint'lerini production'da kapatın.",
        "log": "Log dosyalarını web dizininden kaldırın.",
        "ssh": "SSH key dosyalarını web dizininden kaldırın — acil güvenlik riski!",
    }
    for key, rem in remediations.items():
        if key in path.lower():
            return rem
    return "Bu dosya/endpoint'in public erişime kapalı olması gerekir."


# ------------------------------------------------------------------ #
# 2. JavaScript Analizi
# ------------------------------------------------------------------ #

async def analyze_javascript(base_url: str, session) -> List[ActiveFinding]:
    """Web sitesinin JavaScript dosyalarını indirip credential arar."""
    findings: List[ActiveFinding] = []
    js_urls: Set[str] = set()
    
    # 1. Ana sayfayı çek ve JS URL'lerini bul
    result = await _safe_get(session, base_url)
    if result is None:
        return findings
    
    status, html, headers = result
    
    # script src'lerini bul
    # <script src="...">
    for match in re.finditer(r'<script[^>]*\bsrc=["\']([^"\']+)["\']', html, re.I):
        src = match.group(1)
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = urljoin(base_url, src)
        elif not src.startswith("http"):
            src = urljoin(base_url, src)
        js_urls.add(src)
    
    # Inline JS analizi
    for match in re.finditer(r'<script(?:\s[^>]*)?>(.+?)</script>', html, re.I | re.DOTALL):
        script_content = match.group(1).strip()
        if len(script_content) > 20:
            creds = _analyze_js_content(script_content, base_url, "inline_script")
            findings.extend(creds)
    
    # Yaygın JS bundle path'leri
    common_js = [
        "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
        "/assets/js/app.js", "/js/app.js", "/js/main.js",
        "/dist/main.js", "/dist/bundle.js", "/build/bundle.js",
        "/static/js/main.chunk.js", "/static/js/vendor.chunk.js",
        "/_next/static/chunks/main.js", "/_next/static/chunks/app.js",
    ]
    for path in common_js:
        js_urls.add(urljoin(base_url, path))
    
    # 2. Her JS dosyasını indir ve analiz et
    sem = asyncio.Semaphore(10)
    
    async def analyze_js_url(js_url: str):
        async with sem:
            result = await _safe_get(session, js_url)
            if result is None:
                return []
            status, body, _ = result
            if status != 200 or len(body) < 50:
                return []
            return _analyze_js_content(body, js_url, "external_js")
    
    tasks = [analyze_js_url(url) for url in js_urls]
    results = await asyncio.gather(*tasks)
    
    for result_list in results:
        findings.extend(result_list)
    
    logger.info("js_analysis_complete", base_url=base_url, js_files=len(js_urls), findings=len(findings))
    return findings


def _analyze_js_content(content: str, source_url: str, source_type: str) -> List[ActiveFinding]:
    """JavaScript içeriğinde hardcoded credential ve hassas bilgi arar."""
    findings: List[ActiveFinding] = []
    
    # 1. API_KEY_PATTERNS ile tara
    target = urlparse(source_url).hostname or "unknown"
    creds = extract_credentials_from_text(
        text=content,
        source="js_analysis",
        source_url=source_url,
        target_domain=target,
    )
    
    for cred in creds:
        findings.append(ActiveFinding(
            finding_type=f"js_hardcoded_{cred.credential_type.lower().replace(' ', '_')}",
            severity=cred.severity,
            title=f"JS'de Hardcoded {cred.credential_type}",
            description=f"JavaScript dosyasında hardcoded {cred.credential_type} tespit edildi.",
            url=source_url,
            evidence=cred.matched_value,
            remediation="API key'leri JavaScript'ten kaldırın. Backend proxy kullanın.",
            metadata={"source_type": source_type, "credential_type": cred.credential_type},
        ))
    
    # 2. Ekstra JS-spesifik pattern'ler
    js_patterns = [
        # API endpoints with credentials
        (r'(?:api[_-]?(?:key|token|secret)|apikey|api_key|apiToken|apiSecret)\s*[=:]\s*["\']([^"\']{8,})["\']',
         "Hardcoded API Key/Token", "HIGH"),
        # Base64 encoded secrets
        (r'(?:authorization|auth|bearer)\s*[=:]\s*["\'](?:Basic|Bearer)\s+([A-Za-z0-9+/=]{20,})["\']',
         "Hardcoded Auth Header", "CRITICAL"),
        # Private/Internal URLs
        (r'["\']https?://(?:internal|private|staging|dev|test|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^"\']*["\']',
         "Internal/Private URL Exposure", "MEDIUM"),
        # Hardcoded passwords
        (r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{4,})["\']',
         "Hardcoded Password", "CRITICAL"),
        # AWS region + service patterns
        (r'(?:aws[_-]?region|region)\s*[=:]\s*["\']([a-z]{2}-[a-z]+-\d)["\'].*?(?:bucket|s3|dynamodb|lambda)',
         "AWS Configuration Exposure", "MEDIUM"),
        # Database connection strings in JS
        (r'(?:mysql|postgres|mongodb|redis|amqp)://[^"\'\s]+',
         "Database Connection String in JS", "CRITICAL"),
        # Google Maps API key (common in JS)
        (r'(?:maps|places)\.googleapis\.com[^"\']*key=([A-Za-z0-9_-]{20,})',
         "Google Maps API Key", "MEDIUM"),
        # Firebase config
        (r'(?:apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId)\s*:\s*["\']([^"\']+)["\']',
         "Firebase Config Exposure", "MEDIUM"),
        # Stripe publishable key in JS (not necessarily bad but worth noting)
        (r'pk_(?:live|test)_[0-9a-zA-Z]{24,}',
         "Stripe Key in JS", "MEDIUM"),
    ]
    
    for pattern, name, severity in js_patterns:
        for match in re.finditer(pattern, content, re.I):
            value = match.group(1) if match.lastindex else match.group(0)
            value_hash = hash_credential(value)
            
            # Dedupe
            if any(f.metadata.get("hash") == value_hash for f in findings):
                continue
            
            # Context
            start = max(0, match.start() - 40)
            end = min(len(content), match.end() + 40)
            context = content[start:end].replace("\n", " ").strip()
            
            findings.append(ActiveFinding(
                finding_type=f"js_{name.lower().replace(' ', '_')}",
                severity=severity,
                title=f"JS'de {name}",
                description=f"JavaScript {source_type}'da {name} tespit edildi.",
                url=source_url,
                evidence=mask_credential(value[:80]),
                remediation="Hassas bilgileri client-side koddan kaldırın.",
                metadata={"source_type": source_type, "hash": value_hash, "context": mask_credential(context[:150])},
            ))
    
    return findings


# ------------------------------------------------------------------ #
# 3. HTTP Header Güvenlik Analizi
# ------------------------------------------------------------------ #

async def analyze_headers(base_url: str, session) -> List[ActiveFinding]:
    """HTTP header'larını güvenlik açısından analiz eder."""
    findings: List[ActiveFinding] = []
    
    result = await _safe_get(session, base_url)
    if result is None:
        return findings
    
    status, body, headers = result
    
    # Olması gereken güvenlik header'ları
    security_headers = {
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "desc": "HSTS header eksik — MITM saldırısına açık",
            "remedy": "Strict-Transport-Security: max-age=31536000; includeSubDomains header'ı ekleyin",
        },
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "desc": "CSP header eksik — XSS saldırılarına karşı koruma yok",
            "remedy": "Content-Security-Policy header'ı ile güvenlik politikası belirleyin",
        },
        "X-Frame-Options": {
            "severity": "LOW",
            "desc": "X-Frame-Options eksik — Clickjacking saldırısına açık",
            "remedy": "X-Frame-Options: DENY veya SAMEORIGIN ekleyin",
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "desc": "X-Content-Type-Options eksik — MIME sniffing'e açık",
            "remedy": "X-Content-Type-Options: nosniff ekleyin",
        },
        "X-XSS-Protection": {
            "severity": "LOW",
            "desc": "X-XSS-Protection eksik",
            "remedy": "X-XSS-Protection: 1; mode=block ekleyin",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "desc": "Referrer-Policy eksik — hassas URL bilgileri sızabilir",
            "remedy": "Referrer-Policy: strict-origin-when-cross-origin ekleyin",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "desc": "Permissions-Policy eksik — tarayıcı özellik kısıtlaması yok",
            "remedy": "Permissions-Policy header'ı ile gereksiz tarayıcı özelliklerini kısıtlayın",
        },
    }
    
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    for header_name, info in security_headers.items():
        if header_name.lower() not in headers_lower:
            findings.append(ActiveFinding(
                finding_type="missing_security_header",
                severity=info["severity"],
                title=f"Eksik Header: {header_name}",
                description=info["desc"],
                url=base_url,
                evidence=f"Header '{header_name}' bulunamadı",
                remediation=info["remedy"],
                metadata={"header": header_name},
            ))
    
    # Bilgi sızdıran header'lar
    leaky_headers = {
        "Server": "Sunucu yazılım ve versiyon bilgisi",
        "X-Powered-By": "Backend teknoloji bilgisi",
        "X-AspNet-Version": ".NET versiyon bilgisi",
        "X-AspNetMvc-Version": "ASP.NET MVC versiyon bilgisi",
        "X-Generator": "CMS/Framework bilgisi",
    }
    
    for header_name, desc in leaky_headers.items():
        value = headers_lower.get(header_name.lower())
        if value:
            findings.append(ActiveFinding(
                finding_type="information_leakage_header",
                severity="LOW",
                title=f"Bilgi Sızıntısı: {header_name}",
                description=f"{desc} ifşa oluyor: {value}",
                url=base_url,
                evidence=f"{header_name}: {value}",
                remediation=f"{header_name} header'ını kaldırın veya değerini gizleyin.",
                metadata={"header": header_name, "value": value},
            ))
    
    # CORS misconfiguration
    cors_origin = headers_lower.get("access-control-allow-origin", "")
    if cors_origin == "*":
        findings.append(ActiveFinding(
            finding_type="cors_misconfiguration",
            severity="MEDIUM",
            title="Açık CORS Politikası",
            description="Access-Control-Allow-Origin: * — herhangi bir origin API'ye erişebilir",
            url=base_url,
            evidence="Access-Control-Allow-Origin: *",
            remediation="CORS'u sadece güvenilir origin'lere izin verecek şekilde kısıtlayın.",
        ))
    
    # Cookie güvenlik kontrolleri
    set_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for cookie in set_cookies:
        issues = []
        if "secure" not in cookie.lower():
            issues.append("Secure flag eksik")
        if "httponly" not in cookie.lower():
            issues.append("HttpOnly flag eksik")
        if "samesite" not in cookie.lower():
            issues.append("SameSite flag eksik")
        
        if issues:
            cookie_name = cookie.split("=")[0].strip()
            findings.append(ActiveFinding(
                finding_type="insecure_cookie",
                severity="MEDIUM",
                title=f"Güvensiz Cookie: {cookie_name}",
                description=f"Cookie güvenlik flag'leri eksik: {', '.join(issues)}",
                url=base_url,
                evidence=f"Set-Cookie: {cookie[:100]}",
                remediation="Cookie'lere Secure, HttpOnly ve SameSite flag'larını ekleyin.",
                metadata={"cookie": cookie_name, "issues": issues},
            ))
    
    logger.info("header_analysis_complete", base_url=base_url, findings=len(findings))
    return findings


# ------------------------------------------------------------------ #
# 4. HTML Source Code Analizi
# ------------------------------------------------------------------ #

async def analyze_html(base_url: str, session) -> List[ActiveFinding]:
    """HTML kaynak kodunda hassas bilgi arar."""
    findings: List[ActiveFinding] = []
    
    result = await _safe_get(session, base_url)
    if result is None:
        return findings
    
    status, html, headers = result
    
    # HTML comments'larda hassas bilgi
    for match in re.finditer(r'<!--(.*?)-->', html, re.DOTALL):
        comment = match.group(1).strip()
        if len(comment) < 5:
            continue
        
        # Hassas pattern'ler
        sensitive_patterns = [
            (r'(?:password|passwd|pwd|secret|token|api[_-]?key|credentials?)\s*[=:]\s*\S+', "Credential in Comment"),
            (r'(?:TODO|FIXME|HACK|XXX|BUG).*(?:password|secret|key|token|auth)', "Security TODO in Comment"),
            (r'(?:mysql|postgres|mongodb|redis|ftp|ssh)://[^\s<]+', "Connection String in Comment"),
            (r'(?:internal|staging|dev|test)\.[a-z0-9.-]+\.[a-z]{2,}', "Internal URL in Comment"),
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', "IP Address in Comment"),
        ]
        
        for pattern, name in sensitive_patterns:
            if re.search(pattern, comment, re.I):
                findings.append(ActiveFinding(
                    finding_type="html_comment_leak",
                    severity="MEDIUM" if "Credential" in name or "Connection" in name else "LOW",
                    title=f"HTML Yorum'da Bilgi Sızıntısı: {name}",
                    description=f"HTML yorumunda hassas bilgi tespit edildi.",
                    url=base_url,
                    evidence=mask_credential(comment[:200]),
                    remediation="HTML yorumlarından hassas bilgileri kaldırın. Production build'de yorum temizleme yapın.",
                    metadata={"type": name},
                ))
                break
    
    # Hidden input'larda token/key
    for match in re.finditer(r'<input[^>]*type=["\']hidden["\'][^>]*>', html, re.I):
        tag = match.group(0)
        name_match = re.search(r'name=["\']([^"\']+)["\']', tag)
        value_match = re.search(r'value=["\']([^"\']+)["\']', tag)
        
        if name_match and value_match:
            name = name_match.group(1).lower()
            value = value_match.group(1)
            
            suspicious_names = ["token", "secret", "key", "api", "auth", "password", "csrf", "nonce"]
            if any(s in name for s in suspicious_names) and len(value) > 10:
                if "csrf" in name or "nonce" in name:
                    continue  # CSRF token'lar normal
                findings.append(ActiveFinding(
                    finding_type="hidden_input_secret",
                    severity="HIGH",
                    title=f"Hidden Input'ta Hassas Değer: {name_match.group(1)}",
                    description=f"Hidden input alanında potansiyel hassas veri tespit edildi.",
                    url=base_url,
                    evidence=f"name={name_match.group(1)}, value={mask_credential(value)}",
                    remediation="Hassas verileri hidden input'larda saklamayın.",
                ))
    
    # Form action'lar — HTTP üzerinden gönderim
    for match in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.I):
        action = match.group(1)
        if action.startswith("http://") and "login" in html[max(0, match.start()-200):match.end()+200].lower():
            findings.append(ActiveFinding(
                finding_type="insecure_form_action",
                severity="HIGH",
                title="HTTP Üzerinden Login Form",
                description=f"Login formu şifrelenmemiş HTTP üzerinden gönderiliyor: {action}",
                url=base_url,
                evidence=f"Form action: {action}",
                remediation="Tüm form action'ları HTTPS'e yönlendirin.",
            ))
    
    # Meta tag'larda bilgi
    for match in re.finditer(r'<meta[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']+)["\']', html, re.I):
        meta_name = match.group(1).lower()
        meta_value = match.group(2)
        if meta_name in ("author", "generator"):
            findings.append(ActiveFinding(
                finding_type="meta_info_disclosure",
                severity="INFO",
                title=f"Meta Bilgi Sızıntısı: {meta_name}",
                description=f"Meta tag'da bilgi ifşası: {meta_name}={meta_value}",
                url=base_url,
                evidence=f"<meta name=\"{meta_name}\" content=\"{meta_value}\">",
                remediation="Gereksiz meta tag'ları kaldırın.",
                metadata={"meta_name": meta_name, "meta_value": meta_value},
            ))
    
    logger.info("html_analysis_complete", base_url=base_url, findings=len(findings))
    return findings


# ------------------------------------------------------------------ #
# 5. DNS Subdomain Keşfi
# ------------------------------------------------------------------ #

async def discover_subdomains(domain: str, session) -> List[ActiveFinding]:
    """Subdomain brute-force + crt.sh ile keşif yapar."""
    findings: List[ActiveFinding] = []
    live_subdomains: List[str] = []
    
    # 1. crt.sh ile Certificate Transparency sorgusu
    crt_subs = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        result = await _safe_get(session, url)
        if result and result[0] == 200:
            data = json.loads(result[1])
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        crt_subs.add(sub)
    except Exception as e:
        logger.warning("crtsh_subdomain_error", error=str(e))
    
    # 2. DNS brute-force (aiohttp ile HTTP check)
    all_subs_to_check = set()
    for sub in COMMON_SUBDOMAINS:
        all_subs_to_check.add(f"{sub}.{domain}")
    all_subs_to_check.update(crt_subs)
    
    sem = asyncio.Semaphore(30)
    
    async def check_subdomain(subdomain: str):
        async with sem:
            # DNS resolution check via socket
            try:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.getaddrinfo(subdomain, 443, socket.AF_INET),
                    timeout=3,
                )
                if result:
                    ip = result[0][4][0]
                    return subdomain, ip
            except Exception:
                return None
    
    tasks = [check_subdomain(sub) for sub in all_subs_to_check]
    results = await asyncio.gather(*tasks)
    
    discovered = [(sub, ip) for r in results if r for sub, ip in [r]]
    
    if discovered:
        sub_list = [f"{sub} ({ip})" for sub, ip in discovered[:50]]
        findings.append(ActiveFinding(
            finding_type="subdomain_enumeration",
            severity="INFO",
            title=f"{len(discovered)} Subdomain Keşfedildi",
            description=f"{domain} için {len(discovered)} aktif subdomain tespit edildi.",
            url=f"https://crt.sh/?q=%25.{domain}",
            evidence="\n".join(sub_list[:20]),
            remediation="Kullanılmayan subdomain'leri kaldırın. Wildcard DNS kullanmaktan kaçının.",
            metadata={
                "total": len(discovered),
                "subdomains": [{"name": sub, "ip": ip} for sub, ip in discovered],
                "from_crtsh": len(crt_subs),
            },
        ))
        
        # Her subdomain'de hızlı hassas dosya kontrolü
        for sub, ip in discovered[:10]:  # İlk 10 subdomain
            sub_url = f"https://{sub}"
            quick_paths = ["/.env", "/.git/config", "/phpinfo.php", "/swagger.json", "/api"]
            for path in quick_paths:
                check_url = urljoin(sub_url, path)
                result = await _safe_get(session, check_url)
                if result and result[0] == 200 and len(result[1]) > 50:
                    body = result[1]
                    not_found = any(p in body[:300].lower() for p in ["not found", "404"])
                    if not not_found:
                        findings.append(ActiveFinding(
                            finding_type="subdomain_exposed_file",
                            severity="HIGH" if ".env" in path or ".git" in path else "MEDIUM",
                            title=f"Subdomain Açık Dosya: {sub}{path}",
                            description=f"Subdomain {sub} üzerinde {path} erişilebilir.",
                            url=check_url,
                            evidence=body[:200],
                            remediation=f"{sub} subdomain'inde {path} erişimini engelleyin.",
                            metadata={"subdomain": sub, "ip": ip, "path": path},
                        ))
    
    logger.info("subdomain_discovery_complete", domain=domain, total=len(discovered))
    return findings


# ------------------------------------------------------------------ #
# 6. Robots.txt & Sitemap Analizi
# ------------------------------------------------------------------ #

async def analyze_robots_sitemap(base_url: str, session) -> List[ActiveFinding]:
    """Robots.txt ve sitemap.xml dosyalarını analiz eder."""
    findings: List[ActiveFinding] = []
    domain = urlparse(base_url).hostname or ""
    
    # robots.txt
    robots_url = urljoin(base_url, "/robots.txt")
    result = await _safe_get(session, robots_url)
    if result and result[0] == 200:
        robots_text = result[1]
        
        # Disallow edilen hassas yolları tespit et
        disallowed = re.findall(r'Disallow:\s*(.+)', robots_text)
        sensitive_disallows = []
        for path in disallowed:
            path = path.strip()
            if any(kw in path.lower() for kw in [
                "admin", "api", "config", "secret", "private", "internal",
                "backup", "database", "db", "login", "auth", "dashboard",
                "debug", "test", "staging", "env",
            ]):
                sensitive_disallows.append(path)
        
        if sensitive_disallows:
            findings.append(ActiveFinding(
                finding_type="robots_sensitive_paths",
                severity="LOW",
                title=f"Robots.txt Hassas Yol İfşası ({len(sensitive_disallows)} yol)",
                description="Robots.txt dosyasında hassas yollar listeleniyor — saldırganlar için rehber niteliğinde.",
                url=robots_url,
                evidence="\n".join(sensitive_disallows[:15]),
                remediation="Robots.txt'de hassas yolları listelemeyin. Bunun yerine authentication kullanın.",
                metadata={"paths": sensitive_disallows},
            ))
            
            # Bu hassas yolları da kontrol et
            for path in sensitive_disallows[:5]:
                check_url = urljoin(base_url, path)
                check_result = await _safe_get(session, check_url)
                if check_result and check_result[0] == 200 and len(check_result[1]) > 50:
                    body = check_result[1]
                    if not any(p in body[:300].lower() for p in ["not found", "404"]):
                        findings.append(ActiveFinding(
                            finding_type="robots_disallowed_accessible",
                            severity="MEDIUM",
                            title=f"Robots.txt'de Gizli Ama Erişilebilir: {path}",
                            description=f"Robots.txt'de disallow edilen {path} aslında erişilebilir durumda.",
                            url=check_url,
                            evidence=body[:200],
                            remediation="Bu yolu sadece robots.txt ile değil, authentication ile de koruyun.",
                        ))
    
    # sitemap.xml
    sitemap_url = urljoin(base_url, "/sitemap.xml")
    result = await _safe_get(session, sitemap_url)
    if result and result[0] == 200 and "<?xml" in result[1][:100]:
        sitemap_text = result[1]
        urls = re.findall(r'<loc>(.*?)</loc>', sitemap_text)
        
        # Hassas URL pattern'leri
        sensitive_urls = []
        for url in urls:
            if any(kw in url.lower() for kw in [
                "admin", "api", "internal", "private", "staging", "test",
                "config", "debug", "backup",
            ]):
                sensitive_urls.append(url)
        
        if sensitive_urls:
            findings.append(ActiveFinding(
                finding_type="sitemap_sensitive_urls",
                severity="LOW",
                title=f"Sitemap'te Hassas URL'ler ({len(sensitive_urls)} URL)",
                description="Sitemap dosyasında hassas görünen URL'ler listeleniyor.",
                url=sitemap_url,
                evidence="\n".join(sensitive_urls[:10]),
                remediation="Hassas URL'leri sitemap'ten kaldırın.",
            ))
    
    logger.info("robots_sitemap_complete", base_url=base_url, findings=len(findings))
    return findings


# ------------------------------------------------------------------ #
# 7. S3/Cloud Bucket Keşfi
# ------------------------------------------------------------------ #

async def discover_cloud_buckets(domain: str, session) -> List[ActiveFinding]:
    """Hedef domain ile ilişkili açık S3/GCS bucket'ları arar."""
    findings: List[ActiveFinding] = []
    
    # Domain'den olası bucket isimleri oluştur
    base_name = domain.replace(".", "-")
    domain_parts = domain.split(".")
    org_name = domain_parts[0] if len(domain_parts) > 1 else domain
    
    bucket_names = [
        domain, base_name,
        org_name, f"{org_name}-backup", f"{org_name}-backups",
        f"{org_name}-assets", f"{org_name}-static", f"{org_name}-media",
        f"{org_name}-data", f"{org_name}-db", f"{org_name}-dev",
        f"{org_name}-staging", f"{org_name}-prod", f"{org_name}-production",
        f"{org_name}-files", f"{org_name}-uploads", f"{org_name}-images",
        f"{org_name}-public", f"{org_name}-private", f"{org_name}-logs",
        f"{org_name}-config", f"{org_name}-secrets",
        f"{base_name}-backup", f"{base_name}-assets", f"{base_name}-data",
    ]
    
    # S3 bucket check
    sem = asyncio.Semaphore(15)
    
    async def check_s3(name: str):
        async with sem:
            url = f"https://{name}.s3.amazonaws.com"
            result = await _safe_get(session, url)
            if result is None:
                return None
            
            status, body, _ = result
            if status == 200:
                return ActiveFinding(
                    finding_type="open_s3_bucket",
                    severity="CRITICAL",
                    title=f"Açık S3 Bucket: {name}",
                    description=f"S3 bucket '{name}' public erişime açık — veri sızıntısı riski!",
                    url=url,
                    evidence=body[:300],
                    remediation="S3 bucket'ı private yapın. Block Public Access'i aktifleştirin.",
                    metadata={"bucket": name, "provider": "aws"},
                )
            elif status == 403:
                # Bucket var ama private — çok yaygın, sadece not et, finding olarak ekleme
                return None
            return None
    
    async def check_gcs(name: str):
        async with sem:
            url = f"https://storage.googleapis.com/{name}"
            result = await _safe_get(session, url)
            if result is None:
                return None
            status, body, _ = result
            if status == 200:
                return ActiveFinding(
                    finding_type="open_gcs_bucket",
                    severity="CRITICAL",
                    title=f"Açık GCS Bucket: {name}",
                    description=f"Google Cloud Storage bucket '{name}' public erişime açık!",
                    url=url,
                    evidence=body[:300],
                    remediation="GCS bucket'ı private yapın. IAM politikalarını sıkılaştırın.",
                    metadata={"bucket": name, "provider": "gcp"},
                )
            return None
    
    tasks = []
    for name in bucket_names:
        tasks.append(check_s3(name))
        tasks.append(check_gcs(name))
    
    results = await asyncio.gather(*tasks)
    findings = [r for r in results if r is not None]
    
    logger.info("bucket_discovery_complete", domain=domain, findings=len(findings))
    return findings


# ------------------------------------------------------------------ #
# 8. SSL/TLS Analizi
# ------------------------------------------------------------------ #

async def analyze_ssl(domain: str) -> List[ActiveFinding]:
    """SSL/TLS sertifikası ve yapılandırmasını kontrol eder."""
    findings: List[ActiveFinding] = []
    
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()
        
        if cert:
            # Sertifika süresi kontrolü
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.utcnow()).days
            
            if days_left < 0:
                findings.append(ActiveFinding(
                    finding_type="expired_ssl_cert",
                    severity="CRITICAL",
                    title="Süresi Dolmuş SSL Sertifikası",
                    description=f"SSL sertifikası {abs(days_left)} gün önce süresi dolmuş!",
                    url=f"https://{domain}",
                    evidence=f"Bitiş: {cert['notAfter']}",
                    remediation="SSL sertifikasını hemen yenileyin.",
                ))
            elif days_left < 30:
                findings.append(ActiveFinding(
                    finding_type="expiring_ssl_cert",
                    severity="MEDIUM",
                    title=f"SSL Sertifikası {days_left} Gün Sonra Doluyor",
                    description=f"SSL sertifikasının süresinin dolmasına {days_left} gün kaldı.",
                    url=f"https://{domain}",
                    evidence=f"Bitiş: {cert['notAfter']}",
                    remediation="SSL sertifikasını yenileyin. Auto-renewal kurun.",
                ))
            
            # Subject Alternative Names
            san = cert.get("subjectAltName", ())
            alt_names = [name for typ, name in san if typ == "DNS"]
            
            if alt_names:
                findings.append(ActiveFinding(
                    finding_type="ssl_san_info",
                    severity="INFO",
                    title=f"SSL SAN: {len(alt_names)} Domain",
                    description=f"Sertifikada {len(alt_names)} alternatif domain bulunuyor.",
                    url=f"https://{domain}",
                    evidence=", ".join(alt_names[:20]),
                    remediation="Bilgi amaçlı — gereksiz domain'leri sertifikadan kaldırın.",
                    metadata={"sans": alt_names},
                ))
    
    except ssl.SSLError as e:
        findings.append(ActiveFinding(
            finding_type="ssl_error",
            severity="HIGH",
            title="SSL/TLS Hata",
            description=f"SSL bağlantısında hata: {str(e)}",
            url=f"https://{domain}",
            evidence=str(e)[:200],
            remediation="SSL yapılandırmasını kontrol edin ve düzeltin.",
        ))
    except Exception as e:
        if "refused" in str(e).lower() or "timed out" in str(e).lower():
            findings.append(ActiveFinding(
                finding_type="no_ssl",
                severity="HIGH",
                title="SSL/TLS Desteği Yok",
                description=f"Port 443 üzerinde SSL bağlantısı kurulamadı.",
                url=f"https://{domain}",
                evidence=str(e)[:200],
                remediation="HTTPS desteğini etkinleştirin ve geçerli bir SSL sertifikası kurun.",
            ))
    
    logger.info("ssl_analysis_complete", domain=domain, findings=len(findings))
    return findings


# ------------------------------------------------------------------ #
# 9. Wayback Machine Derinlemesine Tarama
# ------------------------------------------------------------------ #

async def deep_wayback_scan(domain: str, session) -> List[ActiveFinding]:
    """Wayback Machine'den geçmiş snapshot'larda hassas dosya arar."""
    findings: List[ActiveFinding] = []
    
    sensitive_extensions = [
        "env", "sql", "bak", "log", "conf", "cfg", "ini", "key", "pem",
        "json", "yaml", "yml", "xml", "csv", "xls", "xlsx",
    ]
    
    sensitive_paths_wb = [
        ".env", ".git", "wp-config", "config.php", "phpinfo",
        "admin", "swagger", "api-docs", "graphql", "actuator",
        "backup", "dump", "database",
    ]
    
    try:
        # CDX API ile tüm URL'leri çek
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&fl=timestamp,original,statuscode,mimetype"
            f"&collapse=urlkey&limit=500"
        )
        result = await _safe_get(session, url)
        if result is None or result[0] != 200:
            return findings
        
        data = json.loads(result[1])
        if not data or len(data) < 2:
            return findings
        
        headers_row = data[0]
        rows = data[1:]
        
        sensitive_found: List[Dict] = []
        all_urls = set()
        
        for row in rows:
            if len(row) < 4:
                continue
            timestamp, original_url, status_code, mimetype = row[0], row[1], row[2], row[3]
            all_urls.add(original_url)
            
            url_lower = original_url.lower()
            
            # Hassas dosya/path kontrol
            is_sensitive = False
            matched_pattern = ""
            
            for ext in sensitive_extensions:
                if url_lower.endswith(f".{ext}"):
                    is_sensitive = True
                    matched_pattern = f"*.{ext}"
                    break
            
            if not is_sensitive:
                for path in sensitive_paths_wb:
                    if path in url_lower:
                        is_sensitive = True
                        matched_pattern = path
                        break
            
            if is_sensitive:
                sensitive_found.append({
                    "url": original_url,
                    "timestamp": timestamp,
                    "status": status_code,
                    "pattern": matched_pattern,
                    "wayback_url": f"https://web.archive.org/web/{timestamp}/{original_url}",
                })
        
        if sensitive_found:
            findings.append(ActiveFinding(
                finding_type="wayback_sensitive_urls",
                severity="MEDIUM",
                title=f"Wayback Machine: {len(sensitive_found)} Hassas URL",
                description=(
                    f"Wayback Machine arşivinde {len(sensitive_found)} hassas URL tespit edildi. "
                    f"Bu URL'ler geçmişte erişilebilir durumda olmuş olabilir."
                ),
                url=f"https://web.archive.org/web/*/{domain}/*",
                evidence="\n".join(
                    f"[{s['timestamp'][:8]}] {s['pattern']}: {s['url']}"
                    for s in sensitive_found[:15]
                ),
                remediation="Hassas dosyaları sunucudan kaldırın. Wayback Machine'den kaldırma talebi gönderin.",
                metadata={
                    "total_sensitive": len(sensitive_found),
                    "total_urls": len(all_urls),
                    "sensitive_urls": sensitive_found[:30],
                },
            ))
        
        # Genel bilgi
        if all_urls:
            findings.append(ActiveFinding(
                finding_type="wayback_url_count",
                severity="INFO",
                title=f"Wayback Machine: {len(all_urls)} URL Arşivde",
                description=f"Wayback Machine'de {domain} için toplam {len(all_urls)} benzersiz URL arşivlenmiş.",
                url=f"https://web.archive.org/web/*/{domain}/*",
                evidence=f"Toplam URL: {len(all_urls)}",
                remediation="Bilgi amaçlı — geçmiş URL'leri inceleyin.",
                metadata={"total_urls": len(all_urls)},
            ))
        
        # Hassas URL'lerin güncel durumunu kontrol et
        for item in sensitive_found[:5]:  # İlk 5 hassas URL
            check_result = await _safe_get(session, item["url"])
            if check_result and check_result[0] == 200 and len(check_result[1]) > 50:
                body = check_result[1]
                if not any(p in body[:300].lower() for p in ["not found", "404"]):
                    findings.append(ActiveFinding(
                        finding_type="wayback_still_accessible",
                        severity="HIGH",
                        title=f"Wayback'te Bulunan Dosya Hâlâ Erişilebilir",
                        description=f"Wayback Machine'de tespit edilen hassas URL hâlâ aktif: {item['url']}",
                        url=item["url"],
                        evidence=body[:200],
                        remediation="Bu dosyayı sunucudan hemen kaldırın!",
                        metadata={"wayback_timestamp": item["timestamp"]},
                    ))
    
    except Exception as e:
        logger.warning("wayback_deep_error", error=str(e))
    
    logger.info("wayback_deep_complete", domain=domain, findings=len(findings))
    return findings


# ------------------------------------------------------------------ #
# 10. Teknoloji / Port Tarama
# ------------------------------------------------------------------ #

async def scan_common_ports(domain: str) -> List[ActiveFinding]:
    """Yaygın portları kontrol eder — açık veritabanı, admin panel vb."""
    findings: List[ActiveFinding] = []
    
    ports_to_check = {
        21: ("FTP", "HIGH"),
        22: ("SSH", "INFO"),
        23: ("Telnet", "CRITICAL"),
        25: ("SMTP", "LOW"),
        80: ("HTTP", "INFO"),
        443: ("HTTPS", "INFO"),
        445: ("SMB", "HIGH"),
        1433: ("MSSQL", "CRITICAL"),
        1521: ("Oracle DB", "CRITICAL"),
        2375: ("Docker API (Unencrypted)", "CRITICAL"),
        2376: ("Docker API (TLS)", "HIGH"),
        3000: ("Grafana/Dev Server", "MEDIUM"),
        3306: ("MySQL", "HIGH"),
        3389: ("RDP", "HIGH"),
        5432: ("PostgreSQL", "HIGH"),
        5672: ("RabbitMQ", "MEDIUM"),
        5900: ("VNC", "HIGH"),
        6379: ("Redis", "CRITICAL"),
        8080: ("HTTP Alt/Proxy", "LOW"),
        8443: ("HTTPS Alt", "LOW"),
        8888: ("Jupyter Notebook", "HIGH"),
        9090: ("Prometheus", "MEDIUM"),
        9200: ("Elasticsearch", "CRITICAL"),
        9300: ("Elasticsearch Transport", "HIGH"),
        11211: ("Memcached", "HIGH"),
        15672: ("RabbitMQ Management", "MEDIUM"),
        27017: ("MongoDB", "CRITICAL"),
        27018: ("MongoDB Shard", "CRITICAL"),
    }
    
    sem = asyncio.Semaphore(30)
    
    async def check_port(port: int, service: str, severity: str):
        async with sem:
            try:
                loop = asyncio.get_event_loop()
                conn = asyncio.open_connection(domain, port)
                reader, writer = await asyncio.wait_for(conn, timeout=3)
                
                # Banner grabbing
                banner = ""
                try:
                    writer.write(b"\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=2)
                    banner = data.decode("utf-8", errors="replace").strip()[:200]
                except Exception:
                    pass
                
                writer.close()
                
                return ActiveFinding(
                    finding_type=f"open_port_{port}",
                    severity=severity,
                    title=f"Açık Port: {port} ({service})",
                    description=f"Port {port} ({service}) dışarıya açık." + 
                               (f" Banner: {banner[:100]}" if banner else ""),
                    url=f"{domain}:{port}",
                    evidence=f"Port {port} ({service}) OPEN" + (f" | Banner: {banner[:100]}" if banner else ""),
                    remediation=f"Port {port}'u firewall ile kapatın veya erişimi kısıtlayın.",
                    metadata={"port": port, "service": service, "banner": banner},
                )
            except Exception:
                return None
    
    tasks = [check_port(port, svc, sev) for port, (svc, sev) in ports_to_check.items()]
    results = await asyncio.gather(*tasks)
    findings = [r for r in results if r is not None]
    
    # Kritik açık portları vurgula
    critical_open = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    if critical_open:
        logger.warning("critical_ports_open", domain=domain, 
                       ports=[f.metadata.get("port") for f in critical_open])
    
    logger.info("port_scan_complete", domain=domain, open_ports=len(findings))
    return findings


# ------------------------------------------------------------------ #
# 11. GitHub Public Search (API key gerektirmez)
# ------------------------------------------------------------------ #

async def search_github_public(domain: str, session) -> List[ActiveFinding]:
    """GitHub'da domain ile ilgili açık kod arar — API key gerektirmez."""
    findings: List[ActiveFinding] = []
    
    search_queries = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{domain}" token',
        f'"{domain}" credentials',
        f'"{domain}" AWS_ACCESS_KEY',
        f'"{domain}" PRIVATE_KEY',
    ]
    
    for query in search_queries:
        try:
            # GitHub web arama sonuçlarını çek (rate limit'siz)
            url = f"https://github.com/search?q={quote_plus(query)}&type=code"
            result = await _safe_get(session, url)
            if result is None or result[0] != 200:
                continue
            
            body = result[1]
            
            # Sonuç sayısını parse et
            count_match = re.search(r'(\d[\d,]*)\s+(?:code results|results)', body)
            if count_match:
                count_str = count_match.group(1).replace(",", "")
                count = int(count_str) if count_str.isdigit() else 0
                
                if count > 0:
                    # Repo linklerini çek
                    repos = re.findall(r'href="/([^/]+/[^/]+)/blob/', body)
                    unique_repos = list(set(repos))[:5]
                    
                    query_keyword = query.split('"')[1] if '"' in query else query
                    findings.append(ActiveFinding(
                        finding_type="github_code_exposure",
                        severity="HIGH" if any(kw in query for kw in ["password", "secret", "PRIVATE_KEY", "AWS"]) else "MEDIUM",
                        title=f"GitHub'da Kod Ifşası: {query_keyword} ({count} sonuç)",
                        description=f"GitHub'da '{query}' aramasında {count} kod sonucu bulundu.",
                        url=url,
                        evidence=f"Sonuç: {count} | Repo'lar: {', '.join(unique_repos) if unique_repos else 'parse edilemedi'}",
                        remediation="GitHub'da ifşa olan credential'ları revoke edin. Repo'ları private yapın veya hassas veriyi kaldırın.",
                        metadata={"query": query, "count": count, "repos": unique_repos},
                    ))
            
            await asyncio.sleep(2)  # Rate limiting
            
        except Exception as e:
            logger.warning("github_public_search_error", query=query, error=str(e))
    
    logger.info("github_public_complete", domain=domain, findings=len(findings))
    return findings


# ------------------------------------------------------------------ #
# 12. Email Harvesting (theHarvester-style)
# ------------------------------------------------------------------ #

async def harvest_emails(domain: str, session) -> List[ActiveFinding]:
    """Hedef domain'e ait email adreslerini internetten toplar."""
    findings: List[ActiveFinding] = []
    emails_found: Set[str] = set()
    
    # crt.sh'den email
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        result = await _safe_get(session, url)
        if result and result[0] == 200:
            for match in re.finditer(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), result[1]):
                emails_found.add(match.group(0).lower())
    except Exception:
        pass
    
    # Hunter.io public (sınırlı)
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&limit=5"
        result = await _safe_get(session, url)
        if result and result[0] == 200:
            data = json.loads(result[1])
            for email_data in data.get("data", {}).get("emails", []):
                emails_found.add(email_data.get("value", "").lower())
    except Exception:
        pass
    
    if emails_found:
        findings.append(ActiveFinding(
            finding_type="email_harvesting",
            severity="LOW",
            title=f"{len(emails_found)} Email Adresi Tespit Edildi",
            description=f"{domain} domain'ine ait {len(emails_found)} email adresi internet ortamında bulundu.",
            url=f"https://crt.sh/?q=%25.{domain}",
            evidence="\n".join(sorted(emails_found)[:20]),
            remediation="Email harvest'e karşı email obfuscation kullanın. SPF/DKIM/DMARC yapılandırın.",
            metadata={"emails": sorted(emails_found), "count": len(emails_found)},
        ))
    
    logger.info("email_harvest_complete", domain=domain, emails=len(emails_found))
    return findings


# ------------------------------------------------------------------ #
# MASTER ORCHESTRATOR
# ------------------------------------------------------------------ #

class ActiveScanner:
    """
    API key gerektirmeyen aktif web tarayıcı.
    Hedef web sitesini doğrudan ziyaret ederek güvenlik açıklarını tespit eder.
    """
    
    def __init__(self, target: str, modules: Optional[List[str]] = None):
        self.target = target.strip().lower()
        if self.target.startswith(("http://", "https://")):
            parsed = urlparse(self.target)
            self.domain = parsed.hostname or self.target
            self.base_url = self.target
        else:
            self.domain = self.target
            self.base_url = f"https://{self.target}"
        
        self.modules = modules or [
            "sensitive_files", "javascript", "headers", "html",
            "subdomains", "robots_sitemap", "cloud_buckets",
            "ssl", "wayback", "ports", "github", "emails",
        ]
    
    async def run(self) -> Tuple[List[ActiveFinding], Dict]:
        """Tüm aktif tarama modüllerini çalıştırır."""
        all_findings: List[ActiveFinding] = []
        module_stats: Dict[str, int] = {}
        
        logger.info("active_scan_start", target=self.target, modules=self.modules)
        
        async with _get_session() as session:
            # HTTP erişilebilirlik kontrolü
            reachable = await _safe_head(session, self.base_url)
            if reachable is None:
                # HTTPS çalışmıyorsa HTTP dene
                self.base_url = f"http://{self.domain}"
                reachable = await _safe_head(session, self.base_url)
                if reachable is None:
                    logger.error("target_unreachable", target=self.target)
                    return [], {"error": f"Hedef {self.target} erişilebilir değil"}
            
            # Modülleri paralel çalıştır (session gerektirenleri grupla)
            tasks = {}
            
            if "sensitive_files" in self.modules:
                tasks["sensitive_files"] = probe_sensitive_files(self.base_url, session)
            if "javascript" in self.modules:
                tasks["javascript"] = analyze_javascript(self.base_url, session)
            if "headers" in self.modules:
                tasks["headers"] = analyze_headers(self.base_url, session)
            if "html" in self.modules:
                tasks["html"] = analyze_html(self.base_url, session)
            if "subdomains" in self.modules:
                tasks["subdomains"] = discover_subdomains(self.domain, session)
            if "robots_sitemap" in self.modules:
                tasks["robots_sitemap"] = analyze_robots_sitemap(self.base_url, session)
            if "cloud_buckets" in self.modules:
                tasks["cloud_buckets"] = discover_cloud_buckets(self.domain, session)
            if "wayback" in self.modules:
                tasks["wayback"] = deep_wayback_scan(self.domain, session)
            if "github" in self.modules:
                tasks["github"] = search_github_public(self.domain, session)
            if "emails" in self.modules:
                tasks["emails"] = harvest_emails(self.domain, session)
            
            # Session gerektirmeyen modüller ayrı
            if "ssl" in self.modules:
                tasks["ssl"] = analyze_ssl(self.domain)
            if "ports" in self.modules:
                tasks["ports"] = scan_common_ports(self.domain)
            
            # Hepsini parallel çalıştır
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            
            for module_name, result in zip(tasks.keys(), results):
                if isinstance(result, Exception):
                    logger.error("module_failed", module=module_name, error=str(result))
                    module_stats[module_name] = -1
                elif isinstance(result, tuple):
                    # ActiveScanner.run() returns tuple
                    findings_list, _ = result
                    all_findings.extend(findings_list)
                    module_stats[module_name] = len(findings_list)
                elif isinstance(result, list):
                    all_findings.extend(result)
                    module_stats[module_name] = len(result)
        
        # Deduplikasyon
        seen = set()
        unique: List[ActiveFinding] = []
        for f in all_findings:
            key = hash_credential(f.url + f.finding_type + f.evidence[:100])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        
        # Severity sıralaması
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        unique.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        stats = {
            "total": len(unique),
            "critical": sum(1 for f in unique if f.severity == "CRITICAL"),
            "high": sum(1 for f in unique if f.severity == "HIGH"),
            "medium": sum(1 for f in unique if f.severity == "MEDIUM"),
            "low": sum(1 for f in unique if f.severity == "LOW"),
            "info": sum(1 for f in unique if f.severity == "INFO"),
            "modules": module_stats,
        }
        
        logger.info("active_scan_complete", target=self.target, **stats)
        return unique, stats
