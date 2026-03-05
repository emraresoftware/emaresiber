"""
SiberEmare API Leak Scanner — Güçlendirilmiş OSINT Tarayıcı v2.0
=================================================================
Ek Kaynaklar:
  • Certificate Transparency Logs (crt.sh)
  • Wayback Machine (archive.org)
  • VirusTotal
  • Have I Been Pwned (HIBP)
  • LeakCheck
  • Dehashed
  • Hunter.io (Email Intelligence)
  • SecurityTrails (Subdomain enum)
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional

import structlog

logger = structlog.get_logger()


# ---- Lazy import ----
def _get_session(**kwargs):
    import aiohttp
    timeout = aiohttp.ClientTimeout(total=30)
    return aiohttp.ClientSession(timeout=timeout, **kwargs)


async def scan_crtsh(target: str) -> List[Dict]:
    """Certificate Transparency Logs — sertifika şeffaflık kayıtları ile subdomain keşfi."""
    findings = []
    subdomains = set()

    async with _get_session() as session:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub and sub != target and "*" not in sub:
                                subdomains.add(sub)

                    findings.append({
                        "source": "crt.sh",
                        "type": "subdomain_enumeration",
                        "total_certs": len(data),
                        "unique_subdomains": sorted(subdomains),
                        "count": len(subdomains),
                    })
        except Exception as e:
            logger.error("crtsh_error", error=str(e))

    logger.info("crtsh_complete", target=target, subdomains=len(subdomains))
    return findings


async def scan_wayback(target: str) -> List[Dict]:
    """Wayback Machine — geçmişte açığa çıkmış endpoint'ler, config dosyaları."""
    findings = []
    sensitive_extensions = [
        ".env", ".git/config", ".yml", ".yaml", ".json", ".xml",
        ".sql", ".bak", ".backup", ".conf", ".cfg", ".ini",
        ".log", ".key", ".pem", ".p12", ".pfx", ".phpinfo",
        "wp-config.php", "config.php", ".htpasswd", ".htaccess",
        "credentials", "secret", "password", "api_key", "token",
    ]

    async with _get_session() as session:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original,statuscode,mimetype&collapse=urlkey&limit=500"
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if len(data) > 1:
                        sensitive_urls = []
                        all_urls = []
                        for row in data[1:]:  # İlk satır header
                            orig_url = row[0] if len(row) > 0 else ""
                            all_urls.append(orig_url)
                            url_lower = orig_url.lower()
                            for ext in sensitive_extensions:
                                if ext in url_lower:
                                    sensitive_urls.append({
                                        "url": orig_url,
                                        "matched_pattern": ext,
                                        "status": row[1] if len(row) > 1 else "?",
                                    })
                                    break

                        findings.append({
                            "source": "wayback_machine",
                            "type": "historical_exposure",
                            "total_urls_found": len(all_urls),
                            "sensitive_urls": sensitive_urls[:50],
                            "sensitive_count": len(sensitive_urls),
                        })
        except Exception as e:
            logger.error("wayback_error", error=str(e))

    logger.info("wayback_complete", target=target, findings=len(findings))
    return findings


async def scan_virustotal(target: str, vt_key: Optional[str] = None) -> List[Dict]:
    """VirusTotal — domain raporu, ilişkili dosyalar ve URL'ler."""
    findings = []
    key = vt_key or os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        logger.warning("VirusTotal API key yok, atlanıyor")
        return findings

    headers = {"x-apikey": key}
    async with _get_session() as session:
        # Domain raporu
        url = f"https://www.virustotal.com/api/v3/domains/{target}"
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    analysis = attrs.get("last_analysis_stats", {})
                    findings.append({
                        "source": "virustotal",
                        "type": "domain_report",
                        "malicious": analysis.get("malicious", 0),
                        "suspicious": analysis.get("suspicious", 0),
                        "harmless": analysis.get("harmless", 0),
                        "reputation": attrs.get("reputation", 0),
                        "categories": attrs.get("categories", {}),
                        "whois": attrs.get("whois", "")[:500],
                    })

            # Subdomain'ler
            sub_url = f"https://www.virustotal.com/api/v3/domains/{target}/subdomains?limit=40"
            async with session.get(sub_url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subs = [item.get("id", "") for item in data.get("data", [])]
                    if subs:
                        findings.append({
                            "source": "virustotal",
                            "type": "subdomains",
                            "subdomains": subs,
                            "count": len(subs),
                        })

        except Exception as e:
            logger.error("virustotal_error", error=str(e))

    return findings


async def scan_hibp(target: str, hibp_key: Optional[str] = None) -> List[Dict]:
    """Have I Been Pwned — domain breach check."""
    findings = []
    key = hibp_key or os.getenv("HIBP_API_KEY")
    if not key:
        logger.warning("HIBP API key yok, atlanıyor")
        return findings

    headers = {"hibp-api-key": key, "User-Agent": "SiberEmare-LeakScanner"}
    async with _get_session() as session:
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={target}"
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    breaches = await resp.json()
                    for breach in breaches:
                        findings.append({
                            "source": "hibp",
                            "type": "data_breach",
                            "breach_name": breach.get("Name", ""),
                            "breach_date": breach.get("BreachDate", ""),
                            "pwned_count": breach.get("PwnCount", 0),
                            "data_classes": breach.get("DataClasses", []),
                            "description": breach.get("Description", "")[:300],
                            "is_verified": breach.get("IsVerified", False),
                            "is_sensitive": breach.get("IsSensitive", False),
                        })
        except Exception as e:
            logger.error("hibp_error", error=str(e))

    logger.info("hibp_complete", target=target, breaches=len(findings))
    return findings


async def scan_hunter(target: str, hunter_key: Optional[str] = None) -> List[Dict]:
    """Hunter.io — domain email intelligence."""
    findings = []
    key = hunter_key or os.getenv("HUNTER_API_KEY")
    if not key:
        logger.warning("Hunter.io API key yok, atlanıyor")
        return findings

    async with _get_session() as session:
        url = f"https://api.hunter.io/v2/domain-search?domain={target}&api_key={key}&limit=20"
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    domain_data = data.get("data", {})
                    emails = domain_data.get("emails", [])
                    findings.append({
                        "source": "hunter",
                        "type": "email_intelligence",
                        "organization": domain_data.get("organization", ""),
                        "total_emails": domain_data.get("total", 0),
                        "emails_found": [
                            {
                                "email": e.get("value", ""),
                                "type": e.get("type", ""),
                                "confidence": e.get("confidence", 0),
                                "position": e.get("position", ""),
                                "department": e.get("department", ""),
                            }
                            for e in emails[:20]
                        ],
                        "pattern": domain_data.get("pattern", ""),
                    })
        except Exception as e:
            logger.error("hunter_error", error=str(e))

    return findings


async def scan_securitytrails(target: str, st_key: Optional[str] = None) -> List[Dict]:
    """SecurityTrails — gelişmiş subdomain keşfi ve DNS geçmişi."""
    findings = []
    key = st_key or os.getenv("SECURITYTRAILS_API_KEY")
    if not key:
        logger.warning("SecurityTrails API key yok, atlanıyor")
        return findings

    headers = {"APIKEY": key}
    async with _get_session() as session:
        # Subdomain list
        url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subs = data.get("subdomains", [])
                    findings.append({
                        "source": "securitytrails",
                        "type": "subdomain_enumeration",
                        "subdomains": [f"{s}.{target}" for s in subs[:100]],
                        "count": len(subs),
                    })

            # DNS history
            dns_url = f"https://api.securitytrails.com/v1/history/{target}/dns/a"
            async with session.get(dns_url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    records = data.get("records", [])
                    findings.append({
                        "source": "securitytrails",
                        "type": "dns_history",
                        "records": [
                            {
                                "ip": r.get("values", [{}])[0].get("ip", "") if r.get("values") else "",
                                "first_seen": r.get("first_seen", ""),
                                "last_seen": r.get("last_seen", ""),
                            }
                            for r in records[:20]
                        ],
                    })
        except Exception as e:
            logger.error("securitytrails_error", error=str(e))

    return findings


async def scan_dehashed(target: str, dh_email: Optional[str] = None, dh_key: Optional[str] = None) -> List[Dict]:
    """Dehashed — sızıntı veritabanı araması."""
    findings = []
    email = dh_email or os.getenv("DEHASHED_EMAIL")
    key = dh_key or os.getenv("DEHASHED_API_KEY")
    if not email or not key:
        logger.warning("Dehashed credentials yok, atlanıyor")
        return findings

    import aiohttp
    auth = aiohttp.BasicAuth(email, key)
    async with _get_session() as session:
        url = f"https://api.dehashed.com/search?query=domain:{target}&size=50"
        headers = {"Accept": "application/json"}
        try:
            async with session.get(url, headers=headers, auth=auth) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    entries = data.get("entries", [])
                    total = data.get("total", 0)
                    findings.append({
                        "source": "dehashed",
                        "type": "leaked_credentials",
                        "total_results": total,
                        "sample_entries": [
                            {
                                "email": e.get("email", ""),
                                "username": e.get("username", ""),
                                "has_password": bool(e.get("password") or e.get("hashed_password")),
                                "database": e.get("database_name", ""),
                            }
                            for e in entries[:30]
                        ],
                    })
        except Exception as e:
            logger.error("dehashed_error", error=str(e))

    return findings


async def run_enhanced_osint(target: str) -> Dict:
    """Tüm gelişmiş OSINT kaynaklarını paralel çalıştırır."""
    tasks = {
        "crtsh": scan_crtsh(target),
        "wayback": scan_wayback(target),
        "virustotal": scan_virustotal(target),
        "hibp": scan_hibp(target),
        "hunter": scan_hunter(target),
        "securitytrails": scan_securitytrails(target),
        "dehashed": scan_dehashed(target),
    }

    results = {}
    task_list = list(tasks.items())
    gathered = await asyncio.gather(
        *[t for _, t in task_list],
        return_exceptions=True,
    )

    for (name, _), result in zip(task_list, gathered):
        if isinstance(result, Exception):
            results[name] = {"error": str(result)}
            logger.error("enhanced_osint_error", source=name, error=str(result))
        else:
            results[name] = result

    return results
