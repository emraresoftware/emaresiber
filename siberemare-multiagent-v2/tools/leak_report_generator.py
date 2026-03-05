"""
SiberEmare API Leak Scanner — Rapor Üretici
============================================
Markdown, JSON, HTML ve PDF formatlarında profesyonel sızıntı raporu üretir.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

import structlog

logger = structlog.get_logger()


def generate_markdown_report(scan_result, output_dir: str = "reports") -> str:
    """Scan sonucundan profesyonel Markdown rapor üretir."""
    os.makedirs(output_dir, exist_ok=True)

    r = scan_result
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    filename = f"{r.scan_id}_api_leak_report.md"
    filepath = os.path.join(output_dir, filename)

    # Severity emoji ve renk
    sev_icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }

    lines = [
        "# 🔒 SiberEmare API Sızıntı Tarama Raporu",
        "",
        "---",
        "",
        "## 📋 Rapor Bilgileri",
        "",
        f"| Alan | Değer |",
        f"|------|-------|",
        f"| **Tarama ID** | `{r.scan_id}` |",
        f"| **Hedef** | `{r.target}` |",
        f"| **Başlangıç** | {r.started_at} |",
        f"| **Bitiş** | {r.finished_at} |",
        f"| **Rapor Tarihi** | {timestamp} |",
        f"| **Taranan Kaynaklar** | {', '.join(r.sources_scanned)} |",
        "",
        "---",
        "",
        "## 📊 Özet İstatistikler",
        "",
        f"| Severity | Adet |",
        f"|----------|------|",
        f"| 🔴 **CRITICAL** | {r.critical_count} |",
        f"| 🟠 **HIGH** | {r.high_count} |",
        f"| 🟡 **MEDIUM** | {r.medium_count} |",
        f"| 🟢 **LOW** | {r.low_count} |",
        f"| **TOPLAM** | **{r.total_findings}** |",
        "",
    ]

    # Risk skoru hesapla
    risk_score = (r.critical_count * 10 + r.high_count * 7 + r.medium_count * 4 + r.low_count * 1)
    max_possible = max(r.total_findings * 10, 1)
    risk_percentage = min(100, int((risk_score / max_possible) * 100)) if r.total_findings > 0 else 0

    risk_level = "DÜŞÜK"
    if risk_percentage >= 75:
        risk_level = "KRİTİK"
    elif risk_percentage >= 50:
        risk_level = "YÜKSEK"
    elif risk_percentage >= 25:
        risk_level = "ORTA"

    lines.extend([
        f"### Risk Değerlendirmesi",
        f"",
        f"- **Risk Skoru**: {risk_score}/{max_possible} ({risk_percentage}%)",
        f"- **Genel Risk Seviyesi**: **{risk_level}**",
        "",
        "---",
        "",
    ])

    # Yönetici Özeti
    lines.extend([
        "## 📝 Yönetici Özeti",
        "",
        f"`{r.target}` hedefi üzerinde yapılan internet çapında API sızıntı taraması sonucunda "
        f"**toplam {r.total_findings} adet** potansiyel sızıntı tespit edilmiştir.",
        "",
    ])

    if r.critical_count > 0:
        lines.append(
            f"⚠️ **{r.critical_count} adet KRİTİK seviye** sızıntı tespit edilmiştir. "
            f"Bu sızıntılar acil müdahale gerektirmektedir. İlgili API anahtarları derhal "
            f"iptal edilmeli (revoke) ve yeniden oluşturulmalıdır."
        )
        lines.append("")

    if r.high_count > 0:
        lines.append(
            f"🔶 **{r.high_count} adet YÜKSEK seviye** sızıntı tespit edilmiştir. "
            f"Bu anahtarların 24 saat içinde rotate edilmesi önerilir."
        )
        lines.append("")

    lines.extend(["", "---", "", "## 🔍 Detaylı Bulgular", ""])

    # Severity'e göre sırala
    sorted_creds = sorted(r.credentials, key=lambda c: {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3
    }.get(c.severity, 4))

    for i, cred in enumerate(sorted_creds, 1):
        icon = sev_icon.get(cred.severity, "⚪")
        lines.extend([
            f"### {icon} Bulgu #{i}: {cred.credential_type}",
            "",
            f"| Alan | Değer |",
            f"|------|-------|",
            f"| **Tip** | {cred.credential_type} |",
            f"| **Severity** | {icon} {cred.severity} |",
            f"| **Güvenilirlik** | {cred.confidence} |",
            f"| **Kaynak** | {cred.source} |",
            f"| **Değer (maskeli)** | `{cred.matched_value}` |",
            f"| **SHA256** | `{cred.raw_hash[:16]}...` |",
            f"| **Tespit Zamanı** | {cred.found_at} |",
            f"| **URL** | [{cred.source_url[:80]}]({cred.source_url}) |",
            "",
            "**Context:**",
            f"```",
            f"{cred.context_snippet}",
            f"```",
            "",
        ])

        if cred.metadata:
            lines.append("**Metadata:**")
            for k, v in cred.metadata.items():
                lines.append(f"- `{k}`: {v}")
            lines.append("")

        # Remediation önerisi
        remediation = _get_remediation(cred.credential_type)
        if remediation:
            lines.extend([
                "**Önerilen Aksiyon:**",
                "",
                *[f"- {step}" for step in remediation],
                "",
            ])

        lines.append("---")
        lines.append("")

    # Hatalar
    if r.errors:
        lines.extend([
            "## ⚠️ Tarama Hataları",
            "",
            *[f"- {e}" for e in r.errors],
            "",
        ])

    # Aksiyon planı
    lines.extend([
        "## 🛡️ Genel Aksiyon Planı",
        "",
        "### Acil (0-4 saat)",
        "1. Tüm **CRITICAL** seviye anahtarları derhal iptal edin (revoke/rotate)",
        "2. İlgili servislerin erişim loglarını kontrol edin",
        "3. Yetkisiz erişim olup olmadığını doğrulayın",
        "",
        "### Kısa Vade (24-48 saat)",
        "4. **HIGH** seviye anahtarları rotate edin",
        "5. Secret management çözümü implemente edin (HashiCorp Vault, AWS Secrets Manager vb.)",
        "6. GitHub/GitLab'da secret scanning'i aktif edin",
        "",
        "### Orta Vade (1-2 hafta)",
        "7. CI/CD pipeline'a pre-commit hook ekleyin (gitleaks, truffleHog)",
        "8. .env dosyalarının .gitignore'a eklendiğini doğrulayın",
        "9. API key rotation politikası belirleyin",
        "10. Düzenli sızıntı taraması planlayın",
        "",
        "### Uzun Vade (1 ay+)",
        "11. Zero Trust API erişim modeli tasarlayın",
        "12. IP whitelist / service mesh ile API koruma",
        "13. Çalışan güvenlik farkındalık eğitimi",
        "14. SIEM/SOAR entegrasyonlu otomatik alarm sistemi kurun",
        "",
        "---",
        "",
        "## 📎 Ekler",
        "",
        f"- JSON Rapor: `{r.scan_id}_api_leak_report.json`",
        f"- HTML Rapor: `{r.scan_id}_api_leak_report.html`",
        "",
        "---",
        "",
        f"*Bu rapor SiberEmare API Leak Scanner tarafından {timestamp} tarihinde otomatik üretilmiştir.*",
        f"*SiberEmare Siber Güvenlik — Emare Ekosistemi*",
    ])

    report = "\n".join(lines)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report)

    logger.info("markdown_report_saved", path=filepath)
    return filepath


def generate_json_report(scan_result, output_dir: str = "reports") -> str:
    """JSON formatında rapor üretir."""
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{scan_result.scan_id}_api_leak_report.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scan_result.to_dict(), f, ensure_ascii=False, indent=2, default=str)

    logger.info("json_report_saved", path=filepath)
    return filepath


def generate_html_report(scan_result, output_dir: str = "reports") -> str:
    """Interaktif HTML rapor üretir — müşteri sunumu için."""
    os.makedirs(output_dir, exist_ok=True)
    r = scan_result
    filename = f"{r.scan_id}_api_leak_report.html"
    filepath = os.path.join(output_dir, filename)

    # Risk score
    risk_score = (r.critical_count * 10 + r.high_count * 7 + r.medium_count * 4 + r.low_count * 1)
    max_possible = max(r.total_findings * 10, 1)
    risk_pct = min(100, int((risk_score / max_possible) * 100)) if r.total_findings > 0 else 0

    sev_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
    }

    # Bulgu satırları
    finding_rows = ""
    sorted_creds = sorted(r.credentials, key=lambda c: {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3
    }.get(c.severity, 4))

    for i, cred in enumerate(sorted_creds, 1):
        color = sev_colors.get(cred.severity, "#6c757d")
        remediation = _get_remediation(cred.credential_type)
        remediation_html = "<br>".join(f"• {s}" for s in remediation) if remediation else "-"
        finding_rows += f"""
        <tr>
            <td>{i}</td>
            <td><span class="badge" style="background:{color}">{cred.severity}</span></td>
            <td><strong>{cred.credential_type}</strong></td>
            <td><code>{cred.matched_value}</code></td>
            <td>{cred.source}</td>
            <td><a href="{cred.source_url}" target="_blank" rel="noopener">Link</a></td>
            <td><small>{cred.context_snippet[:80]}...</small></td>
            <td><small>{remediation_html}</small></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SiberEmare API Sızıntı Raporu — {r.target}</title>
    <style>
        :root {{
            --bg: #0a0e17;
            --card: #131a2b;
            --accent: #00d4ff;
            --danger: #dc3545;
            --warning: #ffc107;
            --success: #28a745;
            --text: #e8e8e8;
            --muted: #8892a0;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
        header {{
            background: linear-gradient(135deg, #131a2b 0%, #1a2744 100%);
            border-bottom: 2px solid var(--accent);
            padding: 32px 0;
            margin-bottom: 32px;
        }}
        header h1 {{ font-size: 28px; color: var(--accent); }}
        header p {{ color: var(--muted); margin-top: 8px; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .stat-card {{
            background: var(--card);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid rgba(255,255,255,0.06);
            text-align: center;
        }}
        .stat-card h3 {{ font-size: 36px; margin-bottom: 4px; }}
        .stat-card p {{ color: var(--muted); font-size: 14px; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .risk-meter {{
            background: var(--card);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 32px;
            border: 1px solid rgba(255,255,255,0.06);
        }}
        .risk-bar {{
            height: 24px;
            background: #1e2a3a;
            border-radius: 12px;
            overflow: hidden;
            margin-top: 12px;
        }}
        .risk-fill {{
            height: 100%;
            border-radius: 12px;
            transition: width 1s ease;
            background: linear-gradient(90deg, var(--success), var(--warning), var(--danger));
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 32px;
        }}
        th {{
            background: #1a2744;
            padding: 14px 12px;
            text-align: left;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--accent);
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            font-size: 14px;
        }}
        tr:hover {{ background: rgba(0, 212, 255, 0.03); }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            color: #fff;
            text-transform: uppercase;
        }}
        code {{
            background: rgba(0, 212, 255, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }}
        a {{ color: var(--accent); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .section-title {{
            font-size: 22px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        .action-plan {{
            background: var(--card);
            border-radius: 12px;
            padding: 24px;
            border-left: 4px solid var(--accent);
        }}
        .action-plan h4 {{ color: var(--accent); margin-bottom: 8px; }}
        .action-plan ol {{ padding-left: 20px; }}
        .action-plan li {{ margin-bottom: 6px; color: var(--muted); }}
        footer {{
            text-align: center;
            padding: 24px;
            color: var(--muted);
            font-size: 13px;
            border-top: 1px solid rgba(255,255,255,0.06);
            margin-top: 48px;
        }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .stat-card, table, .risk-meter, .action-plan {{ border: 1px solid #ddd; }}
            .badge {{ border: 1px solid currentColor; }}
        }}
    </style>
</head>
<body>

<header>
    <div class="container">
        <h1>🔒 SiberEmare API Sızıntı Tarama Raporu</h1>
        <p>Hedef: <strong>{r.target}</strong> | Tarama: {r.scan_id} | {r.started_at}</p>
    </div>
</header>

<div class="container">

    <div class="stats-grid">
        <div class="stat-card">
            <h3>{r.total_findings}</h3>
            <p>Toplam Bulgu</p>
        </div>
        <div class="stat-card">
            <h3 class="critical">{r.critical_count}</h3>
            <p>Kritik</p>
        </div>
        <div class="stat-card">
            <h3 class="high">{r.high_count}</h3>
            <p>Yüksek</p>
        </div>
        <div class="stat-card">
            <h3 class="medium">{r.medium_count}</h3>
            <p>Orta</p>
        </div>
        <div class="stat-card">
            <h3 class="low">{r.low_count}</h3>
            <p>Düşük</p>
        </div>
        <div class="stat-card">
            <h3>{len(r.sources_scanned)}</h3>
            <p>Kaynak Tarandı</p>
        </div>
    </div>

    <div class="risk-meter">
        <h3 class="section-title">Risk Değerlendirmesi</h3>
        <p>Risk Skoru: <strong>{risk_pct}%</strong></p>
        <div class="risk-bar">
            <div class="risk-fill" style="width: {risk_pct}%"></div>
        </div>
    </div>

    <h2 class="section-title">🔍 Detaylı Bulgular ({r.total_findings})</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Tip</th>
                <th>Değer (Maskeli)</th>
                <th>Kaynak</th>
                <th>URL</th>
                <th>Context</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
            {finding_rows if finding_rows else '<tr><td colspan="8" style="text-align:center; color:var(--success)">✅ Sızıntı bulunamadı!</td></tr>'}
        </tbody>
    </table>

    <h2 class="section-title">🛡️ Aksiyon Planı</h2>
    <div class="action-plan">
        <h4>Acil (0-4 saat)</h4>
        <ol>
            <li>Tüm CRITICAL seviye anahtarları derhal iptal edin (revoke/rotate)</li>
            <li>İlgili servislerin erişim loglarını kontrol edin</li>
            <li>Yetkisiz erişim olup olmadığını doğrulayın</li>
        </ol>
        <h4>Kısa Vade (24-48 saat)</h4>
        <ol start="4">
            <li>HIGH seviye anahtarları rotate edin</li>
            <li>Secret management çözümü implemente edin</li>
            <li>GitHub/GitLab'da secret scanning aktif edin</li>
        </ol>
        <h4>Orta Vade (1-2 hafta)</h4>
        <ol start="7">
            <li>CI/CD pipeline'a pre-commit hook ekleyin (gitleaks, truffleHog)</li>
            <li>.env dosyalarının .gitignore'a eklendiğini doğrulayın</li>
            <li>API key rotation politikası belirleyin</li>
        </ol>
    </div>
</div>

<footer>
    SiberEmare API Leak Scanner | Emare Ekosistemi | {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
</footer>

</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info("html_report_saved", path=filepath)
    return filepath


def _get_remediation(cred_type: str) -> list:
    """Credential tipine göre özel remediation adımları döndürür."""
    remediation_map = {
        "AWS Access Key ID": [
            "AWS Console → IAM → Credentials → Access Key'i devre dışı bırakın",
            "Yeni access key oluşturun ve uygulamaları güncelleyin",
            "CloudTrail loglarını kontrol edin — yetkisiz kullanım olup olmadığını doğrulayın",
            "AWS Secrets Manager veya SSM Parameter Store kullanın",
        ],
        "AWS Secret Access Key": [
            "Derhal ilgili Access Key'i revoke edin",
            "IAM politikalarını minimum yetki prensibiyle güncelle",
            "AWS Config Rules ile compliance izleme kurun",
        ],
        "GCP API Key": [
            "GCP Console → APIs & Services → Credentials'dan key'i kısıtlayın",
            "API key restrictions ekleyin (HTTP referrer, IP, API scope)",
            "Service Account + IAM kullanmaya geçin",
        ],
        "GCP Service Account": [
            "GCP Console → IAM → Service Account key'ini silin",
            "Workload Identity Federation kullanmaya geçin",
            "Service Account'a minimum yetki verin",
        ],
        "Azure Storage Key": [
            "Azure Portal → Storage Account → Access Keys → Regenerate",
            "Azure Key Vault ile yönetin",
            "SAS token'lar için expiry süresi belirleyin",
        ],
        "Stripe Secret Key": [
            "Stripe Dashboard → Developers → API Keys → Roll Key",
            "Eski key'i revoke edin, webhook'ları güncelleyin",
            "Stripe restricted keys kullanın (minimum yetki)",
        ],
        "Slack Bot Token": [
            "Slack Admin → Apps → Token'ı rotate edin",
            "Bot izinlerini gözden geçirin ve kısıtlayın",
        ],
        "GitHub Token (Classic)": [
            "GitHub → Settings → Developer Settings → Personal Access Tokens → Revoke",
            "Fine-grained token'lar kullanmaya geçin",
            "Token expiry süresi belirleyin",
        ],
        "GitHub Token (Fine-grained)": [
            "GitHub → Settings → Developer Settings → Fine-grained Tokens → Revoke",
            "Minimum repository ve permission scope'u belirleyin",
        ],
        "OpenAI API Key": [
            "OpenAI Dashboard → API Keys → Key'i silin ve yenisin oluşturun",
            "Kullanım limitlerini (usage limits) ayarlayın",
            "Environment variable ile yönetin, koda gömmeyin",
        ],
        "Anthropic API Key": [
            "Anthropic Console → API Keys → Revoke",
            "Yeni key oluşturun, spending limit belirleyin",
        ],
        "MongoDB Connection String": [
            "Veritabanı şifresini derhal değiştirin",
            "Ağ erişimini IP whitelist ile kısıtlayın",
            "Authentication ve TLS/SSL etkinleştirin",
        ],
        "PostgreSQL Connection String": [
            "PostgreSQL kullanıcı şifresini değiştirin: ALTER USER ... PASSWORD ...",
            "pg_hba.conf ile erişimi kısıtlayın",
            "SSL bağlantıyı zorunlu kılın",
        ],
        "SSH Private Key": [
            "İlgili public key'i authorized_keys'den kaldırın",
            "Yeni SSH key çifti oluşturun",
            "SSH key'leri passphrase ile koruyun",
            "SSH Certificate Authority kullanmayı değerlendirin",
        ],
        "JWT Token": [
            "JWT signing secret'ı değiştirin (rotate)",
            "Token expiry sürelerini kısaltın",
            "Token blacklist/revocation mekanizması kurun",
        ],
        "SendGrid API Key": [
            "SendGrid → Settings → API Keys → Revoke",
            "Yeni key oluşturun, minimum permission verin",
        ],
        "Firebase API Key": [
            "Firebase Console → Project Settings → API key'i kısıtlayın",
            "Firebase Security Rules'u güncelleyin",
            "App Check etkinleştirin",
        ],
        "Discord Bot Token": [
            "Discord Developer Portal → Bot → Reset Token",
            "Bot izinlerini gözden geçirin",
        ],
        "Telegram Bot Token": [
            "BotFather'dan /revoke komutunu kullanın",
            "Yeni token alın ve uygulamayı güncelleyin",
        ],
    }

    # Direkt eşleşme
    if cred_type in remediation_map:
        return remediation_map[cred_type]

    # Genel remediation
    return [
        "İlgili credential'ı derhal iptal edin (revoke/rotate)",
        "Yetkisiz erişim loglarını kontrol edin",
        "Secret management çözümü kullanın (Vault, AWS SM, Azure KV)",
        "Koda gömülü secret'ları environment variable'lara taşıyın",
    ]
