"""
SiberEmare API Leak Scanner — FastAPI Web Dashboard
====================================================
Profesyonel web arayüzü ile müşteriye sunum kalitesinde rapor sistemi.
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# Path fix
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.api_leak_scanner import APILeakScanner, scan_local_files, ScanResult, LeakedCredential
from tools.leak_report_generator import (
    generate_markdown_report,
    generate_json_report,
    generate_html_report,
)
from tools.enhanced_osint import run_enhanced_osint
from tools.active_scanner import ActiveScanner
from tools.ai_analysis import AIAnalysisEngine

import structlog
logger = structlog.get_logger()

# ------------------------------------------------------------------ #
# FastAPI App
# ------------------------------------------------------------------ #

app = FastAPI(
    title="SiberEmare API Leak Scanner",
    description="Internet ortamında deşifre olmuş API anahtarlarını tarar ve raporlar — AI Destekli",
    version="4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan storage
scan_store: dict = {}
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


# ------------------------------------------------------------------ #
# Models
# ------------------------------------------------------------------ #

class ScanRequest(BaseModel):
    target: str
    sources: list = Field(default=["github", "shodan", "google_dorks", "urlscan", "paste", "intelx"])
    enhanced_osint: bool = Field(default=True, description="Ek OSINT kaynakları")
    github_token: Optional[str] = None
    shodan_key: Optional[str] = None


class ScanStatus(BaseModel):
    scan_id: str
    status: str  # pending / running / completed / failed
    target: str
    progress: int = 0
    started_at: str = ""
    finished_at: str = ""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0


# ------------------------------------------------------------------ #
# Background Scan Task
# ------------------------------------------------------------------ #

async def run_scan_task(scan_id: str, req: ScanRequest):
    """Background'da tam tarama çalıştırır — aktif + pasif tarama."""
    store = scan_store[scan_id]
    store["status"] = "running"
    store["progress"] = 5

    try:
        # ============================================================
        # 1. AKTİF WEB TARAMA (API key gerektirmez — ana motor)
        # ============================================================
        store["progress_text"] = "Aktif web taraması başlatılıyor..."
        active_scanner = ActiveScanner(target=req.target)
        active_findings, active_stats = await active_scanner.run()
        store["progress"] = 40
        store["active_findings"] = [f.to_dict() for f in active_findings]
        store["active_stats"] = active_stats

        # Aktif bulguları LeakedCredential formatına dönüştür (rapor uyumu için)
        active_as_creds = [f.to_leaked_credential(req.target) for f in active_findings
                          if f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]

        # ============================================================
        # 2. PASİF CREDENTIAL TARAMA (API key'li kaynaklar)
        # ============================================================
        store["progress_text"] = "Pasif kaynak taraması..."
        scanner = APILeakScanner(
            target=req.target,
            sources=req.sources,
            github_token=req.github_token,
            shodan_key=req.shodan_key,
        )
        result = await scanner.run()
        store["progress"] = 60

        # Aktif tarama bulgularını result'a ekle
        result.credentials.extend(active_as_creds)
        # Deduplikasyon
        seen_hashes = set()
        unique_creds = []
        for c in result.credentials:
            if c.raw_hash not in seen_hashes:
                seen_hashes.add(c.raw_hash)
                unique_creds.append(c)
        result.credentials = unique_creds
        result.total_findings = len(unique_creds)
        result.critical_count = sum(1 for c in unique_creds if c.severity == "CRITICAL")
        result.high_count = sum(1 for c in unique_creds if c.severity == "HIGH")
        result.medium_count = sum(1 for c in unique_creds if c.severity == "MEDIUM")
        result.low_count = sum(1 for c in unique_creds if c.severity == "LOW")

        # ============================================================
        # 3. Enhanced OSINT
        # ============================================================
        osint_data = {}
        if req.enhanced_osint:
            store["progress_text"] = "OSINT kaynakları taranıyor..."
            osint_data = await run_enhanced_osint(req.target)
            store["progress"] = 85

        # ============================================================
        # 4. Rapor üretimi
        # ============================================================
        store["progress_text"] = "Raporlar oluşturuluyor..."
        md_path = generate_markdown_report(result, REPORTS_DIR)
        json_path = generate_json_report(result, REPORTS_DIR)
        html_path = generate_html_report(result, REPORTS_DIR)
        store["progress"] = 95

        # ============================================================
        # 5. AI Destekli Derin Analiz
        # ============================================================
        store["progress_text"] = "🤖 AI analiz motoru çalışıyor..."
        store["progress"] = 95
        try:
            ai_engine = AIAnalysisEngine()
            creds_dicts = [c.to_dict() for c in result.credentials]
            active_dicts = [f.to_dict() for f in active_findings]
            ai_result = await ai_engine.analyze(
                target=req.target,
                credentials=creds_dicts,
                active_findings=active_dicts,
                osint_data=osint_data,
            )
            store["ai_analysis"] = ai_result.to_dict()
            logger.info("ai_analysis_done", target=req.target, provider=ai_result.provider_used)
        except Exception as ai_err:
            logger.warning("ai_analysis_error", error=str(ai_err))
            store["ai_analysis"] = {"error": str(ai_err), "executive_summary": "AI analizi çalıştırılamadı."}

        # ============================================================
        # 6. Store güncelle
        # ============================================================
        store["status"] = "completed"
        store["progress"] = 100
        store["progress_text"] = "Tarama tamamlandı!"
        store["finished_at"] = datetime.now(timezone.utc).isoformat()
        store["total_findings"] = result.total_findings + len([f for f in active_findings if f.severity == "INFO"])
        store["critical_count"] = result.critical_count
        store["high_count"] = result.high_count
        store["medium_count"] = result.medium_count
        store["low_count"] = result.low_count
        store["info_count"] = sum(1 for f in active_findings if f.severity == "INFO")
        store["sources_scanned"] = result.sources_scanned + ["active_web_scan"]
        store["errors"] = result.errors
        store["osint"] = osint_data
        store["reports"] = {
            "markdown": os.path.basename(md_path),
            "json": os.path.basename(json_path),
            "html": os.path.basename(html_path),
        }
        store["credentials"] = [c.to_dict() for c in result.credentials]

        logger.info("scan_completed", scan_id=scan_id, 
                    total=result.total_findings, 
                    active=len(active_findings),
                    passive=len(result.credentials) - len(active_as_creds))

    except Exception as e:
        store["status"] = "failed"
        store["error"] = str(e)
        logger.error("scan_failed", scan_id=scan_id, error=str(e))


# ------------------------------------------------------------------ #
# API Endpoints
# ------------------------------------------------------------------ #

@app.post("/api/scan", response_model=ScanStatus)
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """Yeni tarama başlatır."""
    scan_id = f"SCAN-{req.target}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    scan_store[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "target": req.target,
        "progress": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": "",
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
    }

    background_tasks.add_task(run_scan_task, scan_id, req)

    return ScanStatus(
        scan_id=scan_id,
        status="pending",
        target=req.target,
        started_at=scan_store[scan_id]["started_at"],
    )


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Tarama durumunu sorgular."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı")
    return scan_store[scan_id]


@app.get("/api/scans")
async def list_scans():
    """Tüm taramaları listeler."""
    return [
        {
            "scan_id": s["scan_id"],
            "status": s["status"],
            "target": s["target"],
            "total_findings": s.get("total_findings", 0),
            "critical_count": s.get("critical_count", 0),
            "started_at": s.get("started_at", ""),
        }
        for s in scan_store.values()
    ]


@app.get("/api/report/{filename}")
async def get_report(filename: str):
    """Rapor dosyasını indirir."""
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Rapor bulunamadı")
    return FileResponse(filepath, filename=filename)


@app.get("/api/ai-analysis/{scan_id}")
async def get_ai_analysis(scan_id: str):
    """AI analiz sonuçlarını döner."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı")
    return scan_store[scan_id].get("ai_analysis", {"error": "AI analizi henüz tamamlanmadı"})


@app.post("/api/ai-reanalyze/{scan_id}")
async def reanalyze_with_ai(scan_id: str):
    """Mevcut tarama sonuçlarını tekrar AI ile analiz eder."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı")
    store = scan_store[scan_id]
    if store.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Tarama henüz tamamlanmadı")
    
    ai_engine = AIAnalysisEngine()
    ai_result = await ai_engine.analyze(
        target=store["target"],
        credentials=store.get("credentials", []),
        active_findings=store.get("active_findings", []),
        osint_data=store.get("osint", {}),
    )
    store["ai_analysis"] = ai_result.to_dict()
    return ai_result.to_dict()


@app.get("/api/llm-status")
async def llm_status():
    """LLM provider durumlarını döner."""
    providers = {
        "anthropic": {"name": "Anthropic Claude 3.5", "configured": bool(os.getenv("ANTHROPIC_API_KEY", "") and not os.getenv("ANTHROPIC_API_KEY", "").startswith("sk-ant-...")), "mode": "cloud"},
        "openai": {"name": "OpenAI GPT-4o", "configured": bool(os.getenv("OPENAI_API_KEY", "") and not os.getenv("OPENAI_API_KEY", "").startswith("sk-...")), "mode": "cloud"},
        "groq": {"name": "Groq Llama 3.3 70B", "configured": bool(os.getenv("GROQ_API_KEY", "")), "mode": "hybrid"},
        "ollama": {"name": "Ollama (Lokal)", "configured": False, "mode": "onprem", "url": os.getenv("OLLAMA_URL", "http://localhost:11434")},
    }
    # Ollama check
    try:
        import aiohttp
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
            async with session.get(f"{providers['ollama']['url']}/api/tags") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    providers['ollama']['configured'] = True
                    providers['ollama']['models'] = [m['name'] for m in data.get('models', [])]
    except Exception:
        pass
    
    current_mode = os.getenv("LLM_MODE", "cloud")
    return {"providers": providers, "current_mode": current_mode}


@app.get("/api/patterns")
async def get_patterns():
    """Desteklenen credential pattern'lerini listeler."""
    from tools.api_leak_scanner import API_KEY_PATTERNS, classify_severity
    return [
        {
            "name": name,
            "severity": classify_severity(name),
            "regex": pattern.pattern[:80],
        }
        for name, pattern in API_KEY_PATTERNS.items()
    ]


@app.get("/api/config")
async def get_config():
    """API key yapılandırma durumu."""
    keys = {
        "GITHUB_TOKEN": {"service": "GitHub Code Search", "configured": bool(os.getenv("GITHUB_TOKEN")), "free": False},
        "SHODAN_API_KEY": {"service": "Shodan", "configured": bool(os.getenv("SHODAN_API_KEY")), "free": False},
        "GOOGLE_API_KEY": {"service": "Google Custom Search", "configured": bool(os.getenv("GOOGLE_API_KEY")), "free": False},
        "VIRUSTOTAL_API_KEY": {"service": "VirusTotal", "configured": bool(os.getenv("VIRUSTOTAL_API_KEY")), "free": True},
        "HIBP_API_KEY": {"service": "Have I Been Pwned", "configured": bool(os.getenv("HIBP_API_KEY")), "free": False},
        "HUNTER_API_KEY": {"service": "Hunter.io", "configured": bool(os.getenv("HUNTER_API_KEY")), "free": True},
        "INTELX_API_KEY": {"service": "Intelligence X", "configured": bool(os.getenv("INTELX_API_KEY")), "free": False},
    }
    free_sources = [
        "Aktif Web Tarama (12 modül)",
        "URLScan.io", "Paste Sites", "crt.sh", "Wayback Machine",
        "DNS Brute-force", "Port Tarama", "SSL Analizi",
        "JS Analizi", "Header Analizi", "S3 Bucket Keşfi",
    ]
    return {"api_keys": keys, "free_sources": free_sources}


# ------------------------------------------------------------------ #
# Web Dashboard — Ana Sayfa
# ------------------------------------------------------------------ #

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Ana web dashboard."""
    return DASHBOARD_HTML


# ------------------------------------------------------------------ #
# Dashboard HTML
# ------------------------------------------------------------------ #

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SiberEmare — API Leak Scanner v4.0 — AI Destekli</title>
<style>
:root{--bg:#0a0e17;--card:#131a2b;--card2:#1a2744;--accent:#00d4ff;--accent2:#7c3aed;
--danger:#ef4444;--warning:#f59e0b;--success:#22c55e;--text:#e8e8e8;--muted:#8892a0;
--border:rgba(255,255,255,0.06)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.container{max-width:1400px;margin:0 auto;padding:20px}

/* Header */
header{background:linear-gradient(135deg,#0f172a 0%,#1e293b 50%,#0f172a 100%);
border-bottom:2px solid var(--accent);padding:20px 0;margin-bottom:30px}
.header-inner{max-width:1400px;margin:0 auto;padding:0 20px;display:flex;align-items:center;justify-content:space-between}
.logo{display:flex;align-items:center;gap:12px}
.logo h1{font-size:24px;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo span{font-size:13px;color:var(--muted);display:block}
.status-badge{padding:6px 14px;border-radius:20px;font-size:12px;font-weight:600;
background:rgba(34,197,94,0.15);color:var(--success);border:1px solid rgba(34,197,94,0.3)}

/* Scan Form */
.scan-form{background:var(--card);border-radius:16px;padding:32px;border:1px solid var(--border);margin-bottom:30px}
.scan-form h2{font-size:20px;margin-bottom:20px;color:var(--accent)}
.form-row{display:flex;gap:16px;flex-wrap:wrap;align-items:flex-end}
.form-group{flex:1;min-width:200px}
.form-group label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px}
.form-group input,.form-group select{width:100%;padding:12px 16px;border-radius:10px;border:1px solid rgba(255,255,255,0.1);
background:var(--bg);color:var(--text);font-size:14px;outline:none;transition:border 0.2s}
.form-group input:focus{border-color:var(--accent)}
.btn{padding:12px 28px;border-radius:10px;border:none;font-weight:600;font-size:14px;cursor:pointer;transition:all 0.2s;display:inline-flex;align-items:center;gap:8px}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff}
.btn-primary:hover{opacity:0.9;transform:translateY(-1px)}
.btn-primary:disabled{opacity:0.5;cursor:not-allowed;transform:none}

/* Stats Grid */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:30px}
.stat-card{background:var(--card);border-radius:14px;padding:24px;text-align:center;border:1px solid var(--border);transition:transform 0.2s}
.stat-card:hover{transform:translateY(-2px)}
.stat-card .number{font-size:40px;font-weight:700;line-height:1}
.stat-card .label{font-size:13px;color:var(--muted);margin-top:6px}
.stat-card.critical .number{color:var(--danger)}
.stat-card.high .number{color:#f97316}
.stat-card.medium .number{color:var(--warning)}
.stat-card.low .number{color:var(--success)}
.stat-card.total .number{color:var(--accent)}

/* Progress */
.progress-wrap{margin:20px 0;display:none}
.progress-bar{height:8px;background:rgba(255,255,255,0.1);border-radius:4px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:4px;transition:width 0.5s ease;width:0%}
.progress-text{font-size:13px;color:var(--muted);margin-top:6px;text-align:center}

/* Results Table */
.results-section{background:var(--card);border-radius:16px;padding:24px;border:1px solid var(--border);margin-bottom:30px}
.results-section h2{font-size:18px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:12px;font-size:12px;text-transform:uppercase;letter-spacing:0.5px;color:var(--accent);
background:var(--card2);border-bottom:2px solid var(--border)}
td{padding:12px;font-size:13px;border-bottom:1px solid var(--border)}
tr:hover{background:rgba(0,212,255,0.03)}
.badge{display:inline-block;padding:3px 10px;border-radius:6px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase}
.badge.CRITICAL{background:var(--danger)}.badge.HIGH{background:#f97316}
.badge.MEDIUM{background:var(--warning);color:#000}.badge.LOW{background:var(--success)}

/* OSINT Section */
.osint-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-top:20px}
.osint-card{background:var(--card2);border-radius:12px;padding:20px;border:1px solid var(--border)}
.osint-card h3{font-size:15px;margin-bottom:10px;color:var(--accent)}
.osint-card ul{list-style:none;padding:0}
.osint-card li{padding:4px 0;font-size:13px;color:var(--muted);border-bottom:1px solid var(--border)}
.osint-card li:last-child{border:none}

/* Reports */
.report-links{display:flex;gap:12px;margin-top:16px;flex-wrap:wrap}
.report-link{padding:10px 20px;border-radius:8px;background:var(--card2);color:var(--text);
text-decoration:none;font-size:13px;font-weight:600;border:1px solid var(--border);transition:all 0.2s}
.report-link:hover{border-color:var(--accent);color:var(--accent)}

/* Tabs */
.tabs{display:flex;gap:4px;margin-bottom:20px;border-bottom:2px solid var(--border);padding-bottom:0}
.tab{padding:10px 20px;cursor:pointer;font-size:14px;color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-2px;transition:all 0.2s}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-content{display:none}.tab-content.active{display:block}

/* Scan History */
.scan-item{display:flex;align-items:center;justify-content:space-between;padding:12px;
background:var(--card2);border-radius:8px;margin-bottom:8px;cursor:pointer;transition:all 0.2s}
.scan-item:hover{background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.2)}
.scan-item .target{font-weight:600}.scan-item .meta{font-size:12px;color:var(--muted)}

/* Empty */
.empty{text-align:center;padding:60px 20px;color:var(--muted)}
.empty .icon{font-size:64px;margin-bottom:16px;opacity:0.5}
.empty p{font-size:15px}

/* Responsive */
@media(max-width:768px){
.form-row{flex-direction:column}
.stats-grid{grid-template-columns:repeat(2,1fr)}
.header-inner{flex-direction:column;gap:12px;text-align:center}
}

/* Animation */
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
.scanning .progress-text{animation:pulse 1.5s infinite}
</style>
</head>
<body>

<header>
<div class="header-inner">
    <div class="logo">
        <div>
            <h1>🔒 SiberEmare API Leak Scanner</h1>
            <span>Aktif Web Tarama + OSINT Platformu v3.0</span>
        </div>
    </div>
    <div class="status-badge" id="statusBadge">● Sistem Hazır</div>
</div>
</header>

<div class="container">

<!-- Scan Form -->
<div class="scan-form">
    <h2>🔍 Yeni Tarama Başlat</h2>
    <div class="form-row">
        <div class="form-group" style="flex:2">
            <label>Hedef Domain / Organizasyon</label>
            <input type="text" id="targetInput" placeholder="example.com veya org-name" autofocus>
        </div>
        <div class="form-group">
            <label>Kaynak Seçimi</label>
            <select id="sourceSelect">
                <option value="all">Tüm Kaynaklar</option>
                <option value="free">Ücretsiz Kaynaklar</option>
                <option value="github,shodan">GitHub + Shodan</option>
                <option value="urlscan,paste">URLScan + Paste</option>
                <option value="custom">Özel</option>
            </select>
        </div>
        <div class="form-group" style="flex:0 0 auto">
            <label>&nbsp;</label>
            <button class="btn btn-primary" id="scanBtn" onclick="startScan()">
                🚀 Taramayı Başlat
            </button>
        </div>
    </div>
    <div class="progress-wrap" id="progressWrap">
        <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
        <div class="progress-text" id="progressText">Tarama başlatılıyor...</div>
    </div>
</div>

<!-- Stats -->
<div class="stats-grid" id="statsGrid" style="display:none">
    <div class="stat-card total"><div class="number" id="statTotal">0</div><div class="label">Toplam Bulgu</div></div>
    <div class="stat-card critical"><div class="number" id="statCritical">0</div><div class="label">Kritik</div></div>
    <div class="stat-card high"><div class="number" id="statHigh">0</div><div class="label">Yüksek</div></div>
    <div class="stat-card medium"><div class="number" id="statMedium">0</div><div class="label">Orta</div></div>
    <div class="stat-card low"><div class="number" id="statLow">0</div><div class="label">Düşük</div></div>
    <div class="stat-card"><div class="number" id="statInfo" style="color:#60a5fa">0</div><div class="label">Bilgi</div></div>
    <div class="stat-card"><div class="number" id="statSources" style="color:var(--accent2)">0</div><div class="label">Kaynak Tarandı</div></div>
</div>

<!-- Tabs -->
<div class="tabs" id="tabsWrap" style="display:none">
    <div class="tab active" onclick="switchTab('active')">🎯 Aktif Tarama</div>
    <div class="tab" onclick="switchTab('findings')">🔍 Credential'lar</div>
    <div class="tab" onclick="switchTab('osint')">🌐 OSINT</div>
    <div class="tab" onclick="switchTab('ai')">🤖 AI Analiz</div>
    <div class="tab" onclick="switchTab('reports')">📄 Raporlar</div>
    <div class="tab" onclick="switchTab('history')">📜 Geçmiş</div>
</div>

<!-- Active Scan Tab -->
<div class="tab-content active" id="tab-active">
    <div class="results-section" id="activeSection" style="display:none">
        <h2>🎯 Aktif Web Tarama Sonuçları</h2>
        <p style="color:var(--muted);margin-bottom:16px;font-size:13px">
            Hedef sitenin doğrudan taranması sonucu tespit edilen güvenlik bulguları
        </p>
        <table>
            <thead>
                <tr><th>#</th><th>Severity</th><th>Bulgu Tipi</th><th>Başlık</th><th>Açıklama</th><th>URL</th></tr>
            </thead>
            <tbody id="activeBody"></tbody>
        </table>
    </div>
    <div class="empty" id="emptyActive">
        <div class="icon">🎯</div>
        <p>Hedef domain girerek aktif web taramasını başlatın.<br>
        <small style="color:var(--accent)">API key gerektirmez — 12 tarama modülü ile doğrudan hedefi analiz eder</small></p>
    </div>
</div>

<!-- Findings Tab -->
<div class="tab-content" id="tab-findings">
    <div class="results-section" id="resultsSection" style="display:none">
        <h2>🔍 Tespit Edilen Credential Sızıntıları</h2>
        <p style="color:var(--muted);margin-bottom:16px;font-size:13px">
            Internet ortamından pasif kaynaklarla tespit edilen credential sızıntıları
        </p>
        <table>
            <thead>
                <tr><th>#</th><th>Severity</th><th>Tip</th><th>Değer</th><th>Kaynak</th><th>URL</th></tr>
            </thead>
            <tbody id="findingsBody"></tbody>
        </table>
    </div>
    <div class="empty" id="emptyState" style="display:none">
        <div class="icon">🔍</div>
        <p>Yukarıdan hedef girerek taramayı başlatın.</p>
    </div>
</div>

<!-- OSINT Tab -->
<div class="tab-content" id="tab-osint">
    <div class="results-section">
        <h2>🌐 Gelişmiş OSINT Sonuçları</h2>
        <div class="osint-grid" id="osintGrid">
            <div class="empty"><p>Tarama tamamlandıktan sonra OSINT verileri burada görünecek.</p></div>
        </div>
    </div>
</div>

<!-- Reports Tab -->
<div class="tab-content" id="tab-reports">
    <div class="results-section">
        <h2>📄 Oluşturulan Raporlar</h2>
        <div class="report-links" id="reportLinks">
            <div class="empty" style="width:100%"><p>Tarama tamamlandıktan sonra raporlar burada görünecek.</p></div>
        </div>
    </div>
</div>

<!-- AI Analysis Tab -->
<div class="tab-content" id="tab-ai">
    <div class="results-section">
        <h2>🤖 AI Destekli Derin Analiz</h2>
        <div id="aiStatusBar" style="display:flex;align-items:center;gap:12px;margin-bottom:20px;padding:12px;background:rgba(124,58,237,0.1);border:1px solid rgba(124,58,237,0.3);border-radius:8px">
            <div id="aiProviderBadge" style="padding:4px 12px;border-radius:12px;font-size:12px;background:rgba(0,212,255,0.15);color:var(--accent)">Provider: Bekleniyor</div>
            <div id="aiDuration" style="font-size:12px;color:var(--muted)"></div>
            <button id="reanalyzeBtn" onclick="reanalyzeAI()" style="margin-left:auto;padding:6px 16px;border:1px solid var(--accent2);background:transparent;color:var(--accent2);border-radius:6px;cursor:pointer;font-size:12px;display:none">🔄 Tekrar Analiz Et</button>
        </div>
        
        <!-- Risk Score Card -->
        <div id="aiRiskCard" style="display:none;margin-bottom:24px;padding:24px;background:linear-gradient(135deg,#131a2b,#1a2744);border-radius:12px;border:1px solid var(--border)">
            <div style="display:flex;align-items:center;gap:20px">
                <div id="aiRiskGauge" style="width:100px;height:100px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:bold;border:4px solid var(--danger)">0</div>
                <div>
                    <h3 id="aiRiskCategory" style="margin-bottom:4px">Risk Kategorisi</h3>
                    <p id="aiRiskBreakdown" style="font-size:13px;color:var(--muted)"></p>
                </div>
            </div>
        </div>
        
        <!-- Attack Chains -->
        <div id="aiAttackChains" style="display:none;margin-bottom:24px">
            <h3 style="margin-bottom:12px;color:var(--danger)">⚔️ Tespit Edilen Saldırı Zincirleri</h3>
            <div id="aiChainsGrid" style="display:grid;gap:12px"></div>
        </div>
        
        <!-- Executive Summary -->
        <div id="aiSummary" style="display:none;margin-bottom:24px">
            <h3 style="margin-bottom:12px;color:var(--accent)">📊 Yönetici Özeti (AI)</h3>
            <div id="aiSummaryContent" style="padding:20px;background:var(--card2);border-radius:8px;font-size:14px;line-height:1.8;white-space:pre-wrap;max-height:600px;overflow-y:auto"></div>
        </div>
        
        <!-- Remediation Plan -->
        <div id="aiRemediation" style="display:none;margin-bottom:24px">
            <h3 style="margin-bottom:12px;color:var(--success)">🛠️ Detaylı Remediation Planı</h3>
            <div id="aiRemediationContent" style="display:grid;gap:10px"></div>
        </div>
        
        <!-- KVKK/GDPR -->
        <div id="aiKvkk" style="display:none;margin-bottom:24px">
            <h3 style="margin-bottom:12px;color:var(--warning)">⚖️ KVKK / GDPR Değerlendirmesi</h3>
            <div id="aiKvkkContent" style="padding:20px;background:var(--card2);border-radius:8px;font-size:14px;line-height:1.6"></div>
        </div>
        
        <div class="empty" id="emptyAI">
            <div class="icon">🤖</div>
            <p>Tarama tamamlandığında AI analizi otomatik çalışacak.<br>
            <small style="color:var(--accent2)">Anthropic Claude / Ollama / Groq / OpenAI ile derin güvenlik analizi</small></p>
        </div>
    </div>
</div>

<!-- History Tab -->
<div class="tab-content" id="tab-history">
    <div class="results-section">
        <h2>📜 Tarama Geçmişi</h2>
        <div id="scanHistory">
            <div class="empty"><p>Henüz tarama geçmişi yok.</p></div>
        </div>
    </div>
</div>

</div>

<script>
let currentScanId = null;
let pollInterval = null;

async function startScan() {
    const target = document.getElementById('targetInput').value.trim();
    if (!target) { alert('Lütfen hedef girin'); return; }

    const btn = document.getElementById('scanBtn');
    btn.disabled = true;
    btn.innerHTML = '⏳ Taranıyor...';

    document.getElementById('progressWrap').style.display = 'block';
    document.getElementById('progressFill').style.width = '5%';
    document.getElementById('progressText').textContent = 'Tarama başlatılıyor...';
    document.getElementById('statusBadge').textContent = '● Taranıyor';
    document.getElementById('statusBadge').style.background = 'rgba(245,158,11,0.15)';
    document.getElementById('statusBadge').style.color = '#f59e0b';
    document.getElementById('emptyState').style.display = 'none';

    let sourceVal = document.getElementById('sourceSelect').value;
    let sources;
    if (sourceVal === 'all') sources = ['github','shodan','google_dorks','urlscan','paste','intelx'];
    else if (sourceVal === 'free') sources = ['urlscan','paste'];
    else sources = sourceVal.split(',');

    try {
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target, sources, enhanced_osint: true })
        });
        const data = await resp.json();
        currentScanId = data.scan_id;
        pollInterval = setInterval(pollStatus, 2000);
    } catch(e) {
        alert('Tarama başlatılamadı: ' + e.message);
        btn.disabled = false;
        btn.innerHTML = '🚀 Taramayı Başlat';
    }
}

async function pollStatus() {
    if (!currentScanId) return;
    try {
        const resp = await fetch('/api/scan/' + currentScanId);
        const data = await resp.json();

        document.getElementById('progressFill').style.width = data.progress + '%';
        const progressMsg = data.progress_text || 
            (data.status === 'completed' ? '✅ Tarama tamamlandı!' :
            data.status === 'failed' ? '❌ Tarama başarısız: ' + (data.error || '') :
            'Taranıyor... %' + data.progress);
        document.getElementById('progressText').textContent = progressMsg;

        if (data.status === 'completed') {
            clearInterval(pollInterval);
            showResults(data);
        } else if (data.status === 'failed') {
            clearInterval(pollInterval);
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('scanBtn').innerHTML = '🚀 Taramayı Başlat';
        }
    } catch(e) { console.error(e); }
}

function showResults(data) {
    const btn = document.getElementById('scanBtn');
    btn.disabled = false;
    btn.innerHTML = '🚀 Taramayı Başlat';
    document.getElementById('statusBadge').textContent = '● Tamamlandı';
    document.getElementById('statusBadge').style.background = 'rgba(34,197,94,0.15)';
    document.getElementById('statusBadge').style.color = '#22c55e';

    // Stats
    document.getElementById('statsGrid').style.display = 'grid';
    document.getElementById('statTotal').textContent = data.total_findings || 0;
    document.getElementById('statCritical').textContent = data.critical_count || 0;
    document.getElementById('statHigh').textContent = data.high_count || 0;
    document.getElementById('statMedium').textContent = data.medium_count || 0;
    document.getElementById('statLow').textContent = data.low_count || 0;
    document.getElementById('statInfo').textContent = data.info_count || 0;
    document.getElementById('statSources').textContent = (data.sources_scanned || []).length;

    // Tabs
    document.getElementById('tabsWrap').style.display = 'flex';

    // === Active Scan Results ===
    const activeBody = document.getElementById('activeBody');
    activeBody.innerHTML = '';
    const activeFindings = data.active_findings || [];
    const sevOrder = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
    activeFindings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
    
    activeFindings.forEach((f, i) => {
        const tr = document.createElement('tr');
        const badgeClass = f.severity === 'INFO' ? 'LOW' : f.severity;
        const descShort = (f.description || '').substring(0, 120) + ((f.description||'').length > 120 ? '...' : '');
        tr.innerHTML = `
            <td>${i+1}</td>
            <td><span class="badge ${badgeClass}">${f.severity}</span></td>
            <td style="white-space:nowrap">${f.finding_type.replace(/_/g,' ')}</td>
            <td><b>${f.title}</b></td>
            <td style="font-size:12px;max-width:300px">${descShort}</td>
            <td><a href="${f.url}" target="_blank" style="color:var(--accent)">Aç →</a></td>`;
        activeBody.appendChild(tr);
    });
    
    if (activeFindings.length > 0) {
        document.getElementById('activeSection').style.display = 'block';
        document.getElementById('emptyActive').style.display = 'none';
    } else {
        document.getElementById('activeSection').style.display = 'none';
        document.getElementById('emptyActive').innerHTML = '<div class="icon">✅</div><p>Aktif taramada bulgu tespit edilemedi.</p>';
    }

    // === Credential Findings ===
    const tbody = document.getElementById('findingsBody');
    tbody.innerHTML = '';
    const creds = (data.credentials || []).sort((a,b) => {
        const order = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
        return (order[a.severity]||4) - (order[b.severity]||4);
    });

    creds.forEach((c, i) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${i+1}</td>
            <td><span class="badge ${c.severity}">${c.severity}</span></td>
            <td>${c.credential_type}</td>
            <td><code style="font-size:12px">${c.matched_value}</code></td>
            <td>${c.source}</td>
            <td><a href="${c.source_url}" target="_blank" style="color:var(--accent)">Aç →</a></td>`;
        tbody.appendChild(tr);
    });

    document.getElementById('resultsSection').style.display = 'block';

    // OSINT
    const osintGrid = document.getElementById('osintGrid');
    osintGrid.innerHTML = '';
    if (data.osint) {
        for (const [key, values] of Object.entries(data.osint)) {
            if (!values || (Array.isArray(values) && values.length === 0)) continue;
            const items = Array.isArray(values) ? values : [values];
            items.forEach(item => {
                const card = document.createElement('div');
                card.className = 'osint-card';
                let title = item.source || key;
                let content = '';

                if (item.type === 'subdomain_enumeration') {
                    title = '🌍 Subdomain Keşfi (' + key + ')';
                    const subs = item.unique_subdomains || item.subdomains || [];
                    content = '<ul>' + subs.slice(0,15).map(s => '<li>'+s+'</li>').join('') + '</ul>';
                    if (subs.length > 15) content += '<p style="color:var(--accent);font-size:12px">+' + (subs.length-15) + ' daha...</p>';
                } else if (item.type === 'historical_exposure') {
                    title = '📜 Wayback Machine';
                    const urls = item.sensitive_urls || [];
                    content = '<p style="margin-bottom:8px">Toplam URL: ' + item.total_urls_found + ' | Hassas: ' + item.sensitive_count + '</p>';
                    content += '<ul>' + urls.slice(0,10).map(u => '<li title="'+u.url+'">'+u.matched_pattern+': '+(u.url||'').substring(0,60)+'</li>').join('') + '</ul>';
                } else if (item.type === 'domain_report') {
                    title = '🛡️ VirusTotal';
                    content = `<p>Malicious: <b style="color:var(--danger)">${item.malicious}</b> | Suspicious: <b>${item.suspicious}</b> | Reputation: ${item.reputation}</p>`;
                } else if (item.type === 'data_breach') {
                    title = '💀 Veri İhlali: ' + (item.breach_name || '');
                    content = `<p>Tarih: ${item.breach_date}<br>Etkilenen: <b>${(item.pwned_count||0).toLocaleString()}</b><br>Veri: ${(item.data_classes||[]).join(', ')}</p>`;
                } else if (item.type === 'email_intelligence') {
                    title = '📧 Email Intelligence';
                    content = `<p>Org: ${item.organization} | Pattern: ${item.pattern} | Toplam: ${item.total_emails}</p>`;
                    const emails = item.emails_found || [];
                    content += '<ul>' + emails.slice(0,8).map(e => '<li>'+e.email+' ('+e.type+', %'+e.confidence+')</li>').join('') + '</ul>';
                } else if (item.type === 'leaked_credentials') {
                    title = '🔑 Sızan Kimlik Bilgileri (Dehashed)';
                    content = `<p>Toplam: <b style="color:var(--danger)">${item.total_results}</b></p>`;
                } else {
                    content = '<pre style="font-size:11px;overflow-x:auto">' + JSON.stringify(item, null, 2).substring(0, 500) + '</pre>';
                }

                card.innerHTML = '<h3>' + title + '</h3>' + content;
                osintGrid.appendChild(card);
            });
        }
    }
    if (!osintGrid.children.length) osintGrid.innerHTML = '<div class="empty"><p>OSINT verisi bulunamadı.</p></div>';

    // Reports
    const reportLinks = document.getElementById('reportLinks');
    reportLinks.innerHTML = '';
    if (data.reports) {
        if (data.reports.html) reportLinks.innerHTML += `<a class="report-link" href="/api/report/${data.reports.html}" target="_blank">🌐 HTML Rapor</a>`;
        if (data.reports.markdown) reportLinks.innerHTML += `<a class="report-link" href="/api/report/${data.reports.markdown}" target="_blank">📋 Markdown Rapor</a>`;
        if (data.reports.json) reportLinks.innerHTML += `<a class="report-link" href="/api/report/${data.reports.json}" target="_blank">📊 JSON Rapor</a>`;
    }

    // === AI Analysis ===
    if (data.ai_analysis) showAIAnalysis(data.ai_analysis);

    // History
    loadHistory();
}

function switchTab(name) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    document.getElementById('tab-' + name).classList.add('active');
}

async function loadHistory() {
    try {
        const resp = await fetch('/api/scans');
        const scans = await resp.json();
        const container = document.getElementById('scanHistory');
        if (!scans.length) return;
        container.innerHTML = '';
        scans.reverse().forEach(s => {
            const div = document.createElement('div');
            div.className = 'scan-item';
            div.innerHTML = `
                <div><span class="target">${s.target}</span>
                <span class="meta">${s.scan_id} | ${s.started_at}</span></div>
                <div>
                    <span class="badge ${s.critical_count > 0 ? 'CRITICAL' : s.total_findings > 0 ? 'MEDIUM' : 'LOW'}">
                        ${s.total_findings} bulgu
                    </span>
                </div>`;
            div.onclick = () => { currentScanId = s.scan_id; fetch('/api/scan/'+s.scan_id).then(r=>r.json()).then(showResults); };
            container.appendChild(div);
        });
    } catch(e) {}
}

// Enter key
document.getElementById('targetInput').addEventListener('keypress', e => { if(e.key==='Enter') startScan(); });

// ============================================================
// AI Analysis UI Functions
// ============================================================
function showAIAnalysis(ai) {
    if (!ai || ai.error) {
        document.getElementById('emptyAI').innerHTML = '<div class="icon">⚠️</div><p>AI analizi çalıştırılamadı: ' + (ai?.error || 'Bilinmeyen hata') + '</p>';
        return;
    }
    document.getElementById('emptyAI').style.display = 'none';
    document.getElementById('reanalyzeBtn').style.display = 'inline-block';
    
    // Provider info
    document.getElementById('aiProviderBadge').textContent = 'Provider: ' + (ai.provider_used || 'rule_engine');
    document.getElementById('aiDuration').textContent = ai.analysis_duration_seconds ? 'Süre: ' + ai.analysis_duration_seconds.toFixed(1) + 's | LLM Çağrısı: ' + (ai.llm_calls_made || 0) : '';
    
    // Risk Score
    if (ai.risk_assessment) {
        document.getElementById('aiRiskCard').style.display = 'block';
        const risk = ai.risk_assessment;
        const score = risk.overall_risk_score || 0;
        const gauge = document.getElementById('aiRiskGauge');
        gauge.textContent = score;
        gauge.style.borderColor = score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : score >= 40 ? '#fb923c' : '#22c55e';
        gauge.style.color = gauge.style.borderColor;
        document.getElementById('aiRiskCategory').textContent = risk.risk_category || 'N/A';
        
        let breakdown = '';
        if (risk.risk_breakdown) {
            const rb = risk.risk_breakdown;
            if (rb.critical_findings !== undefined) {
                breakdown = 'Kritik: ' + (rb.critical_findings||0) + ' | Yüksek: ' + (rb.high_findings||0) + ' | Orta: ' + (rb.medium_findings||0) + ' | Düşük: ' + (rb.low_findings||0);
            } else if (rb.confidentiality !== undefined) {
                breakdown = 'Gizlilik: ' + rb.confidentiality + '/10 | Bütünlük: ' + rb.integrity + '/10 | Erişilebilirlik: ' + rb.availability + '/10';
            }
        }
        if (risk.findings_scored) {
            breakdown += ' | CVSS Skorlanmış: ' + risk.findings_scored.length + ' bulgu';
        }
        document.getElementById('aiRiskBreakdown').textContent = breakdown;
    }
    
    // Attack Chains
    const chains = ai.attack_chains?.attack_chains || ai.attack_chains?.chains || [];
    if (chains.length > 0) {
        document.getElementById('aiAttackChains').style.display = 'block';
        const grid = document.getElementById('aiChainsGrid');
        grid.innerHTML = '';
        chains.forEach((chain, i) => {
            const sevColor = chain.severity === 'CRITICAL' ? '#ef4444' : chain.severity === 'HIGH' ? '#f59e0b' : '#fb923c';
            const card = document.createElement('div');
            card.style.cssText = 'padding:16px;background:var(--card2);border-radius:8px;border-left:4px solid ' + sevColor;
            let html = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">';
            html += '<h4 style="color:' + sevColor + '">' + (i+1) + '. ' + chain.name + '</h4>';
            html += '<span style="font-size:11px;padding:2px 8px;border-radius:4px;background:rgba(255,255,255,0.05)">' + chain.severity + '</span></div>';
            
            if (chain.steps) {
                html += '<div style="font-size:13px;margin-bottom:8px">';
                chain.steps.forEach(step => { html += '<div style="padding:2px 0;color:var(--muted)">→ ' + step + '</div>'; });
                html += '</div>';
            }
            
            if (chain.success_probability) html += '<span style="font-size:12px;color:var(--muted)">Başarı: <b>' + chain.success_probability + '</b></span> ';
            if (chain.potential_damage) html += '<span style="font-size:12px;color:var(--danger)"> | Hasar: ' + chain.potential_damage + '</span>';
            
            card.innerHTML = html;
            grid.appendChild(card);
        });
    }
    
    // Executive Summary
    if (ai.executive_summary) {
        document.getElementById('aiSummary').style.display = 'block';
        let summaryHtml = ai.executive_summary
            .replace(/^### (.+)$/gm, '<h4 style="color:var(--accent);margin-top:16px">$1</h4>')
            .replace(/^## (.+)$/gm, '<h3 style="color:var(--accent);margin-top:20px;padding-bottom:4px;border-bottom:1px solid var(--border)">$1</h3>')
            .replace(/^# (.+)$/gm, '<h2 style="color:var(--accent);margin-bottom:8px">$1</h2>')
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/\n/g, '<br>');
        document.getElementById('aiSummaryContent').innerHTML = summaryHtml;
    }
    
    // Remediation
    const rems = ai.remediation_plan?.remediations || [];
    if (rems.length > 0) {
        document.getElementById('aiRemediation').style.display = 'block';
        const container = document.getElementById('aiRemediationContent');
        container.innerHTML = '';
        rems.forEach((r, i) => {
            const card = document.createElement('div');
            const sevColor = r.severity === 'CRITICAL' ? '#ef4444' : r.severity === 'HIGH' ? '#f59e0b' : '#fb923c';
            card.style.cssText = 'padding:14px;background:var(--card2);border-radius:8px;border-left:3px solid ' + sevColor;
            let html = '<div style="display:flex;gap:12px;align-items:baseline;margin-bottom:6px">';
            html += '<span style="color:' + sevColor + ';font-weight:bold">#' + (r.priority || i+1) + '</span>';
            html += '<strong>' + r.finding + '</strong>';
            html += '<span class="badge ' + r.severity + '" style="font-size:10px">' + r.severity + '</span></div>';
            
            const imm = typeof r.immediate === 'object' ? r.immediate.action : r.immediate;
            const st = typeof r.short_term === 'object' ? r.short_term.action : r.short_term;
            const mt = typeof r.medium_term === 'object' ? r.medium_term.action : r.medium_term;
            
            if (imm) html += '<div style="font-size:12px;margin:4px 0"><span style="color:#ef4444">⚡Acil:</span> ' + imm + '</div>';
            if (st) html += '<div style="font-size:12px;margin:4px 0"><span style="color:#f59e0b">📅Kısa Vade:</span> ' + st + '</div>';
            if (mt) html += '<div style="font-size:12px;margin:4px 0"><span style="color:#22c55e">🔄Orta Vade:</span> ' + mt + '</div>';
            
            card.innerHTML = html;
            container.appendChild(card);
        });
    }
    
    // KVKK/GDPR
    if (ai.kvkk_gdpr && ai.kvkk_gdpr.kvkk_assessment) {
        document.getElementById('aiKvkk').style.display = 'block';
        const kvkk = ai.kvkk_gdpr;
        const ka = kvkk.kvkk_assessment;
        let html = '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px">';
        
        const riskColor = kvkk.risk_to_individuals === 'CRITICAL' ? '#ef4444' : kvkk.risk_to_individuals === 'HIGH' ? '#f59e0b' : kvkk.risk_to_individuals === 'MEDIUM' ? '#fb923c' : '#22c55e';
        html += '<div style="padding:8px 16px;background:rgba(255,255,255,0.03);border-radius:6px"><small style="color:var(--muted)">Bireysel Risk</small><br><b style="color:' + riskColor + '">' + (kvkk.risk_to_individuals || 'N/A') + '</b></div>';
        html += '<div style="padding:8px 16px;background:rgba(255,255,255,0.03);border-radius:6px"><small style="color:var(--muted)">KVKK Bildirim</small><br><b style="color:' + (ka.breach_notification_required ? '#ef4444' : '#22c55e') + '">' + (ka.breach_notification_required ? 'GEREKLİ' : 'Gerekli Değil') + '</b></div>';
        
        if (kvkk.gdpr_assessment) {
            const ga = kvkk.gdpr_assessment;
            html += '<div style="padding:8px 16px;background:rgba(255,255,255,0.03);border-radius:6px"><small style="color:var(--muted)">GDPR Art.33</small><br><b style="color:' + (ga.article_33_triggered ? '#ef4444' : '#22c55e') + '">' + (ga.article_33_triggered ? 'TETİKLENDİ' : 'Hayır') + '</b></div>';
        }
        html += '</div>';
        
        if (ka.data_categories) html += '<p style="font-size:13px;margin:8px 0">Veri Kategorileri: <b>' + ka.data_categories.join(', ') + '</b></p>';
        if (ka.recommended_actions) {
            html += '<div style="margin-top:8px"><p style="font-size:12px;color:var(--muted);margin-bottom:4px">Önerilen Aksiyonlar:</p>';
            ka.recommended_actions.forEach(a => { html += '<div style="font-size:13px;padding:2px 0">→ ' + a + '</div>'; });
            html += '</div>';
        }
        
        document.getElementById('aiKvkkContent').innerHTML = html;
    }
}

async function reanalyzeAI() {
    if (!currentScanId) return;
    const btn = document.getElementById('reanalyzeBtn');
    btn.disabled = true;
    btn.textContent = '⏳ Analiz ediliyor...';
    try {
        const resp = await fetch('/api/ai-reanalyze/' + currentScanId, { method: 'POST' });
        const data = await resp.json();
        showAIAnalysis(data);
        btn.textContent = '✅ Tamamlandı';
        setTimeout(() => { btn.textContent = '🔄 Tekrar Analiz Et'; btn.disabled = false; }, 2000);
    } catch(e) {
        btn.textContent = '❌ Hata';
        btn.disabled = false;
    }
}

// LLM Status check on load
async function checkLLMStatus() {
    try {
        const resp = await fetch('/api/llm-status');
        const data = await resp.json();
        console.log('LLM Status:', data);
    } catch(e) {}
}
checkLLMStatus();

// Load history on start
loadHistory();
</script>
</body>
</html>"""

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
