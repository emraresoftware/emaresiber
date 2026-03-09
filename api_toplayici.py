#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║      Emaresiber — Ücretsiz AI API Toplayıcı                     ║
║                                                                  ║
║  Görev: Çeşitli kaynaklardan ücretsiz / freemium yapay zeka     ║
║         API'lerini toplar ve EmareAPI kasasına kaydeder.        ║
║                                                                  ║
║  Kaynaklar:                                                      ║
║   • GitHub public-apis listesi (Machine Learning kategorisi)    ║
║   • Bilinen ücretsiz AI platformları (curated liste)            ║
║   • Hugging Face Inference API                                   ║
║                                                                  ║
║  Kullanım: python api_toplayici.py                               ║
║  Seçenekler:                                                     ║
║    --dry-run       → Sadece listele, EmareAPI'ye kaydetme       ║
║    --emareapi-url  → EmareAPI adresi (varsayılan: localhost:8000)║
║    --token         → JWT token (giriş yerine kullanılabilir)    ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Optional


# ─── Renk Kodları ─────────────────────────────────────────────────────────────
class R:
    YESIL   = "\033[92m"
    SARI    = "\033[93m"
    KIRMIZI = "\033[91m"
    MAVI    = "\033[94m"
    BEYAZ   = "\033[97m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    KALIN   = "\033[1m"

def log(sembol, renk, mesaj):
    zaman = datetime.now().strftime("%H:%M:%S")
    print(f"{R.DIM}[{zaman}]{R.RESET} {renk}{sembol}{R.RESET} {mesaj}")

def bilgi(m):  log("ℹ", R.MAVI,    m)
def basari(m): log("✅", R.YESIL,  m)
def uyari(m):  log("⚠️", R.SARI,   m)
def hata(m):   log("❌", R.KIRMIZI, m)
def baslik(m): print(f"\n{R.KALIN}{R.BEYAZ}{m}{R.RESET}\n{'─'*60}")


# ─── Curated Ücretsiz AI API Listesi ──────────────────────────────────────────
# Kaynaklar: free-for-dev, platform dokümantasyonları, community listeleri
UCRETSIZ_AI_APILER = [

    # ── LLM / Metin Üretimi ──────────────────────────────────────────────────
    {
        "name": "OPENROUTER_API_KEY",
        "platform": "openrouter",
        "description": "OpenRouter — 50+ model tek API ile (ücretsiz modeller mevcut: Llama, Mistral, Gemma vb.)",
        "kayit_url": "https://openrouter.ai/keys",
        "ucretsiz_limit": "Ücretsiz modeller sınırsız (rate limit var)",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "TOGETHER_API_KEY",
        "platform": "together",
        "description": "Together AI — Llama 3, Mixtral, Gemma ücretsiz katman ($25 başlangıç kredisi)",
        "kayit_url": "https://api.together.ai",
        "ucretsiz_limit": "$25 ücretsiz kredi",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "DEEPINFRA_API_KEY",
        "platform": "deepinfra",
        "description": "DeepInfra — Llama, Mistral, Whisper barındırma, $0.5 ücretsiz kredi",
        "kayit_url": "https://deepinfra.com/dash",
        "ucretsiz_limit": "$0.5 ücretsiz kredi",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "HUGGINGFACE_API_KEY",
        "platform": "huggingface",
        "description": "Hugging Face Inference API — 150+ model ücretsiz (Llama, Mistral, BLOOM vb.)",
        "kayit_url": "https://huggingface.co/settings/tokens",
        "ucretsiz_limit": "Aylık 30,000 istek ücretsiz",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "COHERE_API_KEY",
        "platform": "cohere",
        "description": "Cohere — Command R+ modeli, ücretsiz trial katman (NLP ve embedding)",
        "kayit_url": "https://dashboard.cohere.com/api-keys",
        "ucretsiz_limit": "5 req/dk ücretsiz trial",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "MISTRAL_API_KEY",
        "platform": "mistral",
        "description": "Mistral AI — mistral-small modeli ücretsiz katman, Avrupa tabanlı",
        "kayit_url": "https://console.mistral.ai/api-keys",
        "ucretsiz_limit": "Ücretsiz katman (rate limit var)",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "NOVITA_API_KEY",
        "platform": "novita",
        "description": "Novita AI — Llama, Mistral, DeepSeek; $0.5 ücretsiz kredi",
        "kayit_url": "https://novita.ai/settings/key-management",
        "ucretsiz_limit": "$0.5 ücretsiz başlangıç kredisi",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "CEREBRAS_API_KEY",
        "platform": "cerebras",
        "description": "Cerebras Inference — Llama 3.1 çok hızlı çıkarım, ücretsiz katman",
        "kayit_url": "https://cloud.cerebras.ai",
        "ucretsiz_limit": "Ücretsiz katman (hız sınırı var)",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "SAMBANOVA_API_KEY",
        "platform": "sambanova",
        "description": "SambaNova Cloud — Llama 3.1 405B ücretsiz, yüksek bant genişliği",
        "kayit_url": "https://cloud.sambanova.ai/apis",
        "ucretsiz_limit": "Ücretsiz katman",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "FIREWORKS_API_KEY",
        "platform": "fireworks",
        "description": "Fireworks AI — Llama, Mixtral, FireLLaVA; $1 ücretsiz kredi",
        "kayit_url": "https://fireworks.ai/account/api-keys",
        "ucretsiz_limit": "$1 ücretsiz kredi",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "PERPLEXITY_API_KEY",
        "platform": "perplexity",
        "description": "Perplexity AI — llama-3.1-sonar modeli web aramalı, $5 ücretsiz kredi",
        "kayit_url": "https://www.perplexity.ai/settings/api",
        "ucretsiz_limit": "$5 ücretsiz başlangıç kredisi",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "KLUSTER_API_KEY",
        "platform": "kluster",
        "description": "Kluster AI — batch inference, Llama 3.3 70B ücretsiz",
        "kayit_url": "https://kluster.ai",
        "ucretsiz_limit": "Ücretsiz katman",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "FEATHERLESS_API_KEY",
        "platform": "featherless",
        "description": "Featherless AI — 2000+ serverless model, ücretsiz deneme",
        "kayit_url": "https://featherless.ai",
        "ucretsiz_limit": "Ücretsiz deneme katmanı",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "AIMLAPI_KEY",
        "platform": "aimlapi",
        "description": "AIML API — 200+ model tek API (GPT-4o, Llama, Claude vb.); ücretsiz katman",
        "kayit_url": "https://aimlapi.com/app/keys",
        "ucretsiz_limit": "Ücretsiz katman",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },

    # ── Görüntü Üretimi ──────────────────────────────────────────────────────
    {
        "name": "STABILITY_API_KEY",
        "platform": "stability",
        "description": "Stability AI — Stable Diffusion 3, SDXL görüntü üretimi; 25 ücretsiz kredi/ay",
        "kayit_url": "https://platform.stability.ai/account/keys",
        "ucretsiz_limit": "25 kredi/ay ücretsiz",
        "kategori": "Görüntü Üretimi",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "SEGMIND_API_KEY",
        "platform": "segmind",
        "description": "Segmind — Stable Diffusion, FLUX, FaceSwap vb.; ücretsiz katman",
        "kayit_url": "https://cloud.segmind.com/console/api-keys",
        "ucretsiz_limit": "$0.2 ücretsiz kredi",
        "kategori": "Görüntü Üretimi",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "MONSTER_API_KEY",
        "platform": "monsterapi",
        "description": "Monster API — görüntü & metin üretimi, ücretsiz 150 token/gün",
        "kayit_url": "https://monsterapi.ai/user/dashboard",
        "ucretsiz_limit": "150 ücretsiz token/gün",
        "kategori": "Görüntü Üretimi",
        "allowed_roles": "admin,dervish",
    },

    # ── Ses / TTS / STT ──────────────────────────────────────────────────────
    {
        "name": "ASSEMBLYAI_API_KEY",
        "platform": "assemblyai",
        "description": "AssemblyAI — konuşma tanıma (STT), ücretsiz 100 saat/ay",
        "kayit_url": "https://www.assemblyai.com/dashboard",
        "ucretsiz_limit": "100 saat/ay ücretsiz",
        "kategori": "Ses/STT",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "DEEPGRAM_API_KEY",
        "platform": "deepgram",
        "description": "Deepgram — gerçek zamanlı STT, $200 ücretsiz kredi",
        "kayit_url": "https://console.deepgram.com",
        "ucretsiz_limit": "$200 ücretsiz başlangıç kredisi",
        "kategori": "Ses/STT",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "ELEVENLABS_API_KEY",
        "platform": "elevenlabs",
        "description": "ElevenLabs — TTS ses sentezi, ücretsiz 10,000 karakter/ay",
        "kayit_url": "https://elevenlabs.io/app/settings/api-keys",
        "ucretsiz_limit": "10,000 karakter/ay ücretsiz",
        "kategori": "Ses/TTS",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "GLADIA_API_KEY",
        "platform": "gladia",
        "description": "Gladia — ses transkripsiyonu, ücretsiz 720 dk/ay",
        "kayit_url": "https://app.gladia.io",
        "ucretsiz_limit": "720 dakika/ay ücretsiz",
        "kategori": "Ses/STT",
        "allowed_roles": "admin,dervish",
    },

    # ── Gömme / Vektör ───────────────────────────────────────────────────────
    {
        "name": "VOYAGE_API_KEY",
        "platform": "voyageai",
        "description": "Voyage AI — embedding modelleri (voyage-3-lite), 200M token/ay ücretsiz",
        "kayit_url": "https://dash.voyageai.com/api-keys",
        "ucretsiz_limit": "200M token/ay ücretsiz",
        "kategori": "Embedding",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "JINA_API_KEY",
        "platform": "jina",
        "description": "Jina AI — embedding, reranker, reader API; 1M token/ay ücretsiz",
        "kayit_url": "https://jina.ai/api-key",
        "ucretsiz_limit": "1M token/ay ücretsiz",
        "kategori": "Embedding",
        "allowed_roles": "admin,dervish",
    },

    # ── Çeviri ───────────────────────────────────────────────────────────────
    {
        "name": "DEEPL_API_KEY",
        "platform": "deepl",
        "description": "DeepL Translate — ücretsiz katman 500,000 karakter/ay",
        "kayit_url": "https://www.deepl.com/pro-api",
        "ucretsiz_limit": "500,000 karakter/ay ücretsiz",
        "kategori": "Çeviri",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "LIBRE_TRANSLATE_URL",
        "platform": "libretranslate",
        "description": "LibreTranslate — açık kaynak çeviri API (self-hosted veya public instance)",
        "kayit_url": "https://libretranslate.com",
        "ucretsiz_limit": "Public instance ücretsiz (rate limit var)",
        "kategori": "Çeviri",
        "allowed_roles": "admin,dervish",
    },

    # ── Moderasyon / Analiz ──────────────────────────────────────────────────
    {
        "name": "PERSPECTIVE_API_KEY",
        "platform": "perspective",
        "description": "Google Perspective API — yorum toksiklik analizi, ücretsiz",
        "kayit_url": "https://developers.perspectiveapi.com/s/docs-get-started",
        "ucretsiz_limit": "1 QPS ücretsiz (artırılabilir)",
        "kategori": "Moderasyon",
        "allowed_roles": "admin,dervish",
    },

    # ── Kod Üretimi ──────────────────────────────────────────────────────────
    {
        "name": "CODEIUM_API_KEY",
        "platform": "codeium",
        "description": "Codeium (Windsurf) — kod tamamlama API, bireysel ücretsiz",
        "kayit_url": "https://codeium.com/account/apikeys",
        "ucretsiz_limit": "Bireysel kullanım ücretsiz",
        "kategori": "Kod Üretimi",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "TABNINE_API_KEY",
        "platform": "tabnine",
        "description": "Tabnine — AI kod asistanı, ücretsiz temel plan",
        "kayit_url": "https://www.tabnine.com",
        "ucretsiz_limit": "Temel plan ücretsiz",
        "kategori": "Kod Üretimi",
        "allowed_roles": "admin,dervish",
    },

    # ── Arama / Web Scraping ─────────────────────────────────────────────────
    {
        "name": "TAVILY_API_KEY",
        "platform": "tavily",
        "description": "Tavily — AI-optimized web arama API, 1000 arama/ay ücretsiz",
        "kayit_url": "https://app.tavily.com",
        "ucretsiz_limit": "1000 arama/ay ücretsiz",
        "kategori": "Arama",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "SERPER_API_KEY",
        "platform": "serper",
        "description": "Serper.dev — Google Search API, 2500 arama ücretsiz başlangıç",
        "kayit_url": "https://serper.dev/api-key",
        "ucretsiz_limit": "2500 ücretsiz arama",
        "kategori": "Arama",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "BRAVE_SEARCH_API_KEY",
        "platform": "bravesearch",
        "description": "Brave Search API — bağımsız web araması, 2000 sorgu/ay ücretsiz",
        "kayit_url": "https://api.search.brave.com/app/keys",
        "ucretsiz_limit": "2000 sorgu/ay ücretsiz",
        "kategori": "Arama",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "EXA_API_KEY",
        "platform": "exa",
        "description": "Exa AI Search — semantik web araması, 1000 arama/ay ücretsiz",
        "kayit_url": "https://dashboard.exa.ai/api-keys",
        "ucretsiz_limit": "1000 arama/ay ücretsiz",
        "kategori": "Arama",
        "allowed_roles": "admin,dervish",
    },

    # ── OCR / Görüntü Analizi ────────────────────────────────────────────────
    {
        "name": "OCRSPACE_API_KEY",
        "platform": "ocrspace",
        "description": "OCR.Space — görüntüden metin çıkarma, 25,000 istek/ay ücretsiz",
        "kayit_url": "https://ocr.space/ocrapi/freekey",
        "ucretsiz_limit": "25,000 istek/ay ücretsiz",
        "kategori": "OCR",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "ROBOFLOW_API_KEY",
        "platform": "roboflow",
        "description": "Roboflow — nesne tespiti & görüntü sınıflandırma, ücretsiz katman",
        "kayit_url": "https://app.roboflow.com",
        "ucretsiz_limit": "Ücretsiz workspace (sınırlı)",
        "kategori": "Görüntü Analizi",
        "allowed_roles": "admin,dervish",
    },

    # ── Genel AI Platformları ────────────────────────────────────────────────
    {
        "name": "REPLICATE_API_KEY",
        "platform": "replicate",
        "description": "Replicate — binlerce açık kaynak AI modeli API olarak çalıştır",
        "kayit_url": "https://replicate.com/account/api-tokens",
        "ucretsiz_limit": "$0.05 ücretsiz başlangıç kredisi",
        "kategori": "Genel AI",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "FREEAGENT_API_KEY",
        "platform": "aimlapi",
        "description": "AI/ML API — ücretsiz Llama 3.1, GPT-4o-mini gibi modeller",
        "kayit_url": "https://api.aimlapi.com",
        "ucretsiz_limit": "Günlük ücretsiz istek kotası",
        "kategori": "Genel AI",
        "allowed_roles": "admin,dervish",
    },
    {
        "name": "NVIDIA_API_KEY",
        "platform": "nvidia",
        "description": "NVIDIA AI Foundation Models — Llama, Mistral, Nemotron; ücretsiz katman",
        "kayit_url": "https://build.nvidia.com",
        "ucretsiz_limit": "1000 ücretsiz API çağrısı",
        "kategori": "LLM",
        "allowed_roles": "admin,dervish",
    },
]


# ─── GitHub Public APIs Listesinden Çekme ─────────────────────────────────────
GITHUB_PUBLIC_APIS_URL = (
    "https://raw.githubusercontent.com/public-apis/public-apis/master/apis.json"
)
HEDEF_KATEGORILER = {"Machine Learning", "Artificial Intelligence", "Science"}


def github_dan_cek() -> list[dict]:
    """GitHub public-apis reposundan ML/AI kategorisindeki API'leri çeker."""
    bilgi("GitHub public-apis listesi çekiliyor...")
    try:
        req = urllib.request.Request(
            GITHUB_PUBLIC_APIS_URL,
            headers={"User-Agent": "Emaresiber-APIToplayici/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            veri = json.loads(resp.read().decode())
    except Exception as e:
        uyari(f"GitHub'dan çekilemedi: {e}")
        return []

    sonuc = []
    for girdi in veri.get("entries", []):
        kategori = girdi.get("Category", "")
        if kategori not in HEDEF_KATEGORILER:
            continue
        api = girdi.get("API", "")
        auth = girdi.get("Auth", "")
        https = girdi.get("HTTPS", False)
        link = girdi.get("Link", "")
        desc = girdi.get("Description", "")
        if not (api and link):
            continue
        # Auth gerekiyorsa ve ücretsiz değilse es geç
        if auth in ("OAuth", "X-Mashape-Key"):
            continue
        slug = api.lower().replace(" ", "_").replace("-", "_")
        sonuc.append({
            "name":          f"{slug.upper()}_API_KEY",
            "platform":      slug,
            "description":   f"{api} — {desc} {'(HTTPS)' if https else '(HTTP)'}",
            "kayit_url":     link,
            "ucretsiz_limit": "apiKey" if auth == "apiKey" else "Ücretsiz (auth yok)",
            "kategori":      kategori,
            "allowed_roles": "admin,dervish",
        })

    bilgi(f"GitHub'dan {len(sonuc)} AI/ML API bulundu")
    return sonuc


# ─── EmareAPI İle Etkileşim ────────────────────────────────────────────────────

def emareapi_token_al(base_url: str, kullanici: str, sifre: str) -> Optional[str]:
    """EmareAPI'ye giriş yap ve JWT token al."""
    url = f"{base_url}/auth/login"
    veri = json.dumps({"username": kullanici, "password": sifre}).encode()
    req = urllib.request.Request(
        url, data=veri,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode()).get("access_token")
    except Exception as e:
        hata(f"EmareAPI giriş başarısız: {e}")
        return None


def emareapi_mevcut_anahtarlar(base_url: str, token: str) -> set:
    """EmareAPI'deki anahtar isimlerini çek."""
    url = f"{base_url}/keys/"
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            anahtarlar = json.loads(resp.read().decode())
            return {a["name"] for a in anahtarlar}
    except Exception as e:
        uyari(f"Mevcut anahtarlar alınamadı: {e}")
        return set()


def emareapi_ekle(base_url: str, token: str, api: dict) -> bool:
    """EmareAPI'ye yeni anahtar şablonu ekle."""
    url = f"{base_url}/keys/"
    payload = {
        "name":          api["name"],
        "platform":      api["platform"],
        "value":         "BURAYA_EKLENECEK",
        "description":   f"{api['description']} | Ücretsiz: {api.get('ucretsiz_limit','?')} | Kayıt: {api.get('kayit_url','')}",
        "allowed_roles": api.get("allowed_roles", "admin,dervish"),
    }
    veri = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=veri,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        uyari(f"  {api['name']} eklenemedi ({e.code}): {body[:80]}")
        return False
    except Exception as e:
        uyari(f"  {api['name']} eklenemedi: {e}")
        return False


# ─── Ana Akış ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Emaresiber — Ücretsiz AI API Toplayıcı")
    parser.add_argument("--dry-run",      action="store_true",  help="Sadece listele, kaydetme")
    parser.add_argument("--emareapi-url", default="http://localhost:8000", help="EmareAPI adresi")
    parser.add_argument("--kullanici",    default="admin",       help="EmareAPI kullanıcı adı")
    parser.add_argument("--sifre",        default="admin",       help="EmareAPI şifresi")
    parser.add_argument("--token",        default=None,          help="JWT token (giriş yerine)")
    parser.add_argument("--github",       action="store_true",   help="GitHub listesini de çek")
    args = parser.parse_args()

    baslik("🛡️  Emaresiber — Ücretsiz AI API Toplayıcı")
    bilgi(f"EmareAPI: {args.emareapi_url}")
    bilgi(f"Mod: {'DRY-RUN (kayıt yok)' if args.dry_run else 'CANLI (kayıt var)'}")

    # ── API Listesini Hazırla ──────────────────────────────────────────────
    baslik("📋 API Listesi Hazırlanıyor")
    tum_apiler = list(UCRETSIZ_AI_APILER)
    bilgi(f"Curated liste: {len(tum_apiler)} API")

    if args.github:
        github_apiler = github_dan_cek()
        # Mevcut isimlerle çakışma engellemek için
        mevcut_isimler = {a["name"] for a in tum_apiler}
        yeni = [a for a in github_apiler if a["name"] not in mevcut_isimler]
        tum_apiler.extend(yeni)
        bilgi(f"GitHub'dan {len(yeni)} yeni API eklendi → Toplam: {len(tum_apiler)}")

    # ── Dry Run ───────────────────────────────────────────────────────────
    if args.dry_run:
        baslik(f"📜 Bulunan {len(tum_apiler)} Ücretsiz AI API")
        kategoriler = {}
        for api in tum_apiler:
            kat = api.get("kategori", "Diğer")
            kategoriler.setdefault(kat, []).append(api)
        for kat, apiler in sorted(kategoriler.items()):
            print(f"\n  {R.KALIN}{R.MAVI}{kat}{R.RESET} ({len(apiler)} API)")
            for a in apiler:
                print(f"    {R.YESIL}•{R.RESET} {a['name']:<35} {R.DIM}{a['ucretsiz_limit']}{R.RESET}")
        print()
        bilgi("Dry-run tamamlandı. EmareAPI'ye kayıt yapılmadı.")
        return

    # ── EmareAPI Token Al ─────────────────────────────────────────────────
    baslik("🔐 EmareAPI Bağlantısı")
    token = args.token
    if not token:
        bilgi(f"Giriş yapılıyor: {args.kullanici}@{args.emareapi_url}")
        token = emareapi_token_al(args.emareapi_url, args.kullanici, args.sifre)
        if not token:
            hata("Token alınamadı. --kullanici ve --sifre doğru mu?")
            sys.exit(1)
        basari("Token alındı")

    # ── Mevcut Anahtarları Çek ────────────────────────────────────────────
    baslik("🔍 Mevcut Anahtarlar Kontrol Ediliyor")
    mevcut = emareapi_mevcut_anahtarlar(args.emareapi_url, token)
    bilgi(f"EmareAPI'de {len(mevcut)} anahtar mevcut")

    # ── Yeni Olanları Ekle ────────────────────────────────────────────────
    baslik("📥 EmareAPI'ye Ekleniyor")
    eklendi = 0
    atlandi = 0
    basarisiz = 0

    for api in tum_apiler:
        if api["name"] in mevcut:
            atlandi += 1
            continue
        zaman = datetime.now().strftime("%H:%M:%S")
        sys.stdout.write(f"\r  [{zaman}] Ekleniyor: {api['name']:<40}")
        sys.stdout.flush()
        if emareapi_ekle(args.emareapi_url, token, api):
            eklendi += 1
        else:
            basarisiz += 1
        time.sleep(0.1)  # rate-limit koruması

    print()

    # ── Rapor ─────────────────────────────────────────────────────────────
    baslik("📊 Sonuç Raporu")
    basari(f"Yeni eklenen   : {eklendi}")
    bilgi(f"Zaten mevcut   : {atlandi} (atlandı)")
    if basarisiz:
        hata(f"Eklenemedi     : {basarisiz}")
    print()
    bilgi(f"Toplam işlenen : {len(tum_apiler)}")
    bilgi(f"EmareAPI docs  : {args.emareapi_url}/docs")
    print()
    uyari("Sonraki adım: Admin olarak /docs  'a gir, her anahtara gerçek değerini ekle ve is_active=true yap.")
    print()

    # Sonucu Dergah görev kutusuna yaz
    sonuc_dosyasi = (
        "/Users/emre/Desktop/Emare/emareapi/Dergah/"
        "Emaresiber Dervishi/gorev_kutusu/tamamlanan/"
        "gorev_ucretsiz_ai_api_topla_SONUC.json"
    )
    import os, pathlib
    pathlib.Path(os.path.dirname(sonuc_dosyasi)).mkdir(parents=True, exist_ok=True)
    with open(sonuc_dosyasi, "w", encoding="utf-8") as f:
        json.dump({
            "gorev_id":  "gorev_ucretsiz_ai_api_topla",
            "durum":     "tamamlandi",
            "tamamlanma": datetime.now().isoformat(),
            "sonuc": {
                "toplam_api":   len(tum_apiler),
                "yeni_eklenen": eklendi,
                "atlanan":      atlandi,
                "basarisiz":    basarisiz,
            }
        }, f, ensure_ascii=False, indent=2)
    basari(f"Görev sonucu Dergah'a yazıldı → {sonuc_dosyasi}")


if __name__ == "__main__":
    main()
