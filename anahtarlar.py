"""
Emaresiber — Merkezi Anahtar Yöneticisi
========================================
Tüm API anahtarlarını EmareAPI kasasından çeker.

Kullanım (herhangi bir modülde):
    from anahtarlar import gemini_key, openai_key, groq_key
    # veya
    from anahtarlar import anahtar
    key = anahtar("ANTHROPIC_API_KEY")
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

# Geliştirme ortamında .env'den doğrudan okunabilir (fallback)
_FALLBACK = {
    "GEMINI_API_KEY":    os.getenv("GEMINI_API_KEY", ""),
    "GOOGLE_API_KEY":    os.getenv("GOOGLE_API_KEY", ""),
    "OPENAI_API_KEY":    os.getenv("OPENAI_API_KEY", ""),
    "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY", ""),
    "GROQ_API_KEY":      os.getenv("GROQ_API_KEY", ""),
}


@lru_cache(maxsize=1)
def _client():
    """EmareAPI istemcisini oluştur ve cache'le."""
    try:
        from emareapi_client import EmareAPIClient
        return EmareAPIClient()
    except Exception as e:
        print(f"[anahtarlar] EmareAPI client başlatılamadı: {e}")
        return None


def anahtar(isim: str) -> str:
    """
    İsme göre API anahtarını döndür.
    Önce EmareAPI'den çeker; başarısız olursa .env fallback'ine bakar.

    Örnek:
        key = anahtar("GEMINI_API_KEY")
        key = anahtar("OPENAI_API_KEY")
    """
    isim = isim.upper()
    client = _client()
    if client:
        try:
            val = client.get(isim)
            if val and val != "BURAYA_EKLENECEK":
                return val
        except Exception as e:
            print(f"[anahtarlar] EmareAPI'den {isim} alınamadı: {e}")

    # Fallback: .env'den oku
    fallback = _FALLBACK.get(isim) or os.getenv(isim, "")
    if fallback:
        return fallback

    raise ValueError(
        f"'{isim}' anahtarı bulunamadı.\n"
        f"  1. EmareAPI çalışıyor mu? → http://localhost:8000\n"
        f"  2. EMAREAPI_USERNAME/PASSWORD doğru mu? (.env)\n"
        f"  3. Admin panelden is_active=true yapıldı mı? → /docs\n"
    )


# ── Hazır Değişkenler ─────────────────────────────────────────────────────────
# Modülü import edince otomatik yüklenecek kısayollar

def _lazy(isim: str) -> str:
    """İlk çağrıda yükle."""
    return anahtar(isim)


class _LazyKey:
    """str gibi davranır ama ilk kullanımda EmareAPI'den çeker."""
    def __init__(self, isim: str):
        self._isim = isim
        self._deger: Optional[str] = None

    def _al(self) -> str:
        if self._deger is None:
            self._deger = anahtar(self._isim)
        return self._deger

    def __str__(self):      return self._al()
    def __repr__(self):     return f"LazyKey({self._isim})"
    def __len__(self):      return len(self._al())
    def __bool__(self):     return bool(self._al())
    def __eq__(self, other): return self._al() == other
    def __add__(self, other): return self._al() + other


# Kullanıma hazır kısayollar
gemini_key    = _LazyKey("GEMINI_API_KEY")
google_key    = _LazyKey("GOOGLE_API_KEY")
openai_key    = _LazyKey("OPENAI_API_KEY")
anthropic_key = _LazyKey("ANTHROPIC_API_KEY")
groq_key      = _LazyKey("GROQ_API_KEY")
