# SiberEmare API Leak Scanner — API Anahtarları Rehberi

## Mevcut Durum

Sistem şu an **12 aktif tarama modülü** ile API key gerektirmeden çalışıyor.  
Ek API anahtarları tanımlandığında daha fazla kaynak aktif olur.

---

## Ücretsiz Kaynaklar (API Key Gerekmez)

| Kaynak | Açıklama |
|--------|----------|
| Aktif Web Tarama | 12 modül: hassas dosya probing, JS analizi, header kontrolü, port tarama vb. |
| URLScan.io | Domain tarama sonuçları |
| Paste Sites | Pastebin ve benzeri siteler |
| crt.sh | Certificate Transparency subdomain keşfi |
| Wayback Machine | Geçmiş snapshot analizi |
| DNS Brute-force | Subdomain keşfi |
| Port Tarama | 30 yaygın port kontrolü |
| SSL/TLS Analizi | Sertifika ve yapılandırma kontrolü |
| S3/GCS Bucket Keşfi | Açık cloud bucket tespiti |

---

## API Anahtarı Gerektiren Kaynaklar

### 1. GitHub Token
- **Değişken:** `GITHUB_TOKEN`
- **Kayıt:** https://github.com/settings/tokens
- **Ücretsiz:** Evet (Personal Access Token)
- **Kullanım:** GitHub Code Search — hedef domain'e ait açık kodda credential tarama
- **Oluşturma:** Settings → Developer settings → Personal access tokens → Generate new token
- **Gerekli İzinler:** `public_repo` (sadece public repo taraması için yeterli)

### 2. Shodan API Key
- **Değişken:** `SHODAN_API_KEY`
- **Kayıt:** https://account.shodan.io/register
- **Ücretsiz:** Evet (sınırlı — 100 sorgu/ay)
- **Kullanım:** Açık portlar, servisler, açık veritabanları, API endpoint tespiti
- **Oluşturma:** Kayıt ol → Account → API Key

### 3. Google Custom Search
- **Değişkenler:** `GOOGLE_API_KEY` ve `GOOGLE_CX`
- **Kayıt:** https://console.cloud.google.com
- **Ücretsiz:** Evet (100 sorgu/gün)
- **Kullanım:** Google Dorking — hassas dosya ve credential araması
- **Oluşturma:**
  1. Google Cloud Console → API & Services → Credentials → Create API Key
  2. https://programmablesearchengine.google.com → Yeni arama motoru oluştur → CX ID al

### 4. VirusTotal API Key
- **Değişken:** `VIRUSTOTAL_API_KEY`
- **Kayıt:** https://www.virustotal.com/gui/join-us
- **Ücretsiz:** Evet (500 sorgu/gün)
- **Kullanım:** Domain reputation, malicious/suspicious tespiti, ilişkili URL'ler
- **Oluşturma:** Kayıt ol → Profil → API Key

### 5. Have I Been Pwned (HIBP)
- **Değişken:** `HIBP_API_KEY`
- **Kayıt:** https://haveibeenpwned.com/API/Key
- **Ücretsiz:** Hayır ($3.50/ay)
- **Kullanım:** Veri ihlali kontrolü — domain'e ait email'lerin sızdığı ihlaller
- **Oluşturma:** Kayıt ol → Subscribe → API Key al

### 6. Hunter.io
- **Değişken:** `HUNTER_API_KEY`
- **Kayıt:** https://hunter.io/users/sign_up
- **Ücretsiz:** Evet (25 sorgu/ay)
- **Kullanım:** Email intelligence — domain'e ait email adresleri, email pattern'i
- **Oluşturma:** Kayıt ol → API → API Key

### 7. SecurityTrails
- **Değişken:** `SECURITYTRAILS_API_KEY`
- **Kayıt:** https://securitytrails.com/app/signup
- **Ücretsiz:** Evet (50 sorgu/ay)
- **Kullanım:** Subdomain keşfi, DNS geçmişi, WHOIS değişiklikleri
- **Oluşturma:** Kayıt ol → Account → API Key

### 8. Intelligence X (IntelX)
- **Değişken:** `INTELX_API_KEY`
- **Kayıt:** https://intelx.io/signup
- **Ücretsiz:** Kısıtlı (akademik)
- **Kullanım:** Derin web araması — paste siteleri, dark web, veri sızıntıları
- **Oluşturma:** Kayıt ol → Account → API Key

### 9. Dehashed
- **Değişkenler:** `DEHASHED_EMAIL` ve `DEHASHED_API_KEY`
- **Kayıt:** https://dehashed.com
- **Ücretsiz:** Hayır (ücretli abonelik)
- **Kullanım:** Sızdırılmış credential veritabanı — email, username, password hash'leri
- **Oluşturma:** Kayıt ol → Abonelik al → API → API Key

---

## Sunucuya API Key Ekleme

Sunucu: `185.189.54.107`

```bash
# 1. Sunucuya bağlan
ssh root@185.189.54.107

# 2. .env dosyasını düzenle
nano /opt/siberemare-leak-scanner/.env

# 3. İlgili satıra API key'i yaz, örneğin:
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SHODAN_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
VIRUSTOTAL_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# 4. Container'ı yeniden başlat
docker restart siberemare-leak-scanner
```

---

## Önerilen Öncelik Sırası

API key alırken şu sıraya göre başlayın (ücretsiz + en faydalı → ücretli):

| Öncelik | Kaynak | Maliyet | Değer |
|---------|--------|---------|-------|
| 1 | **GitHub Token** | Ücretsiz | ⭐⭐⭐⭐⭐ |
| 2 | **Shodan** | Ücretsiz | ⭐⭐⭐⭐⭐ |
| 3 | **VirusTotal** | Ücretsiz | ⭐⭐⭐⭐ |
| 4 | **SecurityTrails** | Ücretsiz | ⭐⭐⭐⭐ |
| 5 | **Google Custom Search** | Ücretsiz | ⭐⭐⭐ |
| 6 | **Hunter.io** | Ücretsiz | ⭐⭐⭐ |
| 7 | **HIBP** | $3.50/ay | ⭐⭐⭐⭐ |
| 8 | **IntelX** | Kısıtlı | ⭐⭐⭐ |
| 9 | **Dehashed** | Ücretli | ⭐⭐⭐ |

---

## Dashboard Erişimi

**URL:** http://185.189.54.107:8080

Tarama başlatmak için domain girin ve "Taramayı Başlat" butonuna tıklayın.
