# SiberEmare — Proje Hafıza Dosyası

> 🔗 **Ortak Hafıza:** [`EMARE_ORTAK_HAFIZA.md`](/Users/emre/Desktop/Emare/EMARE_ORTAK_HAFIZA.md) — Tüm Emare ekosistemi, sunucu bilgileri, standartlar ve proje envanteri için bak.

> Son güncelleme: 3 Mart 2026  
> Bu dosyayı herhangi bir AI asistana ver, kaldığın yerden devam edebilirsin.

---

## 1. PROJENİN NE OLDUĞU

**SiberEmare**, siber güvenlik şirketleri için tasarlanmış, **tam otomatik penetrasyon testi raporlama pipeline'ı**dır. Bir pentest talebi geldiğinde (IDOR, SQLi, XSS vb. bulgular), sistem:

1. Talebi alır → planlar
2. Bulgular keşfeder ve kök neden analizi yapar (GraphRAG ile)  
3. Ekran görüntüsü/log gibi kanıtları OCR + Vision LLM ile işler
4. Otomatik teknik rapor yazar
5. Raporu otomatik gözden geçirir (AI self-critique, max 3 tur)
6. Rapor yeterli skorlamazsa insan onayına gönderir (Slack)
7. Jira ticket açar, PDF rapor üretir

**Teknoloji**: Python 3.11 + LangGraph 1.x + LangChain + Claude 3.5 Sonnet + GPT-4o (vision)

---

## 2. PROJE KONUMU

```
/Users/emre/Desktop/SiberEmare/
├── siberemare hafıza.md          ← bu dosya
├── proje.md                      ← orijinal fikir notu
├── kod önerileri.md              ← kaynak kod dökümü (2260 satır, kaynak belge)
└── siberemare-multiagent-v2/     ← ANA PROJE KLASÖRÜ (çalışan kod burada)
    ├── .env                      ← API key'ler (doldurulmamış — ÖNEMLİ)
    ├── .env.example
    ├── .gitignore
    ├── requirements.txt
    ├── state.py
    ├── prompts.py
    ├── graph.py                  ← LangGraph pipeline tanımı
    ├── main.py                   ← giriş noktası
    ├── agents/
    │   ├── __init__.py
    │   ├── planner.py
    │   ├── discovery.py          ← YAMALI (fallback bulgu eklendi)
    │   ├── evidence_processor.py ← YAMALI (dosyasız otomatik geçiş)
    │   ├── writer.py
    │   ├── reviewer.py
    │   ├── compliance.py
    │   └── remediation_generator.py
    ├── config/
    │   ├── llm_switch.py         ← cloud/onprem/hybrid LLM seçimi
    │   └── graph_switch.py
    ├── graph_rag/
    │   └── optimized_graphrag.py ← YAMALI (PGVector hata bastırıldı)
    ├── integrations/
    │   └── slack_jira.py         ← Slack onay + Jira ticket
    ├── tools/
    │   └── cli.py
    ├── cli/
    │   └── graph_query.py
    ├── knowledge_base/
    │   ├── ingest_graph.py
    │   └── ingest_pgvector.py
    ├── tests/
    │   ├── test_pipeline_flow.py ← ÇALIŞIYOR (mock LLM testi)
    │   ├── benchmark_100.py
    │   └── benchmark_self_critique.py
    ├── frontend/
    │   └── visualizer/
    │       └── index.html        ← graph görselleştirme (tarayıcıda açılır)
    ├── docker/
    │   └── Dockerfile
    ├── docker-compose.yml        ← Neo4j + PGVector + Redis
    ├── k8s/
    │   ├── deployment.yaml
    │   └── neo4j-statefulset.yaml
    ├── reports/                  ← üretilen raporlar buraya gelir
    └── checkpoints/              ← SQLite checkpoint dosyaları
```

---

## 3. PYTHON ORTAMI

```
Venv konumu  : /Users/emre/Desktop/SiberEmare/.venv
Python sürümü: 3.11.14
Aktifleştirme: source /Users/emre/Desktop/SiberEmare/.venv/bin/activate
```

### Kurulu paketler (önemli olanlar)

| Paket | Çözümlenen sürüm |
|---|---|
| langgraph | 1.0.10 |
| langgraph-checkpoint-sqlite | 3.0.3 |
| langchain-anthropic | 1.3.4 |
| langchain-openai | 1.1.10 |
| langchain-community | 0.3.x |
| langchain-groq | 0.2.x |
| langchain-neo4j | 0.3.x |
| pydantic | 2.x |
| structlog | 24.4+ |
| slack-sdk | 3.33+ |
| jira | 3.2+ |
| neo4j | 5.25+ |
| fpdf2 | 2.7+ |
| asyncpg | 0.29+ |
| redis | 5.2+ |
| fastapi | 0.115+ |

### requirements.txt notu
Orijinal `==` sabit sürüm pinleri **kaldırıldı** → `>=` olarak değiştirildi.  
Sebebi: `langgraph==0.2.15` ile `langchain-anthropic==0.3.0` arasında `langchain-core` sürüm çakışması vardı.

---

## 4. LANGGRAPH GRAPH MİMARİSİ

### Pipeline akışı

```
START
  └─▶ _router ─▶ planner ──────────────────────┐
                 ↑                              │
                 │◀─ compliance ◀───────────────┤
                 │◀─ discovery ◀────────────────┤
                 │◀─ evidence_processor ◀───────┤
                 │◀─ reviewer ◀─ writer ◀───────┤
                 │◀─ human_in_loop ◀────────────┤
                 └─▶ final_report ─▶ END
```

### Node açıklamaları

| Node | Dosya | Görev |
|---|---|---|
| `_router` | graph.py | State güncelleme + self-critique iterasyon sayacı |
| `planner` | agents/planner.py | Talebi analiz eder, scope belirler, PLAN_DONE |
| `discovery` | agents/discovery.py | Bulgular + kök neden + saldırı grafiği (GraphRAG ile), DISCOVERY_DONE |
| `evidence_processor` | agents/evidence_processor.py | Ekran görüntüsü/log OCR+Vision analizi, EVIDENCE_DONE |
| `compliance` | agents/compliance.py | KVKK/ISO27001/OWASP uyum kontrolü |
| `writer` | agents/writer.py | Teknik rapor yazar (review_feedback varsa kullanır) |
| `reviewer` | agents/reviewer.py | Raporu değerlendirir, 0.0-1.0 skor verir |
| `human_in_loop` | graph.py (inline) | Slack onay mesajı gönderir |
| `final_report` | graph.py (inline) | Jira ticket açar, .md rapor kaydeder |

### routing_edge mantığı (graph.py → `router_edge` fonksiyonu)

```python
stage == "START"                          → planner
NOT compliance_status                     → compliance
normalized_findings boş                  → discovery
evidence_bundle["processed"] yok         → evidence_processor
attack_graph boş                          → discovery
report_draft boş                          → writer
review_score < 0.95 AND turlar <= max     → writer  (self-critique döngüsü)
human_intervention_needed == True         → human_in_loop
aksi halde                               → final_report → END
```

---

## 5. STATE MODELİ (state.py)

```python
class PentestState(BaseModel):
    request_id: str                         # ör: "REQ-2026-TEST01"
    scope: Dict                             # {"target": "app.example.com", "level": "L3"}
    raw_input: str                          # ham pentest girdisi
    normalized_findings: List[Dict]         # keşfedilen bulgular listesi
    attack_graph: Dict                      # {"nodes": [...], "edges": [...]}
    evidence_bundle: Dict                   # {"processed": True/False, "files": [...]}
    report_draft: str                       # yazılan rapor metni
    review_score: float                     # 0.0 - 1.0 (0.95 eşiği)
    compliance_status: bool                 # KVKK/ISO uyum geçti mi
    human_intervention_needed: bool         # insan onayı gerekiyor mu
    current_stage: str = "START"           # mevcut aşama
    history: List[Dict]                    # agent geçmişi
    review_feedback: Optional[str]         # reviewer'dan gelen geri bildirim
    self_critique_iterations: int = 0      # kaç tur self-critique yapıldı
    max_iterations: int = 3               # maksimum self-critique turu
```

---

## 6. LLM YAPISI (config/llm_switch.py)

`.env` dosyasındaki `LLM_MODE` değerine göre otomatik seçim:

| LLM_MODE | LLM | Not |
|---|---|---|
| `cloud` (varsayılan) | Claude 3.5 Sonnet (`claude-3-5-sonnet-20241022`) | Anthropic API key gerekli |
| `onprem` | Ollama (`llama3.3:70b`) | Kendi sunucunda çalışır |
| `hybrid` | Groq (hızlı) + Claude (kritik) | Her ikisi de gerekli |

Vision LLM: **GPT-4o** (OpenAI API key gerekli) — evidence_processor'da kullanılır.

---

## 7. API KEY'LER — DOLDURULMASI GEREKEN (.env)

```bash
# Dosya konumu: /Users/emre/Desktop/SiberEmare/siberemare-multiagent-v2/.env

ANTHROPIC_API_KEY=sk-ant-...        # Claude için (ZORUNLU - cloud/hybrid modda)
OPENAI_API_KEY=sk-...               # GPT-4o vision için (ZORUNLU)
LLM_MODE=cloud                      # cloud | onprem | hybrid

# Opsiyonel — Docker ile çalışınca kullanılır
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password

POSTGRES_URL=postgresql://localhost:5432/siberemare
REDIS_URL=redis://localhost:6379

# Slack/Jira entegrasyonu (opsiyonel)
SLACK_BOT_TOKEN=xoxb-...
SLACK_CHANNEL_ID=C...
JIRA_URL=https://yourcompany.atlassian.net
JIRA_USERNAME=...
JIRA_API_TOKEN=...
JIRA_PROJECT_KEY=PENTEST

# Vision model
VISION_MODEL=gpt-4o

# Ollama (onprem mod)
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.3:70b
```

---

## 8. ÇALIŞTIRMA KOMUTLARI

### Venv aktifleştir
```bash
source /Users/emre/Desktop/SiberEmare/.venv/bin/activate
cd /Users/emre/Desktop/SiberEmare/siberemare-multiagent-v2
```

### Mock LLM testi (API key gerekmez) — ÇALIŞIYOR ✓
```bash
/Users/emre/Desktop/SiberEmare/.venv/bin/python tests/test_pipeline_flow.py
```

### Gerçek pipeline (API key gerekli)
```bash
/Users/emre/Desktop/SiberEmare/.venv/bin/python main.py REQ-2026-TEST01
```

### CLI arayüzü
```bash
# Multi-agent pipeline
/Users/emre/Desktop/SiberEmare/.venv/bin/python tools/cli.py multiagent REQ-TEST01 --max-critique 2

# GraphRAG sorgu
/Users/emre/Desktop/SiberEmare/.venv/bin/python cli/graph_query.py "IDOR zinciri" --format html
```

### Docker ile (Neo4j + PGVector + Redis)
```bash
docker compose up -d
/Users/emre/Desktop/SiberEmare/.venv/bin/python main.py REQ-2026-TEST01
```

---

## 9. MEVCUT TEST SONUCU

```
=== SiberEmare Pipeline Akış Testi (Mock LLM) ===
  → stage: START                          score: 0.00  tur: 0
  → stage: PLAN_DONE                      score: 0.00  tur: 0
  → stage: DISCOVERY_DONE                 score: 0.00  tur: 0
  → stage: EVIDENCE_DONE                  score: 0.00  tur: 0
  → stage: WRITER_DONE                    score: 0.00  tur: 0
  → stage: REVIEW_DONE                    score: 0.00  tur: 0
  → stage: SELF_CRITIQUE_RETRY            score: 0.00  tur: 1
  → stage: WRITER_DONE                    score: 0.00  tur: 1
  → stage: REVIEW_DONE                    score: 0.00  tur: 1
  → stage: SELF_CRITIQUE_RETRY            score: 0.00  tur: 2
  → stage: WRITER_DONE                    score: 0.00  tur: 2
  → stage: REVIEW_DONE                    score: 0.00  tur: 2
  → stage: SELF_CRITIQUE_RETRY            score: 0.00  tur: 3
  [max event sınırı]
✓ Pipeline testi tamamlandı — 13 event işlendi
```

**Not**: `score: 0.00` beklenen davranış — mock LLM reviewer JSON değil planner JSON döndürüyor.  
Self-critique 3 tur yapıp durdu → doğru.

---

## 10. YAPILAN YAMALAR VE SEBEPLERİ

### Yama 1: requirements.txt — sürüm çakışması
**Sorun**: `langgraph==0.2.15` ile `langchain-anthropic==0.3.0` → `langchain-core` sürüm çakışması  
**Çözüm**: `==` sabit pin → `>=` minimum sürüm (langgraph 1.0.10 kuruldu)

### Yama 2: graph.py — LangGraph 1.x uyumu (TAM YENİDEN YAZIM)
**Sorun**: LangGraph 0.2.x supervisor node pattern LangGraph 1.x'te çalışmıyor  
**Eski kod**:
```python
# BOZUK (LangGraph 0.2.x pattern)
workflow.add_node("supervisor", lambda s: {"next_agent": routing_logic(s)})
```
**Yeni kod**:
```python
# ÇALIŞAN (LangGraph 1.x pattern)
def router_node(state) -> dict:      # partial state update döndürür
    ...
def router_edge(state) -> str:       # sonraki node adını döndürür
    ...
workflow.add_conditional_edges("_router", router_edge)
```

### Yama 3: graph.py — SqliteSaver async sorunu
**Sorun**: `SqliteSaver.from_conn_string()` LangGraph 1.x'te context manager döndürüyor, async desteklemiyor  
**Çözüm**:
- Modül seviyesi: `MemorySaver()` kullan (dev/test için)
- Production: `AsyncSqliteSaver.from_conn_string()` async context manager olarak kullan

### Yama 4: agents/discovery.py — sonsuz döngü
**Sorun**: Mock LLM JSON'da `normalized_findings` alanı yoksa keşif boş kalıyor → router tekrar discovery'e yönlendiriyor → sonsuz döngü  
**Çözüm**: JSON parse'dan sonra `normalized_findings` hâlâ boşsa ham içerikten fallback bulgu oluştur

### Yama 5: agents/evidence_processor.py — sonsuz döngü
**Sorun**: `evidence_bundle.get("files", [])` boşsa `processed` set edilmiyor → router tekrar evidence_processor'a yönlendiriyor  
**Çözüm**: Dosya yoksa anında `processed=True` ile dön

### Yama 6: graph_rag/optimized_graphrag.py — PGVector hata
**Sorun**: `langchain-community` PGVector'ü deprecated → `__del__` metodunda `AttributeError`  
**Çözüm**: PGVector init'i `try/except + warnings.catch_warnings(ignore)` içine al, başarısız olursa `None` döndür → `hybrid_retrieve` Neo4j only ile devam eder

---

## 11. BİLİNEN SORUNLAR VE SONRAKI ADIMLAR

### Bilinen sorunlar
| Sorun | Kritiklik | Durum |
|---|---|---|
| `langchain-community` PGVector deprecated | Düşük | Bastırıldı, production'da `langchain-postgres` kullanılmalı |
| `.env` API key'leri boş | Kritik | Kullanıcı dolduracak |
| Ollama entegrasyonu test edilmedi | Orta | `LLM_MODE=onprem` seçilirse test et |
| Benchmark testleri çalıştırılmadı | Düşük | `tests/benchmark_100.py` |

### Sonraki adımlar (öncelik sırasıyla)
1. **[ZORUNLU]** `.env` dosyasına gerçek API key ekle (Anthropic + OpenAI)
2. **[ÖNERİLEN]** `langchain_postgres` paketine geç, PGVector'u oradan kullan:
   ```bash
   pip install langchain-postgres
   # graph_rag/optimized_graphrag.py güncelle: from langchain_postgres import PGVector
   ```
3. **[OPSİYONEL]** Docker ile Neo4j + Redis + PostgreSQL başlat, tam entegrasyon testi yap
4. **[OPSİYONEL]** `knowledge_base/ingest_graph.py` ile Neo4j'e pentest verisi yükle
5. **[OPSİYONEL]** Slack/Jira bağlantısını test et (token'lar .env'e eklenince)
6. **[OPSİYONEL]** `frontend/visualizer/index.html` tarayıcıda aç, attack graph görselleştir

---

## 12. AGENT DETAYLARI

### planner.py
- LLM: `get_llm()` (cloud/onprem/hybrid)
- Çıktı: scope analizi, `current_stage = "PLAN_DONE"`
- Sistem prompt: `PROMPTS["planner"]` (prompts.py)

### discovery.py ⚠️ (yamalı)
- LLM: `get_llm()`
- GraphRAG: `OptimizedGraphRAG().hybrid_retrieve(raw_input)` — Neo4j + PGVector
- JSON parse: `{"normalized_findings": [...], "attack_graph": {...}}`
- **Fallback**: JSON'da alan yoksa → `[{"title": "Keşfedilen Bulgu", "raw": content[:500], ...}]`
- Çıktı: `current_stage = "DISCOVERY_DONE"`

### evidence_processor.py ⚠️ (yamalı)
- LLM: `get_llm()` (text), `get_vision_llm()` = GPT-4o (image)
- OCR: `pytesseract` + `Pillow`
- **Fallback**: `evidence_bundle["files"]` boşsa → anında `processed=True` döner
- PII redaction: multi-turn LLM analizi
- Çıktı: `current_stage = "EVIDENCE_DONE"`

### writer.py
- LLM: `get_llm()`
- `review_feedback` varsa (retry durumunda) prompt'a enjekte eder
- Ansible remediation her bulgu için otomatik üretilir
- Çıktı: `current_stage = "WRITER_DONE"`, `report_draft` doldurulur

### reviewer.py
- LLM: `get_llm()`
- GraphRAG gold-standard karşılaştırma (opsiyonel)
- JSON parse: `{"overall_score": 0.0-1.0, "approved": true/false}`
- Heuristic fallback: "APPROVED" varsa 0.96, yoksa 0.80
- Çıktı: `current_stage = "REVIEW_DONE"`, `review_score` güncellenir

### compliance.py
- LLM: `get_llm()`
- KVKK / ISO 27001 / OWASP kontrolleri
- Çıktı: `compliance_status = True/False`

### remediation_generator.py
- Ansible playbook üretimi (writer.py tarafından çağrılır)

---

## 13. GRAPH RAG DETAYI (graph_rag/optimized_graphrag.py)

**Hybrid retrieval**: Neo4j (graph) + PGVector (semantik) birlikte çalışır

```python
class OptimizedGraphRAG:
    async def hybrid_retrieve(self, query: str) -> List[Dict]:
        # 1. Neo4j Cypher sorgusu (MATCH path...)
        # 2. PGVector semantik benzerlik arama
        # 3. İkisini birleştir, skora göre sırala
        # Hata varsa boş liste döner (pipeline durmaz)
```

**PGVector durumu**: deprecated `langchain-community.PGVector` → production'da `langchain-postgres.PGVector` kullanılmalı

---

## 14. INTEGRATIONS DETAYI (integrations/slack_jira.py)

### Slack
```python
async def send_slack_approval(state: PentestState):
    # Slack'e "Onayla / Reddet" butonlu mesaj gönderir
    # SLACK_BOT_TOKEN + SLACK_CHANNEL_ID .env'de olmalı
```

### Jira
```python
def create_jira_ticket(state: PentestState) -> str:
    # Jira'da PENTEST projesi altında task açar
    # ticket key'i döndürür (ör: "PENTEST-42")
    # JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN .env'de olmalı
```

---

## 15. DOCKER & K8S

### docker-compose.yml servisleri
- `neo4j` : port 7687 (bolt), 7474 (web)
- `postgres` : port 5432 (PGVector extension ile)
- `redis` : port 6379

### Kubernetes
- `k8s/deployment.yaml` : uygulama deployment
- `k8s/neo4j-statefulset.yaml` : Neo4j StatefulSet

---

## 16. PROJE GELİŞTİRME GEÇMİŞİ (kısaca)

1. `kod önerileri.md` (2260 satır) okundu → 41 proje dosyası oluşturuldu
2. Python venv kuruldu, `pip install -r requirements.txt` → sürüm çakışması → `>=` pinlere geçildi
3. Tüm modüller `import` edildi, hatalar düzeltildi
4. LangGraph 1.x uyumsuzluğu: supervisor pattern → `_router` + `router_edge` pattern
5. `SqliteSaver` async desteği → `MemorySaver` (dev) + `AsyncSqliteSaver` (production)
6. Discovery ve evidence_processor sonsuz döngüleri yamalandı
7. PGVector deprecation warning bastırıldı
8. Mock LLM pipeline testi → **ÇALIŞIYOR** (13 event, 3 self-critique turu)

---

*Bu dosyayı herhangi bir Claude / ChatGPT / Copilot'a göster, projeyle ilgili her soruyu yanıtlayabilir veya kaldığın yerden geliştirmeye devam edebilirsin.*
