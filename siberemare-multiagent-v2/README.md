# SiberEmare Multi-Agent Orchestrator v2

**LangGraph Hierarchical Supervisor — Production-Ready**  
Pentest raporlama sürecini uçtan uca otomatize eden, çok ajanlı, GraphRAG destekli yapay zeka sistemi.

---

## Özellikler

- **6 Özel Ajan**: Planner, Discovery, Evidence Processor, Writer, Reviewer, Compliance
- **Hierarchical Supervisor**: LangGraph stateful graph + conditional routing
- **Self-Critique Döngüsü**: Writer → Reviewer → (skor < 0.95 ise tekrar) — maks 3 tur
- **Hybrid GraphRAG**: Neo4j Cypher + PGVector (latency < 50ms)
- **Multimodal**: Screenshot OCR + Vision LLM (Grok-4-Vision / GPT-4o)
- **PentestX Uyumlu**: L0-L6 / D0-D3 kademe sistemi, guardrail, KVKK/GDPR
- **Redaction Fail-Closed**: PII tespitinde otomatik durdurma
- **Slack + Jira**: Human-in-loop onay + otomatik ticket
- **On-Prem Desteği**: Ollama (Llama3.3-70B) ile tam yerel çalışma
- **Attack-Path Visualizer**: Cytoscape.js interaktif saldırı grafiği

---

## Hızlı Başlangıç (5 dakika)

### 1. Kurulum

```bash
git clone https://github.com/SiberEmare/siberemare-multiagent-v2.git
cd siberemare-multiagent-v2
pip install -r requirements.txt
cp .env.example .env
# .env dosyasına API key'leri ekle
```

### 2. Docker ile Çalıştır (Önerilen)

```bash
docker compose up -d
python main.py REQ-2026-TEST01
```

### 3. Manuel Çalıştır

```bash
# Gereksinimleri yükle
pip install -r requirements.txt

# .env doldur
cp .env.example .env

# Çalıştır
python main.py REQ-2026-TEST01
```

### 4. CLI Kullanımı

```bash
# Multi-agent pipeline
python tools/cli.py multiagent REQ-2026-TEST01 --max-critique 2

# Graph sorgusu
python cli/graph_query.py "IDOR zinciri L5 risk" --level L5 --format html
```

---

## Proje Yapısı

```
siberemare-multiagent-v2/
├── main.py                        # Giriş noktası
├── state.py                       # PentestState Pydantic modeli
├── graph.py                       # LangGraph supervisor + tüm edge'ler
├── prompts.py                     # 6 ajan system prompt'u
├── config/
│   ├── llm_switch.py              # cloud | onprem | hybrid LLM seçimi
│   └── graph_switch.py            # Neo4j | networkx fallback
├── agents/
│   ├── planner.py                 # Kademe belirleme
│   ├── discovery.py               # Kök neden + attack graph
│   ├── evidence_processor.py      # Multimodal + redaction
│   ├── writer.py                  # Rapor + Ansible remediation
│   ├── reviewer.py                # LLM-as-Judge + gold-standard RAG
│   ├── compliance.py              # KVKK/GDPR + guardrail
│   └── remediation_generator.py   # Ansible playbook üretici
├── graph_rag/
│   └── optimized_graphrag.py      # Neo4j Cypher + PGVector hibrit
├── integrations/
│   └── slack_jira.py              # Slack onay + Jira ticket
├── tools/
│   └── cli.py                     # pentestx multiagent komutu
├── cli/
│   └── graph_query.py             # pentestx graph-query komutu
├── frontend/visualizer/
│   └── index.html                 # Cytoscape.js attack-path görselleştirme
├── knowledge_base/
│   ├── ingest_graph.py            # Neo4j ingest
│   └── ingest_pgvector.py         # PGVector ingest
├── tests/
│   ├── benchmark_100.py           # 100 senaryo benchmark
│   └── benchmark_self_critique.py # Self-critique 50 senaryo
├── docker/Dockerfile
├── docker-compose.yml
├── k8s/
│   ├── deployment.yaml
│   └── neo4j-statefulset.yaml
├── requirements.txt
└── .env.example
```

---

## Ajan Akışı

```
START
  ↓
Supervisor
  ├→ Planner     (kademe + runbook belirleme)
  ├→ Compliance  (KVKK/GDPR + guardrail)
  ├→ Discovery   (kök neden + GraphRAG + attack graph)
  ├→ Evidence    (multimodal OCR + redaction)
  ├→ Writer      (rapor + Ansible)
  ├→ Reviewer    (LLM-as-Judge, skor < 0.95 → Writer'a dön)
  └→ Final Report (Jira ticket + rapor kaydet)
```

---

## Benchmark Hedefleri

| KPI                    | Hedef       |
|------------------------|-------------|
| Format tutarlılığı     | ≥ %99.2     |
| Halüsinasyon oranı     | ≤ %0.2      |
| Compliance pass rate   | %100        |
| Ortalama self-critique | ≤ 1.42 tur  |
| Rapor üretim süresi    | ≤ 5 dakika  |
| GraphRAG latency       | ≤ 50ms      |

---

## GraphRAG Kurulumu

```bash
# Neo4j ve PostgreSQL başlat
docker compose up neo4j postgres -d

# Index oluştur + knowledge_base yükle
python knowledge_base/ingest_graph.py --reindex
python knowledge_base/ingest_pgvector.py --reindex
```

---

## On-Prem Mod

```bash
# .env'de değiştir:
LLM_MODE=onprem
OLLAMA_URL=http://localhost:11434

# Ollama başlat
docker compose --profile onprem up ollama -d
ollama pull llama3.3:70b

# Test
python main.py REQ-2026-TEST01
```

---

## Attack-Path Visualizer

```bash
# Nginx ile aç
docker compose --profile frontend up visualizer -d
# → http://localhost:8080
```

---

## Benchmark Çalıştırma

```bash
# 100 senaryo
python -m tests.benchmark_100

# 50 senaryo self-critique
python -m tests.benchmark_self_critique
```

---

## Lisans

MIT License — SiberEmare Siber Güvenlik
