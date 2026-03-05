# 📁 SiberEmare — Dosya Yapısı

> **Oluşturulma:** Otomatik  
> **Amaç:** Yapay zekalar kod yazmadan önce mevcut dosya yapısını incelemeli

---

## Proje Dosya Ağacı

```
/Users/emre/Desktop/Emare/Emaresiber
├── EMARE_AI_COLLECTIVE.md
├── EMARE_ORTAK_CALISMA -> /Users/emre/Desktop/Emare/EMARE_ORTAK_CALISMA
├── EMARE_ORTAK_HAFIZA.md
├── checkpoints
│   └── checkpoints.db
├── kod önerileri.md
├── proje.md
├── siberemare hafıza.md
├── siberemare-multiagent-v2
│   ├── .env
│   ├── .env.example
│   ├── .gitignore
│   ├── README.md
│   ├── agents
│   │   ├── __init__.py
│   │   ├── compliance.py
│   │   ├── discovery.py
│   │   ├── evidence_processor.py
│   │   ├── planner.py
│   │   ├── remediation_generator.py
│   │   ├── reviewer.py
│   │   └── writer.py
│   ├── checkpoints
│   │   ├── .gitkeep
│   │   └── checkpoints.db
│   ├── cli
│   │   ├── __init__.py
│   │   └── graph_query.py
│   ├── config
│   │   ├── __init__.py
│   │   ├── graph_switch.py
│   │   └── llm_switch.py
│   ├── docker
│   │   └── Dockerfile
│   ├── docker-compose.yml
│   ├── frontend
│   │   └── visualizer
│   │       └── index.html
│   ├── graph.py
│   ├── graph_rag
│   │   ├── __init__.py
│   │   └── optimized_graphrag.py
│   ├── integrations
│   │   ├── __init__.py
│   │   └── slack_jira.py
│   ├── k8s
│   │   ├── deployment.yaml
│   │   └── neo4j-statefulset.yaml
│   ├── knowledge_base
│   │   ├── ingest_graph.py
│   │   └── ingest_pgvector.py
│   ├── main.py
│   ├── prompts.py
│   ├── reports
│   │   └── .gitkeep
│   ├── requirements.txt
│   ├── state.py
│   ├── tests
│   │   ├── __init__.py
│   │   ├── benchmark_100.py
│   │   ├── benchmark_self_critique.py
│   │   ├── test_cases
│   │   │   └── README.md
│   │   └── test_pipeline_flow.py
│   └── tools
│       └── cli.py
└── yeni öneriler.md

19 directories, 49 files

```

---

## 📌 Kullanım Talimatları (AI İçin)

Bu dosya, kod üretmeden önce projenin mevcut yapısını kontrol etmek içindir:

1. **Yeni dosya oluşturmadan önce:** Bu ağaçta benzer bir dosya var mı kontrol et
2. **Yeni klasör oluşturmadan önce:** Mevcut klasör yapısına uygun mu kontrol et
3. **Import/require yapmadan önce:** Dosya yolu doğru mu kontrol et
4. **Kod kopyalamadan önce:** Aynı fonksiyon başka dosyada var mı kontrol et

**Örnek:**
- ❌ "Yeni bir auth.py oluşturalım" → ✅ Kontrol et, zaten `app/auth.py` var mı?
- ❌ "config/ klasörü oluşturalım" → ✅ Kontrol et, zaten `config/` var mı?
- ❌ `from utils import helper` → ✅ Kontrol et, `utils/helper.py` gerçekten var mı?

---

**Not:** Bu dosya otomatik oluşturulmuştur. Proje yapısı değiştikçe güncellenmelidir.

```bash
# Güncelleme komutu
python3 /Users/emre/Desktop/Emare/create_dosya_yapisi.py
```
