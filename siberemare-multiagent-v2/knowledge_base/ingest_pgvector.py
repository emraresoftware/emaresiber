"""PGVector Ingest — knowledge_base bulgularını PostgreSQL'e yükle (HNSW index)"""
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.graph_switch import PGVECTOR_URL

INIT_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS pentest_findings (
    id TEXT PRIMARY KEY,
    title TEXT,
    chunk TEXT,
    embedding VECTOR(3072),
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pentest_hnsw ON pentest_findings
USING hnsw (embedding vector_cosine_ops)
WITH (m = 32, ef_construction = 200);

CREATE INDEX IF NOT EXISTS idx_metadata_gin ON pentest_findings USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_llevel ON pentest_findings ((metadata->>'l_level'));
CREATE INDEX IF NOT EXISTS idx_severity ON pentest_findings ((metadata->>'severity'));
"""

UPSERT_SQL = """
INSERT INTO pentest_findings (id, title, chunk, embedding, metadata)
VALUES ($1, $2, $3, $4, $5::jsonb)
ON CONFLICT (id) DO UPDATE
SET embedding = EXCLUDED.embedding,
    metadata = EXCLUDED.metadata,
    chunk = EXCLUDED.chunk;
"""


async def main(reindex: bool = False):
    import asyncpg
    from langchain_openai import OpenAIEmbeddings

    embeddings = OpenAIEmbeddings(model="text-embedding-3-large", dimensions=3072)
    conn = await asyncpg.connect(PGVECTOR_URL)

    if reindex:
        print("PGVector tablosu + indexler oluşturuluyor...")
        await conn.execute(INIT_SQL)
        print("✅ Tablo ve indexler hazır")

    kb_path = Path(__file__).parent
    files = list(kb_path.rglob("*.json"))
    print(f"{len(files)} bulgu dosyası bulundu")

    for fpath in files:
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)

            items = data if isinstance(data, list) else [data]
            for item in items:
                text = f"{item.get('title', '')} {item.get('description', '')} {item.get('root_cause', '')}"
                emb = embeddings.embed_query(text)
                meta = json.dumps(
                    {
                        "l_level": item.get("l_level", "L3"),
                        "severity": item.get("severity", "MEDIUM"),
                        "cvss": item.get("cvss", 0.0),
                        "cwe": item.get("cwe", ""),
                        "redacted": item.get("redacted", True),
                        "kvkk_flag": item.get("kvkk_flag", False),
                    }
                )
                await conn.execute(
                    UPSERT_SQL,
                    item["id"],
                    item.get("title", ""),
                    text[:2000],
                    emb,
                    meta,
                )
                print(f"  → {item['id']}: {item.get('title', '')}")
        except Exception as e:
            print(f"  ⚠️  {fpath}: {e}")

    await conn.close()
    print("✅ PGVector ingest tamamlandı")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--reindex", action="store_true")
    args = parser.parse_args()
    asyncio.run(main(reindex=args.reindex))
