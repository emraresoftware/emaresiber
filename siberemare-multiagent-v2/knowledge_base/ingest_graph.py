"""Neo4j Graph Ingest — knowledge_base klasöründen bulgular → Neo4j MERGE"""
import asyncio
import json
import os
import sys
from glob import glob
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_openai import OpenAIEmbeddings
from config.graph_switch import NEO4J_URI, NEO4J_AUTH

MERGE_QUERY = """
MERGE (f:Finding {id: $id})
SET f += $props,
    f.embedding = $embedding_vector,
    f.updated_at = datetime()

WITH f
UNWIND $relations AS rel
MERGE (target:Finding {id: rel.target_id})
MERGE (f)-[r:LEADS_TO {confidence: rel.confidence, cvss: rel.cvss}]->(target)
"""

INIT_QUERIES = [
    "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE;",
    "CREATE CONSTRAINT asset_name IF NOT EXISTS FOR (a:Asset) REQUIRE a.name IS UNIQUE;",
    """CREATE VECTOR INDEX pentest_vector_idx IF NOT EXISTS
    FOR (f:Finding) ON f.embedding
    OPTIONS {indexConfig: {`vector.dimensions`: 3072, `vector.similarity_function`: 'cosine'}};""",
    "CREATE TEXT INDEX finding_text_idx IF NOT EXISTS FOR (f:Finding) ON f.title;",
    "CREATE INDEX finding_cvss_idx IF NOT EXISTS FOR (f:Finding) ON (f.cvss, f.severity);",
]


def init_indexes(driver):
    with driver.session() as session:
        for q in INIT_QUERIES:
            try:
                session.run(q)
                print(f"✅ Index/constraint oluşturuldu")
            except Exception as e:
                print(f"⚠️  {e}")


async def ingest_finding(driver, finding: dict, embeddings: OpenAIEmbeddings):
    text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('root_cause', '')}"
    embedding_vector = embeddings.embed_query(text)

    props = {
        "title": finding.get("title", ""),
        "severity": finding.get("severity", "MEDIUM"),
        "cvss": finding.get("cvss", 0.0),
        "cwe": finding.get("cwe", ""),
        "l_level": finding.get("l_level", "L3"),
    }

    with driver.session() as session:
        session.run(
            MERGE_QUERY,
            id=finding["id"],
            props=props,
            embedding_vector=embedding_vector,
            relations=finding.get("relations", []),
        )
    print(f"  → İçe aktarıldı: {finding['id']} ({finding.get('title', '')})")


async def main(reindex: bool = False):
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
    embeddings = OpenAIEmbeddings(model="text-embedding-3-large", dimensions=3072)

    if reindex:
        print("Indexler oluşturuluyor...")
        init_indexes(driver)

    # JSON bulgu dosyalarını yükle
    kb_path = Path(__file__).parent
    files = list(kb_path.rglob("*.json"))
    print(f"{len(files)} bulgu dosyası bulundu")

    for fpath in files:
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    await ingest_finding(driver, item, embeddings)
            elif isinstance(data, dict):
                await ingest_finding(driver, data, embeddings)
        except Exception as e:
            print(f"  ⚠️  {fpath}: {e}")

    driver.close()
    print("✅ Graph ingest tamamlandı")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--reindex", action="store_true")
    args = parser.parse_args()
    asyncio.run(main(reindex=args.reindex))
