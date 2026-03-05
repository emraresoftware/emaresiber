"""Graph Backend Switch — neo4j_local | networkx_fallback | faiss_fallback"""
import os


GRAPH_MODE = os.getenv("GRAPH_MODE", "neo4j_local")  # neo4j_local | networkx_fallback
GDS_ENABLED = os.getenv("GDS_ENABLED", "true").lower() == "true"
VECTOR_INDEX_DIM = int(os.getenv("VECTOR_INDEX_DIM", "3072"))

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_AUTH = (
    os.getenv("NEO4J_USER", "neo4j"),
    os.getenv("NEO4J_PASSWORD", "password"),
)

PGVECTOR_MODE = os.getenv("PGVECTOR_MODE", "hnsw")  # hnsw | ivfflat | faiss_fallback
PGVECTOR_URL = os.getenv("PGVECTOR_URL", "postgresql://user:pass@localhost:5432/pentest")
GRAPH_CACHE = os.getenv("GRAPH_CACHE", "redis://localhost:6379")


def is_neo4j_available() -> bool:
    """Ping Neo4j connection."""
    if os.getenv("LLM_MODE", "cloud") == "onprem" and GRAPH_MODE == "networkx_fallback":
        return False
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        driver.verify_connectivity()
        driver.close()
        return True
    except Exception:
        return False
