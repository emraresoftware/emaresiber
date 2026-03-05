"""Optimized GraphRAG — Neo4j (Cypher + GDS) + PGVector hibrit retrieval"""
from __future__ import annotations
import json
import os
from typing import Any

from langchain_openai import OpenAIEmbeddings
from config.graph_switch import (
    NEO4J_URI,
    NEO4J_AUTH,
    PGVECTOR_URL,
    GDS_ENABLED,
    VECTOR_INDEX_DIM,
)

OPTIMIZED_HYBRID_QUERY = """
MATCH (f:Finding)
WHERE f.embedding IS NOT NULL
WITH f, vector.similarity.cosine(f.embedding, $query_embedding) AS vec_score
WHERE vec_score >= $min_score

OPTIONAL MATCH path = (f)-[r*1..3]-(related)
WHERE ALL(rel IN r WHERE rel.confidence >= 0.7)

WITH f, vec_score,
     reduce(total=0, rel IN relationships(path) | total + rel.confidence) AS path_score,
     collect(DISTINCT related) AS community

RETURN
    f.id AS finding_id,
    f.title AS title,
    vec_score,
    path_score,
    community,
    vec_score * 0.6 + path_score * 0.4 AS final_score
ORDER BY final_score DESC
LIMIT $k
"""

ATTACK_PATH_QUERY = """
MATCH p = shortestPath((start:Finding {id: $start_id})-[:LEADS_TO*1..6]->(end:Finding))
WHERE end.severity = 'CRITICAL'
RETURN
    [n IN nodes(p) | n.title] AS attack_chain,
    reduce(risk=0, rel IN relationships(p) | risk + coalesce(rel.probability, 0) * coalesce(rel.cvss, 5)) AS total_risk,
    length(p) AS hop_count
ORDER BY total_risk DESC
LIMIT 10
"""


class OptimizedGraphRAG:
    """Hibrit GraphRAG: Neo4j Cypher + PGVector (latency < 50ms hedefi)"""

    def __init__(self):
        self.embeddings = OpenAIEmbeddings(
            model="text-embedding-3-large", dimensions=VECTOR_INDEX_DIM
        )
        self._neo4j_driver = None
        self._vector_store = None
        self._cache: dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Neo4j
    # ------------------------------------------------------------------ #

    @property
    def neo4j_driver(self):
        if self._neo4j_driver is None:
            from neo4j import GraphDatabase
            self._neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        return self._neo4j_driver

    # ------------------------------------------------------------------ #
    # PGVector
    # ------------------------------------------------------------------ #

    @property
    def vector_store(self):
        if self._vector_store is None:
            try:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    from langchain_community.vectorstores import PGVector
                self._vector_store = PGVector(
                    collection_name="pentest_graph",
                    connection_string=PGVECTOR_URL,
                    embedding_function=self.embeddings,
                )
            except Exception as e:
                # PGVector bağlantısı kurulamazsa None kalır — hybrid_retrieve fallback'e düşer
                self._vector_store = None
        return self._vector_store

    # ------------------------------------------------------------------ #
    # Core Methods
    # ------------------------------------------------------------------ #

    async def hybrid_retrieve(
        self, query: str, k: int = 5, min_score: float = 0.75
    ) -> list[dict]:
        """Vector search + Neo4j graph traversal → re-ranked results."""
        cache_key = f"{query}:{k}:{min_score}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        results: list[dict] = []

        # 1. PGVector semantic search
        try:
            vec_results = self.vector_store.similarity_search_with_score(query, k=k * 2)
            for doc, score in vec_results:
                if score >= min_score:
                    results.append(
                        {
                            "source": "pgvector",
                            "id": doc.metadata.get("graph_id", ""),
                            "content": doc.page_content[:500],
                            "score": float(score),
                        }
                    )
        except Exception as e:
            results.append({"source": "pgvector_error", "error": str(e), "score": 0})

        # 2. Neo4j graph traversal (only if driver is reachable)
        try:
            query_embedding = self.embeddings.embed_query(query)
            with self.neo4j_driver.session() as session:
                record_set = session.run(
                    OPTIMIZED_HYBRID_QUERY,
                    query_embedding=query_embedding,
                    min_score=min_score,
                    k=k,
                )
                for record in record_set:
                    results.append(
                        {
                            "source": "neo4j",
                            "id": record["finding_id"],
                            "title": record["title"],
                            "score": float(record["final_score"] or 0),
                        }
                    )
        except Exception as e:
            results.append({"source": "neo4j_error", "error": str(e), "score": 0})

        # Re-rank by score descending
        results.sort(key=lambda r: r.get("score", 0), reverse=True)
        results = results[:k]

        self._cache[cache_key] = results
        return results

    async def get_full_attack_path(self, start_id: str) -> dict:
        """Saldırı zincirleri + visualizer node/edge formatı."""
        try:
            with self.neo4j_driver.session() as session:
                records = session.run(ATTACK_PATH_QUERY, start_id=start_id)
                chains = [r.data() for r in records]
            return {"start_id": start_id, "attack_chains": chains, "nodes": [], "edges": []}
        except Exception as e:
            return {"start_id": start_id, "error": str(e), "nodes": [], "edges": []}

    async def hybrid_graph_query(self, query: str, level: str = "L3") -> dict:
        """CLI graph-query komutunun backend çağrısı."""
        results = await self.hybrid_retrieve(query)
        return {
            "query": query,
            "level": level,
            "results": results,
            "attack_chains": [r.get("title", "") for r in results if "title" in r],
            "visualizer_link": f"http://localhost:8080?query={query.replace(' ', '_')}",
        }

    def close(self):
        if self._neo4j_driver:
            self._neo4j_driver.close()
