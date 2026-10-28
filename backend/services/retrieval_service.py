"""
Retrieval service using Qdrant vector database.
Supports local persistent storage and remote Qdrant instances.
Preserves source IDs, provenance, and MITRE/NIST cybersecurity metadata.
"""
import uuid
import logging
from typing import List, Dict, Any, Optional
from qdrant_client import QdrantClient
from qdrant_client.models import (
    VectorParams,
    Distance,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
)
from backend.config import settings
from backend.services.embedding_service import embedding_service

logger = logging.getLogger("serc.retrieval_service")

# Deterministic namespace for converting incident_id (INC-000001) to a valid Qdrant UUID
UUID_NAMESPACE = uuid.UUID("3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f")


class RetrievalService:
    def __init__(self):
        self.collection_name = settings.qdrant_collection
        self._client: Optional[QdrantClient] = None

    @property
    def client(self) -> QdrantClient:
        if self._client is None:
            self._client = self._init_client()
        return self._client

    def _init_client(self) -> QdrantClient:
        """Initializes embedded disk Qdrant or remote client based on configuration."""
        if settings.qdrant_url:
            logger.info(f"Connecting to remote Qdrant instance at {settings.qdrant_url}")
            return QdrantClient(
                url=settings.qdrant_url,
                api_key=settings.qdrant_api_key or None,
            )
        else:
            storage_path = settings.qdrant_storage_dir
            if storage_path:
                storage_path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Initializing embedded persistent Qdrant at {storage_path}")
                return QdrantClient(path=str(storage_path))
            else:
                logger.info("Initializing in-memory Qdrant instance")
                return QdrantClient(":memory:")

    def ensure_collection(self, recreate: bool = False):
        """Ensures the collection exists with cosine distance and correct vector size."""
        cl = self.client
        exists = cl.collection_exists(self.collection_name)
        if exists and recreate:
            logger.warning(f"Recreating existing collection: {self.collection_name}")
            cl.delete_collection(self.collection_name)
            exists = False

        if not exists:
            dim = embedding_service.dimension
            logger.info(f"Creating Qdrant collection '{self.collection_name}' (vector size: {dim})")
            cl.create_collection(
                collection_name=self.collection_name,
                vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
            )

    def upsert_batch(self, records: List[Dict[str, Any]], embeddings: List[List[float]]):
        """Upserts a batch of records with deterministic UUIDs."""
        self.ensure_collection(recreate=False)
        points = []

        for record, vec in zip(records, embeddings):
            inc_id = str(record.get("incident_id", "")).strip()
            # Generate deterministic UUID from incident_id so repeated ingestion won't create duplicates
            point_id = str(uuid.uuid5(UUID_NAMESPACE, inc_id)) if inc_id else str(uuid.uuid4())

            payload = {
                "incident_id": inc_id,
                "attack_type": record.get("attack_type", ""),
                "incident_description": record.get("incident_description", ""),
                "target_system": record.get("target_system", ""),
                "outcome": record.get("outcome", ""),
                "attack_severity": record.get("attack_severity", ""),
                "knowledge_set": record.get("knowledge_set", ""),
                "source_type": record.get("source_type", ""),
                "source_reference": record.get("source_reference", ""),
                "mapping_method": record.get("mapping_method", ""),
                "mapping_confidence": record.get("mapping_confidence", ""),
                "mitre_tactic": record.get("mitre_tactic", ""),
                "mitre_technique_id": record.get("mitre_technique_id", ""),
                "mitre_technique_name": record.get("mitre_technique_name", ""),
                "mitre_description": record.get("mitre_description", ""),
                "mitre_mitigations": record.get("mitre_mitigations", ""),
                "mitre_detection": record.get("mitre_detection", ""),
                "nist_function": record.get("nist_function", ""),
                "nist_category": record.get("nist_category", ""),
                "nist_subcategory": record.get("nist_subcategory", ""),
                "nist_description": record.get("nist_description", ""),
                "detection_indicators": record.get("detection_indicators", ""),
                "investigation_steps": record.get("investigation_steps", ""),
                "containment_steps": record.get("containment_steps", ""),
                "eradication_steps": record.get("eradication_steps", ""),
                "recovery_steps": record.get("recovery_steps", ""),
                "recommended_response": record.get("recommended_response", ""),
                "combined_knowledge_text": record.get("combined_knowledge_text", "")[:1000],
            }

            points.append(PointStruct(id=point_id, vector=vec, payload=payload))

        self.client.upsert(collection_name=self.collection_name, points=points)

    def search_evidence(
        self,
        query: str,
        top_k: int = 5,
        knowledge_set: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Searches Qdrant for relevant cybersecurity records matching the query.
        Returns empty list if no points or collection doesn't exist yet.
        """
        if not self.client.collection_exists(self.collection_name):
            logger.info("Qdrant collection does not exist yet; returning empty evidence.")
            return []

        # Check count of points
        count_res = self.client.count(collection_name=self.collection_name)
        if count_res.count == 0:
            logger.info("Qdrant collection has 0 points; returning empty evidence.")
            return []

        query_vec = embedding_service.embed_query(query)

        query_filter = None
        if knowledge_set:
            query_filter = Filter(
                must=[FieldCondition(key="knowledge_set", match=MatchValue(value=knowledge_set))]
            )

        search_result = self.client.query_points(
            collection_name=self.collection_name,
            query=query_vec,
            query_filter=query_filter,
            limit=top_k,
            with_payload=True
        )

        results = []
        for hit in search_result.points:
            payload = hit.payload or {}
            # Format clean snippet
            text_snippet = (
                payload.get("incident_description") or
                payload.get("combined_knowledge_text") or
                f"Incident {payload.get('incident_id')} - {payload.get('attack_type')}"
            )

            results.append({
                "incident_id": payload.get("incident_id", ""),
                "similarity_score": round(float(hit.score), 4) if hit.score is not None else 0.0,
                "attack_type": payload.get("attack_type", ""),
                "incident_description": payload.get("incident_description", ""),
                "mitre_tactic": payload.get("mitre_tactic", ""),
                "mitre_technique_id": payload.get("mitre_technique_id", ""),
                "mitre_technique_name": payload.get("mitre_technique_name", ""),
                "mitre_description": payload.get("mitre_description", ""),
                "mitre_mitigations": payload.get("mitre_mitigations", ""),
                "nist_function": payload.get("nist_function", ""),
                "nist_category": payload.get("nist_category", ""),
                "nist_subcategory": payload.get("nist_subcategory", ""),
                "knowledge_set": payload.get("knowledge_set", ""),
                "source_type": payload.get("source_type", ""),
                "source_reference": payload.get("source_reference", ""),
                "mapping_confidence": payload.get("mapping_confidence", ""),
                "detection_indicators": payload.get("detection_indicators", ""),
                "investigation_steps": payload.get("investigation_steps", ""),
                "recommended_response": payload.get("recommended_response", ""),
                "snippet": text_snippet[:350],
            })

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Returns collection stats for the UI and health checks."""
        try:
            if not self.client.collection_exists(self.collection_name):
                return {"exists": False, "total_vectors": 0, "collection_name": self.collection_name}
            count_res = self.client.count(collection_name=self.collection_name)
            return {
                "exists": True,
                "total_vectors": count_res.count,
                "collection_name": self.collection_name
            }
        except Exception as e:
            return {"exists": False, "error": str(e), "total_vectors": 0}


retrieval_service = RetrievalService()
