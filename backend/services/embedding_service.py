"""
Embedding service supporting BAAI/bge-large-en-v1.5.
Loads cached weights offline or gracefully manages embedding batching.
"""
import os
import math
import logging
import hashlib
from typing import List, Optional
from backend.config import settings

logger = logging.getLogger("serc.embedding_service")


class EmbeddingService:
    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or settings.embedding_model_name
        self.model = None
        self._dim = 1024  # BGE-large produces 1024-dimensional vectors
        self._initialized = False

    def load_model(self):
        """Loads the SentenceTransformer model if not already in memory."""
        if self._initialized:
            return

        try:
            # Set offline flags to prevent blocking on network if cached
            os.environ["HF_HUB_OFFLINE"] = "1"
            os.environ["TRANSFORMERS_OFFLINE"] = "1"

            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading embedding model: {self.model_name}")
            self.model = SentenceTransformer(self.model_name, local_files_only=True)
            if hasattr(self.model, "get_embedding_dimension"):
                self._dim = self.model.get_embedding_dimension()
            else:
                self._dim = self.model.get_sentence_embedding_dimension()
            self._initialized = True
            logger.info(f"Model loaded successfully with dimension: {self._dim}")
        except Exception as e:
            logger.warning(f"Could not load local BGE model directly ({e}). Attempting fallback...")
            try:
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer(self.model_name)
                if hasattr(self.model, "get_embedding_dimension"):
                    self._dim = self.model.get_embedding_dimension()
                else:
                    self._dim = self.model.get_sentence_embedding_dimension()
                self._initialized = True
            except Exception as e2:
                logger.error(f"Failed to initialize BGE model: {e2}. Fallback mock embeddings will be used.")
                self.model = None
                self._initialized = True

    @property
    def dimension(self) -> int:
        return self._dim

    def embed_texts(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """Encodes a list of texts in batches."""
        if not self._initialized:
            self.load_model()

        if self.model is not None:
            # SentenceTransformer encode
            embeddings = self.model.encode(
                texts,
                batch_size=batch_size,
                show_progress_bar=False,
                normalize_embeddings=True
            )
            return embeddings.tolist()

        # Deterministic fallback vector generation based on sha256 hash (unit tests / fallback)
        logger.debug("Generating deterministic mock embeddings (model not loaded)")
        return [self._mock_embed(t) for t in texts]

    def embed_query(self, query: str) -> List[float]:
        """Encodes a single query string."""
        return self.embed_texts([query])[0]

    def _mock_embed(self, text: str) -> List[float]:
        """Creates a normalized deterministic pseudo-embedding vector for offline mock/testing."""
        h = hashlib.sha256(text.encode("utf-8")).digest()
        vec = []
        for i in range(self._dim):
            byte_val = h[i % len(h)]
            # Spread into pseudo floating values
            vec.append((byte_val - 128.0) / 128.0 + math.sin(i + (byte_val / 256.0)))
        # Normalize vector
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [x / norm for x in vec]


embedding_service = EmbeddingService()
