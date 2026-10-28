"""
Dataset Ingestion Script for SERC.
Reads the 100,000-row cybersecurity dataset, builds rich document texts,
generates BGE-large-en-v1.5 embeddings in batches, and persists vectors & metadata in Qdrant.

Usage:
    python backend/scripts/ingest_dataset.py --limit 500 --batch-size 32
    python backend/scripts/ingest_dataset.py --limit 10000 --batch-size 64
"""
import sys
import time
import argparse
import logging
from pathlib import Path

# Add project root to sys.path so modules can be imported directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import settings
from backend.services.dataset_service import dataset_service
from backend.services.embedding_service import embedding_service
from backend.services.retrieval_service import retrieval_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("serc.ingest")


def run_ingestion(limit: int = 1000, batch_size: int = 32, recreate: bool = False):
    start_time = time.time()
    logger.info("=" * 60)
    logger.info("Starting SERC Dataset Ingestion Pipeline")
    logger.info(f"Target Qdrant Collection: {settings.qdrant_collection}")
    logger.info(f"Target Record Limit: {limit} | Batch Size: {batch_size}")
    logger.info(f"Embedding Model: {settings.embedding_model_name}")
    logger.info("=" * 60)

    # 1. Inspect dataset provenance
    inspection = dataset_service.inspect_dataset(max_sample_rows=100)
    if not inspection.get("available"):
        logger.error(f"Cannot proceed with ingestion: {inspection.get('error')}")
        logger.error(f"Please ensure '{settings.dataset_path}' exists in the project root or backend/data directory.")
        return

    logger.info(f"Dataset found at: {inspection['file_path']}")
    logger.info(f"Columns present ({inspection['column_count']}): {inspection['columns'][:10]}...")
    logger.info(f"Knowledge sets identified: {inspection['knowledge_sets']}")
    logger.info(f"Mapping confidences: {inspection['mapping_confidences']}")

    # 2. Prepare vector collection
    retrieval_service.ensure_collection(recreate=recreate)

    # 3. Stream and ingest in batches
    batch_records = []
    batch_texts = []
    total_processed = 0
    total_failed = 0

    record_stream = dataset_service.iter_records(limit=limit)

    for record in record_stream:
        search_text = dataset_service.build_search_text(record)
        if not search_text or len(search_text.strip()) < 10:
            total_failed += 1
            continue

        batch_records.append(record)
        batch_texts.append(search_text)

        if len(batch_records) >= batch_size:
            try:
                embeddings = embedding_service.embed_texts(batch_texts, batch_size=batch_size)
                retrieval_service.upsert_batch(batch_records, embeddings)
                total_processed += len(batch_records)
                logger.info(f"Ingested {total_processed}/{limit} records...")
            except Exception as e:
                logger.error(f"Failed to upsert batch: {e}")
                total_failed += len(batch_records)
            finally:
                batch_records = []
                batch_texts = []

    # Final trailing batch
    if batch_records:
        try:
            embeddings = embedding_service.embed_texts(batch_texts, batch_size=batch_size)
            retrieval_service.upsert_batch(batch_records, embeddings)
            total_processed += len(batch_records)
            logger.info(f"Ingested {total_processed}/{limit} records (final batch).")
        except Exception as e:
            logger.error(f"Failed to upsert final batch: {e}")
            total_failed += len(batch_records)

    elapsed = round(time.time() - start_time, 2)
    stats = retrieval_service.get_stats()

    logger.info("=" * 60)
    logger.info(f"Ingestion Finished in {elapsed}s")
    logger.info(f"Total Successfully Processed: {total_processed}")
    logger.info(f"Total Skipped / Failed: {total_failed}")
    logger.info(f"Total Vectors in Qdrant: {stats.get('total_vectors', 0)}")
    logger.info("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest cybersecurity dataset into Qdrant")
    parser.add_argument("--limit", type=int, default=1000, help="Number of rows to ingest (default: 1000)")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size for embedding generation (default: 32)")
    parser.add_argument("--recreate", action="store_true", help="Recreate collection before ingestion")
    args = parser.parse_args()

    run_ingestion(limit=args.limit, batch_size=args.batch_size, recreate=args.recreate)
