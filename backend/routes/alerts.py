"""
FastAPI route definitions for SERC:
Health, sample alerts, alert validation, RAG analysis pipeline, evidence, and feedback.
"""
import time
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from fastapi import APIRouter, HTTPException, UploadFile, File, Body
from pydantic import BaseModel, Field

from backend.config import settings
from backend.services.dataset_service import dataset_service
from backend.services.embedding_service import embedding_service
from backend.services.retrieval_service import retrieval_service
from backend.services.pixtral_service import pixtral_service
from backend.services.gpt_analysis_service import gpt_analysis_service
from backend.services.evidence_validator import evidence_validator

logger = logging.getLogger("serc.routes.alerts")
router = APIRouter(prefix="/api", tags=["alerts"])


# --- Pydantic Request/Response Models ---
class FeedbackRequest(BaseModel):
    alert_id: str
    claim_id: Optional[str] = None
    claim_text: Optional[str] = None
    decision: str = Field(..., description="accepted, rejected, or needs_review")
    notes: Optional[str] = ""


class AnalyzeRequest(BaseModel):
    alert: Optional[Dict[str, Any]] = None
    alert_id: Optional[str] = None
    top_k: Optional[int] = 5


# In-memory cache for recent analysis evidence lookup by alert_id
RECENT_EVIDENCE_CACHE: Dict[str, List[Dict[str, Any]]] = {}


def load_all_sample_alerts() -> List[Dict[str, Any]]:
    """Loads synthetic sample alerts from sample_alerts.json."""
    sample_file = settings.sample_alerts_file
    if not sample_file.exists():
        raise HTTPException(status_code=404, detail=f"Sample alerts file not found at {sample_file}")

    try:
        with open(sample_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("sample_alerts.json must contain a JSON array of alerts.")
            return data
    except Exception as e:
        logger.error(f"Failed to parse sample alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to parse sample alerts: {str(e)}")


def validate_wazuh_structure(alert: Dict[str, Any]) -> List[str]:
    """Validates basic Wazuh event schema requirements."""
    errors = []
    if not isinstance(alert, dict):
        return ["Alert payload must be a JSON object."]

    if "id" not in alert:
        errors.append("Missing required top-level field: 'id'")
    if "rule" not in alert or not isinstance(alert["rule"], dict):
        errors.append("Missing or invalid 'rule' object (must contain 'id', 'level', 'description').")
    else:
        rule = alert["rule"]
        if "id" not in rule:
            errors.append("Missing 'rule.id'")
        if "level" not in rule:
            errors.append("Missing 'rule.level'")
        if "description" not in rule:
            errors.append("Missing 'rule.description'")

    if "agent" not in alert or not isinstance(alert["agent"], dict):
        errors.append("Missing or invalid 'agent' object (must contain 'id', 'name').")

    return errors


# --- Endpoints ---

@router.get("/health")
def get_health() -> Dict[str, Any]:
    """System health check and configuration status."""
    dataset_status = dataset_service.find_dataset_file()
    qdrant_stats = retrieval_service.get_stats()

    return {
        "status": "healthy",
        "service": "SERC - Security Event Response Copilot",
        "timestamp": time.time(),
        "environment": settings.environment,
        "mock_mode": settings.is_mock,
        "models": {
            "embedding": settings.embedding_model_name,
            "pixtral": settings.pixtral_model,
            "gpt": settings.openai_model
        },
        "dataset_available": dataset_status is not None,
        "dataset_file": str(dataset_status) if dataset_status else None,
        "qdrant_vectors": qdrant_stats.get("total_vectors", 0),
        "qdrant_collection": settings.qdrant_collection
    }


@router.get("/alerts/samples")
def list_sample_alerts() -> List[Dict[str, Any]]:
    """Lists summary cards for all available sample alerts."""
    alerts = load_all_sample_alerts()
    summaries = []
    for a in alerts:
        rule = a.get("rule", {})
        agent = a.get("agent", {})
        summaries.append({
            "id": a.get("id"),
            "timestamp": a.get("timestamp"),
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "agent_name": agent.get("name"),
            "agent_ip": agent.get("ip"),
            "decoder": a.get("decoder", {}).get("name")
        })
    return summaries


@router.get("/alerts/samples/{alert_id}")
def get_sample_alert(alert_id: str) -> Dict[str, Any]:
    """Retrieves full JSON for a specific sample alert."""
    alerts = load_all_sample_alerts()
    for a in alerts:
        if a.get("id") == alert_id:
            return a
    raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found.")


@router.post("/alerts/validate")
def validate_alert(alert: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Validates an uploaded or submitted alert JSON structure."""
    errors = validate_wazuh_structure(alert)
    if errors:
        return {"valid": False, "errors": errors}
    return {
        "valid": True,
        "alert_id": alert.get("id"),
        "rule_id": alert.get("rule", {}).get("id"),
        "rule_level": alert.get("rule", {}).get("level"),
        "message": "Valid Wazuh alert schema."
    }


@router.post("/alerts/upload")
async def upload_alert(file: UploadFile = File(...)) -> Dict[str, Any]:
    """Validates an uploaded JSON file directly."""
    try:
        content = await file.read()
        alert = json.loads(content.decode("utf-8"))
        errors = validate_wazuh_structure(alert)
        if errors:
            return {"valid": False, "errors": errors, "filename": file.filename}
        return {"valid": True, "alert": alert, "filename": file.filename}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Malformed JSON file: {str(e)}")


@router.post("/alerts/analyze")
def run_analysis_pipeline(request: AnalyzeRequest) -> Dict[str, Any]:
    """
    Complete RAG Analysis Pipeline:
    Alert Validation -> Pixtral Interpretation -> Search Query Creation ->
    BGE Embeddings -> Qdrant Similarity Search -> Relevant Evidence ->
    GPT-4o Analysis -> Evidence-Backed Response Validator -> Results & Metrics.
    """
    start_time = time.time()

    # 1. Resolve alert
    alert = request.alert
    if not alert and request.alert_id:
        alerts = load_all_sample_alerts()
        for a in alerts:
            if a.get("id") == request.alert_id:
                alert = a
                break

    if not alert:
        raise HTTPException(status_code=400, detail="Must provide either 'alert' object or valid 'alert_id'.")

    # Validate structure
    errors = validate_wazuh_structure(alert)
    if errors:
        raise HTTPException(status_code=422, detail={"message": "Invalid Wazuh alert", "errors": errors})

    alert_id = str(alert.get("id", "UNKNOWN"))

    # 2. Pixtral 12B Alert Interpretation
    pixtral_res = pixtral_service.interpret_alert(alert)
    search_query = pixtral_res.get("search_query") or pixtral_res.get("extracted_problem") or alert.get("rule", {}).get("description", "")

    # 3. Vector Similarity Retrieval via Qdrant
    top_k = request.top_k or settings.top_k_retrieval
    retrieved_evidence = retrieval_service.search_evidence(query=search_query, top_k=top_k)

    # Cache for evidence inspection endpoint
    RECENT_EVIDENCE_CACHE[alert_id] = retrieved_evidence

    # 4. GPT-4o RAG Analysis
    analysis = gpt_analysis_service.analyze_alert(
        alert=alert,
        pixtral_info=pixtral_res,
        evidence=retrieved_evidence
    )

    # 5. Evidence-Backed Response Validator
    validation = evidence_validator.validate_analysis(
        analysis=analysis,
        raw_alert=alert,
        retrieved_evidence=retrieved_evidence
    )

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    return {
        "alert_id": alert_id,
        "elapsed_ms": elapsed_ms,
        "pixtral_interpretation": pixtral_res,
        "retrieved_evidence": retrieved_evidence,
        "analysis": analysis,
        "validation": validation,
        "pipeline_metadata": {
            "is_mock": settings.is_mock or analysis.get("is_simulated", False),
            "evidence_count": len(retrieved_evidence),
            "query_used": search_query,
            "models_used": {
                "interpretation": settings.pixtral_model,
                "retrieval": settings.embedding_model_name,
                "reasoning": settings.openai_model
            }
        }
    }


@router.get("/alerts/{alert_id}/evidence")
def get_alert_evidence(alert_id: str) -> Dict[str, Any]:
    """Retrieves cached or matching evidence for an alert."""
    if alert_id in RECENT_EVIDENCE_CACHE:
        return {"alert_id": alert_id, "evidence": RECENT_EVIDENCE_CACHE[alert_id]}

    # If not cached, fetch the sample alert and query retrieval
    alerts = load_all_sample_alerts()
    for a in alerts:
        if a.get("id") == alert_id:
            rule_desc = a.get("rule", {}).get("description", "")
            ev = retrieval_service.search_evidence(query=rule_desc, top_k=5)
            return {"alert_id": alert_id, "evidence": ev}

    raise HTTPException(status_code=404, detail=f"No evidence found for alert '{alert_id}'.")


@router.post("/feedback")
def submit_analyst_feedback(payload: FeedbackRequest) -> Dict[str, Any]:
    """Records analyst review decision into SQLite feedback storage."""
    result = evidence_validator.save_feedback(
        alert_id=payload.alert_id,
        analyst_decision=payload.decision,
        claim_id=payload.claim_id,
        claim_text=payload.claim_text,
        analyst_notes=payload.notes
    )
    return result


@router.get("/feedback/{alert_id}")
def get_alert_feedback(alert_id: str) -> List[Dict[str, Any]]:
    """Retrieves all feedback for a specific alert."""
    return evidence_validator.get_feedback_for_alert(alert_id)


@router.get("/dataset/stats")
def get_dataset_stats() -> Dict[str, Any]:
    """Returns dataset inspection metrics and Qdrant ingestion statistics."""
    inspection = dataset_service.inspect_dataset(max_sample_rows=200)
    qdrant_info = retrieval_service.get_stats()
    return {
        "dataset_inspection": inspection,
        "qdrant_stats": qdrant_info
    }
