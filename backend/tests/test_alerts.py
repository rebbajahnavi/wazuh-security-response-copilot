"""
Unit and integration tests for SERC sample alerts, schema validation,
dataset inspection, pipeline execution, and feedback persistence.
"""
import pytest
from backend.config import settings
from backend.services.dataset_service import dataset_service
from backend.routes.alerts import (
    load_all_sample_alerts,
    validate_wazuh_structure,
    get_health,
    list_sample_alerts,
    get_sample_alert,
    validate_alert,
    run_analysis_pipeline,
    submit_analyst_feedback,
    get_alert_feedback,
    AnalyzeRequest,
    FeedbackRequest,
)


def test_sample_alerts_file_exists_and_count():
    """Verify that sample_alerts.json exists and contains at least 50 distinct realistic alerts."""
    alerts = load_all_sample_alerts()
    assert isinstance(alerts, list), "sample_alerts.json must be a list"
    assert len(alerts) >= 50, f"Expected at least 50 alerts, got {len(alerts)}"


def test_sample_alerts_unique_ids():
    """Verify that all alert IDs in sample_alerts.json are unique."""
    alerts = load_all_sample_alerts()
    ids = [a["id"] for a in alerts if "id" in a]
    assert len(ids) == len(alerts), "Every alert must have an 'id' field"
    assert len(ids) == len(set(ids)), "All alert IDs must be unique"


def test_sample_alerts_schema_integrity():
    """Verify that each synthetic alert has the required Wazuh fields and correct data types."""
    alerts = load_all_sample_alerts()
    for a in alerts:
        errors = validate_wazuh_structure(a)
        assert len(errors) == 0, f"Alert {a.get('id')} failed schema validation: {errors}"
        assert "timestamp" in a
        assert "full_log" in a
        assert "agent" in a
        assert isinstance(a["rule"]["level"], int)
        assert 1 <= a["rule"]["level"] <= 16


def test_sample_alerts_severity_diversity():
    """Verify diversity of severity levels (low, medium, high, critical)."""
    alerts = load_all_sample_alerts()
    levels = [a["rule"]["level"] for a in alerts]
    assert any(lvl <= 4 for lvl in levels), "Must contain low/informational severity alerts"
    assert any(5 <= lvl <= 9 for lvl in levels), "Must contain medium severity alerts"
    assert any(lvl >= 10 for lvl in levels), "Must contain high/critical severity alerts"


def test_validate_wazuh_structure_invalid_inputs():
    """Verify that the validator rejects malformed inputs and provides clear diagnostic messages."""
    assert len(validate_wazuh_structure({})) > 0
    assert len(validate_wazuh_structure({"id": "123"})) > 0
    assert len(validate_wazuh_structure({"id": "123", "rule": "not_a_dict"})) > 0
    assert len(validate_wazuh_structure({"id": "123", "rule": {"id": "1", "level": 3}})) > 0  # missing description


def test_dataset_schema_inspection():
    """Inspect dataset columns and provenance without replacing with fabricated data."""
    inspection = dataset_service.inspect_dataset(max_sample_rows=50)
    assert inspection["available"] is True
    assert inspection["column_count"] == 49
    assert "incident_id" in inspection["columns"]
    assert "attack_type" in inspection["columns"]
    assert "mitre_technique_id" in inspection["columns"]
    assert "nist_function" in inspection["columns"]
    assert "knowledge_set" in inspection["columns"]
    assert "source_reference" in inspection["columns"]
    assert "mapping_confidence" in inspection["columns"]


def test_health_endpoint_logic():
    """Test get_health() endpoint logic."""
    data = get_health()
    assert data["status"] == "healthy"
    assert "models" in data
    assert "mock_mode" in data
    assert data["dataset_available"] is True


def test_samples_endpoint_logic():
    """Test sample alert listing and individual retrieval."""
    samples = list_sample_alerts()
    assert len(samples) >= 50

    first_id = samples[0]["id"]
    detail = get_sample_alert(first_id)
    assert detail["id"] == first_id
    assert "rule" in detail


def test_validate_alert_endpoint_logic():
    """Test validate_alert endpoint logic."""
    valid_payload = {
        "id": "test.001",
        "rule": {"id": "5710", "level": 5, "description": "Test alert"},
        "agent": {"id": "001", "name": "host-1", "ip": "10.0.0.1"}
    }
    res_valid = validate_alert(valid_payload)
    assert res_valid["valid"] is True

    bad_payload = {"id": "test.002"}
    res_bad = validate_alert(bad_payload)
    assert res_bad["valid"] is False


def test_analyze_and_feedback_pipeline():
    """Test complete RAG analysis call and persistent analyst feedback."""
    alerts = load_all_sample_alerts()
    sample = alerts[0]

    # Run analysis
    req = AnalyzeRequest(alert=sample, top_k=3)
    result = run_analysis_pipeline(req)

    assert "alert_id" in result
    assert "pixtral_interpretation" in result
    assert "analysis" in result
    assert "validation" in result

    # Check validation claims exist
    claims = result["validation"]["claims"]
    assert len(claims) > 0
    first_claim_id = claims[0]["claim_id"]

    # Submit feedback
    fb_req = FeedbackRequest(
        alert_id=sample["id"],
        claim_id=first_claim_id,
        decision="accepted",
        notes="Verified by automated test suite"
    )
    fb_res = submit_analyst_feedback(fb_req)
    assert fb_res["success"] is True

    # Retrieve feedback
    history = get_alert_feedback(sample["id"])
    assert len(history) >= 1
    assert any(h["analyst_decision"] == "accepted" for h in history)
