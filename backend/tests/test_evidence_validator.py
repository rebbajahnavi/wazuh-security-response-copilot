"""
Unit tests specifically targeting the Evidence-Backed Response Validator:
Deterministic validation, hallucination detection, conflicting evidence flags,
safety enforcement (no unsubstantiated compromise declarations), and claim grounding.
"""
import pytest
from backend.services.evidence_validator import (
    evidence_validator,
    STATUS_SUPPORTED,
    STATUS_PARTIALLY_SUPPORTED,
    STATUS_CONFLICTING,
    STATUS_INSUFFICIENT,
    STATUS_REQUIRES_REVIEW
)


@pytest.fixture
def sample_alert():
    return {
        "id": "test-alert-001",
        "timestamp": "2026-09-30T10:00:00.000+0000",
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "mitre": {
                "id": ["T1110.001"],
                "technique": ["Password Guessing"],
                "tactic": ["Credential Access"]
            }
        },
        "agent": {"id": "001", "name": "server-prod-01", "ip": "192.168.1.20"},
        "data": {
            "srcip": "198.51.100.50",
            "dstport": "22",
            "srcuser": "admin"
        },
        "full_log": "Failed password for invalid user admin from 198.51.100.50 port 54321 ssh2"
    }


@pytest.fixture
def sample_retrieved_evidence():
    return [
        {
            "incident_id": "INC-000042",
            "attack_type": "Brute Force",
            "similarity_score": 0.88,
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "mitre_tactic": "Credential Access",
            "source_reference": "NIST CSF 2.0 / MITRE ATT&CK Corpus",
            "investigation_steps": "Review authentication logs for repeated login failures.",
            "recommended_response": "Implement IP rate-limiting."
        }
    ]


def test_validator_supported_observed_fact(sample_alert, sample_retrieved_evidence):
    """Accurate claims citing real rule and agent must receive Supported status."""
    analysis = {
        "observed_facts": [
            "Alert triggered Wazuh rule 5710 at severity level 5 on agent 'server-prod-01' (192.168.1.20).",
            "Network connection originated from source IP 198.51.100.50."
        ],
        "risk_assessment": {"level": "Medium", "reason": "Rule level 5"},
        "mitre_mappings": [],
        "possible_interpretations": [],
        "response_recommendations": []
    }

    result = evidence_validator.validate_analysis(analysis, sample_alert, sample_retrieved_evidence)
    assert result["summary"][STATUS_SUPPORTED] >= 2
    for c in result["claims"]:
        if c["claim_type"] == "Observed Fact":
            assert c["status"] == STATUS_SUPPORTED
            assert c["missing_evidence"] is None


def test_validator_catches_hallucinated_ip(sample_alert, sample_retrieved_evidence):
    """When the LLM hallucinates an IP address not present in the alert, flag Conflicting."""
    analysis = {
        "observed_facts": [
            "Network connection originated from rogue attacker IP 10.99.88.77."
        ],
        "risk_assessment": {"level": "Medium"},
        "mitre_mappings": [],
        "possible_interpretations": [],
        "response_recommendations": []
    }

    result = evidence_validator.validate_analysis(analysis, sample_alert, sample_retrieved_evidence)
    assert result["summary"][STATUS_CONFLICTING] >= 1
    hallucinated_claim = next(c for c in result["claims"] if "10.99.88.77" in c["claim_text"])
    assert hallucinated_claim["status"] == STATUS_CONFLICTING
    assert "10.99.88.77" in hallucinated_claim["reason"]


def test_validator_catches_rule_id_mismatch(sample_alert, sample_retrieved_evidence):
    """When the LLM misidentifies the triggered rule ID, flag Conflicting."""
    analysis = {
        "observed_facts": [
            "Alert triggered Wazuh rule 99999 on agent 'server-prod-01'."
        ],
        "risk_assessment": {"level": "Medium"},
        "mitre_mappings": [],
        "possible_interpretations": [],
        "response_recommendations": []
    }

    result = evidence_validator.validate_analysis(analysis, sample_alert, sample_retrieved_evidence)
    mismatch_claim = next(c for c in result["claims"] if "rule 99999" in c["claim_text"])
    assert mismatch_claim["status"] == STATUS_CONFLICTING
    assert "cites rule 99999" in mismatch_claim["reason"]


def test_validator_mitre_mapping_from_rule(sample_alert, sample_retrieved_evidence):
    """MITRE technique matching the Wazuh rule definition must be Supported."""
    analysis = {
        "observed_facts": [],
        "risk_assessment": {"level": "Medium"},
        "mitre_mappings": [
            {
                "technique_id": "T1110.001",
                "technique_name": "Password Guessing",
                "tactic": "Credential Access",
                "source": "alert_rule"
            }
        ],
        "possible_interpretations": [],
        "response_recommendations": []
    }

    result = evidence_validator.validate_analysis(analysis, sample_alert, sample_retrieved_evidence)
    mapping_claim = next(c for c in result["claims"] if c["claim_type"] == "MITRE Mapping")
    assert mapping_claim["status"] == STATUS_SUPPORTED
    assert "Wazuh alert rule metadata" in mapping_claim["reason"]


def test_validator_mitre_mapping_from_retrieved_evidence(sample_alert, sample_retrieved_evidence):
    """MITRE technique not in rule, but corroborated by retrieved dataset record, must be Supported."""
    analysis = {
        "observed_facts": [],
        "risk_assessment": {"level": "Medium"},
        "mitre_mappings": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "source": "dataset_record"
            }
        ],
        "possible_interpretations": [],
        "response_recommendations": []
    }

    result = evidence_validator.validate_analysis(analysis, sample_alert, sample_retrieved_evidence)
    mapping_claim = next(c for c in result["claims"] if c["claim_type"] == "MITRE Mapping")
    assert mapping_claim["status"] == STATUS_SUPPORTED
    assert "INC-000042" in mapping_claim["reason"]


def test_validator_mitre_mapping_uncorroborated_requires_review(sample_alert, sample_retrieved_evidence):
    """Uncorroborated MITRE technique from model must require review."""
    analysis = {
        "observed_facts": [],
        "risk_assessment": {"level": "Medium"},
        "mitre_mappings": [
            {
                "technique_id": "T1055",  # Process Injection - completely irrelevant to sshd
                "technique_name": "Process Injection",
                "tactic": "Defense Evasion",
                "source": "model_inferred"
            }
        ],
        "possible_interpretations": [],
        "response_recommendations": []
    }

    result = evidence_validator.validate_analysis(analysis, sample_alert, sample_retrieved_evidence)
    mapping_claim = next(c for c in result["claims"] if c["claim_type"] == "MITRE Mapping")
    assert mapping_claim["status"] == STATUS_REQUIRES_REVIEW
    assert "not explicitly cited" in mapping_claim["reason"]


def test_validator_rejects_premature_compromise_declaration(sample_alert, sample_retrieved_evidence):
    """SERC safety rule: declaring compromise without definitive evidence must be flagged as Conflicting."""
    analysis = {
        "observed_facts": [],
        "risk_assessment": {"level": "Medium"},
        "mitre_mappings": [],
        "possible_interpretations": [
            "The system is compromised and the adversary successfully gained root access."
        ],
        "response_recommendations": []
    }

    result = evidence_validator.validate_analysis(analysis, sample_alert, sample_retrieved_evidence)
    comp_claim = next(c for c in result["claims"] if "is compromised" in c["claim_text"])
    assert comp_claim["status"] == STATUS_CONFLICTING
    assert "without conclusive forensic evidence" in comp_claim["reason"]


def test_validator_unsupported_evidence_citation(sample_alert, sample_retrieved_evidence):
    """When a recommendation cites a non-existent dataset incident ID, flag Conflicting."""
    analysis = {
        "observed_facts": [],
        "risk_assessment": {"level": "Medium"},
        "mitre_mappings": [],
        "possible_interpretations": [],
        "response_recommendations": [
            "Follow containment procedure per INC-999999 immediately."
        ]
    }

    result = evidence_validator.validate_analysis(analysis, sample_alert, sample_retrieved_evidence)
    rec_claim = next(c for c in result["claims"] if "INC-999999" in c["claim_text"])
    assert rec_claim["status"] == STATUS_CONFLICTING
    assert "NOT in the retrieved evidence set" in rec_claim["reason"]
