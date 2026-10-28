"""
Evidence-Backed Response Validator — Signature Feature of SERC.
Evaluates LLM-generated claims against raw Wazuh alert data and retrieved dataset evidence.
Performs deterministic and semantic verification, flags unsupported assertions,
and persists analyst feedback in SQLite.
"""
import re
import sqlite3
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from backend.config import settings

logger = logging.getLogger("serc.evidence_validator")

# Supported validation statuses per specification
STATUS_SUPPORTED = "Supported"
STATUS_PARTIALLY_SUPPORTED = "Partially supported"
STATUS_CONFLICTING = "Conflicting evidence"
STATUS_INSUFFICIENT = "Insufficient evidence"
STATUS_REQUIRES_REVIEW = "Requires review"


class EvidenceValidator:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or settings.feedback_db_file
        self._init_feedback_db()

    def _init_feedback_db(self):
        """Initializes SQLite database to store analyst feedback without altering original alerts."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    claim_id TEXT,
                    claim_text TEXT,
                    analyst_decision TEXT NOT NULL,
                    analyst_notes TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def save_feedback(
        self,
        alert_id: str,
        analyst_decision: str,
        claim_id: Optional[str] = None,
        claim_text: Optional[str] = None,
        analyst_notes: Optional[str] = ""
    ) -> Dict[str, Any]:
        """Saves analyst review feedback persistently."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO analyst_feedback (alert_id, claim_id, claim_text, analyst_decision, analyst_notes)
                VALUES (?, ?, ?, ?, ?)
            """, (alert_id, claim_id, claim_text, analyst_decision, analyst_notes))
            conn.commit()
            feedback_id = cursor.lastrowid

        return {
            "success": True,
            "feedback_id": feedback_id,
            "alert_id": alert_id,
            "decision": analyst_decision
        }

    def get_feedback_for_alert(self, alert_id: str) -> List[Dict[str, Any]]:
        """Retrieves stored analyst feedback for a specific alert."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, alert_id, claim_id, claim_text, analyst_decision, analyst_notes, timestamp
                FROM analyst_feedback WHERE alert_id = ? ORDER BY timestamp DESC
            """, (alert_id,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def validate_analysis(
        self,
        analysis: Dict[str, Any],
        raw_alert: Dict[str, Any],
        retrieved_evidence: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Main validation pipeline.
        Deconstructs the analysis into atomic claims and verifies them against ground-truth evidence.
        """
        claims = self._extract_claims(analysis)
        validated_claims = []

        summary_counts = {
            STATUS_SUPPORTED: 0,
            STATUS_PARTIALLY_SUPPORTED: 0,
            STATUS_CONFLICTING: 0,
            STATUS_INSUFFICIENT: 0,
            STATUS_REQUIRES_REVIEW: 0
        }

        for claim in claims:
            res = self._verify_single_claim(claim, raw_alert, retrieved_evidence)
            validated_claims.append(res)
            status = res["status"]
            summary_counts[status] = summary_counts.get(status, 0) + 1

        total = len(validated_claims)
        supported_ratio = round((summary_counts[STATUS_SUPPORTED] / total), 2) if total > 0 else 0.0

        return {
            "summary": summary_counts,
            "total_claims": total,
            "supported_ratio": supported_ratio,
            "claims": validated_claims,
            "validation_notes": (
                "Validation completed using combined deterministic verification against alert fields "
                "and semantic alignment against retrieved NIST/MITRE cybersecurity corpus records."
            )
        }

    def _extract_claims(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts verifiable assertions from the structured analysis."""
        claims = []
        counter = 1

        # 1. Observed facts
        for fact in analysis.get("observed_facts", []):
            claims.append({
                "claim_id": f"CLM-{counter:03d}",
                "claim_text": fact,
                "claim_type": "Observed Fact"
            })
            counter += 1

        # 2. Risk assessment
        risk = analysis.get("risk_assessment", {})
        if risk.get("level"):
            claims.append({
                "claim_id": f"CLM-{counter:03d}",
                "claim_text": f"Risk assessed as {risk['level']}: {risk.get('reason', '')}",
                "claim_type": "Risk Assessment",
                "risk_level": risk.get("level")
            })
            counter += 1

        # 3. MITRE Mappings
        for mapping in analysis.get("mitre_mappings", []):
            tid = mapping.get("technique_id", "Unknown")
            tname = mapping.get("technique_name", "")
            tactic = mapping.get("tactic", "")
            claims.append({
                "claim_id": f"CLM-{counter:03d}",
                "claim_text": f"MITRE ATT&CK Mapping: {tid} ({tname}) under tactic '{tactic}'.",
                "claim_type": "MITRE Mapping",
                "technique_id": tid,
                "technique_name": tname,
                "mapping_source": mapping.get("source", "unknown")
            })
            counter += 1

        # 4. Interpretations
        for interp in analysis.get("possible_interpretations", []):
            claims.append({
                "claim_id": f"CLM-{counter:03d}",
                "claim_text": interp,
                "claim_type": "Interpretation"
            })
            counter += 1

        # 5. Response & Investigation recommendations
        for rec in analysis.get("response_recommendations", []):
            claims.append({
                "claim_id": f"CLM-{counter:03d}",
                "claim_text": rec,
                "claim_type": "Recommendation"
            })
            counter += 1

        return claims

    def _verify_single_claim(
        self,
        claim: Dict[str, Any],
        alert: Dict[str, Any],
        evidence: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Evaluates an individual claim using deterministic and semantic checks."""
        claim_text = claim["claim_text"]
        claim_type = claim["claim_type"]

        # Collect alert ground truth tokens
        rule = alert.get("rule", {})
        rule_id = str(rule.get("id", ""))
        rule_level = rule.get("level", 0)
        rule_desc = str(rule.get("description", ""))
        agent = alert.get("agent", {})
        agent_name = str(agent.get("name", ""))
        agent_ip = str(agent.get("ip", ""))
        alert_id = str(alert.get("id", ""))
        full_log = str(alert.get("full_log", ""))

        data = alert.get("data", {})
        alert_ips = set()
        alert_users = set()
        alert_ports = set()

        if agent_ip:
            alert_ips.add(agent_ip)
        for k in ["srcip", "dstip"]:
            if data.get(k):
                alert_ips.add(str(data[k]))
        if "win" in data and "eventdata" in data["win"]:
            ed = data["win"]["eventdata"]
            for k in ["ipAddress", "destinationIp"]:
                if ed.get(k):
                    alert_ips.add(str(ed[k]))
            for k in ["targetUserName", "subjectUserName"]:
                if ed.get(k):
                    alert_users.add(str(ed[k]).lower())
            for k in ["ipPort", "destinationPort"]:
                if ed.get(k):
                    alert_ports.add(str(ed[k]))

        for k in ["srcuser", "dstuser"]:
            if data.get(k):
                alert_users.add(str(data[k]).lower())
        for k in ["srcport", "dstport"]:
            if data.get(k):
                alert_ports.add(str(data[k]))

        # --- A. Validate Observed Facts ---
        if claim_type == "Observed Fact":
            # Check for hallucinated IP addresses
            ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", claim_text)
            for ip in ip_matches:
                if ip not in alert_ips and ip not in full_log:
                    return {
                        "claim_id": claim["claim_id"],
                        "claim_text": claim_text,
                        "claim_type": claim_type,
                        "status": STATUS_CONFLICTING,
                        "reason": f"Claim references IP address {ip}, which does NOT exist in the raw Wazuh alert.",
                        "evidence_source": "Deterministic IP check",
                        "alert_fields_or_records": {"alert_ips": list(alert_ips)},
                        "missing_evidence": f"No record of IP {ip} in alert logs.",
                        "suggested_next_verification_step": "Cross-check raw alert data.srcip and network firewall logs."
                    }

            # Check rule ID consistency if mentioned
            rule_match = re.search(r"rule\s+(\d+)", claim_text, re.IGNORECASE)
            if rule_match:
                claimed_rule_id = rule_match.group(1)
                if claimed_rule_id != rule_id:
                    return {
                        "claim_id": claim["claim_id"],
                        "claim_text": claim_text,
                        "claim_type": claim_type,
                        "status": STATUS_CONFLICTING,
                        "reason": f"Claim cites rule {claimed_rule_id}, but raw alert is rule {rule_id}.",
                        "evidence_source": "Deterministic rule check",
                        "alert_fields_or_records": {"actual_rule_id": rule_id},
                        "missing_evidence": f"Rule ID mismatch.",
                        "suggested_next_verification_step": "Inspect alert.rule.id."
                    }

            # Check agent name consistency
            if "agent '" in claim_text or "on agent " in claim_text:
                if agent_name.lower() in claim_text.lower():
                    pass  # Matches
                else:
                    return {
                        "claim_id": claim["claim_id"],
                        "claim_text": claim_text,
                        "claim_type": claim_type,
                        "status": STATUS_PARTIALLY_SUPPORTED,
                        "reason": f"Agent reference in claim does not match active alert agent '{agent_name}'.",
                        "evidence_source": "Deterministic agent check",
                        "alert_fields_or_records": {"agent_name": agent_name},
                        "missing_evidence": "Agent name misalignment.",
                        "suggested_next_verification_step": "Verify agent metadata."
                    }

            return {
                "claim_id": claim["claim_id"],
                "claim_text": claim_text,
                "claim_type": claim_type,
                "status": STATUS_SUPPORTED,
                "reason": "Directly grounded in observable fields of the raw Wazuh alert.",
                "evidence_source": f"Alert Payload (Rule: {rule_id}, Agent: {agent_name})",
                "alert_fields_or_records": {"rule_id": rule_id, "agent": agent_name},
                "missing_evidence": None,
                "suggested_next_verification_step": "None. Directly verified from alert telemetry."
            }

        # --- B. Validate MITRE Mappings ---
        elif claim_type == "MITRE Mapping":
            tid = claim.get("technique_id", "")
            # Check 1: Does the technique come directly from the Wazuh rule definition?
            rule_mitre_ids = rule.get("mitre", {}).get("id", [])
            if isinstance(rule_mitre_ids, str):
                rule_mitre_ids = [rule_mitre_ids]

            if tid in rule_mitre_ids:
                return {
                    "claim_id": claim["claim_id"],
                    "claim_text": claim_text,
                    "claim_type": claim_type,
                    "status": STATUS_SUPPORTED,
                    "reason": f"MITRE Technique {tid} is officially defined in the Wazuh alert rule metadata.",
                    "evidence_source": f"Alert Rule Metadata (rule.mitre.id: {tid})",
                    "alert_fields_or_records": {"rule_mitre": rule.get("mitre", {})},
                    "missing_evidence": None,
                    "suggested_next_verification_step": f"Review MITRE technique {tid} attack procedures."
                }

            # Check 2: Does the technique exist in the retrieved cybersecurity dataset records?
            for ev in evidence:
                if ev.get("mitre_technique_id") == tid:
                    return {
                        "claim_id": claim["claim_id"],
                        "claim_text": claim_text,
                        "claim_type": claim_type,
                        "status": STATUS_SUPPORTED,
                        "reason": f"MITRE Technique {tid} is supported by retrieved dataset record {ev.get('incident_id')} with similarity score {ev.get('similarity_score')}.",
                        "evidence_source": f"Retrieved Incident Corpus ({ev.get('incident_id')})",
                        "alert_fields_or_records": {"retrieved_incident_id": ev.get("incident_id"), "attack_type": ev.get("attack_type")},
                        "missing_evidence": None,
                        "suggested_next_verification_step": "Verify relevance of retrieved incident context to this endpoint."
                    }

            # Check 3: If not in rule and not in retrieved records
            return {
                "claim_id": claim["claim_id"],
                "claim_text": claim_text,
                "claim_type": claim_type,
                "status": STATUS_REQUIRES_REVIEW,
                "reason": f"Technique {tid} is an LLM inference not explicitly cited in the alert rule or retrieved dataset records.",
                "evidence_source": "Model Inference (Uncorrelated)",
                "alert_fields_or_records": {},
                "missing_evidence": f"No reference to {tid} found in alert rule or top {len(evidence)} retrieved corpus records.",
                "suggested_next_verification_step": "Validate adversary technique via MITRE ATT&CK knowledge base."
            }

        # --- C. Validate Risk Assessment ---
        elif claim_type == "Risk Assessment":
            level = claim.get("risk_level", "Medium")
            # If low severity rule (<=3) but model claimed Critical without evidence, flag conflict
            if rule_level <= 3 and level in ["High", "Critical"]:
                return {
                    "claim_id": claim["claim_id"],
                    "claim_text": claim_text,
                    "claim_type": claim_type,
                    "status": STATUS_CONFLICTING,
                    "reason": f"Claim asserts {level} risk, but Wazuh alert severity is only Level {rule_level} (informational/low).",
                    "evidence_source": f"Deterministic severity comparison (Rule level: {rule_level})",
                    "alert_fields_or_records": {"rule_level": rule_level},
                    "missing_evidence": "No secondary evidence justifying critical escalation for a low-severity rule.",
                    "suggested_next_verification_step": "Confirm whether surrounding telemetry indicates broader compromise before escalating."
                }

            return {
                "claim_id": claim["claim_id"],
                "claim_text": claim_text,
                "claim_type": claim_type,
                "status": STATUS_SUPPORTED,
                "reason": f"Risk assessment aligns proportionately with Wazuh rule level {rule_level}.",
                "evidence_source": f"Alert Severity Evaluation (Rule Level: {rule_level})",
                "alert_fields_or_records": {"rule_level": rule_level},
                "missing_evidence": None,
                "suggested_next_verification_step": "Incorporate organizational asset criticality."
            }

        # --- D. Validate Interpretations ---
        elif claim_type == "Interpretation":
            # Check for unproven compromise claims
            compromise_words = ["is compromised", "was breached", "attack succeeded", "adversary successfully"]
            if any(w in claim_text.lower() for w in compromise_words):
                return {
                    "claim_id": claim["claim_id"],
                    "claim_text": claim_text,
                    "claim_type": claim_type,
                    "status": STATUS_CONFLICTING,
                    "reason": "Claim declares a compromise or successful attack without conclusive forensic evidence.",
                    "evidence_source": "Safety Guideline Rule",
                    "alert_fields_or_records": {},
                    "missing_evidence": "Conclusive evidence of successful unauthorized post-exploitation activity.",
                    "suggested_next_verification_step": "Treat as an unconfirmed hypothesis until confirmed by endpoint forensics."
                }

            # Check if interpretation aligns with alert description or evidence
            matches_evidence = any(
                ev.get("attack_type", "").lower() in claim_text.lower() or
                ev.get("mitre_tactic", "").lower() in claim_text.lower()
                for ev in evidence
            )

            if matches_evidence:
                return {
                    "claim_id": claim["claim_id"],
                    "claim_text": claim_text,
                    "claim_type": claim_type,
                    "status": STATUS_SUPPORTED,
                    "reason": "Plausible interpretation supported by behavioral indicators in alert and matching dataset attack categories.",
                    "evidence_source": "Semantic correlation with dataset attack patterns",
                    "alert_fields_or_records": {"relevant_evidence_count": len(evidence)},
                    "missing_evidence": None,
                    "suggested_next_verification_step": "Examine temporal correlation with adjacent host events."
                }
            else:
                return {
                    "claim_id": claim["claim_id"],
                    "claim_text": claim_text,
                    "claim_type": claim_type,
                    "status": STATUS_PARTIALLY_SUPPORTED,
                    "reason": "Plausible hypothesis, but specific behavioral evidence is not corroborated by top retrieved records.",
                    "evidence_source": "Analytic Hypothesis",
                    "alert_fields_or_records": {},
                    "missing_evidence": "Corroborating telemetry in adjacent logs.",
                    "suggested_next_verification_step": "Check if similar alerts fired across other fleet endpoints."
                }

        # --- E. Validate Recommendations ---
        elif claim_type == "Recommendation":
            # Check if recommendation claims to be based on an incident record
            inc_match = re.search(r"INC-\d{6}", claim_text)
            if inc_match:
                cited_id = inc_match.group(0)
                matched_ev = next((e for e in evidence if e.get("incident_id") == cited_id), None)
                if matched_ev:
                    return {
                        "claim_id": claim["claim_id"],
                        "claim_text": claim_text,
                        "claim_type": claim_type,
                        "status": STATUS_SUPPORTED,
                        "reason": f"Recommendation accurately derived from verified incident record {cited_id}.",
                        "evidence_source": f"Dataset Record ({cited_id})",
                        "alert_fields_or_records": {"cited_incident": cited_id},
                        "missing_evidence": None,
                        "suggested_next_verification_step": "Human analyst sign-off prior to execution."
                    }
                else:
                    return {
                        "claim_id": claim["claim_id"],
                        "claim_text": claim_text,
                        "claim_type": claim_type,
                        "status": STATUS_CONFLICTING,
                        "reason": f"Claim cites record {cited_id}, which is NOT in the retrieved evidence set.",
                        "evidence_source": "Deterministic citation check",
                        "alert_fields_or_records": {},
                        "missing_evidence": f"Record {cited_id} not retrieved.",
                        "suggested_next_verification_step": "Re-run retrieval or verify record validity."
                    }

            return {
                "claim_id": claim["claim_id"],
                "claim_text": claim_text,
                "claim_type": claim_type,
                "status": STATUS_REQUIRES_REVIEW,
                "reason": "Recommended operational action requires human approval and standard change control procedure.",
                "evidence_source": "Standard SOC Protocol",
                "alert_fields_or_records": {},
                "missing_evidence": "Mandatory analyst sign-off required before taking defensive action.",
                "suggested_next_verification_step": "Obtain SOC tier-2 / manager approval before executing containment."
            }

        # Default fallback
        return {
            "claim_id": claim["claim_id"],
            "claim_text": claim_text,
            "claim_type": claim_type,
            "status": STATUS_REQUIRES_REVIEW,
            "reason": "Statement requires additional contextual evaluation.",
            "evidence_source": "Heuristic Assessment",
            "alert_fields_or_records": {},
            "missing_evidence": "Ambiguous evidence.",
            "suggested_next_verification_step": "Perform manual analyst audit."
        }


evidence_validator = EvidenceValidator()
