"""
Pixtral 12B Alert Interpretation Service.
Interprets raw Wazuh JSON alerts, extracts observable indicators without hallucination,
and produces clean structured JSON.
"""
import json
import logging
import httpx
from typing import Dict, Any
from backend.config import settings

logger = logging.getLogger("serc.pixtral_service")


class PixtralService:
    def __init__(self):
        self.api_key = settings.pixtral_api_key
        self.api_base = settings.pixtral_api_base.rstrip("/")
        self.model = settings.pixtral_model
        self.mock_mode = settings.is_mock

    def interpret_alert(self, alert_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        Interprets a raw Wazuh alert JSON.
        Calls Pixtral 12B API if configured, otherwise uses high-fidelity deterministic extractor.
        """
        if self.mock_mode or not self.api_key:
            logger.info("Using deterministic Pixtral alert interpreter (mock/offline mode)")
            return self._deterministic_extract(alert_json)

        try:
            return self._call_pixtral_api(alert_json)
        except Exception as e:
            logger.warning(f"Pixtral API call failed: {e}. Falling back to deterministic extraction.")
            return self._deterministic_extract(alert_json)

    def _call_pixtral_api(self, alert_json: Dict[str, Any]) -> Dict[str, Any]:
        """Calls the configured Pixtral / Mistral endpoint."""
        prompt = (
            "You are a cybersecurity alert interpreter. Analyze the following raw Wazuh security event log JSON. "
            "Extract ONLY observable facts present in the log. Do not assume compromise or invent missing fields. "
            "Return valid JSON matching this exact structure:\n"
            "{\n"
            '  "summary": "Plain language explanation of what occurred",\n'
            '  "rule_description": "Exact rule description",\n'
            '  "severity_level": 5,\n'
            '  "affected_agent": {"id": "...", "name": "...", "ip": "..."},\n'
            '  "observable_indicators": {"source_ip": null, "destination_ip": null, "destination_port": null, "source_user": null, "target_user": null, "file_path": null, "command": null},\n'
            '  "extracted_problem": "Concise summary of the issue",\n'
            '  "search_query": "Keyword query for MITRE/NIST retrieval"\n'
            "}\n\n"
            "Raw Alert:\n" + json.dumps(alert_json)
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity log parser. Respond strictly with JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }

        with httpx.Client(timeout=30.0) as client:
            resp = client.post(f"{self.api_base}/chat/completions", headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            return parsed

    def _deterministic_extract(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Robust deterministic extractor directly reading Wazuh schema fields.
        Ensures strict accuracy without missing fields or hallucinating.
        """
        rule = alert.get("rule", {})
        rule_desc = rule.get("description", "Unknown Wazuh alert")
        rule_level = rule.get("level", 0)
        rule_id = rule.get("id", "N/A")
        agent = alert.get("agent", {})
        data = alert.get("data", {})
        full_log = alert.get("full_log", "")
        mitre_data = rule.get("mitre", {})

        # Extract observable network / entity indicators
        src_ip = data.get("srcip") or (data.get("win", {}).get("eventdata", {}).get("ipAddress"))
        dst_ip = data.get("dstip") or (data.get("win", {}).get("eventdata", {}).get("destinationIp"))
        dst_port = data.get("dstport") or (data.get("win", {}).get("eventdata", {}).get("destinationPort"))
        src_user = data.get("srcuser") or (data.get("win", {}).get("eventdata", {}).get("subjectUserName"))
        tgt_user = data.get("dstuser") or (data.get("win", {}).get("eventdata", {}).get("targetUserName"))
        file_path = data.get("file") or (data.get("win", {}).get("eventdata", {}).get("image")) or (data.get("win", {}).get("eventdata", {}).get("path"))
        command = data.get("command") or (data.get("win", {}).get("eventdata", {}).get("commandLine")) or (data.get("audit", {}).get("command"))

        # Build plain language summary
        agent_name = agent.get("name", "Unknown agent")
        summary = f"Wazuh alert (Rule {rule_id}, Level {rule_level}) observed on host '{agent_name}': {rule_desc}."
        if src_ip:
            summary += f" Originating source IP: {src_ip}."
        if src_user or tgt_user:
            user_label = tgt_user or src_user
            summary += f" Involving user account: '{user_label}'."

        # Problem extraction
        extracted_problem = f"{rule_desc} on agent '{agent_name}' ({agent.get('ip', 'N/A')})"

        # Formulate query for BGE semantic search
        search_terms = [rule_desc]
        if mitre_data.get("technique"):
            techs = mitre_data["technique"] if isinstance(mitre_data["technique"], list) else [mitre_data["technique"]]
            search_terms.extend(techs)
        if mitre_data.get("tactic"):
            tactics = mitre_data["tactic"] if isinstance(mitre_data["tactic"], list) else [mitre_data["tactic"]]
            search_terms.extend(tactics)
        if rule.get("groups"):
            search_terms.extend(rule["groups"][:3])

        search_query = " ".join(search_terms)

        return {
            "summary": summary,
            "rule_description": rule_desc,
            "severity_level": rule_level,
            "affected_agent": {
                "id": str(agent.get("id", "N/A")),
                "name": str(agent.get("name", "N/A")),
                "ip": str(agent.get("ip", "N/A")),
            },
            "observable_indicators": {
                "source_ip": str(src_ip) if src_ip else None,
                "destination_ip": str(dst_ip) if dst_ip else None,
                "destination_port": str(dst_port) if dst_port else None,
                "source_user": str(src_user) if src_user else None,
                "target_user": str(tgt_user) if tgt_user else None,
                "file_path": str(file_path) if file_path else None,
                "command": str(command) if command else None,
            },
            "extracted_problem": extracted_problem,
            "search_query": search_query,
            "is_simulated": self.mock_mode or not self.api_key
        }


pixtral_service = PixtralService()
