# SERC — Security Event Response Copilot

> **Retrieval-Augmented Guidance and Evidence-Backed Grounding for Wazuh Security Operations Center (SOC) Alerts.**

SERC is a specialized, beginner-friendly, and production-ready cybersecurity copilot application designed to assist SOC analysts in investigating Wazuh security event logs. By combining local semantic retrieval across a 100,000-record cybersecurity incident corpus (grounded in **NIST CSF 2.0** and **MITRE ATT&CK**) with large language model reasoning, SERC accelerates threat triage while maintaining rigorous evidence validation.

---

## 1. Architectural Overview & Workflow

SERC implements a multi-stage RAG pipeline with a **human-in-the-loop** safety philosophy. It does not automatically declare systems compromised and prohibits unapproved destructive containment actions.

```
       Wazuh Security Event Alert (JSON)
                      │
                      ▼
            Alert Schema Validation
                      │
                      ▼
         Pixtral 12B Alert Interpretation
         (Observable indicators extracted)
                      │
                      ▼
            Search Query Generation
                      │
                      ▼
         BGE Semantic Vector Embeddings
             (BAAI/bge-large-en-v1.5)
                      │
                      ▼
          Qdrant Similarity Retrieval
             (Persistent Vector DB)
                      │
                      ▼
        Retrieved Dataset Evidence Records
         (NIST CSF 2.0 & MITRE ATT&CK)
                      │
                      ▼
          GPT-4o Evidence-Grounded Analysis
   (Observed facts vs. interpretations vs. steps)
                      │
                      ▼
    ★ Evidence-Backed Response Validator ★
   (Deterministic checks + semantic verification)
                      │
                      ▼
   Analyst Workspace & Persistent Feedback Review
             (Accepted / Rejected / SQLite)
```

### Component Roles
- **Frontend (`frontend/`)**: Lightweight, clean, light-themed analyst dashboard built strictly with vanilla **HTML5, CSS3, and JavaScript**. Communicates with the backend using HTTP `fetch()`.
- **Backend (`backend/main.py`)**: Asynchronous Python API built with **FastAPI** and **Pydantic**.
- **Pixtral 12B Service (`backend/services/pixtral_service.py`)**: Interprets raw Wazuh logs, extracts observable indicators without hallucination, and formats search queries.
- **BGE Embeddings (`backend/services/embedding_service.py`)**: Uses `BAAI/bge-large-en-v1.5` (1024-dimensional dense vectors) to encode incident records and queries.
- **Qdrant Vector DB (`backend/services/retrieval_service.py`)**: Persistent vector database storing records with complete provenance, source references, and cybersecurity taxonomies.
- **GPT-4o Analysis Service (`backend/services/gpt_analysis_service.py`)**: Synthesizes the alert and retrieved evidence into risk assessments, MITRE ATT&CK mappings, and response procedures.
- **Evidence-Backed Response Validator (`backend/services/evidence_validator.py`)**: The signature feature of SERC. Deconstructs LLM assertions into atomic claims, tests them deterministically and semantically against the ground-truth alert and retrieved records, flags unsupported or conflicting statements, and records analyst feedback in SQLite (`backend/data/feedback.db`).

---

## 2. Project Directory Structure

```text
serc/
│
├── frontend/
│   ├── index.html            # Complete semantic light-themed UI
│   ├── style.css             # Cohesive, clean design styling
│   └── script.js             # Vanilla JS API client & reactive UI controller
│
├── backend/
│   ├── main.py               # FastAPI entry point & static asset mount
│   ├── config.py             # Pydantic environment configuration
│   ├── requirements.txt      # Dependency specification
│   ├── .env.example          # Environment variable template
│   ├── .env                  # Local runtime configuration
│   │
│   ├── routes/
│   │   └── alerts.py         # REST endpoints for health, samples, validate, analyze, feedback
│   │
│   ├── services/
│   │   ├── dataset_service.py      # 100,000-row dataset inspection & streaming
│   │   ├── embedding_service.py    # BAAI/bge-large-en-v1.5 embedding engine
│   │   ├── retrieval_service.py    # Persistent Qdrant vector retrieval
│   │   ├── pixtral_service.py      # Pixtral 12B alert interpretation
│   │   ├── gpt_analysis_service.py # GPT-4o RAG reasoning
│   │   └── evidence_validator.py   # Signature claim validation & feedback engine
│   │
│   ├── data/
│   │   ├── sample_alerts.json      # 55 distinct realistic synthetic Wazuh alerts
│   │   ├── README.md               # Data documentation & synthetic methodology
│   │   ├── feedback.db             # Local SQLite analyst review feedback database
│   │   └── qdrant_storage/         # Local persistent Qdrant collection files
│   │
│   ├── scripts/
│   │   ├── generate_sample_alerts.py # Generator for the 55 synthetic alerts
│   │   └── ingest_dataset.py         # Batch ingestion pipeline for the 100k dataset
│   │
│   └── tests/
│       ├── test_alerts.py            # Tests for alert parsing, schema, API endpoints
│       └── test_evidence_validator.py# Tests for claim verification & hallucination catching
│
├── combined_security_dataset_final.zip # Real 100,000-row cybersecurity dataset
├── .gitignore
└── README.md
```

---

## 3. Prerequisites

- **Operating System**: Windows 10/11, macOS, or Linux.
- **Python**: Version **3.10 to 3.14** (Python 3.14 recommended).
- **RAM**: Minimum 8 GB recommended (for running local BGE embeddings).
- **Optional External API Keys**:
  - OpenAI API key (for live GPT-4o).
  - Mistral or OpenRouter API key (for live Pixtral 12B).
  *Note: SERC includes a complete, deterministic offline simulation mode (`MOCK_LLM_MODE=true`) so you can run, test, and evaluate the entire application and validator immediately without external paid API keys.*

---

## 4. Quick Start & Setup

### Step 1: Clone / Navigate to Project Directory
```powershell
cd c:\Users\jahna\Downloads\WAZUH
```

### Step 2: (Optional) Create and Activate Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate on Windows PowerShell
.\venv\Scripts\Activate.ps1

# (Activate on Linux / macOS: source venv/bin/activate)
```

### Step 3: Install Dependencies
```powershell
pip install -r backend/requirements.txt
```

### Step 4: Configure Environment Variables
Copy `backend/.env.example` to `backend/.env` (or edit the existing `.env`):
```powershell
cp backend/.env.example backend/.env
```
Key configuration parameters in `backend/.env`:
```ini
# Server
HOST=127.0.0.1
PORT=8000

# Persistent Qdrant vector storage directory
QDRANT_PATH=backend/data/qdrant_storage
QDRANT_COLLECTION=serc_security_knowledge

# Embeddings
EMBEDDING_MODEL_NAME=BAAI/bge-large-en-v1.5
TOP_K_RETRIEVAL=5

# Dataset
DATASET_PATH=combined_security_dataset_final.zip

# LLM Providers (Optional - leave blank if running offline simulation)
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o

PIXTRAL_API_KEY=
PIXTRAL_MODEL=pixtral-12b-2409

# Simulation Mode (true = runs deterministic simulation; false = calls live APIs)
MOCK_LLM_MODE=true
```

---

## 5. Dataset Ingestion & Qdrant Setup

SERC works directly with your real **100,000-row, 49-column cybersecurity dataset** (`combined_security_dataset_final.zip` or `.csv`).

### Ingesting Records into Qdrant
The ingestion pipeline streams records, builds semantically enriched documents, generates BGE embeddings in batches, and indexes them into Qdrant.

To ingest an initial set of records (e.g. 500 records for fast local verification):
```powershell
python backend/scripts/ingest_dataset.py --limit 500 --batch-size 32
```

To index a larger portion or the full dataset:
```powershell
python backend/scripts/ingest_dataset.py --limit 10000 --batch-size 64
```

*Key Ingestion Features:*
- **Idempotent & Resumable**: Generates deterministic point UUIDs based on `incident_id`, preventing duplicate insertions on rerun.
- **Provenance Preserved**: Retains `incident_id`, `source_reference`, `source_type`, `mitre_technique_id`, `nist_function`, `nist_category`, and `mapping_confidence`.
- **Zero Hallucination**: Does not send all 100,000 records to an LLM; only semantically relevant top-k records are retrieved at analysis time.

---

## 6. Running the Application

### Launch the SERC Backend Server
Run the FastAPI application:
```powershell
python backend/main.py
```
Or using Uvicorn:
```powershell
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### Access the Web Interface
Open your web browser and navigate to:
```
http://127.0.0.1:8000
```
The FastAPI backend automatically serves the frontend at the root URL. If developing the frontend independently, you can also open `frontend/index.html` via any local static server (e.g., Live Server on port 5500) because CORS is preconfigured.

---

## 7. Using SERC: Analyst Investigation Workflow

1. **Select an Alert Scenario**:
   - In **Area A**, select any of the 55 pre-loaded Wazuh scenarios from the dropdown (covering SSH brute force, Windows Mimikatz, webshells, privilege escalation, routine backups, etc.).
   - Alternatively, click **Upload Alert JSON** to test custom Wazuh event logs.
2. **Review Alert Telemetry**:
   - Inspect the quick metadata summary (Rule ID, Severity level, Agent name, Description).
   - Expand the **Raw Alert JSON** viewer to inspect or edit the underlying log structure.
3. **Run Analysis**:
   - Click **Analyze Alert**.
   - The system validates the schema, interprets log observables via Pixtral, executes vector search in Qdrant, and runs RAG analysis.
4. **Inspect Analysis Results (Area B)**:
   - Read the plain-language summary.
   - Examine **Directly Observed Facts** (verified telemetry) separately from **Plausible Interpretations**.
   - Review MITRE ATT&CK technique alignments, ordered investigation steps, and mitigation recommendations.
5. **Verify Claims & Evidence (Area C — Signature Feature)**:
   - View the claim summary counters (**Supported**, **Partially Supported**, **Conflicting Evidence**, **Insufficient Evidence**, **Requires Review**).
   - Review the justification and evidence source for each claim.
   - Inspect the retrieved cybersecurity dataset records and similarity scores.
6. **Submit Analyst Feedback**:
   - Click **Accept**, **Reject**, or **Review** on individual claim cards.
   - Feedback is saved persistently in `backend/data/feedback.db` without altering the original alert.

---

## 8. API Reference Documentation

Interactive OpenAPI documentation is available at: `http://127.0.0.1:8000/docs`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Backend status, active models, vector corpus count |
| `GET` | `/api/alerts/samples` | Lists 55+ sample alert summaries |
| `GET` | `/api/alerts/samples/{alert_id}` | Retrieves full JSON for a sample alert |
| `POST` | `/api/alerts/validate` | Validates Wazuh schema structure |
| `POST` | `/api/alerts/upload` | Validates an uploaded JSON file |
| `POST` | `/api/alerts/analyze` | Executes the complete RAG analysis and validation pipeline |
| `GET` | `/api/alerts/{alert_id}/evidence` | Retrieves grounding evidence records for an alert |
| `POST` | `/api/feedback` | Saves analyst claim review decisions to SQLite |
| `GET` | `/api/feedback/{alert_id}` | Retrieves all recorded feedback for an alert |
| `GET` | `/api/dataset/stats` | Dataset schema inspection and Qdrant ingestion statistics |

---

## 9. Running the Test Suite

Run all automated unit and integration tests using pytest:
```powershell
python -m pytest -v
```

To run individual test modules:
```powershell
# Run alert schema, API route, and feedback tests
python -m pytest backend/tests/test_alerts.py -v

# Run Evidence-Backed Response Validator tests
python -m pytest backend/tests/test_evidence_validator.py -v
```

---

## 10. Evidence Validator: How Grounding Works

The Evidence-Backed Response Validator addresses the core weakness of LLMs in security operations: **unsupported assertions and plausible-sounding hallucinations**.

### Claim Evaluation Rules
1. **IP & Host Consistency**: If a claim asserts an IP address or host that does not exist in the raw Wazuh event or surrounding network fields, it is flagged as **`Conflicting evidence`**.
2. **Rule Level Proportionality**: If an alert has an informational severity level (e.g., Level 2 routine backup) and the model declares a Critical emergency without corroborating telemetry, it is flagged as **`Conflicting evidence`**.
3. **No Unsubstantiated Compromise Declarations**: Claims declaring that a system "is compromised" or "attack succeeded" without forensic proof are flagged as **`Conflicting evidence`**.
4. **MITRE Technique Grounding**:
   - If present in the Wazuh rule definition: **`Supported`**.
   - If corroborated by retrieved dataset records: **`Supported`**.
   - If an ungrounded model inference: **`Requires review`**.
5. **Evidence Citation Verification**: If a response cites a dataset identifier (e.g. `INC-000042`) that was not part of the retrieved evidence set, it is flagged as **`Conflicting evidence`**.

---

## 11. Security, Reliability & Responsible Use

- **No Destructive Automation**: SERC is an analyst advisor. It will never disable user accounts, modify firewall rules, or shut down hosts automatically.
- **Untrusted Input Sanitation**: All raw logs and retrieved text are treated as untrusted data to protect against prompt injection.
- **Zero API Key Leakage**: API credentials remain strictly confined to `backend/.env` and are never exposed to client-side JavaScript.
- **Synthetic Data Safety**: All sample alerts use synthetic hostnames, fictional user accounts, and RFC-reserved private/documentation IP addresses (`192.168.0.0/16`, `10.0.0.0/8`, `198.51.100.0/24`, `203.0.113.0/24`).
- **Human Accountability**: All AI-assisted triage decisions must remain subject to human security analyst oversight.

---

## 12. Troubleshooting & Common Issues

| Issue | Cause | Solution |
|---|---|---|
| `Backend Offline` pill in UI | FastAPI server not running on port 8000 | Run `python backend/main.py` in your terminal |
| `Corpus: 0 vectors` in UI | Ingestion script hasn't been run yet | Run `python backend/scripts/ingest_dataset.py --limit 500` |
| `Dataset file not found` | Zip archive moved or renamed | Verify `combined_security_dataset_final.zip` is in the workspace root |
| Slow first embedding run | PyTorch initializing model weights on CPU | Normal for first inference; cached model weights load from disk in ~15-20s |
| API rate limit / key errors | Invalid or expired OpenAI / Mistral key | Set `MOCK_LLM_MODE=true` in `backend/.env` to use deterministic simulation mode |
