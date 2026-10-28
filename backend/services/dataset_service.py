"""
Dataset inspection and streaming service for the 100,000-row cybersecurity dataset.
Supports streaming directly from compressed .zip or extracted .csv files.
"""
import io
import csv
import zipfile
import logging
from pathlib import Path
from typing import Dict, Any, Generator, List, Optional
from backend.config import settings, PROJECT_ROOT

logger = logging.getLogger("serc.dataset_service")


class DatasetService:
    def __init__(self, dataset_path: Optional[str] = None):
        self.dataset_path = Path(dataset_path) if dataset_path else settings.dataset_file

    def find_dataset_file(self) -> Optional[Path]:
        """Locates the dataset zip or csv file across standard project paths."""
        candidates = [
            self.dataset_path,
            Path("combined_security_dataset_final.zip"),
            Path("combined_security_dataset_final.csv"),
            Path("backend/data/combined_security_dataset_final.zip"),
            Path("backend/data/combined_security_dataset_final.csv"),
            PROJECT_ROOT / "combined_security_dataset_final.zip",
            PROJECT_ROOT / "combined_security_dataset_final.csv",
        ]
        for c in candidates:
            if c and c.exists():
                return c.resolve()
        return None

    def get_csv_reader(self):
        """Returns a context manager / file handle yielding a csv.DictReader."""
        file_path = self.find_dataset_file()
        if not file_path:
            raise FileNotFoundError(f"Dataset file not found at {self.dataset_path} or default locations.")

        if file_path.suffix.lower() == ".zip":
            zf = zipfile.ZipFile(file_path, "r")
            csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
            if not csv_names:
                raise ValueError(f"No CSV file found inside zip archive {file_path}")
            csv_file = zf.open(csv_names[0])
            text_stream = io.TextIOWrapper(csv_file, encoding="utf-8", errors="replace")
            reader = csv.DictReader(text_stream)
            return zf, csv_file, text_stream, reader
        else:
            fh = open(file_path, "r", encoding="utf-8", errors="replace")
            reader = csv.DictReader(fh)
            return None, None, fh, reader

    def inspect_dataset(self, max_sample_rows: int = 1000) -> Dict[str, Any]:
        """
        Inspects dataset schema, column names, data types, missing values,
        and knowledge set distributions without loading the entire 1GB file into RAM.
        """
        file_path = self.find_dataset_file()
        if not file_path:
            return {
                "available": False,
                "error": f"Dataset file not found at {self.dataset_path}",
                "expected_schema_columns": 49
            }

        zf, cf, ts, reader = self.get_csv_reader()
        try:
            columns = reader.fieldnames or []
            total_sampled = 0
            missing_counts = {col: 0 for col in columns}
            knowledge_sets = set()
            source_types = set()
            mapping_methods = set()
            mapping_confidences = set()
            attack_types = set()
            sample_rows = []

            for row in reader:
                total_sampled += 1
                if total_sampled <= 5:
                    # Keep 5 representative sample rows
                    sample_rows.append({k: row.get(k, "") for k in list(row.keys())[:15]})

                for col in columns:
                    val = row.get(col, "").strip()
                    if not val:
                        missing_counts[col] += 1

                if row.get("knowledge_set"):
                    knowledge_sets.add(row.get("knowledge_set"))
                if row.get("source_type"):
                    source_types.add(row.get("source_type"))
                if row.get("mapping_method"):
                    mapping_methods.add(row.get("mapping_method"))
                if row.get("mapping_confidence"):
                    mapping_confidences.add(row.get("mapping_confidence"))
                if row.get("attack_type"):
                    attack_types.add(row.get("attack_type"))

                if total_sampled >= max_sample_rows:
                    break

            return {
                "available": True,
                "file_path": str(file_path),
                "file_size_bytes": file_path.stat().st_size,
                "column_count": len(columns),
                "columns": columns,
                "sample_analyzed": total_sampled,
                "knowledge_sets": sorted(list(knowledge_sets)),
                "source_types": list(source_types)[:5],
                "mapping_methods": list(mapping_methods)[:5],
                "mapping_confidences": sorted(list(mapping_confidences)),
                "attack_types_sample": sorted(list(attack_types))[:10],
                "missing_value_summary": {k: missing_counts[k] for k in list(missing_counts.keys())[:10]},
                "representative_records": sample_rows,
            }
        finally:
            if ts:
                ts.close()
            if cf:
                cf.close()
            if zf:
                zf.close()

    def iter_records(self, limit: Optional[int] = None) -> Generator[Dict[str, Any], None, None]:
        """Streams records one by one up to an optional limit."""
        zf, cf, ts, reader = self.get_csv_reader()
        try:
            count = 0
            for row in reader:
                yield row
                count += 1
                if limit and count >= limit:
                    break
        finally:
            if ts:
                ts.close()
            if cf:
                cf.close()
            if zf:
                zf.close()

    @staticmethod
    def build_search_text(record: Dict[str, Any]) -> str:
        """
        Extracts or formats the rich semantic document text used for embedding.
        Prefers the pre-computed combined_knowledge_text if available,
        otherwise synthesizes a structured summary from available fields.
        """
        if record.get("combined_knowledge_text") and len(record["combined_knowledge_text"].strip()) > 30:
            return record["combined_knowledge_text"].strip()

        parts = []
        if record.get("attack_type"):
            parts.append(f"Attack Type: {record['attack_type']}")
        if record.get("incident_description"):
            parts.append(f"Description: {record['incident_description']}")
        if record.get("mitre_technique_id") or record.get("mitre_technique_name"):
            parts.append(f"MITRE ATT&CK: {record.get('mitre_technique_id', '')} - {record.get('mitre_technique_name', '')}")
        if record.get("mitre_tactic"):
            parts.append(f"MITRE Tactic: {record['mitre_tactic']}")
        if record.get("detection_indicators"):
            parts.append(f"Indicators: {record['detection_indicators']}")
        if record.get("investigation_steps"):
            parts.append(f"Investigation Steps: {record['investigation_steps']}")
        if record.get("recommended_response"):
            parts.append(f"Recommended Response: {record['recommended_response']}")
        if record.get("nist_function") or record.get("nist_category"):
            parts.append(f"NIST CSF: {record.get('nist_function', '')} {record.get('nist_category', '')}")

        return " | ".join(parts)


dataset_service = DatasetService()
