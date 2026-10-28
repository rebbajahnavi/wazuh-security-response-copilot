from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent


class Settings(BaseSettings):
    # Server settings
    host: str = "127.0.0.1"
    port: int = 8000
    environment: str = "development"
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000"

    # Qdrant settings
    qdrant_path: Optional[str] = "backend/data/qdrant_storage"
    qdrant_url: Optional[str] = None
    qdrant_api_key: Optional[str] = None
    qdrant_collection: str = "serc_security_knowledge"

    # Embedding model settings
    embedding_model_name: str = "BAAI/bge-large-en-v1.5"
    embedding_batch_size: int = 32
    top_k_retrieval: int = 5

    # Dataset & Storage
    dataset_path: str = "combined_security_dataset_final.zip"
    sample_alerts_path: str = "backend/data/sample_alerts.json"
    feedback_db_path: str = "backend/data/feedback.db"

    # LLM Settings
    openai_api_key: Optional[str] = ""
    openai_api_base: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o"

    pixtral_api_key: Optional[str] = ""
    pixtral_api_base: str = "https://api.mistral.ai/v1"
    pixtral_model: str = "pixtral-12b-2409"

    mock_llm_mode: bool = True

    model_config = SettingsConfigDict(
        env_file=(BASE_DIR / ".env", PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def get_cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    def resolve_path(self, relative_or_absolute: str) -> Path:
        p = Path(relative_or_absolute)
        if p.is_absolute():
            return p
        # Check relative to backend dir or project root
        if (BASE_DIR / p).exists():
            return (BASE_DIR / p).resolve()
        if (PROJECT_ROOT / p).exists():
            return (PROJECT_ROOT / p).resolve()
        # Default to PROJECT_ROOT / p
        return (PROJECT_ROOT / p).resolve()

    @property
    def dataset_file(self) -> Path:
        return self.resolve_path(self.dataset_path)

    @property
    def sample_alerts_file(self) -> Path:
        return self.resolve_path(self.sample_alerts_path)

    @property
    def feedback_db_file(self) -> Path:
        return self.resolve_path(self.feedback_db_path)

    @property
    def qdrant_storage_dir(self) -> Optional[Path]:
        if self.qdrant_path:
            return self.resolve_path(self.qdrant_path)
        return None

    @property
    def is_mock(self) -> bool:
        # Mock is active if explicitly set or if API keys are missing
        if self.mock_llm_mode:
            return True
        if not self.openai_api_key or not self.pixtral_api_key:
            return True
        return False


settings = Settings()
