"""
Centralized configuration via pydantic-settings.
Reads from .env file or environment variables.
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # LLM proxy target
    llm_api_url: str = "https://api.openai.com/v1/chat/completions"
    llm_api_key: str = "sk-test"
    llm_model: str = "gpt-3.5-turbo"

    # Firewall behavior
    firewall_mode: str = "enforce"  # enforce | monitor | passthrough
    block_threshold: float = 0.70
    pii_enabled: bool = True
    semantic_enabled: bool = True
    rule_engine_enabled: bool = True

    # Paths
    db_path: str = str(BASE_DIR / "data" / "audit.db")
    rules_dir: str = str(BASE_DIR / "engine" / "rules")
    threat_store_path: str = str(BASE_DIR / "data" / "threats" / "threat_vectors.json")

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"


settings = Settings()
