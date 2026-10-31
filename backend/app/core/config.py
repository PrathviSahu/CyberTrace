# CyberTrace Core Configuration
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberTrace"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    # Base directories
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "app" / "data" / "sample_logs"
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR}/cybertrace.db"
    
    # Ingestion Limits
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    MAX_EVENTS_PER_BATCH: int = 50000
    
    # BharatCode AI Configuration
    BHARATCODE_API_KEY: Optional[str] = None
    BHARATCODE_BASE_URL: str = "https://bharatcode.ai/api/model/v1"
    BHARATCODE_MODEL: str = "qwen-3.8-27b"
    BHARATCODE_TIMEOUT_SECONDS: float = 30.0
    
    # Detection Thresholds
    BRUTE_FORCE_FAILURE_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_SECONDS: int = 300  # 5 minutes
    COMPROMISE_WINDOW_SECONDS: int = 900   # 15 minutes
    PRIVILEGE_ESCALATION_WINDOW_SECONDS: int = 1800  # 30 minutes
    OUTBOUND_EGRESS_THRESHOLD_BYTES: int = 50 * 1024 * 1024  # 50 MB
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
