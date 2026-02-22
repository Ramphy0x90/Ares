from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/ares.db"
    WS_HEARTBEAT_INTERVAL: int = 30
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 3600
    DATA_DIR: Path = Path("data")

    OIDC_ISSUER: str = ""
    OIDC_CLIENT_ID: str = ""

    model_config = {"env_file": ".env"}


settings = Settings()
