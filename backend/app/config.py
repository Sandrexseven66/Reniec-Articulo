from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "RENIEC-DEMO Offline Authenticator"
    database_path: Path = Path(__file__).resolve().parents[1] / "data" / "reniec_demo.db"
    key_path: Path = Path(__file__).resolve().parents[1] / "data" / "ed25519-private.pem"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    max_image_bytes: int = 4_000_000

    @property
    def origins(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


settings = Settings()
settings.database_path.parent.mkdir(parents=True, exist_ok=True)
