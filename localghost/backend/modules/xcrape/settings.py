"""Capture-specific limits and storage, separate from scanner configuration."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

from backend.utils.paths import PROJECT_DIR, SOURCE_CHECKOUT, data_path


def integer(values: dict, name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(values.get(name, default))
    except ValueError as exc:
        raise ValueError(f"{name} must be a whole number.") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


@dataclass
class Settings:
    database: Path = field(default_factory=lambda: data_path("captures.db"))
    workers: int = 1
    queue_size: int = 20
    scrape_timeout: int = 60
    port: int = 8000
    selector_limit: int = 500
    image_bytes: int = 5 * 1024 * 1024
    preview_bytes: int = 32 * 1024 * 1024
    archive_bytes: int = 20 * 1024 * 1024
    archive_images: int = 50


settings = Settings()


def load_settings() -> Settings:
    """Read module configuration atomically without changing the host environment."""
    default_env = PROJECT_DIR.parent / ".env" if SOURCE_CHECKOUT else Path.cwd() / ".env"
    env_file = Path(os.environ.get("XCRAPE_ENV_FILE", default_env))
    values = {**{key: value for key, value in dotenv_values(env_file).items() if value is not None}, **os.environ}
    database = data_path("captures.db")
    if values.get("LOCALGHOST_CAPTURE_DB_PATH"):
        database = Path(values["LOCALGHOST_CAPTURE_DB_PATH"]).expanduser()
    elif values.get("DATABASE_URL"):
        value = values["DATABASE_URL"]
        prefix = next((p for p in ("sqlite+aiosqlite:///", "sqlite:///") if value.startswith(p)), None)
        if not prefix:
            raise ValueError("DATABASE_URL must be a SQLite file URL.")
        database = Path(value[len(prefix) :])
        if str(database) in (".", ":memory:") or "?" in str(database):
            raise ValueError("DATABASE_URL must name a SQLite file.")
        database = (PROJECT_DIR if SOURCE_CHECKOUT else Path.cwd()) / database
    candidate = Settings(
        database=database,
        workers=integer(values, "XCRAPE_WORKERS", 1, 1, 4),
        queue_size=integer(values, "XCRAPE_QUEUE_SIZE", 20, 1, 100),
        scrape_timeout=integer(values, "XCRAPE_TIMEOUT", 60, 10, 180),
        port=integer(values, "PORT", 8000, 1, 65535),
    )
    settings.__dict__.update(candidate.__dict__)
    return settings
