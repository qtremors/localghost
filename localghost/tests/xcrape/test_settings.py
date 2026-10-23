import pytest

from backend.modules.xcrape.settings import PROJECT_DIR, load_settings, settings


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    previous = settings.__dict__.copy()
    for name in (
        "LOCALGHOST_CAPTURE_DB_PATH",
        "DATABASE_URL",
        "PORT",
        "XCRAPE_WORKERS",
        "XCRAPE_QUEUE_SIZE",
        "XCRAPE_TIMEOUT",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("XCRAPE_ENV_FILE", str(tmp_path / ".env"))
    yield
    settings.__dict__.update(previous)


def test_environment_file_and_relative_database_paths_from_another_directory(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("DATABASE_URL=sqlite:///data/legacy.db\nPORT=8769\nXCRAPE_WORKERS=3\n")
    monkeypatch.chdir(tmp_path)
    configured = load_settings()
    assert configured.database == PROJECT_DIR / "data/legacy.db"
    assert configured.port == 8769 and configured.workers == 3


def test_environment_overrides_file_and_localghost_path_overrides_legacy_url(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("XCRAPE_WORKERS=4\nDATABASE_URL=sqlite:///old.db\n")
    monkeypatch.setenv("XCRAPE_WORKERS", "2")
    monkeypatch.setenv("LOCALGHOST_CAPTURE_DB_PATH", str(tmp_path / "new.db"))
    configured = load_settings()
    assert configured.workers == 2 and configured.database == tmp_path / "new.db"


@pytest.mark.parametrize("prefix", ["sqlite:///", "sqlite+aiosqlite:///"])
def test_legacy_absolute_database_url(prefix, tmp_path, monkeypatch):
    path = tmp_path / "saved.db"
    monkeypatch.setenv("DATABASE_URL", prefix + str(path))
    assert load_settings().database == path


@pytest.mark.parametrize(
    "name,value",
    [
        ("XCRAPE_WORKERS", "0"),
        ("XCRAPE_WORKERS", "5"),
        ("XCRAPE_WORKERS", "bad"),
        ("XCRAPE_QUEUE_SIZE", "101"),
        ("XCRAPE_TIMEOUT", "9"),
        ("PORT", "65536"),
        ("DATABASE_URL", "postgres:///db"),
        ("DATABASE_URL", "sqlite:///:memory:"),
    ],
)
def test_invalid_configuration_does_not_partially_replace_settings(name, value, monkeypatch):
    previous = settings.__dict__.copy()
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        load_settings()
    assert settings.__dict__ == previous


def test_module_env_file_does_not_change_host_environment(tmp_path, monkeypatch):
    import os

    monkeypatch.delenv("AUDIT_HOST_VALUE", raising=False)
    (tmp_path / ".env").write_text("AUDIT_HOST_VALUE=private\nXCRAPE_WORKERS=2\n")
    assert load_settings().workers == 2
    assert "AUDIT_HOST_VALUE" not in os.environ
