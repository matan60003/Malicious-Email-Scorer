from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Malicious Email Scorer"
    API_V1_STR: str = "/api/v1"

    VIRUSTOTAL_API_KEY: str | None = None
    SAFE_BROWSING_API_KEY: str | None = None
    API_KEY_SECRET: str = "super_secret_dev_key"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
