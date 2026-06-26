"""配置加载 - pydantic-settings 从环境变量读取所有配置。"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SSO_", env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8000
    issuer_url: str = "http://localhost:8000"

    db_path: str = "./sso.db"

    jwt_secret: str = "change-me"

    client_id: str = "outline"
    client_secret: str = "change-me"
    redirect_uris: str = "https://wiki.example.com/auth/oidc.callback"

    seed_username: str = "admin"
    seed_password: str = "admin123"
    seed_email: str = "admin@example.com"
    seed_name: str = "Administrator"

    email_domain: str = "local.sso.invalid"

    access_token_expires: int = 3600
    code_expires: int = 600

    session_secret: str = "change-me"
    session_max_age: int = 28800

    page_size: int = 20

    @property
    def redirect_uri_list(self) -> list[str]:
        return [u.strip() for u in self.redirect_uris.split(",") if u.strip()]


settings = Settings()
