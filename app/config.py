"""DevGuard AI Configuration Settings.

Parses environment variables and .env file for Akamai Hosted AI Inference,
Linode Cloud Firewall API, GitHub REST API, and Valkey host configurations.
"""
import os
from pathlib import Path
from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Preload .env if available in workspace
ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
if ENV_FILE.exists():
    load_dotenv(ENV_FILE, override=False)


def _get_default_inference_endpoint() -> str:
    """Return configured inference endpoint or workshop base URL fallback."""
    explicit = os.getenv("INFERENCE_ENDPOINT")
    if explicit:
        return explicit
    openai_base = os.getenv("OPENAI_BASE_URL")
    if openai_base:
        base = openai_base.rstrip("/")
        return base if base.endswith("/chat/completions") else f"{base}/chat/completions"
    return "https://api.linode.com/v1/ai/completions"


def _get_default_inference_key() -> str:
    """Return inference API key or OpenAI key fallback."""
    return os.getenv("INFERENCE_API_KEY") or os.getenv("OPENAI_API_KEY") or "mock_key"


def _get_default_mock_mode() -> bool:
    """Determine mock mode from environment or presence of real keys."""
    raw = os.getenv("MOCK_MODE", "True").strip().lower()
    return raw in ("true", "1", "yes")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    INFERENCE_ENDPOINT: str = Field(default_factory=_get_default_inference_endpoint)
    INFERENCE_API_KEY: str = Field(default_factory=_get_default_inference_key)
    GITHUB_TOKEN: str = Field(default_factory=lambda: os.getenv("GITHUB_TOKEN", "mock_github"))
    LINODE_TOKEN: str = Field(default_factory=lambda: os.getenv("LINODE_TOKEN", "mock_linode"))
    VALKEY_HOST: str = Field(default_factory=lambda: os.getenv("VALKEY_HOST", "valkey"))
    VALKEY_PORT: int = Field(default_factory=lambda: int(os.getenv("VALKEY_PORT", "6379")))
    VALKEY_URL: str = Field(default_factory=lambda: os.getenv("VALKEY_URL", ""))
    MOCK_MODE: bool = Field(default_factory=_get_default_mock_mode)

    @property
    def is_inference_mock(self) -> bool:
        """True if mock mode is forced or inference credentials are absent."""
        if self.MOCK_MODE:
            return True
        key = (self.INFERENCE_API_KEY or "").strip()
        return not key or key == "mock_key" or key == "paste_your_team_key_here"

    @property
    def is_linode_mock(self) -> bool:
        """True if mock mode is forced or Linode token is absent."""
        if self.MOCK_MODE:
            return True
        token = (self.LINODE_TOKEN or "").strip()
        return not token or token == "mock_linode"

    @property
    def is_github_mock(self) -> bool:
        """True if mock mode is forced or GitHub token is absent."""
        if self.MOCK_MODE:
            return True
        token = (self.GITHUB_TOKEN or "").strip()
        return not token or token == "mock_github"


settings = Settings()
