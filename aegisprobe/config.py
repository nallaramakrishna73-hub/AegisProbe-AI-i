"""
Configuration management for AegisProbe AI.
Supports ~/.config/aegisprobe/config.yaml, environment variables, and CLI overrides.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
import yaml
from pydantic import BaseModel, Field


CONFIG_DIR = Path(os.path.expanduser("~/.config/aegisprobe"))
CONFIG_FILE = CONFIG_DIR / "config.yaml"


class SafetyConfig(BaseModel):
    require_authorization: bool = True
    allow_external_targets: bool = False
    rate_limit_rps: float = 5.0
    max_scan_timeout_sec: int = 180


class BrowserConfig(BaseModel):
    max_pages: int = 10
    max_actions: int = 30
    timeout_sec: int = 30
    headless: bool = True


class ReportingConfig(BaseModel):
    format: str = "html"
    output_dir: str = "./reports"


class AegisConfig(BaseModel):
    provider: str = Field(default_factory=lambda: os.getenv("AI_PROVIDER", "ollama"))
    model: str = Field(default_factory=lambda: os.getenv("AI_MODEL", "llama3"))
    api_key: Optional[str] = Field(default_factory=lambda: os.getenv("AI_API_KEY", ""))
    base_url: str = Field(default_factory=lambda: os.getenv("AI_BASE_URL", "http://127.0.0.1:11434"))
    timeout: int = 30
    database_url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///aegisprobe.db"))
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)


def load_config() -> AegisConfig:
    """Load configuration from disk with fallback to defaults and environment."""
    config_dict: Dict[str, Any] = {}
    
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    config_dict = loaded
        except Exception:
            pass
    elif Path("config.yaml").exists():
        try:
            with open("config.yaml", "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    config_dict = loaded
        except Exception:
            pass

    return AegisConfig(**config_dict)


def save_config(cfg: AegisConfig) -> None:
    """Save config to ~/.config/aegisprobe/config.yaml."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg.model_dump(), f, sort_keys=False)
