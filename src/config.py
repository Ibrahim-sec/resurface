"""
Resurface configuration management
"""
import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LLMConfig:
    provider: str = "gemini"
    model: str = "gemini-2.0-flash"
    api_key: str = ""
    temperature: float = 0.1
    max_tokens: int = 4096


@dataclass
class ScraperConfig:
    platform: str = "hackerone"
    rate_limit: float = 2.0
    cache_dir: str = "data/reports"
    user_agent: str = "Resurface/1.0 (Security Research)"


@dataclass  
class EngineConfig:
    timeout: int = 30
    max_retries: int = 3
    follow_redirects: bool = True
    verify_ssl: bool = True
    proxy: str = ""


@dataclass
class BrowserConfig:
    headless: bool = True
    timeout: int = 60000
    screenshot: bool = True
    video: bool = False
    viewport_width: int = 1280
    viewport_height: int = 720


@dataclass
class ValidatorConfig:
    confidence_threshold: float = 0.7
    evidence_capture: bool = True


@dataclass
class ReporterConfig:
    output_dir: str = "data/results"
    formats: list = field(default_factory=lambda: ["html", "json"])
    include_evidence: bool = True


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    scraper: ScraperConfig = field(default_factory=ScraperConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    validator: ValidatorConfig = field(default_factory=ValidatorConfig)
    reporter: ReporterConfig = field(default_factory=ReporterConfig)
    database_url: str = "sqlite:///data/resurface.db"
    log_level: str = "INFO"
    base_dir: str = ""

    def __post_init__(self):
        if not self.base_dir:
            self.base_dir = str(Path(__file__).parent.parent)


def load_config(config_path: str = None) -> Config:
    """Load configuration from YAML file and environment variables"""
    config = Config()
    
    # Try loading from file
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        
        if 'llm' in data:
            for k, v in data['llm'].items():
                if hasattr(config.llm, k):
                    setattr(config.llm, k, v)
        if 'scraper' in data:
            for k, v in data['scraper'].items():
                if hasattr(config.scraper, k):
                    setattr(config.scraper, k, v)
        if 'engine' in data:
            for k, v in data['engine'].items():
                if hasattr(config.engine, k):
                    setattr(config.engine, k, v)
        if 'browser' in data:
            for k, v in data['browser'].items():
                if k == 'viewport':
                    config.browser.viewport_width = v.get('width', 1280)
                    config.browser.viewport_height = v.get('height', 720)
                elif hasattr(config.browser, k):
                    setattr(config.browser, k, v)
        if 'database' in data:
            config.database_url = data['database'].get('url', config.database_url)
    
    # Environment variable overrides
    env_key = os.environ.get('RESURFACE_LLM_API_KEY', '')
    if env_key:
        config.llm.api_key = env_key
    
    gemini_key = os.environ.get('GEMINI_API_KEY', '')
    if gemini_key and not config.llm.api_key:
        config.llm.api_key = gemini_key
        config.llm.provider = 'gemini'
    
    groq_key = os.environ.get('GROQ_API_KEY', '')
    if groq_key:
        config.llm.api_key = groq_key
        config.llm.provider = 'groq'
        if config.llm.model.startswith('gemini'):
            config.llm.model = 'llama-3.3-70b-versatile'
    
    return config
