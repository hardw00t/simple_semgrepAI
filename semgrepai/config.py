from pathlib import Path
from typing import Optional, Dict, List, Set
import yaml
from pydantic import BaseModel, Field, ConfigDict
from .llm.providers import LLMProviderConfig

class LLMConfig(BaseModel):
    provider: LLMProviderConfig = Field(
        default_factory=lambda: LLMProviderConfig(
            provider="openai",
            model="gpt-4.1-mini",
            temperature=0
        )
    )
    cache_dir: Path = Field(default_factory=lambda: Path(".cache/llm"))
    max_workers: Optional[int] = 4
    batch_size: int = 10

    model_config = ConfigDict(protected_namespaces=())

class SemgrepConfig(BaseModel):
    default_rules: List[str] = ["auto"]
    max_target_files: int = 1000
    timeout: int = 300
    jobs: Optional[int] = None

    model_config = ConfigDict(protected_namespaces=())

class CodeAnalysisConfig(BaseModel):
    max_file_size: int = 1_000_000  # Max file size to analyze in bytes
    max_related_files: int = 10  # Max number of related files to analyze
    analyze_imports: bool = True  # Whether to analyze imported files
    analyze_references: bool = True  # Whether to analyze file references
    excluded_dirs: Set[str] = Field(default_factory=lambda: {
        'venv', 'node_modules', '.git', '__pycache__',
        'build', 'dist', 'migrations'
    })
    excluded_files: Set[str] = Field(default_factory=lambda: {
        '*.pyc', '*.pyo', '*.pyd', '*.so', '*.dylib',
        '*.min.js', '*.min.css', '*.map'
    })
    languages: Set[str] = Field(default_factory=lambda: {
        'python', 'javascript', 'typescript', 'java',
        'ruby', 'php', 'go', 'csharp'
    })
    max_analysis_time: int = 30  # Maximum time in seconds to spend analyzing a single file
    cache_analysis: bool = True  # Whether to cache analysis results

    model_config = ConfigDict(protected_namespaces=())

class RAGConfig(BaseModel):
    persist_dir: Path = Field(default_factory=lambda: Path(".semgrepai/db"))
    collection_name: str = "findings"
    distance_metric: str = "cosine"
    embeddings_model: str = "all-MiniLM-L6-v2"

    model_config = ConfigDict(protected_namespaces=())

class ReportConfig(BaseModel):
    output_dir: Path = Field(default_factory=lambda: Path("reports"))
    formats: List[str] = ["html", "json", "sarif"]
    max_findings_per_page: int = 50

    model_config = ConfigDict(protected_namespaces=())


class AsyncConfig(BaseModel):
    """Configuration for async processing."""
    max_concurrent_requests: int = 4
    """Maximum number of concurrent LLM requests."""

    requests_per_minute: int = 60
    """Rate limit: maximum requests per minute."""

    retry_max_attempts: int = 3
    """Maximum number of retry attempts for failed requests."""

    retry_base_delay: float = 1.0
    """Base delay in seconds for exponential backoff."""

    retry_max_delay: float = 60.0
    """Maximum delay in seconds for exponential backoff."""

    enable_jitter: bool = True
    """Add random jitter to retry delays to prevent thundering herd."""

    model_config = ConfigDict(protected_namespaces=())


class APIConfig(BaseModel):
    """Configuration for the web API server."""
    host: str = "127.0.0.1"
    """Host to bind the server to."""

    port: int = 8080
    """Port to bind the server to."""

    cors_origins: List[str] = Field(default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"])
    """Allowed CORS origins for the frontend."""

    db_url: str = "sqlite+aiosqlite:///.semgrepai/semgrepai.db"
    """Database URL for async SQLAlchemy."""

    secret_key: Optional[str] = None
    """Secret key for session management. If not set, a random one is generated."""

    debug: bool = False
    """Enable debug mode with auto-reload."""

    log_level: str = "info"
    """Logging level for the API server."""

    model_config = ConfigDict(protected_namespaces=())


class Config(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    rag: RAGConfig = Field(default_factory=RAGConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    analysis: CodeAnalysisConfig = Field(default_factory=CodeAnalysisConfig)
    async_config: AsyncConfig = Field(default_factory=AsyncConfig, alias="async")
    api: APIConfig = Field(default_factory=APIConfig)

    model_config = ConfigDict(
        protected_namespaces=(),
        populate_by_name=True  # Allow using alias 'async' in config files
    )

class ConfigManager:
    DEFAULT_CONFIG_PATHS = [
        Path("semgrepai.yml"),
        Path("~/.config/semgrepai/config.yml"),
        Path("/etc/semgrepai/config.yml")
    ]

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)

    def _load_config(self, config_path: Optional[str]) -> Config:
        """Load configuration from file or use defaults."""
        config_data = {}
        
        # Try loading from specified path
        if config_path:
            path = Path(config_path)
            if path.exists():
                with open(path) as f:
                    config_data = yaml.safe_load(f)
        
        # Try default paths if no config loaded
        if not config_data:
            for path in self.DEFAULT_CONFIG_PATHS:
                path = path.expanduser()
                if path.exists():
                    with open(path) as f:
                        config_data = yaml.safe_load(f)
                    break
        
        return Config(**config_data if config_data else {})

    def save_config(self, path: Optional[Path] = None) -> None:
        """Save current configuration to file."""
        save_path = path or self.DEFAULT_CONFIG_PATHS[0]
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(save_path, 'w') as f:
            yaml.dump(self.config.dict(), f, default_flow_style=False)

    @classmethod
    def generate_default_config(cls, path: Path) -> None:
        """Generate a default configuration file."""
        config = Config()
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            yaml.dump(config.dict(), f, default_flow_style=False)
            
    def update_config(self, updates: Dict) -> None:
        """Update configuration with new values."""
        current_dict = self.config.dict()
        self._deep_update(current_dict, updates)
        self.config = Config(**current_dict)
        
    def _deep_update(self, base_dict: Dict, update_dict: Dict) -> None:
        """Recursively update a dictionary."""
        for key, value in update_dict.items():
            if (
                key in base_dict 
                and isinstance(base_dict[key], dict) 
                and isinstance(value, dict)
            ):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value
