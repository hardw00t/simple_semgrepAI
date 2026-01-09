# Simple SemgrepAI

An AI-powered code security scanner that combines Semgrep's static analysis with LLM-based validation to provide accurate and actionable security findings.

## Quick Start

```bash
# Clone and install (requires uv and Node.js)
git clone https://github.com/hardw00t/simple_semgrepAI.git
cd simple_semgrepAI
make install

# Set your API key
export ANTHROPIC_API_KEY='your-key'  # or OPENAI_API_KEY

# Start the web UI
uv run semgrepai serve

# Or run a CLI scan
uv run semgrepai scan /path/to/code
```

Open http://localhost:8082 to access the Web UI.

## Features

- **Advanced Static Analysis**
  - Runs Semgrep scans with default or custom rules
  - Built-in security rules for SQL injection, XSS, and weak cryptography
  - Supports multiple programming languages

- **AI-Powered Validation**
  - Uses LLM to validate findings and reduce false positives
  - Provides detailed security analysis for each finding
  - Includes risk scoring and impact assessment
  - Multi-provider support (OpenAI, Anthropic, Ollama, OpenRouter)
  - Automatic retry with exponential backoff
  - Rate limiting to respect API quotas

- **Machine Learning & False Positive Learning**
  - RAG-based learning from historical validations
  - Automatic detection of similar false positives
  - Contextual insights from past findings

- **Web UI Dashboard**
  - Real-time scan progress with WebSocket updates
  - Interactive findings table with filtering and sorting
  - Finding detail panel with AI analysis
  - Triage workflow (True Positive, False Positive, Needs Review)
  - Severity distribution visualization

- **Comprehensive Reporting**
  - JSON and SARIF report formats
  - Interactive HTML reports with visualizations
  - Proof of concept and attack vectors
  - Actionable remediation steps
  - Cost tracking and API usage metrics

- **Performance Optimizations**
  - Validation result caching
  - Async processing with configurable workers
  - Batch processing for large codebases

- **Cost Management**
  - Real-time API cost tracking
  - Token usage monitoring
  - Per-model cost breakdown

## Installation

### Prerequisites

- Python 3.10+
- [UV](https://docs.astral.sh/uv/) package manager (recommended)
- Node.js 18+ (for Web UI)
- Semgrep CLI (installed automatically)

### Install UV (Recommended)

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Install from Source

```bash
git clone https://github.com/hardw00t/simple_semgrepAI.git
cd simple_semgrepAI

# Single command installation (Python + Frontend)
make install

# Run commands with uv
uv run semgrepai --help
```

### Alternative: Manual Installation

```bash
# Install Python dependencies with UV
uv sync --all-extras

# Build frontend
cd semgrepai/web/frontend && npm ci && npm run build && cd ../../..

# Or with pip (legacy)
pip install -e .
cd semgrepai/web/frontend && npm ci && npm run build
```

### Configure API Keys

Choose your preferred LLM provider:

```bash
# Anthropic (recommended)
export ANTHROPIC_API_KEY='your-anthropic-key'

# OpenAI
export OPENAI_API_KEY='your-openai-key'

# OpenRouter
export OPENROUTER_API_KEY='your-openrouter-key'
```

For local Ollama, no API key is needed - just ensure Ollama is running.

## Usage

### Web UI (Recommended)

```bash
uv run semgrepai serve
```

Open http://localhost:8082 in your browser.

### CLI Scan

```bash
# Basic scan
uv run semgrepai scan /path/to/your/code

# Scan with custom rules
uv run semgrepai scan /path/to/code --rules-path /path/to/rules.yml

# Scan with built-in security rules
uv run semgrepai scan /path/to/code --rules-path semgrepai/rules/common_vulnerabilities.yml

# Scan with specific output directory
uv run semgrepai scan /path/to/code --output-dir ./reports
```

### Built-in Security Rules

SemgrepAI includes custom rules for common vulnerabilities:

| Rule ID | Vulnerability | Severity |
|---------|---------------|----------|
| `python-sql-injection-*` | SQL Injection (f-string, concat, format) | ERROR |
| `python-flask-xss-*` | Cross-Site Scripting | ERROR/WARNING |
| `python-weak-hash-*` | Weak Cryptography (MD5, SHA1) | WARNING |

Use them with:
```bash
uv run semgrepai scan /path/to/code --rules-path semgrepai/rules/common_vulnerabilities.yml
```

### Custom Rules

Create custom rules in YAML:

```yaml
# custom_rules.yml
rules:
  - id: custom-sql-injection
    pattern: "$DB.execute(\"...\" + $X + \"...\")"
    message: "SQL injection vulnerability detected"
    severity: ERROR
    languages: [python]
```

## Development

### Commands

```bash
make help              # Show all commands
make install           # Install Python + Frontend
make dev               # Start development server
make test              # Run all tests with coverage
make test-unit         # Run fast unit tests only
make test-integration  # Run integration tests
make test-e2e          # Run E2E tests (requires API keys)
make lint              # Run linters
make format            # Format code
make clean             # Clean build artifacts
make clean-all         # Deep clean (includes venv, node_modules)
```

### Testing

```bash
# Run all tests
uv run pytest tests/ -v

# Run unit tests only (fast, no API calls)
uv run pytest tests/unit -v

# Run integration tests
uv run pytest tests/integration -v

# Run with coverage
uv run pytest tests/ --cov=semgrepai --cov-report=html
```

Test markers:
- `@pytest.mark.unit` - Fast tests, no external dependencies
- `@pytest.mark.integration` - Tests with external services
- `@pytest.mark.e2e` - End-to-end tests (may incur API costs)

## Configuration

Create a `semgrepai.yml` file to customize settings:

```yaml
llm:
  provider:
    provider: anthropic  # Options: openai, anthropic, openrouter, ollama
    model: claude-sonnet-4-5-20250514
    temperature: 0.1
    max_tokens: 8192

    # Retry and rate limiting
    max_retries: 3
    retry_delay: 1.0
    retry_exponential_backoff: true
    max_retry_delay: 60.0

    # Cost tracking
    enable_cost_tracking: true
    cost_metrics_path: .cache/llm/cost_metrics.json

  cache_dir: .cache/llm
  max_workers: 4
  batch_size: 10

semgrep:
  default_rules:
    - auto
  timeout: 300

analysis:
  max_file_size: 1000000
  analyze_imports: true
  analyze_references: true

rag:
  persist_dir: .semgrepai/db
  collection_name: findings
  embeddings_model: all-MiniLM-L6-v2
```

### LLM Provider Examples

**Anthropic (Recommended):**
```yaml
llm:
  provider:
    provider: anthropic
    model: claude-sonnet-4-5-20250514  # Best for coding tasks
    # model: claude-haiku-4-5-20250901  # Fastest, cost-effective
    # model: claude-opus-4-5-20251101   # Most intelligent
```

**OpenAI:**
```yaml
llm:
  provider:
    provider: openai
    model: gpt-4o           # General purpose
    # model: gpt-4.1        # Best for coding, 1M context
    # model: gpt-4.1-mini   # Cost-effective
    # model: o3             # Advanced reasoning
    # model: o4-mini        # Fast reasoning
```

**Ollama (Local):**
```yaml
llm:
  provider:
    provider: ollama
    model: llama3.3:latest      # Latest Llama
    # model: deepseek-r1:14b    # DeepSeek reasoning
    # model: qwen2.5-coder:latest  # Coding focused
```

**OpenRouter:**
```yaml
llm:
  provider:
    provider: openrouter
    model: anthropic/claude-sonnet-4-5
    # model: openai/gpt-4.1
    # model: google/gemini-2.0-flash
```

## Output Files

The tool generates reports in the `reports` directory:

| File | Description |
|------|-------------|
| `semgrep.json` | Raw Semgrep findings (JSON) |
| `semgrep.sarif` | Raw Semgrep findings (SARIF) |
| `report.json` | Validated findings with AI analysis |
| `report.html` | Interactive HTML report |

## Web UI Features

- **Dashboard**: Overview of scans, severity distribution, AI verdicts
- **Scans List**: Create, view, and manage security scans
- **Scan Detail**: Real-time progress, findings table, filtering
- **Finding Panel**: Detailed AI analysis including:
  - Verdict with confidence score
  - Risk assessment (1-10)
  - Impact assessment
  - Vulnerability classification
  - Attack vectors and trigger steps
  - Proof of concept
  - Recommended fixes

## Supported Models

### Anthropic Claude 4.x
| Model | Description | Context |
|-------|-------------|---------|
| `claude-opus-4-5-20251101` | Most intelligent | 200K |
| `claude-sonnet-4-5-20250514` | Best for coding | 1M |
| `claude-haiku-4-5-20250901` | Fastest | 200K |

### OpenAI
| Model | Description | Context |
|-------|-------------|---------|
| `gpt-4o` | General purpose | 128K |
| `gpt-4.1` | Best for coding | 1M |
| `gpt-4.1-mini` | Cost-effective | 1M |
| `o3` | Advanced reasoning | 200K |
| `o4-mini` | Fast reasoning | 128K |

### Ollama (Local)
| Model | Description |
|-------|-------------|
| `llama3.3:latest` | Latest Llama |
| `deepseek-r1:14b` | DeepSeek reasoning |
| `qwen2.5-coder:latest` | Coding focused |
| `mistral:latest` | Mistral |

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## Security

If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md) for responsible disclosure.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Semgrep](https://semgrep.dev/) for their excellent static analysis engine
- [OpenAI](https://openai.com/) and [Anthropic](https://anthropic.com/) for their powerful language models
- [React](https://react.dev/) and [Vite](https://vite.dev/) for the frontend framework
