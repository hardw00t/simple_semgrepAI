# Simple SemgrepAI

An AI-powered code security scanner that combines Semgrep's static analysis with LLM-based validation to provide accurate and actionable security findings.

## Features

- **Advanced Static Analysis**
  - Runs Semgrep scans with default or custom rules
  - Supports multiple programming languages
  - Configurable scan depth and scope

- **AI-Powered Validation**
  - Uses LLM to validate findings and reduce false positives
  - Provides detailed security analysis for each finding
  - Includes risk scoring and impact assessment
  - Multi-provider support (OpenAI, Anthropic, Ollama, OpenRouter)
  - Automatic retry with exponential backoff for failed API calls
  - Rate limiting to respect API quotas

- **Machine Learning & False Positive Learning**
  - RAG-based learning from historical validations
  - Automatic detection of similar false positives
  - Contextual insights from past findings
  - Validation history tracking and statistics

- **Web UI Dashboard**
  - Real-time scan progress with WebSocket updates
  - Interactive findings table with filtering and sorting
  - Finding detail panel with AI analysis
  - Triage workflow (True Positive, False Positive, Needs Review)
  - Severity distribution visualization

- **Comprehensive Reporting**
  - Generates both JSON and SARIF reports
  - Creates beautiful HTML reports with detailed analysis
  - Includes proof of concept and attack vectors
  - Provides actionable remediation steps
  - Cost tracking and API usage metrics
  - Enhanced visualizations with risk distribution
  - Performance metrics and processing times
  - Vulnerability category breakdowns

- **Performance Optimizations**
  - Caches validation results for faster rescans
  - Automatic cache size management with LRU eviction
  - Configurable cache limits and auto-cleanup
  - Async processing with configurable workers
  - Batch processing for large codebases

- **Cost Management**
  - Real-time API cost tracking
  - Token usage monitoring (input/output)
  - Per-model cost breakdown
  - Failed and retried request tracking
  - Cost metrics persistence and reporting

## Installation

### Prerequisites

- Python 3.10+
- Node.js 18+ (for Web UI development)
- Semgrep CLI

### Install from source

```bash
git clone https://github.com/hardw00t/simple_semgrepAI.git
cd simple_semgrepAI
pip install -e .
```

### Configure API Keys

Choose your preferred LLM provider:

```bash
# OpenAI
export OPENAI_API_KEY='your-openai-key'

# Anthropic
export ANTHROPIC_API_KEY='your-anthropic-key'

# OpenRouter
export OPENROUTER_API_KEY='your-openrouter-key'
```

For local Ollama, no API key is needed - just ensure Ollama is running.

## Usage

### Web UI (Recommended)

Start the web server:

```bash
semgrepai server
```

Then open http://localhost:8082 in your browser.

### CLI Scan

```bash
# Basic scan
semgrepai scan /path/to/your/code

# Scan with custom rules
semgrepai scan /path/to/your/code --rules-path /path/to/rules.yml

# Scan with specific output directory
semgrepai scan /path/to/your/code --output-dir ./reports
```

### Custom Rules

Add custom rules in a YAML file:

```yaml
# custom_rules.yml
rules:
  - id: custom-sql-injection
    pattern: "$DB.execute(\"...\" + $X + \"...\")"
    message: "SQL injection vulnerability detected"
    severity: ERROR
    languages: [python]
```

Then run:
```bash
semgrepai scan /path/to/code --rules-path custom_rules.yml
```

## Output Files

The tool generates several output files in the `reports` directory:

| File | Description |
|------|-------------|
| `semgrep.json` | Raw Semgrep findings in JSON format |
| `semgrep.sarif` | Raw Semgrep findings in SARIF format |
| `report.json` | Validated findings with AI analysis, cost tracking, performance metrics |
| `report.html` | Interactive HTML report with visualizations |

The HTML report includes:
- Cost analysis dashboard
- Risk distribution charts
- Vulnerability category breakdown
- Performance metrics visualization
- Code snippets and remediation steps

## Configuration

Create a `semgrepai.yml` file to customize settings:

```yaml
llm:
  provider:
    provider: anthropic  # Options: openai, anthropic, openrouter, ollama
    model: claude-sonnet-4-5-20241022
    temperature: 0.1
    max_tokens: 8192

    # Retry and rate limiting
    max_retries: 3
    retry_delay: 1.0
    retry_exponential_backoff: true
    max_retry_delay: 60.0
    rate_limit_requests_per_minute: null  # Optional
    rate_limit_tokens_per_minute: null    # Optional

    # Cost tracking
    enable_cost_tracking: true
    cost_metrics_path: .cache/llm/cost_metrics.json

  cache_dir: .cache/llm
  cache_max_entries: 10000  # Maximum cache entries
  cache_cleanup_interval: 100  # Auto-cleanup frequency
  max_workers: 4
  batch_size: 10

semgrep:
  default_rules:
    - auto
  max_target_files: 1000
  timeout: 300

analysis:
  max_file_size: 1000000
  analyze_imports: true
  analyze_references: true

rag:  # RAG configuration for learning
  persist_dir: .semgrepai/db
  collection_name: findings
  distance_metric: cosine
  embeddings_model: all-MiniLM-L6-v2

# Web server settings
server:
  host: 127.0.0.1
  port: 8082
```

### LLM Provider Examples

**OpenAI:**
```yaml
llm:
  provider:
    provider: openai
    model: gpt-4o
```

**Anthropic:**
```yaml
llm:
  provider:
    provider: anthropic
    model: claude-sonnet-4-5-20241022
```

**Ollama (Local):**
```yaml
llm:
  provider:
    provider: ollama
    model: deepseek-r1:14b
    base_url: http://localhost:11434
```

**OpenRouter:**
```yaml
llm:
  provider:
    provider: openrouter
    model: anthropic/claude-3.5-sonnet
    base_url: https://openrouter.ai/api/v1
```

## Web UI Features

The Web UI provides:

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
- All our contributors and users
