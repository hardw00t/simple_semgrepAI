# Simple SemgrepAI

An AI-powered code security scanner that combines Semgrep's static analysis with LLM-based validation to provide accurate and actionable security findings.

## Features

- 🔍 **Advanced Static Analysis**
  - Runs Semgrep scans with default or custom rules
  - Supports multiple programming languages
  - Configurable scan depth and scope

- 🤖 **AI-Powered Validation**
  - Uses LLM to validate findings and reduce false positives
  - Provides detailed security analysis for each finding
  - Includes risk scoring and impact assessment

- 📊 **Comprehensive Reporting**
  - Generates both JSON and SARIF reports
  - Creates beautiful HTML reports with detailed analysis
  - Includes proof of concept and attack vectors
  - Provides actionable remediation steps

- 💾 **Performance Optimizations**
  - Caches validation results for faster rescans
  - Supports parallel processing
  - Configurable batch sizes and workers

## Installation

1. Clone the repository:
```bash
git clone https://github.com/hardw00t/simple_semgrepAI.git
cd simple_semgrepAI
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure your OpenAI API key:
```bash
export OPENAI_API_KEY='your-api-key'
```

## Usage

### Basic Scan
```bash
python -m semgrepai.cli scan /path/to/your/code
```

### Scan with Custom Rules
```bash
python -m semgrepai.cli scan /path/to/your/code --rules-path /path/to/rules.yml
```

### Custom Rules

You can add custom rules in two ways:

1. In the configuration file (`semgrepai.yml`):
```yaml
semgrep:
  default_rules:
    - auto  # Include default rules
    - rules:  # Add inline custom rules
        - id: custom-sql-injection
          pattern: "$DB.execute(\"...\" + $X + \"...\")"
          message: "SQL injection vulnerability detected"
          severity: ERROR
```

2. In a separate rules file:
```yaml
# custom_rules.yml
rules:
  - id: custom-xss
    pattern: "$RES.write(\"...\" + $USER_INPUT + \"...\")"
    message: "XSS vulnerability detected"
    severity: ERROR
```

Then run:
```bash
python -m semgrepai.cli scan /path/to/code --rules-path custom_rules.yml
```

## Output Files

The tool generates several output files in the `reports` directory:

- `semgrep.json`: Raw Semgrep findings in JSON format
- `semgrep.sarif`: Raw Semgrep findings in SARIF format
- `report.json`: Validated findings with AI analysis
- `report.html`: Human-readable report with:
  - Vulnerability details
  - Code snippets
  - Risk assessment
  - Attack vectors
  - Remediation steps

## Configuration

The tool can be configured through `semgrepai.yml`:

```yaml
llm:
  provider:
    provider: openai
    model: gpt-4
    temperature: 0.1
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
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## Security

If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md) for responsible disclosure.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Semgrep](https://semgrep.dev/) for their excellent static analysis engine
- OpenAI for their powerful language models
- All our contributors and users
