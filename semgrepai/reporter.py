from pathlib import Path
from typing import Dict, List, Optional
from jinja2 import Environment, FileSystemLoader
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class HTMLReporter:
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        self.template_dir.mkdir(exist_ok=True)
        self._create_template()

        self.env = Environment(loader=FileSystemLoader(str(self.template_dir)))
        self.template = self.env.get_template("report.html")

    def _create_template(self):
        """Create the HTML template file if it doesn't exist."""
        template_path = self.template_dir / "report.html"
        if not template_path.exists():
            template_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SemgrepAI Security Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .finding {
            background: #fff;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .true-positive {
            border-left: 4px solid #dc3545;
        }
        .false-positive {
            border-left: 4px solid #28a745;
        }
        .unknown {
            border-left: 4px solid #ffc107;
        }
        .severity {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            color: #fff;
            font-weight: bold;
        }
        .severity.high { background: #dc3545; }
        .severity.medium { background: #ffc107; }
        .severity.low { background: #28a745; }
        .code {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Monaco', 'Consolas', monospace;
            overflow-x: auto;
        }
        .section {
            margin: 15px 0;
        }
        .section-title {
            font-weight: bold;
            margin-bottom: 10px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #fff;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        .true-positive-card { border-top: 3px solid #dc3545; }
        .false-positive-card { border-top: 3px solid #28a745; }
        .warning-card { border-top: 3px solid #ffc107; }
        .critical-card { border-top: 3px solid #8b0000; }
        .high-card { border-top: 3px solid #dc3545; }
        .medium-card { border-top: 3px solid #ffc107; }
        .low-card { border-top: 3px solid #28a745; }
        .vuln-list {
            margin-top: 15px;
        }
        .vuln-item {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            background: #f8f9fa;
            margin: 5px 0;
            border-radius: 4px;
        }
        .vuln-name {
            font-weight: bold;
        }
        .vuln-count {
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>SemgrepAI Security Report</h1>
        <p>Generated on: {{ timestamp }}</p>
    </div>

    <div class="stats">
        <div class="stat-card">
            <h3>Total Findings</h3>
            <p class="stat-number">{{ stats.total_findings }}</p>
        </div>
        <div class="stat-card true-positive-card">
            <h3>True Positives</h3>
            <p class="stat-number">{{ stats.true_positives }}</p>
            <small>{{ stats.true_positive_rate }}</small>
        </div>
        <div class="stat-card false-positive-card">
            <h3>False Positives</h3>
            <p class="stat-number">{{ stats.false_positives }}</p>
            <small>{{ stats.false_positive_rate }}</small>
        </div>
        <div class="stat-card warning-card">
            <h3>Needs Review</h3>
            <p class="stat-number">{{ stats.needs_review }}</p>
        </div>
    </div>

    <div class="stats">
        <div class="stat-card critical-card">
            <h3>Critical Risk (≥8)</h3>
            <p class="stat-number">{{ stats.critical_findings }}</p>
        </div>
        <div class="stat-card high-card">
            <h3>High Risk (6-7)</h3>
            <p class="stat-number">{{ stats.high_findings }}</p>
        </div>
        <div class="stat-card medium-card">
            <h3>Medium Risk (4-5)</h3>
            <p class="stat-number">{{ stats.medium_findings }}</p>
        </div>
        <div class="stat-card low-card">
            <h3>Low Risk (<4)</h3>
            <p class="stat-number">{{ stats.low_findings }}</p>
        </div>
    </div>

    {% if stats.cost_metrics %}
    <div class="header">
        <h2>Cost Analysis</h2>
        <div class="stats">
            <div class="stat-card">
                <h3>Total Cost</h3>
                <p class="stat-number">${{ "%.4f"|format(stats.cost_metrics.total_cost) }}</p>
            </div>
            <div class="stat-card">
                <h3>Total Requests</h3>
                <p class="stat-number">{{ stats.cost_metrics.total_requests }}</p>
                <small>{{ stats.cost_metrics.retried_requests }} retried</small>
            </div>
            <div class="stat-card">
                <h3>Total Tokens</h3>
                <p class="stat-number">{{ stats.cost_metrics.total_input_tokens + stats.cost_metrics.total_output_tokens }}</p>
                <small>{{ stats.cost_metrics.total_input_tokens }} in / {{ stats.cost_metrics.total_output_tokens }} out</small>
            </div>
            <div class="stat-card">
                <h3>Avg Latency</h3>
                <p class="stat-number">{{ "%.2f"|format(stats.cost_metrics.total_latency / stats.cost_metrics.total_requests if stats.cost_metrics.total_requests > 0 else 0) }}s</p>
            </div>
        </div>
    </div>
    {% endif %}

    <div class="header">
        <h2>Performance Metrics</h2>
        <div class="stats">
            <div class="stat-card">
                <h3>Total Processing Time</h3>
                <p class="stat-number">{{ stats.total_processing_time }}</p>
            </div>
            <div class="stat-card">
                <h3>Avg Time per Finding</h3>
                <p class="stat-number">{{ stats.average_processing_time }}</p>
            </div>
            <div class="stat-card">
                <h3>Avg Risk Score</h3>
                <p class="stat-number">{{ stats.average_risk_score }}</p>
            </div>
        </div>
    </div>

    {% if stats.vulnerability_categories %}
    <div class="header">
        <h2>Top Vulnerability Categories</h2>
        <div class="vuln-list">
            {% for category, count in stats.vulnerability_categories.items() %}
            <div class="vuln-item">
                <span class="vuln-name">{{ category }}</span>
                <span class="vuln-count">{{ count }} findings</span>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    {% for finding in findings %}
    <div class="finding {% if finding.ai_validation.is_true_positive %}true-positive{% elif finding.ai_validation.is_true_positive == false %}false-positive{% else %}unknown{% endif %}">
        <h2>{{ finding.rule_id }}</h2>
        <span class="severity {{ finding.severity|lower }}">{{ finding.severity }}</span>
        
        <div class="section">
            <div class="section-title">Location</div>
            <p>{{ finding.path }}:{{ finding.line }}</p>
        </div>

        <div class="section">
            <div class="section-title">Message</div>
            <p>{{ finding.message }}</p>
        </div>

        <div class="section">
            <div class="section-title">Code</div>
            <pre class="code">{{ finding.code }}</pre>
        </div>

        {% if finding.dataflow %}
        <div class="section">
            <div class="section-title">Data Flow</div>
            <ul>
            {% for step in finding.dataflow %}
                <li>{{ step.type }}: {{ step.content }} at {{ step.location }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endif %}

        <div class="section">
            <div class="section-title">AI Validation</div>
            <p><strong>Verdict:</strong> {% if finding.ai_validation.is_true_positive %}True Positive{% elif finding.ai_validation.is_true_positive == false %}False Positive{% else %}Unknown{% endif %}</p>
            
            {% if finding.ai_validation.justification %}
            <p><strong>Justification:</strong></p>
            <p>{{ finding.ai_validation.justification }}</p>
            {% endif %}

            {% if finding.ai_validation.is_true_positive %}
                {% if finding.ai_validation.poc %}
                <p><strong>Proof of Concept:</strong></p>
                <pre class="code">{{ finding.ai_validation.poc }}</pre>
                {% endif %}

                {% if finding.ai_validation.attack_vectors %}
                <p><strong>Attack Vectors:</strong></p>
                <ul>
                {% for vector in finding.ai_validation.attack_vectors %}
                    <li>{{ vector }}</li>
                {% endfor %}
                </ul>
                {% endif %}

                {% if finding.ai_validation.trigger_steps %}
                <p><strong>Steps to Trigger:</strong></p>
                <ol>
                {% for step in finding.ai_validation.trigger_steps %}
                    <li>{{ step }}</li>
                {% endfor %}
                </ol>
                {% endif %}

                {% if finding.ai_validation.recommended_fixes %}
                <p><strong>Recommended Fixes:</strong></p>
                <ul>
                {% for fix in finding.ai_validation.recommended_fixes %}
                    <li>{{ fix }}</li>
                {% endfor %}
                </ul>
                {% endif %}
            {% endif %}
        </div>
    </div>
    {% endfor %}
</body>
</html>
            """
            template_path.write_text(template_content)

    def generate_report(self, findings: List[Dict], output_dir: Path, metrics: Optional[Dict] = None, cost_metrics: Optional[Dict] = None):
        """Generate HTML report from findings with enhanced statistics."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Calculate enhanced statistics
        stats = self._calculate_statistics(findings, metrics, cost_metrics)

        # Generate HTML report
        html_report = self.template.render(
            findings=findings,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            stats=stats
        )

        # Save HTML report
        html_path = output_dir / "report.html"
        html_path.write_text(html_report)

        # Save JSON report with all metadata
        json_report = {
            'generated_at': datetime.now().isoformat(),
            'statistics': stats,
            'findings': findings
        }
        json_path = output_dir / "report.json"
        json_path.write_text(json.dumps(json_report, indent=2))

        return html_path

    def _calculate_statistics(self, findings: List[Dict], metrics: Optional[Dict] = None, cost_metrics: Optional[Dict] = None) -> Dict:
        """Calculate comprehensive statistics for the report."""
        total_findings = len(findings)
        true_positives = sum(1 for f in findings if f.get('ai_validation', {}).get('is_valid') == True)
        false_positives = sum(1 for f in findings if f.get('ai_validation', {}).get('is_valid') == False)
        needs_review = sum(1 for f in findings if f.get('ai_validation', {}).get('verdict', '').lower() == 'needs review')

        # Severity distribution
        severity_dist = {}
        for f in findings:
            sev = f.get('severity', 'Unknown')
            severity_dist[sev] = severity_dist.get(sev, 0) + 1

        # Risk score distribution
        risk_scores = [f.get('ai_validation', {}).get('risk_score', 0) for f in findings if f.get('ai_validation')]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        critical_findings = sum(1 for score in risk_scores if score >= 8)
        high_findings = sum(1 for score in risk_scores if 6 <= score < 8)
        medium_findings = sum(1 for score in risk_scores if 4 <= score < 6)
        low_findings = sum(1 for score in risk_scores if score < 4)

        # Vulnerability categories
        vuln_categories = {}
        for f in findings:
            vuln = f.get('ai_validation', {}).get('vulnerability', {}).get('primary', 'Unknown')
            if vuln != 'Unknown':
                vuln_categories[vuln] = vuln_categories.get(vuln, 0) + 1

        # Processing metrics
        processing_times = [f.get('processing_time', 0) for f in findings]
        total_processing_time = sum(processing_times)
        avg_processing_time = total_processing_time / len(processing_times) if processing_times else 0

        stats = {
            'total_findings': total_findings,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'needs_review': needs_review,
            'true_positive_rate': f"{(true_positives / total_findings * 100):.1f}%" if total_findings > 0 else "0%",
            'false_positive_rate': f"{(false_positives / total_findings * 100):.1f}%" if total_findings > 0 else "0%",
            'severity_distribution': severity_dist,
            'average_risk_score': f"{avg_risk_score:.1f}",
            'critical_findings': critical_findings,
            'high_findings': high_findings,
            'medium_findings': medium_findings,
            'low_findings': low_findings,
            'vulnerability_categories': dict(sorted(vuln_categories.items(), key=lambda x: x[1], reverse=True)[:10]),
            'total_processing_time': f"{total_processing_time:.2f}s",
            'average_processing_time': f"{avg_processing_time:.2f}s",
        }

        # Add validation metrics if provided
        if metrics:
            stats['validation_metrics'] = metrics

        # Add cost metrics if provided
        if cost_metrics:
            stats['cost_metrics'] = cost_metrics

        return stats
