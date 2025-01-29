from pathlib import Path
from typing import Dict, List
from jinja2 import Environment, FileSystemLoader
import json
from datetime import datetime

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
            <p>{{ findings|length }}</p>
        </div>
        <div class="stat-card">
            <h3>True Positives</h3>
            <p>{{ findings|selectattr('ai_validation.is_true_positive', 'true')|list|length }}</p>
        </div>
        <div class="stat-card">
            <h3>False Positives</h3>
            <p>{{ findings|selectattr('ai_validation.is_true_positive', 'false')|list|length }}</p>
        </div>
    </div>

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

    def generate_report(self, findings: List[Dict], output_dir: Path):
        """Generate HTML report from findings."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate HTML report
        html_report = self.template.render(
            findings=findings,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        # Save HTML report
        html_path = output_dir / "report.html"
        html_path.write_text(html_report)
        
        # Save JSON report
        json_path = output_dir / "report.json"
        json_path.write_text(json.dumps(findings, indent=2))
        
        return html_path
