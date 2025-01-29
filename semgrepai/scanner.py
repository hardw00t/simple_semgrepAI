import subprocess
import json
from pathlib import Path
from typing import Optional, Dict, List
import tempfile
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

class SemgrepScanner:
    def __init__(self):
        self.verify_semgrep_installation()

    def verify_semgrep_installation(self):
        """Verify that semgrep is installed and accessible."""
        try:
            result = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, check=True)
            console.print(f"[green]✓[/green] Semgrep version: {result.stdout.strip()}")
        except subprocess.CalledProcessError:
            raise RuntimeError("Semgrep is not installed or not accessible")

    def scan(self, target_path: Path, rules_path: Optional[Path] = None) -> Dict:
        """Run Semgrep scan and return findings."""
        # Ensure reports directory exists
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            console.print(f"\n[cyan]Starting Semgrep scan on:[/cyan] {target_path}")
            if rules_path:
                console.print(f"[cyan]Using custom rules from:[/cyan] {rules_path}")
            else:
                console.print("[cyan]Using default Semgrep rules[/cyan]")

            task = progress.add_task("[yellow]Running Semgrep scan...", total=1)
            
            # Define output files
            json_output_file = reports_dir / "semgrep.json"
            sarif_output_file = reports_dir / "semgrep.sarif"
            
            # Build base command
            cmd = ["semgrep", "scan"]
            
            if rules_path:
                cmd.extend(["--config", str(rules_path)])
            else:
                cmd.append("--config=auto")
            
            # Add target path
            cmd.append(str(target_path))
            
            try:
                # Run JSON scan
                json_cmd = cmd + ["--json", "--output", str(json_output_file)]
                json_result = subprocess.run(json_cmd, check=True, capture_output=True, text=True)
                
                # Run SARIF scan
                sarif_cmd = cmd + ["--sarif", "--output", str(sarif_output_file)]
                sarif_result = subprocess.run(sarif_cmd, check=True, capture_output=True, text=True)
                
                # Read outputs
                try:
                    with open(json_output_file) as f:
                        json_results = json.load(f)
                except json.JSONDecodeError as e:
                    console.print("[red]Error:[/red] Failed to parse JSON output")
                    console.print(f"JSON output file contents:")
                    with open(json_output_file) as f:
                        console.print(f.read())
                    raise RuntimeError(f"Failed to parse JSON output: {e}")
                    
                try:
                    with open(sarif_output_file) as f:
                        sarif_results = json.load(f)
                except json.JSONDecodeError as e:
                    console.print("[red]Error:[/red] Failed to parse SARIF output")
                    console.print(f"SARIF output file contents:")
                    with open(sarif_output_file) as f:
                        console.print(f.read())
                    raise RuntimeError(f"Failed to parse SARIF output: {e}")
                
                results = {
                    'json': json_results,
                    'sarif': sarif_results
                }
                
                progress.advance(task)
                console.print("[green]✓[/green] Scan completed")
                console.print(f"[green]Raw results saved to:[/green]")
                console.print(f"  - JSON: {json_output_file}")
                console.print(f"  - SARIF: {sarif_output_file}")
                
            except subprocess.CalledProcessError as e:
                console.print(f"[red]Error:[/red] Semgrep scan failed")
                console.print(e.stderr)
                raise RuntimeError(f"Semgrep scan failed: {e.stderr}")
            
            processed_results = self._process_results(results)
            console.print(f"\n[green]Found {len(processed_results)} potential issues[/green]")
            
            return processed_results

    def _extract_code(self, result: Dict) -> str:
        """Extract code snippet with context from a finding."""
        # First try to get from result
        code = result.get('lines', '')
        if code and code != "requires login":
            return code.strip()
            
        # Then try extra.lines
        if 'extra' in result:
            code = result['extra'].get('lines', '')
            if code and code != "requires login":
                return code.strip()
        
        # If we got here, try to read from file
        try:
            raw_path = result.get('path', '')
            if not raw_path:
                return "No file path available"
                
            # Handle relative paths
            path = Path(raw_path)
            if not path.is_absolute():
                # First try relative to cwd
                cwd_path = Path.cwd() / path
                if cwd_path.exists():
                    path = cwd_path
                else:
                    # Try cleaning up path
                    clean_path = Path(raw_path.lstrip('./'))
                    cwd_path = Path.cwd() / clean_path
                    if cwd_path.exists():
                        path = cwd_path
                    
            if not path.exists():
                return f"File not found: {raw_path}"
                
            # Read the file and extract relevant lines
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            # Get line numbers
            start_line = result.get('start', {}).get('line', 0)
            end_line = result.get('end', {}).get('line', start_line)
            
            # Validate line numbers
            if start_line < 1 or start_line > len(lines):
                return f"Invalid start line: {start_line}"
            if end_line < start_line or end_line > len(lines):
                end_line = start_line
                
            # Get context lines
            context_lines = 10
            start_idx = max(0, start_line - 1 - context_lines)
            end_idx = min(len(lines), end_line + context_lines)
            
            # Extract the lines
            code_lines = lines[start_idx:end_idx]
            
            # Add line numbers and highlight the vulnerable lines
            numbered_lines = []
            for i, line in enumerate(code_lines, start=start_idx + 1):
                prefix = f"{i:4d} | "
                if start_line <= i <= end_line:
                    numbered_lines.append(f">>> {prefix}{line.rstrip()}")
                else:
                    numbered_lines.append(f"    {prefix}{line.rstrip()}")
            
            return '\n'.join(numbered_lines)
            
        except Exception as e:
            return f"Error extracting code: {str(e)}"

    def _process_results(self, results: Dict) -> List[Dict]:
        """Process and normalize Semgrep results."""
        findings = []
        
        for result in results['json'].get('results', []):
            # Extract metadata
            metadata = result.get('extra', {}).get('metadata', {})
            
            # Extract code with context
            code = self._extract_code(result)
            
            finding = {
                'rule_id': result.get('check_id'),
                'severity': result.get('extra', {}).get('severity', 'UNKNOWN'),
                'message': result.get('extra', {}).get('message', ''),
                'path': result.get('path', ''),
                'line': result.get('start', {}).get('line', 0),
                'code': code,
                'dataflow': self._extract_dataflow(result),
                'references': self._extract_references(result),
                'security_patterns': self._extract_security_patterns(result),
                'metadata': {
                    'cwe': metadata.get('cwe', []),
                    'owasp': metadata.get('owasp', ''),
                    'category': metadata.get('category', ''),
                    'technology': metadata.get('technology', []),
                    'vulnerability_class': metadata.get('vulnerability_class', []),
                    'confidence': metadata.get('confidence', 'UNKNOWN'),
                    'source': metadata.get('source', ''),
                    'shortlink': metadata.get('shortlink', '')
                }
            }
            findings.append(finding)

        return findings

    def _extract_dataflow(self, result: Dict) -> List[Dict]:
        """Extract dataflow information from a finding."""
        dataflow = []
        if 'dataflow_trace' in result:
            for step in result['dataflow_trace']:
                dataflow.append({
                    'location': step.get('location'),
                    'content': step.get('content'),
                    'type': step.get('type')
                })
        return dataflow

    def _extract_references(self, result: Dict) -> List[Dict]:
        """Extract reference information from a finding."""
        references = []
        if 'related_locations' in result:
            for ref in result['related_locations']:
                references.append({
                    'path': ref.get('path'),
                    'line': ref.get('start', {}).get('line'),
                    'snippet': ref.get('snippet')
                })
        return references

    def _extract_security_patterns(self, result: Dict) -> List[Dict]:
        """Extract security pattern information from a finding."""
        security_patterns = []
        if 'security-patterns' in result:
            for pattern in result['security-patterns']:
                security_patterns.append({
                    'pattern': pattern.get('pattern'),
                    'severity': pattern.get('severity')
                })
        return security_patterns
