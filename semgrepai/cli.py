import typer
from pathlib import Path
from rich.console import Console
from typing import Optional
from .scanner import SemgrepScanner
from .validator import AIValidator
from .reporter import HTMLReporter
from .rag import RAGStore

app = typer.Typer()
console = Console()

@app.command()
def scan(
    target_path: Path = typer.Argument(..., help="Path to the code to scan"),
    rules_path: Optional[Path] = typer.Option(None, help="Path to custom rules"),
    output_dir: Path = typer.Option("./reports", help="Directory for output reports"),
):
    """Run Semgrep scan with optional custom rules and generate reports."""
    try:
        scanner = SemgrepScanner()
        findings = scanner.scan(target_path, rules_path)
        
        # Store findings in RAG
        rag = RAGStore()
        rag.store_findings(findings)
        
        # Validate findings using AI
        validator = AIValidator()
        validated_findings = validator.validate_findings(findings)
        
        # Generate reports
        reporter = HTMLReporter()
        reporter.generate_report(validated_findings, output_dir)
        
        console.print("[green]✓[/green] Scan completed successfully!")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise typer.Exit(1)

@app.command()
def search(
    query: str = typer.Argument(..., help="Search query for findings"),
):
    """Search through previous findings using RAG."""
    try:
        rag = RAGStore()
        results = rag.search(query)
        for result in results:
            console.print(result)
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
