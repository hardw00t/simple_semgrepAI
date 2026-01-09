import typer
import asyncio
from pathlib import Path
from rich.console import Console
from typing import Optional
from .scanner import SemgrepScanner
from .validator import AIValidator
from .reporter import HTMLReporter
from .rag import RAGStore
from .config import ConfigManager

app = typer.Typer(
    name="semgrepai",
    help="AI-powered Semgrep vulnerability validator",
    add_completion=False,
)
console = Console()

@app.command()
def scan(
    target_path: Path = typer.Argument(..., help="Path to the code to scan"),
    rules_path: Optional[Path] = typer.Option(None, help="Path to custom rules"),
    output_dir: Path = typer.Option("./reports", help="Directory for output reports"),
    config_path: Optional[Path] = typer.Option(None, help="Path to configuration file"),
):
    """Run Semgrep scan with optional custom rules and generate reports."""
    try:
        console.print("[bold blue]Starting SemgrepAI Security Scan[/bold blue]")
        console.print(f"Target: {target_path}")

        # Initialize scanner
        scanner = SemgrepScanner()
        results = scanner.scan(target_path, rules_path)

        # Extract findings from results
        if results and isinstance(results, dict) and 'json' in results and isinstance(results['json'], dict):
            scan_findings = scanner._process_results(results)

            if scan_findings:
                console.print(f"\n[cyan]Found {len(scan_findings)} findings to analyze[/cyan]")

                # Initialize RAG store for false positive learning
                rag = RAGStore()

                # Store scan findings in RAG
                rag.store_findings(scan_findings)

                # Validate findings using AI with RAG integration
                validator = AIValidator(config_path=config_path, rag_store=rag)
                validated_findings = validator.validate_findings(scan_findings)

                # Get cost metrics if available
                cost_metrics = None
                if hasattr(validator.llm, 'cost_metrics') and validator.llm.cost_metrics:
                    # Save cost metrics before generating report
                    if hasattr(validator.llm, 'config') and validator.llm.config.cost_metrics_path:
                        validator.llm.cost_metrics.save(validator.llm.config.cost_metrics_path)

                    cost_metrics = {
                        'total_cost': validator.llm.cost_metrics.total_cost,
                        'total_requests': validator.llm.cost_metrics.total_requests,
                        'total_input_tokens': validator.llm.cost_metrics.total_input_tokens,
                        'total_output_tokens': validator.llm.cost_metrics.total_output_tokens,
                        'failed_requests': validator.llm.cost_metrics.failed_requests,
                        'retried_requests': validator.llm.cost_metrics.retried_requests,
                        'total_latency': validator.llm.cost_metrics.total_latency,
                        'costs_by_model': validator.llm.cost_metrics.costs_by_model,
                    }

                    # Display cost summary
                    console.print(f"\n[bold green]Cost Summary:[/bold green]")
                    console.print(f"  Total Cost: ${cost_metrics['total_cost']:.4f}")
                    console.print(f"  Total Requests: {cost_metrics['total_requests']}")
                    console.print(f"  Total Tokens: {cost_metrics['total_input_tokens'] + cost_metrics['total_output_tokens']:,}")

                # Get validation metrics
                validation_metrics = None
                if hasattr(validator, 'metrics') and validator.metrics:
                    validation_metrics = validator.metrics.get_current_metrics()

                # Display cache statistics
                if hasattr(validator, 'cache') and validator.cache:
                    try:
                        if hasattr(validator.cache, 'get_statistics'):
                            cache_stats = validator.cache.get_statistics()
                            console.print(f"\n[bold green]Cache Performance:[/bold green]")
                            console.print(f"  Hit Rate: {cache_stats.get('hit_rate', 'N/A')}")
                            console.print(f"  Total Entries: {cache_stats.get('total_entries', 0)}")
                            console.print(f"  Capacity: {cache_stats.get('capacity_used', 'N/A')}")
                        elif hasattr(validator.cache, 'cache'):
                            console.print(f"\n[bold green]Cache Performance:[/bold green]")
                            console.print(f"  Total Entries: {len(validator.cache.cache)}")
                    except Exception:
                        pass  # Cache stats are optional

                # Display RAG statistics if available
                try:
                    rag_stats = rag.get_validation_statistics()
                    if rag_stats.get('total_validations', 0) > 0:
                        console.print(f"\n[bold green]Learning Database:[/bold green]")
                        console.print(f"  Historical Validations: {rag_stats['total_validations']}")
                        console.print(f"  True Positives: {rag_stats['true_positives']}")
                        console.print(f"  False Positives: {rag_stats['false_positives']}")
                except Exception as e:
                    pass  # RAG stats are optional

                # Generate reports with enhanced statistics
                console.print(f"\n[bold blue]Generating reports...[/bold blue]")
                reporter = HTMLReporter()
                report_path = reporter.generate_report(
                    validated_findings,
                    output_dir,
                    metrics=validation_metrics,
                    cost_metrics=cost_metrics
                )

                console.print(f"[green]✓[/green] Report generated: {report_path}")
            else:
                console.print("[yellow]No findings to analyze[/yellow]")
        else:
            console.print("[yellow]No scan results found[/yellow]")

        console.print("\n[green]✓[/green] Scan completed successfully!")

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        import traceback
        console.print(f"[red]{traceback.format_exc()}[/red]")
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


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind the server to"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind the server to"),
    reload: bool = typer.Option(False, "--reload", "-r", help="Enable auto-reload for development"),
):
    """Start the SemgrepAI web server with REST API and Web UI."""
    try:
        import uvicorn

        console.print(f"[cyan]Starting SemgrepAI web server...[/cyan]")
        console.print(f"[green]API docs:[/green] http://{host}:{port}/api/docs")
        console.print(f"[green]Web UI:[/green] http://{host}:{port}/")

        uvicorn.run(
            "semgrepai.api.main:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info",
        )
    except ImportError:
        console.print("[red]Error:[/red] uvicorn is not installed. Install it with: pip install uvicorn[standard]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise typer.Exit(1)


@app.command(name="init-db")
def init_db():
    """Initialize the database schema."""
    try:
        from .api.db import init_db as _init_db

        console.print("[cyan]Initializing database...[/cyan]")
        asyncio.run(_init_db())
        console.print("[green]Database initialized successfully![/green]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise typer.Exit(1)


@app.command()
def config(
    generate: bool = typer.Option(False, "--generate", "-g", help="Generate a default configuration file"),
    show: bool = typer.Option(False, "--show", "-s", help="Show current configuration"),
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Path for config file"),
):
    """Manage SemgrepAI configuration."""
    try:
        if generate:
            output_path = path or Path("semgrepai.yml")
            ConfigManager.generate_default_config(output_path)
            console.print(f"[green]Configuration file generated at:[/green] {output_path}")
        elif show:
            config_manager = ConfigManager(str(path) if path else None)
            import yaml
            console.print(yaml.dump(config_manager.config.model_dump(), default_flow_style=False))
        else:
            console.print("Use --generate to create a config file or --show to display current config")
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    console.print("[cyan]SemgrepAI[/cyan] version 0.2.0")


if __name__ == "__main__":
    app()
