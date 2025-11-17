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
                    validation_metrics = validator.metrics.get_summary()

                # Display cache statistics
                if hasattr(validator, 'cache'):
                    cache_stats = validator.cache.get_statistics()
                    console.print(f"\n[bold green]Cache Performance:[/bold green]")
                    console.print(f"  Hit Rate: {cache_stats.get('hit_rate', 'N/A')}")
                    console.print(f"  Total Entries: {cache_stats.get('total_entries', 0)}")
                    console.print(f"  Capacity: {cache_stats.get('capacity_used', 'N/A')}")

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

if __name__ == "__main__":
    app()
