from typing import Dict, List
import os
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich.box import ROUNDED
from threading import Lock
from .config import ConfigManager
from .cache import ValidationCache
from .parallel import ValidationBatchProcessor
from .logging import get_logger
from .metrics import MetricsCollector
from .analyzers.code_analyzer import CodeAnalyzer, shutdown_flag
from pathlib import Path
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from .llm.providers import LLMFactory
import re
import random

load_dotenv()
console = Console()
console_lock = Lock()
logger = get_logger(__name__)

class AIValidator:
    def __init__(self, config_path=None):
        # Load configuration
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.config
        
        # Initialize cache
        self.cache = ValidationCache(self.config.llm.cache_dir)
        
        # Initialize metrics
        metrics_dir = self.config.llm.cache_dir / "metrics"
        self.metrics = MetricsCollector(metrics_dir)
        
        # Initialize code analyzer
        self.analyzer = CodeAnalyzer(Path.cwd())
        
        # Initialize LLM
        logger.info(f"Initializing LLM with provider: {self.config.llm.provider.provider}, model: {self.config.llm.provider.model}")
        self.llm = LLMFactory.create_llm(self.config.llm.provider)
        
        self.validation_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a senior security expert analyzing potential vulnerabilities. Your task is to thoroughly analyze the provided finding and determine if it's a true or false positive.
                
                Provide your analysis in the following structured format:
                
                Verdict: [True Positive/False Positive/Needs Review]
                Confidence: [High/Medium/Low]
                Risk Score: [1-10, where 10 is most severe]
                
                Impact Assessment:
                - Business Impact: [Critical/High/Medium/Low]
                  Consider: Financial loss, reputation damage, regulatory compliance
                - Data Sensitivity: [High/Medium/Low]
                  Consider: PII, credentials, business secrets
                - Exploit Likelihood: [High/Medium/Low]
                  Consider: Technical complexity, required access, available tools
                
                Vulnerability Category:
                - Primary: [e.g., Injection, XSS, CSRF, etc.]
                - Sub-category: [More specific classification]
                
                Justification:
                [Detailed explanation of why this is a true/false positive, including:
                - Analysis of the code pattern
                - Security implications
                - Potential impact
                - Context-specific factors]
                
                Technical Details:
                - Language/Framework: [Affected technology]
                - Component Type: [e.g., API, UI, Database, etc.]
                - Scope: [Local/Remote]
                
                Proof of Concept:
                [Provide a detailed, step-by-step PoC that demonstrates the vulnerability.
                Include exact commands, payloads, or requests needed to reproduce.
                If it's a false positive, explain why the suspected attack wouldn't work.]
                
                Attack Vectors:
                [List potential attack vectors, each with:
                - Attack method
                - Required access/position
                - Likelihood of success
                - Potential impact]
                
                Steps to Trigger:
                1. [Detailed steps to reproduce]
                2. [Include specific inputs/conditions]
                3. [Note any required setup/prerequisites]
                
                Recommended Fixes:
                [Prioritized list of fixes, each with:
                - Clear code changes or configuration updates
                - Security best practices to implement
                - Additional hardening measures
                Mark each fix as [Critical/High/Medium/Low] priority]
                
                Additional Notes:
                - [Security best practices relevant to this issue]
                - [Related vulnerabilities to check]
                - [Security testing recommendations]
                - [Long-term security improvements]"""),
            ("human", """Finding Details:
                Rule ID: {rule_id}
                Severity: {severity}
                Message: {message}
                
                Code:
                {code}
                
                Path: {path}
                Line: {line}
                
                Function Context: {function_name}
                Class Context: {class_name}
                Imports: {imports}
                
                Dataflow:
                {dataflow}
                
                References:
                {references}
                
                Security Patterns:
                {security_patterns}
                
                Metadata:
                {metadata}
                
                Please analyze this finding and provide a detailed security assessment.""")
        ])
        
        # Create a chain using the new pattern
        self.validation_chain = self.validation_prompt | self.llm
        logger.debug("Validator initialization complete")

    def _get_cache_key(self, finding: Dict) -> str:
        """Generate a cache key for a finding."""
        # Use relevant fields to create a unique key
        key_parts = [
            finding.get('rule_id', ''),
            finding.get('path', ''),
            str(finding.get('line', '')),
            finding.get('message', '')
        ]
        return '|'.join(key_parts)

    def _format_dataflow(self, dataflow: List[Dict]) -> str:
        """Format dataflow information in a readable way."""
        if not dataflow:
            return 'No dataflow found'
            
        # Group dataflows by type for better organization
        flows_by_type = {}
        for flow in dataflow:
            flow_type = flow['type']
            if flow_type not in flows_by_type:
                flows_by_type[flow_type] = []
            flows_by_type[flow_type].append(flow)
        
        formatted_flows = []
        
        # Format URL operations first as they're most relevant for security
        if 'url_operation' in flows_by_type:
            formatted_flows.append("URL Operations:")
            for flow in flows_by_type['url_operation']:
                formatted_flows.append(f"  Line {flow['line']}: {flow['description']}")
        
        # Format assignments
        if 'assignment' in flows_by_type:
            formatted_flows.append("Variable Assignments:")
            for flow in flows_by_type['assignment']:
                formatted_flows.append(f"  Line {flow['line']}: {flow['description']}")
        
        # Format function calls
        if 'call' in flows_by_type:
            formatted_flows.append("Function Calls:")
            for flow in flows_by_type['call']:
                formatted_flows.append(f"  Line {flow['line']}: {flow['description']}")
        
        # Format any other types
        for flow_type, flows in flows_by_type.items():
            if flow_type not in ('url_operation', 'assignment', 'call'):
                formatted_flows.append(f"{flow_type.title()}:")
                for flow in flows:
                    formatted_flows.append(f"  Line {flow['line']}: {flow['description']}")
        
        return '\n'.join(formatted_flows)

    def _prepare_finding_context(self, finding: Dict, progress=None, task_id=None) -> Dict:
        """Prepare context for a finding including code snippet and analysis."""
        try:
            file_path = Path(finding['path'])
            line_number = finding.get('line', 0)
            
            # Get code context from analyzer
            context = self.analyzer.analyze_file(file_path)
            if context:
                # Extract code snippet with context
                code_snippet = self.analyzer.extract_code_snippet(file_path, line_number)
                
                # Update finding with context
                finding.update({
                    'code': code_snippet,
                    'function_name': context.function_name or 'Not in function',
                    'class_name': context.class_name or 'Not in class',
                    'imports': '\n'.join(context.imports) if context.imports else 'No imports',
                    'dataflow': self._format_dataflow(context.dataflow),
                    'references': '\n'.join(
                        f"Line {ref['line']}: {ref['content']}"
                        for ref in context.references
                    ) if context.references else 'No references found',
                    'security_patterns': {
                        'user_input_sources': [f"Line {src['line']}: {src['content']}" for src in context.user_input_sources] if context.user_input_sources else [],
                        'dangerous_sinks': [f"Line {sink['line']}: {sink['content']}" for sink in context.dangerous_sinks] if context.dangerous_sinks else [],
                        'sanitization_functions': [f"Line {san['line']}: {san['content']}" for san in context.sanitization_functions] if context.sanitization_functions else []
                    }
                })
            else:
                # Fallback if analysis fails
                finding.update({
                    'code': 'Could not analyze file',
                    'function_name': 'Unknown',
                    'class_name': 'Unknown',
                    'imports': 'Unknown',
                    'dataflow': 'Unknown',
                    'references': 'Unknown',
                    'security_patterns': {}
                })
                
        except Exception as e:
            logger.error(f"Error preparing finding context: {e}")
            finding.update({
                'code': 'Error analyzing code',
                'function_name': 'Error',
                'class_name': 'Error',
                'imports': 'Error',
                'dataflow': 'Error',
                'references': 'Error',
                'security_patterns': {}
            })
        
        return finding

    def validate_findings(self, findings: List[Dict], progress=None, task_id=None) -> List[Dict]:
        """Validate findings using AI analysis."""
        total_findings = len(findings)
        logger.info(f"Processing {total_findings} findings...")
        
        # Reset cache counters
        self.cache.hits = 0
        self.cache.misses = 0

        # Create progress bar
        progress = Progress(
            SpinnerColumn(),
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            "•",
            TextColumn("[blue]{task.completed}/{task.total} processed"),
            "•",
            TextColumn("[green]Cache hits: {task.fields[cache_hits]}"),
            "•",
            TextColumn("[yellow]{task.fields[current]}"),
            console=console,
            transient=True,
            expand=True
        )

        with progress:
            # Add main progress task
            task = progress.add_task(
                "Validating findings...",
                total=total_findings,
                completed=0,
                cache_hits=0,
                current="Starting..."
            )

            validated_findings = []
            start_time = time.time()
            
            # Process findings in parallel
            with ThreadPoolExecutor(max_workers=self.config.llm.max_workers) as executor:
                futures = []
                
                # Submit all tasks
                for i in range(0, len(findings), self.config.llm.batch_size):
                    batch = findings[i:i + self.config.llm.batch_size]
                    future = executor.submit(self._process_batch, batch, progress, task)
                    futures.append(future)
                
                # Process results as they complete
                for future in as_completed(futures):
                    try:
                        batch_results = future.result()
                        validated_findings.extend(batch_results)
                        
                        # Update progress
                        progress.update(
                            task,
                            advance=len(batch_results),
                            completed=len(validated_findings),
                            cache_hits=self.cache.hits,
                            current=f"Processed batch ({len(batch_results)} findings)"
                        )
                    except Exception as e:
                        logger.error(f"Error processing batch: {e}")
                        
            # Calculate statistics
            end_time = time.time()
            processing_time = end_time - start_time
            
            # Display final statistics
            self._display_validation_statistics(
                total_findings=total_findings,
                validated_findings=validated_findings,
                processing_time=processing_time
            )
            
            return validated_findings

    def _process_batch(self, batch: List[Dict], progress, task) -> List[Dict]:
        """Process a batch of findings."""
        results = []
        for finding in batch:
            try:
                # Update progress with current finding details
                progress.update(
                    task,
                    current=f"[cyan]{finding.get('check_id', 'Unknown rule')}[/cyan] in {finding.get('path', 'Unknown file')}"
                )
                
                # Process the finding
                result = self._validate_single_finding(finding)
                results.append(result)
                
            except Exception as e:
                logger.error(f"Error processing finding: {e}")
                results.append(finding)  # Keep original finding on error
                
        return results

    def _validate_single_finding(self, finding: Dict) -> Dict:
        """Validate a single finding using the LLM."""
        try:
            start_time = time.time()
            
            # Prepare finding context if not already done
            if 'code' not in finding or not finding['code']:
                finding = self._prepare_finding_context(finding)
            
            # Ensure required fields exist
            finding.setdefault('function_name', 'Not in function')
            finding.setdefault('class_name', 'Not in class')
            finding.setdefault('imports', 'No imports')
            finding.setdefault('dataflow', 'No dataflow found')
            finding.setdefault('references', 'No references found')
            finding.setdefault('security_patterns', {})
            
            # Format metadata for display
            metadata = finding.get('metadata', {})
            formatted_metadata = []
            if metadata.get('cwe'):
                formatted_metadata.append(f"CWE: {', '.join(metadata['cwe'])}")
            if metadata.get('owasp'):
                formatted_metadata.append(f"OWASP: {metadata['owasp']}")
            if metadata.get('vulnerability_class'):
                formatted_metadata.append(f"Vulnerability: {', '.join(metadata['vulnerability_class'])}")
            if metadata.get('confidence'):
                formatted_metadata.append(f"Confidence: {metadata['confidence']}")
            if metadata.get('shortlink'):
                formatted_metadata.append(f"Rule Details: {metadata['shortlink']}")
            
            # Get AI analysis using the context
            result = self.validation_chain.invoke({
                'rule_id': finding.get('rule_id', 'Unknown'),
                'severity': finding.get('severity', 'Unknown'),
                'message': finding.get('message', ''),
                'code': finding.get('code', ''),
                'path': finding.get('path', ''),
                'line': finding.get('line', 0),
                'function_name': finding['function_name'],
                'class_name': finding['class_name'],
                'imports': finding['imports'],
                'dataflow': finding['dataflow'],
                'references': finding['references'],
                'security_patterns': finding['security_patterns'],
                'metadata': '\n'.join(formatted_metadata)
            })
            
            # Parse the validation result
            validation = self._parse_validation_result(result)
            
            # Record processing time
            end_time = time.time()
            processing_time = end_time - start_time
            
            # Add validation result and metadata to finding
            finding['ai_validation'] = validation
            finding['processing_time'] = processing_time
            
            return finding
            
        except Exception as e:
            logger.error(f"Error validating finding: {e}", exc_info=True)
            finding['ai_validation'] = {
                'is_valid': None,
                'confidence': 0.0,
                'verdict': 'Error',
                'risk_score': 0,
                'impact': {
                    'business': 'Unknown',
                    'data_sensitivity': 'Unknown',
                    'exploit_likelihood': 'Unknown'
                },
                'vulnerability': {
                    'primary': 'Unknown',
                    'subcategory': 'Unknown'
                },
                'technical': {
                    'language': 'Unknown',
                    'component': 'Unknown',
                    'scope': 'Unknown'
                },
                'justification': f"Error during validation: {str(e)}",
                'poc': '',
                'attack_vectors': [],
                'trigger_steps': [],
                'recommended_fixes': [],
                'notes': []
            }
            return finding

    def _parse_validation_result(self, result) -> Dict:
        """Parse the validation result into a structured format."""
        try:
            content = result.content if hasattr(result, 'content') else str(result)
            
            # Initialize validation dictionary with default values
            validation = {
                'is_valid': None,
                'confidence': 0.0,
                'verdict': 'Unknown',
                'risk_score': 0,
                'impact': {
                    'business': 'Unknown',
                    'data_sensitivity': 'Unknown',
                    'exploit_likelihood': 'Unknown'
                },
                'vulnerability': {
                    'primary': 'Unknown',
                    'subcategory': 'Unknown'
                },
                'technical': {
                    'language': 'Unknown',
                    'component': 'Unknown',
                    'scope': 'Unknown'
                },
                'justification': '',
                'poc': '',
                'attack_vectors': [],
                'trigger_steps': [],
                'recommended_fixes': [],
                'notes': []
            }
            
            # Extract sections using regex patterns
            sections = {
                'Verdict:': r'Verdict:\s*([^\n]+)',
                'Confidence:': r'Confidence:\s*([^\n]+)',
                'Risk Score:': r'Risk Score:\s*(\d+)',
                'Business Impact:': r'Business Impact:\s*([^\n]+)',
                'Data Sensitivity:': r'Data Sensitivity:\s*([^\n]+)',
                'Exploit Likelihood:': r'Exploit Likelihood:\s*([^\n]+)',
                'Primary:': r'Primary:\s*([^\n]+)',
                'Sub-category:': r'Sub-category:\s*([^\n]+)',
                'Language/Framework:': r'Language/Framework:\s*([^\n]+)',
                'Component Type:': r'Component Type:\s*([^\n]+)',
                'Scope:': r'Scope:\s*([^\n]+)',
                'Justification:': r'Justification:\s*([^\n]+(?:\n(?!\w+:)[^\n]+)*)',
                'Proof of Concept:': r'Proof of Concept:\s*([^\n]+(?:\n(?!\w+:)[^\n]+)*)',
                'Attack Vectors:': r'Attack Vectors:\s*([^\n]+(?:\n(?![\w\s]+:)[^\n]+)*)',
                'Steps to Trigger:': r'Steps to Trigger:\s*([^\n]+(?:\n(?![\w\s]+:)[^\n]+)*)',
                'Recommended Fixes:': r'Recommended Fixes:\s*([^\n]+(?:\n(?![\w\s]+:)[^\n]+)*)',
                'Additional Notes:': r'Additional Notes:\s*([^\n]+(?:\n(?![\w\s]+:)[^\n]+)*)'
            }
            
            import re
            for key, pattern in sections.items():
                match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
                if match:
                    value = match.group(1).strip()
                    
                    # Map the extracted values to the validation dictionary
                    if key == 'Verdict:':
                        validation['verdict'] = value
                        validation['is_valid'] = value.lower() == 'true positive'
                    elif key == 'Confidence:':
                        validation['confidence'] = {'High': 0.9, 'Medium': 0.6, 'Low': 0.3}.get(value, 0.0)
                    elif key == 'Risk Score:':
                        validation['risk_score'] = int(value)
                    elif key == 'Business Impact:':
                        validation['impact']['business'] = value
                    elif key == 'Data Sensitivity:':
                        validation['impact']['data_sensitivity'] = value
                    elif key == 'Exploit Likelihood:':
                        validation['impact']['exploit_likelihood'] = value
                    elif key == 'Primary:':
                        validation['vulnerability']['primary'] = value
                    elif key == 'Sub-category:':
                        validation['vulnerability']['subcategory'] = value
                    elif key == 'Language/Framework:':
                        validation['technical']['language'] = value
                    elif key == 'Component Type:':
                        validation['technical']['component'] = value
                    elif key == 'Scope:':
                        validation['technical']['scope'] = value
                    elif key == 'Justification:':
                        validation['justification'] = value
                    elif key == 'Proof of Concept:':
                        validation['poc'] = value
                    elif key == 'Attack Vectors:':
                        validation['attack_vectors'] = [v.strip() for v in value.split('\n') if v.strip()]
                    elif key == 'Steps to Trigger:':
                        validation['trigger_steps'] = [v.strip() for v in value.split('\n') if v.strip()]
                    elif key == 'Recommended Fixes:':
                        validation['recommended_fixes'] = [v.strip() for v in value.split('\n') if v.strip()]
                    elif key == 'Additional Notes:':
                        validation['notes'] = [v.strip() for v in value.split('\n') if v.strip()]
            
            return validation
            
        except Exception as e:
            logger.error(f"Error parsing validation result: {e}", exc_info=True)
            return {
                'is_valid': None,
                'confidence': 0.0,
                'verdict': 'Error',
                'risk_score': 0,
                'impact': {
                    'business': 'Unknown',
                    'data_sensitivity': 'Unknown',
                    'exploit_likelihood': 'Unknown'
                },
                'vulnerability': {
                    'primary': 'Unknown',
                    'subcategory': 'Unknown'
                },
                'technical': {
                    'language': 'Unknown',
                    'component': 'Unknown',
                    'scope': 'Unknown'
                },
                'justification': f"Error parsing validation result: {str(e)}",
                'poc': '',
                'attack_vectors': [],
                'trigger_steps': [],
                'recommended_fixes': [],
                'notes': []
            }

    def _display_validation_statistics(self, total_findings: int, validated_findings: List[Dict], processing_time: float):
        """Display validation statistics in a formatted table."""
        table = Table(title="Validation Statistics", box=ROUNDED)
        
        # Add columns
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        # Basic stats
        table.add_row("Total Findings", str(total_findings))
        table.add_row("Processing Time", f"{processing_time:.2f} seconds")
        table.add_row("Average Time per Finding", f"{processing_time/total_findings:.2f} seconds")
        
        # Cache stats
        table.add_row("Cache Hits", str(self.cache.hits))
        table.add_row("Cache Misses", str(self.cache.misses))
        if total_findings > 0:
            table.add_row("Cache Hit Rate", f"{(self.cache.hits/total_findings)*100:.1f}%")
        
        # Verdict distribution
        verdict_counts = {
            'True Positive': 0,
            'False Positive': 0,
            'Needs Review': 0,
            'Error': 0
        }
        
        # Risk score stats
        risk_scores = []
        
        # Impact stats
        impact_counts = {
            'business': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
            'data_sensitivity': {'High': 0, 'Medium': 0, 'Low': 0},
            'exploit_likelihood': {'High': 0, 'Medium': 0, 'Low': 0}
        }
        
        # Vulnerability category stats
        vuln_categories = {}
        
        for finding in validated_findings:
            validation = finding.get('ai_validation', {})
            
            # Count verdicts
            verdict = validation.get('verdict', 'Error')
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            
            # Collect risk scores
            risk_score = validation.get('risk_score', 0)
            if risk_score > 0:
                risk_scores.append(risk_score)
            
            # Count impacts
            impact = validation.get('impact', {})
            for impact_type in ['business', 'data_sensitivity', 'exploit_likelihood']:
                level = impact.get(impact_type, 'Unknown')
                if level != 'Unknown':
                    impact_counts[impact_type][level] = impact_counts[impact_type].get(level, 0) + 1
            
            # Count vulnerability categories
            vuln_info = validation.get('vulnerability', {})
            category = vuln_info.get('primary', 'Unknown')
            if category != 'Unknown':
                vuln_categories[category] = vuln_categories.get(category, 0) + 1
        
        # Add verdict distribution
        table.add_section()
        for verdict, count in verdict_counts.items():
            if count > 0:
                percentage = (count/total_findings)*100 if total_findings > 0 else 0
                table.add_row(f"{verdict} Findings", f"{count} ({percentage:.1f}%)")
        
        # Add risk score statistics
        if risk_scores:
            table.add_section()
            table.add_row("Average Risk Score", f"{sum(risk_scores)/len(risk_scores):.1f}")
            table.add_row("Highest Risk Score", str(max(risk_scores)))
            table.add_row("Critical Findings (Risk ≥ 8)", str(len([s for s in risk_scores if s >= 8])))
        
        # Add impact statistics
        table.add_section()
        table.add_row("Business Impact Distribution", "")
        for level in ['Critical', 'High', 'Medium', 'Low']:
            count = impact_counts['business'][level]
            if count > 0:
                percentage = (count/total_findings)*100 if total_findings > 0 else 0
                table.add_row(f"  {level}", f"{count} ({percentage:.1f}%)")
        
        table.add_section()
        table.add_row("Data Sensitivity Distribution", "")
        for level in ['High', 'Medium', 'Low']:
            count = impact_counts['data_sensitivity'][level]
            if count > 0:
                percentage = (count/total_findings)*100 if total_findings > 0 else 0
                table.add_row(f"  {level}", f"{count} ({percentage:.1f}%)")
        
        table.add_section()
        table.add_row("Exploit Likelihood Distribution", "")
        for level in ['High', 'Medium', 'Low']:
            count = impact_counts['exploit_likelihood'][level]
            if count > 0:
                percentage = (count/total_findings)*100 if total_findings > 0 else 0
                table.add_row(f"  {level}", f"{count} ({percentage:.1f}%)")
        
        # Add top vulnerability categories
        if vuln_categories:
            table.add_section()
            table.add_row("Top Vulnerability Categories", "")
            sorted_categories = sorted(vuln_categories.items(), key=lambda x: x[1], reverse=True)
            for category, count in sorted_categories[:5]:  # Show top 5
                percentage = (count/total_findings)*100 if total_findings > 0 else 0
                table.add_row(f"  {category}", f"{count} ({percentage:.1f}%)")
        
        # Print the table
        with console_lock:
            console.print(table)

class ValidationBatchProcessor:
    def __init__(self, validator, max_workers=None):
        self.validator = validator
        self.max_workers = max_workers
        self.progress = None
        self.overall_task = None
        self.current_tasks = {}
        
    def process_findings(self, findings: List[Dict], progress) -> List[Dict]:
        """Process findings in parallel batches."""
        self.progress = progress
        processed_findings = []
        
        try:
            # Create overall progress bar
            self.overall_task = progress.add_task(
                f"[yellow]Processing {len(findings)} findings...[/yellow]",
                total=len(findings)
            )
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all tasks
                future_to_finding = {
                    executor.submit(self._process_single_finding, finding): finding 
                    for finding in findings
                }
                
                # Process completed tasks
                for future in as_completed(future_to_finding):
                    if shutdown_flag.is_set():
                        break
                        
                    finding = future_to_finding[future]
                    try:
                        result = future.result()
                        if result:
                            processed_findings.append(result)
                        progress.update(self.overall_task, advance=1)
                    except Exception as e:
                        logger.error(f"Error processing finding: {e}")
                        # Add the original finding without validation
                        processed_findings.append(finding)
                        progress.update(self.overall_task, advance=1)
            
            return processed_findings
            
        finally:
            self.progress = None
            self.overall_task = None
            self.current_tasks.clear()
    
    def _process_single_finding(self, finding: Dict) -> Dict:
        """Process a single finding with progress tracking."""
        try:
            # Create task for this finding
            task_id = self.progress.add_task(
                f"[cyan]Analyzing {finding.get('rule_id', 'unknown')}...[/cyan]",
                total=100,
                visible=False
            )
            self.current_tasks[id(finding)] = task_id
            
            # Process the finding
            result = self.validator._validate_single_finding(finding, self.progress, task_id)
            
            # Cleanup
            self.progress.remove_task(task_id)
            self.current_tasks.pop(id(finding), None)
            
            return result
        except Exception as e:
            logger.error(f"Error in _process_single_finding: {e}")
            if id(finding) in self.current_tasks:
                self.progress.remove_task(self.current_tasks.pop(id(finding)))
            raise
