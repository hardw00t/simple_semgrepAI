from typing import Dict, List, Optional, Set
from pathlib import Path
import logging
from dataclasses import dataclass
from rich.console import Console
import re
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import time
import ast
from typing import Any, Union

logger = logging.getLogger(__name__)
console = Console()

# Global flag for graceful shutdown
shutdown_flag = threading.Event()

def handle_interrupt(signum, frame):
    """Handle interrupt signal gracefully."""
    logger.info("Received interrupt signal, initiating graceful shutdown...")
    shutdown_flag.set()

# Register signal handlers
signal.signal(signal.SIGINT, handle_interrupt)
signal.signal(signal.SIGTERM, handle_interrupt)

@dataclass
class CodeContext:
    """Represents the context of code being analyzed."""
    file_path: Path
    code_snippet: str
    line_number: int
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    references: Optional[List[Dict]] = None
    imports: Optional[List[str]] = None
    user_input_sources: Optional[List[Dict]] = None
    dangerous_sinks: Optional[List[Dict]] = None
    sanitization_functions: Optional[List[Dict]] = None
    variables: Optional[Dict[str, Any]] = None
    functions: Optional[Dict[str, Dict]] = None
    classes: Optional[Dict[str, Dict]] = None
    dataflow: Optional[List[Dict]] = None
    
    def __post_init__(self):
        """Initialize empty collections if None."""
        self.references = self.references or []
        self.imports = self.imports or []
        self.user_input_sources = self.user_input_sources or []
        self.dangerous_sinks = self.dangerous_sinks or []
        self.sanitization_functions = self.sanitization_functions or []
        self.variables = self.variables or {}
        self.functions = self.functions or {}
        self.classes = self.classes or {}
        self.dataflow = self.dataflow or []
        
    def add_dataflow(self, flow_type: str, description: str, line: int, **details):
        """Add a dataflow entry with consistent formatting."""
        flow = {
            'type': flow_type,
            'description': description,
            'line': line,
            **details
        }
        self.dataflow.append(flow)

class CodeAnalyzer:
    """Analyzes code for security vulnerabilities with deep context understanding."""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.file_cache = {}
        self.import_graph = {}
        self.class_definitions = {}
        self.function_definitions = {}
        self.progress = None
        self.task_id = None
        
        # Reset shutdown flag
        shutdown_flag.clear()
        
        # Common patterns for security analysis
        self.user_input_patterns = {
            'python': [
                r'request\.(get|post|args|form|values|params)',
                r'input\(',
                r'sys\.argv',
                r'os\.environ',
                r'url(?:lib)?\.(?:request|parse|open)',
            ],
            'ruby': [
                r'params\[',
                r'request\.',
                r'ENV\[',
                r'ARGV',
            ]
        }
        
        self.dangerous_sink_patterns = {
            'python': [
                r'eval\(',
                r'exec\(',
                r'subprocess\.',
                r'os\.system',
                r'open\(',
                r'url(?:lib)?\.(?:request\.)?(?:urlopen|urlretrieve)',
            ],
            'ruby': [
                r'eval\(',
                r'system\(',
                r'exec\(',
                r'\`.*\`',
                r'File\.',
            ]
        }
        
        self.sanitization_patterns = {
            'python': [
                r'escape\(',
                r'sanitize\(',
                r'html\.escape',
                r'markupsafe',
            ],
            'ruby': [
                r'html_escape',
                r'sanitize',
                r'escape_javascript',
                r'h\(',
            ]
        }
        
        self.url_patterns = {
            'python': [
                (r'url(?:lib)?\.(?:request\.)?(?:urlopen|urlretrieve)', 'URL operation'),
                (r'requests\.(?:get|post|put|delete|head|options)', 'HTTP request'),
                (r'urllib\.parse\.(?:urljoin|urlparse)', 'URL parsing'),
            ]
        }

    def analyze_finding(self, finding: Dict, progress=None, task_id=None) -> CodeContext:
        """Analyze a finding with full context."""
        try:
            file_path = Path(finding['path'])
            line_number = finding['line']
            
            logger.info(f"Analyzing finding in {file_path}:{line_number}")
            
            # Store progress info
            self.progress = progress
            self.task_id = task_id
            
            try:
                # Get file content if not in cache
                if file_path not in self.file_cache:
                    self.file_cache[file_path] = file_path.read_text()
                
                file_content = self.file_cache[file_path]
                
                # Create initial context
                context = CodeContext(
                    file_path=file_path,
                    code_snippet=finding['code'],
                    line_number=line_number
                )
                
                if self.progress and self.task_id:
                    self.progress.update(self.task_id, description=f"[cyan]Analyzing {file_path.name}...[/cyan]", advance=20)
                
                # Check for shutdown
                if shutdown_flag.is_set():
                    raise KeyboardInterrupt("Analysis interrupted by user")
                
                # Analyze the file
                self._analyze_file_content(context, file_content)
                if self.progress and self.task_id:
                    self.progress.update(self.task_id, advance=20)
                
                # Check for shutdown
                if shutdown_flag.is_set():
                    raise KeyboardInterrupt("Analysis interrupted by user")
                
                # Find related files and analyze them
                related_files = self._find_related_files(context)
                if self.progress and self.task_id:
                    self.progress.update(self.task_id, advance=20)
                
                # Check for shutdown
                if shutdown_flag.is_set():
                    raise KeyboardInterrupt("Analysis interrupted by user")
                
                self._analyze_related_files(context, related_files)
                if self.progress and self.task_id:
                    self.progress.update(self.task_id, advance=20)
                
                # Check for shutdown
                if shutdown_flag.is_set():
                    raise KeyboardInterrupt("Analysis interrupted by user")
                
                # Find security patterns
                self._find_security_patterns(context)
                if self.progress and self.task_id:
                    self.progress.update(self.task_id, advance=20)
                
                return context
                
            except Exception as e:
                logger.error(f"Error analyzing file {file_path}: {e}")
                raise
            
        except KeyboardInterrupt:
            logger.info("Analysis interrupted by user")
            raise
        except Exception as e:
            logger.error(f"Error analyzing finding: {e}", exc_info=True)
            raise
        finally:
            self.progress = None
            self.task_id = None

    def extract_code_snippet(self, file_path: Path, line_number: int, context_lines: int = 3) -> str:
        """Extract code snippet with surrounding context lines."""
        try:
            # Convert line number to 0-based index
            line_idx = line_number - 1
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if not lines:
                return "Empty file"
                
            # Calculate start and end lines with context
            start_idx = max(0, line_idx - context_lines)
            end_idx = min(len(lines), line_idx + context_lines + 1)
            
            # Extract the lines with context
            snippet_lines = []
            for i in range(start_idx, end_idx):
                prefix = '> ' if i == line_idx else '  '
                line_num = i + 1
                line = lines[i].rstrip()
                snippet_lines.append(f"{prefix}{line_num}: {line}")
            
            return '\n'.join(snippet_lines)
            
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return "File not found"
        except Exception as e:
            logger.error(f"Error extracting code snippet from {file_path}: {e}")
            return f"Error extracting code: {str(e)}"

    def analyze_file(self, file_path: Path) -> CodeContext:
        """Analyze a single file and return its context."""
        try:
            if not file_path.exists():
                logger.warning(f"File not found: {file_path}")
                return None

            # Initialize context
            context = CodeContext(
                file_path=file_path,
                code_snippet="",  # Will be set later
                line_number=0,    # Will be set later
                imports=[],
                user_input_sources=[],
                dangerous_sinks=[],
                sanitization_functions=[],
                variables={},
                functions={},
                classes={},
                dataflow=[],
                references=[]
            )

            # Read and parse file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Store file content in cache
            self.file_cache[str(file_path)] = content
            
            try:
                tree = ast.parse(content)
            except SyntaxError:
                logger.debug(f"Could not parse {file_path} as Python")
                return context
                
            # Track current function and class during traversal
            current_function = []
            current_class = []
            
            class ContextVisitor(ast.NodeVisitor):
                def __init__(self, analyzer, context):
                    self.analyzer = analyzer
                    self.context = context
                    
                def visit_Import(self, node):
                    for name in node.names:
                        self.context.imports.append(name.name)
                    self.generic_visit(node)
                    
                def visit_ImportFrom(self, node):
                    module = node.module or ''
                    for name in node.names:
                        self.context.imports.append(f"{module}.{name.name}")
                    self.generic_visit(node)
                    
                def visit_FunctionDef(self, node):
                    current_function.append(node.name)
                    func_info = {
                        'name': node.name,
                        'line': node.lineno,
                        'args': [arg.arg for arg in node.args.args],
                        'class': current_class[-1] if current_class else None
                    }
                    self.context.functions[node.name] = func_info
                    self.generic_visit(node)
                    current_function.pop()
                    
                def visit_ClassDef(self, node):
                    current_class.append(node.name)
                    class_info = {
                        'name': node.name,
                        'line': node.lineno,
                        'bases': [base.id for base in node.bases if isinstance(base, ast.Name)]
                    }
                    self.context.classes[node.name] = class_info
                    self.generic_visit(node)
                    current_class.pop()
                    
                def visit_Call(self, node):
                    # Check for security patterns
                    code_line = content.splitlines()[node.lineno - 1]
                    
                    # Check for user input sources
                    for pattern in self.analyzer.user_input_patterns['python']:
                        if re.search(pattern, code_line):
                            self.context.user_input_sources.append({
                                'line': node.lineno,
                                'content': code_line.strip()
                            })
                    
                    # Check for dangerous sinks
                    for pattern in self.analyzer.dangerous_sink_patterns['python']:
                        if re.search(pattern, code_line):
                            self.context.dangerous_sinks.append({
                                'line': node.lineno,
                                'content': code_line.strip()
                            })
                    
                    # Check for sanitization functions
                    for pattern in self.analyzer.sanitization_patterns['python']:
                        if re.search(pattern, code_line):
                            self.context.sanitization_functions.append({
                                'line': node.lineno,
                                'content': code_line.strip()
                            })
                    
                    self.generic_visit(node)
            
            # Visit the AST
            visitor = ContextVisitor(self, context)
            visitor.visit(tree)
            
            return context
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return None

    def _analyze_file_content(self, context: CodeContext, content: str):
        """Analyze the content of a single file."""
        try:
            # Parse Python code
            tree = ast.parse(content)
            
            # Initialize all containers
            context.imports = []
            context.variables = {}
            context.functions = {}
            context.classes = {}
            context.dataflow = []
            context.references = []
            context.user_input_sources = []
            context.dangerous_sinks = []
            context.sanitization_functions = []
            
            # Analyze the AST
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self._analyze_import(context, node)
                elif isinstance(node, ast.ImportFrom):
                    self._analyze_import_from(context, node)
                elif isinstance(node, ast.FunctionDef):
                    self._analyze_function(context, node)
                elif isinstance(node, ast.ClassDef):
                    self._analyze_class(context, node)
                elif isinstance(node, ast.Assign):
                    self._analyze_assignment(context, node)
                    self._analyze_dataflow(context, node)
                elif isinstance(node, ast.Call):
                    self._analyze_call_dataflow(context, node)
                
        except SyntaxError:
            # Not a Python file or invalid syntax
            logger.debug(f"Could not parse {context.file_path} as Python")
            # Initialize empty containers for non-Python files
            context.imports = []
            context.variables = {}
            context.functions = {}
            context.classes = {}
            context.dataflow = []
            context.references = []
            context.user_input_sources = []
            context.dangerous_sinks = []
            context.sanitization_functions = []
        except Exception as e:
            logger.error(f"Error analyzing file content: {e}")
            # Initialize empty containers on error
            context.imports = []
            context.variables = {}
            context.functions = {}
            context.classes = {}
            context.dataflow = []
            context.references = []
            context.user_input_sources = []
            context.dangerous_sinks = []
            context.sanitization_functions = []

    def _analyze_import(self, context: CodeContext, node: ast.Import):
        """Analyze an import statement."""
        for name in node.names:
            context.imports.append(name.name)

    def _analyze_import_from(self, context: CodeContext, node: ast.ImportFrom):
        """Analyze an import from statement."""
        if node.module:
            for name in node.names:
                context.imports.append(f"{node.module}.{name.name}")

    def _analyze_function(self, context: CodeContext, node: ast.FunctionDef):
        """Analyze a function definition."""
        func_info = {
            'name': node.name,
            'line': node.lineno,
            'args': [arg.arg for arg in node.args.args],
            'returns': [],
            'calls': [],
        }
        
        # Find return values and function calls
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                func_info['returns'].append(ast.unparse(child.value))
            elif isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    func_info['calls'].append(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    func_info['calls'].append(ast.unparse(child.func))
        
        context.functions[node.name] = func_info

    def _analyze_class(self, context: CodeContext, node: ast.ClassDef):
        """Analyze a class definition."""
        class_info = {
            'name': node.name,
            'line': node.lineno,
            'bases': [ast.unparse(base) for base in node.bases],
            'methods': {},
        }
        
        # Analyze methods
        for child in node.body:
            if isinstance(child, ast.FunctionDef):
                method_info = {
                    'name': child.name,
                    'line': child.lineno,
                    'args': [arg.arg for arg in child.args.args],
                }
                class_info['methods'][child.name] = method_info
        
        context.classes[node.name] = class_info

    def _analyze_assignment(self, context: CodeContext, node: ast.Assign):
        """Analyze a variable assignment."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_info = {
                    'name': target.id,
                    'line': target.lineno,
                    'type': None,
                    'value': None,
                    'tainted': False,
                    'source': None
                }
                
                try:
                    # Try to get literal value
                    value = ast.literal_eval(node.value)
                    var_info['value'] = value
                    var_info['type'] = type(value).__name__
                except (ValueError, SyntaxError):
                    # For non-literal values, get the source
                    var_info['value'] = ast.unparse(node.value)
                    
                    # Check if value comes from user input
                    if isinstance(node.value, ast.Call):
                        call_source = ast.unparse(node.value.func)
                        for pattern in self.user_input_patterns['python']:
                            if re.search(pattern, call_source):
                                var_info['tainted'] = True
                                var_info['source'] = call_source
                                break
                    
                    # Check if value depends on other variables
                    for other_var in context.variables:
                        if other_var in ast.unparse(node.value):
                            # Inherit taint status from dependent variables
                            if context.variables[other_var].get('tainted'):
                                var_info['tainted'] = True
                                var_info['source'] = context.variables[other_var].get('source')
                
                context.variables[target.id] = var_info
                
                # Add to dataflow if tainted
                if var_info['tainted']:
                    context.add_dataflow(
                        'assignment',
                        f"Tainted variable '{target.id}' from {var_info['source']}",
                        target.lineno,
                        variable=target.id,
                        source=var_info['source']
                    )

    def _analyze_dataflow(self, context: CodeContext, node: ast.Assign):
        """Analyze dataflow for assignments."""
        try:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # Track variable dependencies
                    deps = set()
                    for node in ast.walk(node.value):
                        if isinstance(node, ast.Name):
                            deps.add(node.id)
                    
                    # Add dataflow entry for variable dependencies
                    if deps:
                        context.add_dataflow(
                            'dependency',
                            f"Variable '{target.id}' depends on: {', '.join(deps)}",
                            target.lineno,
                            variable=target.id,
                            dependencies=list(deps)
                        )
        except Exception as e:
            logger.error(f"Error analyzing dataflow: {e}")

    def _analyze_call_dataflow(self, context: CodeContext, node: ast.Call):
        """Analyze dataflow for function calls."""
        try:
            # Get function name and arguments
            func_name = ast.unparse(node.func)
            args_repr = []
            
            # Format positional arguments
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    args_repr.append(f"variable {arg.id}")
                elif isinstance(arg, ast.Constant):
                    args_repr.append(f"constant {str(arg.value)}")
                else:
                    args_repr.append(ast.unparse(arg))
            
            # Format keyword arguments
            for kw in node.keywords:
                if isinstance(kw.value, ast.Name):
                    args_repr.append(f"{kw.arg}=variable {kw.value.id}")
                elif isinstance(kw.value, ast.Constant):
                    args_repr.append(f"{kw.arg}=constant {str(kw.value.value)}")
                else:
                    args_repr.append(f"{kw.arg}={ast.unparse(kw.value)}")
            
            # Add basic call dataflow
            context.add_dataflow('call', 
                               f"Function call to {func_name}({', '.join(args_repr)})", 
                               node.lineno,
                               function=func_name,
                               arguments=args_repr)
            
            # Check for URL-related operations
            for pattern, op_type in self.url_patterns['python']:
                if re.search(pattern, func_name):
                    # Add URL-specific dataflow information
                    url_source = None
                    if node.args:
                        url_arg = node.args[0]
                        if isinstance(url_arg, ast.Constant):
                            url_source = f"hardcoded URL: {url_arg.value}"
                        elif isinstance(url_arg, ast.Name):
                            url_source = f"variable: {url_arg.id}"
                        else:
                            url_source = f"dynamic expression: {ast.unparse(url_arg)}"
                    
                    context.add_dataflow('url_operation',
                                       f"{op_type} using {url_source}",
                                       node.lineno,
                                       operation=op_type,
                                       url_source=url_source,
                                       function=func_name)
                    break
            
        except Exception as e:
            logger.debug(f"Error analyzing dataflow for function call: {e}")

    def _find_related_files(self, context: CodeContext) -> Set[Path]:
        """Find files related to the current context."""
        related_files = set()
        
        # Add imported files
        if context.imports:
            for import_name in context.imports:
                related_file = self._find_import_file(import_name)
                if related_file:
                    related_files.add(related_file)
        
        # Add files with matching class/function names
        if context.class_name or context.function_name:
            for file_path in self.project_root.rglob('*.py'):
                if file_path != context.file_path and file_path.is_file():
                    related_files.add(file_path)
        
        return related_files

    def _find_import_file(self, import_name: str) -> Optional[Path]:
        """Find the file corresponding to an import."""
        parts = import_name.split('.')
        
        # Try direct file match
        for ext in ['.py', '.pyi']:
            file_path = self.project_root / f"{'/'.join(parts)}{ext}"
            if file_path.is_file():
                return file_path
        
        # Try as package
        init_path = self.project_root / '/'.join(parts) / '__init__.py'
        if init_path.is_file():
            return init_path
        
        return None

    def _analyze_related_files(self, context: CodeContext, related_files: Set[Path]):
        """Analyze files related to the current context."""
        if not related_files:
            return
            
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            
            for file_path in related_files:
                if shutdown_flag.is_set():
                    break
                    
                if file_path not in self.file_cache:
                    try:
                        future = executor.submit(self._analyze_single_file, file_path, context)
                        futures.append(future)
                    except Exception:
                        continue
            
            # Wait for all futures to complete or until shutdown
            for future in futures:
                try:
                    if not shutdown_flag.is_set():
                        future.result(timeout=5)  # 5 second timeout per file
                except (TimeoutError, Exception) as e:
                    logger.warning(f"Error analyzing related file: {e}")
                    continue

    def _analyze_single_file(self, file_path: Path, context: CodeContext) -> None:
        """Analyze a single related file."""
        try:
            content = file_path.read_text()
            self.file_cache[str(file_path)] = content
            
            # Find references to our context
            references = []
            
            patterns = []
            if context.function_name:
                patterns.append(context.function_name)
            if context.class_name:
                patterns.append(context.class_name)
            
            for pattern in patterns:
                if shutdown_flag.is_set():
                    break
                    
                for i, line in enumerate(content.splitlines(), 1):
                    if pattern in line:
                        references.append({
                            'file': str(file_path),
                            'line': i,
                            'content': line.strip()
                        })
            
            if references:
                if not context.references:
                    context.references = []
                context.references.extend(references)
                
        except Exception as e:
            logger.warning(f"Error analyzing file {file_path}: {e}")
            return None

    def _find_security_patterns(self, context: CodeContext):
        """Find security-related patterns in the code."""
        content = self.file_cache[context.file_path]
        
        # Determine language (simple approach)
        language = 'python' if context.file_path.suffix == '.py' else 'ruby'
        
        # Find user input sources
        context.user_input_sources = []
        for pattern in self.user_input_patterns[language]:
            for match in re.finditer(pattern, content):
                line_no = content.count('\n', 0, match.start()) + 1
                context.user_input_sources.append({
                    'pattern': pattern,
                    'line': line_no,
                    'content': content.splitlines()[line_no-1].strip()
                })
        
        # Find sinks
        context.dangerous_sinks = []
        for pattern in self.dangerous_sink_patterns[language]:
            for match in re.finditer(pattern, content):
                line_no = content.count('\n', 0, match.start()) + 1
                context.dangerous_sinks.append({
                    'pattern': pattern,
                    'line': line_no,
                    'content': content.splitlines()[line_no-1].strip()
                })
        
        # Find sanitizers
        context.sanitization_functions = []
        for pattern in self.sanitization_patterns[language]:
            for match in re.finditer(pattern, content):
                line_no = content.count('\n', 0, match.start()) + 1
                context.sanitization_functions.append({
                    'pattern': pattern,
                    'line': line_no,
                    'content': content.splitlines()[line_no-1].strip()
                })
