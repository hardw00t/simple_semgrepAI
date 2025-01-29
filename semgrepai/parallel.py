from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Callable, TypeVar, Generic
from dataclasses import dataclass
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console
import time
from queue import Queue
from threading import Lock

console = Console()

T = TypeVar('T')
R = TypeVar('R')

@dataclass
class WorkItem(Generic[T, R]):
    input_data: T
    result: R = None
    error: Exception = None
    start_time: float = None
    end_time: float = None

    @property
    def processing_time(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0

class ParallelProcessor:
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers
        self.progress_lock = Lock()
        self.console_lock = Lock()

    def process_batch(
        self,
        items: List[T],
        process_func: Callable[[T], R],
        progress: Progress,
        description: str = "Processing"
    ) -> List[WorkItem[T, R]]:
        """
        Process a batch of items in parallel with progress tracking.
        """
        work_items = [WorkItem(item) for item in items]
        completed_queue = Queue()
        
        # Create progress task
        with self.progress_lock:
            task = progress.add_task(description, total=len(items))
        
        def process_item(work_item: WorkItem[T, R]) -> WorkItem[T, R]:
            """Process a single work item with timing."""
            work_item.start_time = time.time()
            try:
                work_item.result = process_func(work_item.input_data)
            except Exception as e:
                work_item.error = e
            work_item.end_time = time.time()
            completed_queue.put(work_item)
            return work_item

        # Process items in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_item = {
                executor.submit(process_item, item): item 
                for item in work_items
            }
            
            # Track progress
            while future_to_item:
                # Check for completed items
                completed = completed_queue.get()
                with self.progress_lock:
                    progress.advance(task)
                
                # Remove completed future
                completed_futures = [
                    f for f, item in future_to_item.items() 
                    if item.input_data == completed.input_data
                ]
                for f in completed_futures:
                    del future_to_item[f]
            
        return work_items

class ValidationBatchProcessor(ParallelProcessor):
    def __init__(self, validator, max_workers: int = None):
        super().__init__(max_workers)
        self.validator = validator
    
    def process_findings(
        self,
        findings: List[Dict],
        progress: Progress
    ) -> List[Dict]:
        """Process a batch of findings in parallel."""
        work_items = self.process_batch(
            items=findings,
            process_func=self._process_single_finding,
            progress=progress,
            description="[cyan]Analyzing findings in parallel..."
        )
        
        # Collect results and handle errors
        validated_findings = []
        for work_item in work_items:
            finding = work_item.input_data
            if work_item.error:
                with self.console_lock:
                    console.print(
                        f"[red]Error processing {finding['rule_id']}: {work_item.error}[/red]"
                    )
                # Add original finding without validation
                validated_findings.append(finding)
            else:
                finding['ai_validation'] = work_item.result
                finding['processing_time'] = work_item.processing_time
                validated_findings.append(finding)
                
                with self.console_lock:
                    status = (
                        "[green]True Positive[/green]" 
                        if work_item.result['is_true_positive'] 
                        else "[red]False Positive[/red]"
                    )
                    console.print(
                        f"Result for {finding['rule_id']}: {status} "
                        f"(took {work_item.processing_time:.2f}s)"
                    )
        
        return validated_findings
    
    def _process_single_finding(self, finding: Dict) -> Dict:
        """Process a single finding using the validator."""
        return self.validator._validate_single_finding(finding)
