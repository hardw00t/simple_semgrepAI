from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time
import psutil
import json
from pathlib import Path
import logging
from threading import Lock

logger = logging.getLogger(__name__)

@dataclass
class ValidationMetrics:
    total_findings: int = 0
    processed_findings: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    true_positives: int = 0
    false_positives: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    processing_times: List[float] = field(default_factory=list)
    memory_usage: List[float] = field(default_factory=list)
    cpu_usage: List[float] = field(default_factory=list)
    
    @property
    def total_time(self) -> float:
        """Get total processing time in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    @property
    def average_time_per_finding(self) -> float:
        """Get average processing time per finding."""
        if not self.processing_times:
            return 0
        return sum(self.processing_times) / len(self.processing_times)
    
    @property
    def cache_hit_rate(self) -> float:
        """Get cache hit rate as percentage."""
        total = self.cache_hits + self.cache_misses
        if total == 0:
            return 0
        return (self.cache_hits / total) * 100
    
    @property
    def true_positive_rate(self) -> float:
        """Get true positive rate as percentage."""
        total = self.true_positives + self.false_positives
        if total == 0:
            return 0
        return (self.true_positives / total) * 100
    
    @property
    def average_memory_usage(self) -> float:
        """Get average memory usage in MB."""
        if not self.memory_usage:
            return 0
        return sum(self.memory_usage) / len(self.memory_usage)
    
    @property
    def average_cpu_usage(self) -> float:
        """Get average CPU usage percentage."""
        if not self.cpu_usage:
            return 0
        return sum(self.cpu_usage) / len(self.cpu_usage)
    
    def to_dict(self) -> Dict:
        """Convert metrics to dictionary."""
        return {
            'total_findings': self.total_findings,
            'processed_findings': self.processed_findings,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'errors': self.errors,
            'total_time': self.total_time,
            'average_time_per_finding': self.average_time_per_finding,
            'cache_hit_rate': self.cache_hit_rate,
            'true_positive_rate': self.true_positive_rate,
            'average_memory_usage': self.average_memory_usage,
            'average_cpu_usage': self.average_cpu_usage
        }

class MetricsCollector:
    def __init__(self, metrics_dir: Path):
        self.metrics_dir = metrics_dir
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        self.current_metrics = ValidationMetrics()
        self._lock = Lock()
        
        # Start resource monitoring
        self._start_resource_monitoring()
    
    def _start_resource_monitoring(self):
        """Start monitoring system resources."""
        process = psutil.Process()
        
        def monitor():
            while True:
                with self._lock:
                    if self.current_metrics.end_time:
                        break
                    
                    # Get memory usage in MB
                    memory = process.memory_info().rss / 1024 / 1024
                    self.current_metrics.memory_usage.append(memory)
                    
                    # Get CPU usage
                    cpu = process.cpu_percent()
                    self.current_metrics.cpu_usage.append(cpu)
                
                time.sleep(1)  # Monitor every second
        
        import threading
        self._monitor_thread = threading.Thread(target=monitor, daemon=True)
        self._monitor_thread.start()
    
    def record_finding(self, finding: Dict, processing_time: float):
        """Record metrics for a processed finding."""
        with self._lock:
            self.current_metrics.processed_findings += 1
            self.current_metrics.processing_times.append(processing_time)
            
            if 'ai_validation' in finding:
                validation = finding['ai_validation']
                if validation.get('is_true_positive'):
                    self.current_metrics.true_positives += 1
                else:
                    self.current_metrics.false_positives += 1
            else:
                self.current_metrics.errors += 1
    
    def record_cache_hit(self):
        """Record a cache hit."""
        with self._lock:
            self.current_metrics.cache_hits += 1
    
    def record_cache_miss(self):
        """Record a cache miss."""
        with self._lock:
            self.current_metrics.cache_misses += 1
    
    def complete_session(self):
        """Complete the current metrics session."""
        with self._lock:
            self.current_metrics.end_time = time.time()
            
            # Save metrics to file
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            metrics_file = self.metrics_dir / f'metrics_{timestamp}.json'
            
            with open(metrics_file, 'w') as f:
                json.dump(self.current_metrics.to_dict(), f, indent=2)
            
            logger.info(f"Metrics saved to {metrics_file}")
    
    def get_current_metrics(self) -> Dict:
        """Get current metrics as dictionary."""
        with self._lock:
            return self.current_metrics.to_dict()
