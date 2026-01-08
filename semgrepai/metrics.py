from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time
import psutil
import json
from pathlib import Path
import logging
from threading import Lock
import asyncio
from contextlib import contextmanager, asynccontextmanager

logger = logging.getLogger(__name__)

@dataclass
class ValidationMetrics:
    total_findings: int = 0
    processed_findings: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    true_positives: int = 0
    false_positives: int = 0
    needs_review: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    processing_times: List[float] = field(default_factory=list)
    memory_usage: List[float] = field(default_factory=list)
    cpu_usage: List[float] = field(default_factory=list)
    
    # Detailed metrics
    vulnerability_categories: Dict[str, int] = field(default_factory=dict)
    risk_scores: List[int] = field(default_factory=list)
    confidence_levels: Dict[str, int] = field(default_factory=dict)
    business_impact: Dict[str, int] = field(default_factory=dict)
    data_sensitivity: Dict[str, int] = field(default_factory=dict)
    exploit_likelihood: Dict[str, int] = field(default_factory=dict)
    
    # Performance metrics
    llm_response_times: List[float] = field(default_factory=list)
    context_preparation_times: List[float] = field(default_factory=list)
    parsing_times: List[float] = field(default_factory=list)
    
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
    def average_risk_score(self) -> float:
        """Get average risk score."""
        if not self.risk_scores:
            return 0
        return sum(self.risk_scores) / len(self.risk_scores)
    
    @property
    def performance_breakdown(self) -> Dict[str, float]:
        """Get average times for different processing stages."""
        return {
            'llm_response': sum(self.llm_response_times) / len(self.llm_response_times) if self.llm_response_times else 0,
            'context_preparation': sum(self.context_preparation_times) / len(self.context_preparation_times) if self.context_preparation_times else 0,
            'parsing': sum(self.parsing_times) / len(self.parsing_times) if self.parsing_times else 0
        }

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
            'needs_review': self.needs_review,
            'errors': self.errors,
            'total_time': self.total_time,
            'average_time_per_finding': self.average_time_per_finding,
            'cache_hit_rate': self.cache_hit_rate,
            'true_positive_rate': self.true_positive_rate,
            'average_risk_score': self.average_risk_score,
            'performance_breakdown': self.performance_breakdown,
            'average_memory_usage': self.average_memory_usage,
            'average_cpu_usage': self.average_cpu_usage,
            'vulnerability_categories': self.vulnerability_categories,
            'confidence_levels': self.confidence_levels,
            'business_impact': self.business_impact,
            'data_sensitivity': self.data_sensitivity,
            'exploit_likelihood': self.exploit_likelihood
        }

class MetricsCollector:
    def __init__(self, metrics_dir: Path):
        self.metrics_dir = metrics_dir
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        self.current_metrics = ValidationMetrics()
        self._lock = Lock()
        self._async_lock: Optional[asyncio.Lock] = None

        # Start resource monitoring
        self._start_resource_monitoring()

    def _get_async_lock(self) -> asyncio.Lock:
        """Lazily create async lock to avoid event loop issues."""
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    @contextmanager
    def _sync_lock(self):
        """Context manager for synchronous locking."""
        self._lock.acquire()
        try:
            yield
        finally:
            self._lock.release()

    @asynccontextmanager
    async def _async_lock_ctx(self):
        """Context manager for asynchronous locking."""
        async with self._get_async_lock():
            yield
    
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
    
    def record_finding(self, finding: Dict, processing_time: float, timing_details: Dict = None):
        """Record metrics for a processed finding."""
        with self._lock:
            self.current_metrics.processed_findings += 1
            self.current_metrics.processing_times.append(processing_time)
            
            # Record detailed timing metrics
            if timing_details:
                if 'llm_response' in timing_details:
                    self.current_metrics.llm_response_times.append(timing_details['llm_response'])
                if 'context_preparation' in timing_details:
                    self.current_metrics.context_preparation_times.append(timing_details['context_preparation'])
                if 'parsing' in timing_details:
                    self.current_metrics.parsing_times.append(timing_details['parsing'])
            
            # Record finding details
            verdict = finding.get('verdict', 'unknown').lower()
            if verdict == 'true positive':
                self.current_metrics.true_positives += 1
            elif verdict == 'false positive':
                self.current_metrics.false_positives += 1
            elif verdict == 'needs review':
                self.current_metrics.needs_review += 1
            
            # Record vulnerability category
            category = finding.get('vulnerability_category', {}).get('primary', 'unknown')
            self.current_metrics.vulnerability_categories[category] = \
                self.current_metrics.vulnerability_categories.get(category, 0) + 1
            
            # Record risk score
            if 'risk_score' in finding:
                self.current_metrics.risk_scores.append(finding['risk_score'])
            
            # Record confidence level
            confidence = finding.get('confidence', 'unknown')
            self.current_metrics.confidence_levels[confidence] = \
                self.current_metrics.confidence_levels.get(confidence, 0) + 1
            
            # Record impact assessments
            impact = finding.get('impact_assessment', {})
            if 'business_impact' in impact:
                self.current_metrics.business_impact[impact['business_impact']] = \
                    self.current_metrics.business_impact.get(impact['business_impact'], 0) + 1
            if 'data_sensitivity' in impact:
                self.current_metrics.data_sensitivity[impact['data_sensitivity']] = \
                    self.current_metrics.data_sensitivity.get(impact['data_sensitivity'], 0) + 1
            if 'exploit_likelihood' in impact:
                self.current_metrics.exploit_likelihood[impact['exploit_likelihood']] = \
                    self.current_metrics.exploit_likelihood.get(impact['exploit_likelihood'], 0) + 1

    def _record_finding_internal(self, finding: Dict, processing_time: float, timing_details: Dict = None):
        """Internal method to record finding metrics (no locking)."""
        self.current_metrics.processed_findings += 1
        self.current_metrics.processing_times.append(processing_time)

        # Record detailed timing metrics
        if timing_details:
            if 'llm_response' in timing_details:
                self.current_metrics.llm_response_times.append(timing_details['llm_response'])
            if 'context_preparation' in timing_details:
                self.current_metrics.context_preparation_times.append(timing_details['context_preparation'])
            if 'parsing' in timing_details:
                self.current_metrics.parsing_times.append(timing_details['parsing'])

        # Record finding details
        verdict = finding.get('verdict', 'unknown').lower()
        if verdict == 'true positive':
            self.current_metrics.true_positives += 1
        elif verdict == 'false positive':
            self.current_metrics.false_positives += 1
        elif verdict == 'needs review':
            self.current_metrics.needs_review += 1

        # Record vulnerability category
        category = finding.get('vulnerability_category', {}).get('primary', 'unknown')
        self.current_metrics.vulnerability_categories[category] = \
            self.current_metrics.vulnerability_categories.get(category, 0) + 1

        # Record risk score
        if 'risk_score' in finding:
            self.current_metrics.risk_scores.append(finding['risk_score'])

        # Record confidence level
        confidence = finding.get('confidence', 'unknown')
        self.current_metrics.confidence_levels[confidence] = \
            self.current_metrics.confidence_levels.get(confidence, 0) + 1

        # Record impact assessments
        impact = finding.get('impact_assessment', {})
        if 'business_impact' in impact:
            self.current_metrics.business_impact[impact['business_impact']] = \
                self.current_metrics.business_impact.get(impact['business_impact'], 0) + 1
        if 'data_sensitivity' in impact:
            self.current_metrics.data_sensitivity[impact['data_sensitivity']] = \
                self.current_metrics.data_sensitivity.get(impact['data_sensitivity'], 0) + 1
        if 'exploit_likelihood' in impact:
            self.current_metrics.exploit_likelihood[impact['exploit_likelihood']] = \
                self.current_metrics.exploit_likelihood.get(impact['exploit_likelihood'], 0) + 1

    async def record_finding_async(self, finding: Dict, processing_time: float, timing_details: Dict = None):
        """Record metrics for a processed finding (async version)."""
        async with self._async_lock_ctx():
            self._record_finding_internal(finding, processing_time, timing_details)

    def record_cache_hit(self):
        """Record a cache hit."""
        with self._lock:
            self.current_metrics.cache_hits += 1

    async def record_cache_hit_async(self):
        """Record a cache hit (async version)."""
        async with self._async_lock_ctx():
            self.current_metrics.cache_hits += 1

    def record_cache_miss(self):
        """Record a cache miss."""
        with self._lock:
            self.current_metrics.cache_misses += 1

    async def record_cache_miss_async(self):
        """Record a cache miss (async version)."""
        async with self._async_lock_ctx():
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

    async def complete_session_async(self):
        """Complete the current metrics session (async version)."""
        async with self._async_lock_ctx():
            self.current_metrics.end_time = time.time()

            # Save metrics to file
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            metrics_file = self.metrics_dir / f'metrics_{timestamp}.json'

            with open(metrics_file, 'w') as f:
                json.dump(self.current_metrics.to_dict(), f, indent=2)

            logger.info(f"Metrics saved to {metrics_file}")

    async def get_current_metrics_async(self) -> Dict:
        """Get current metrics as dictionary (async version)."""
        async with self._async_lock_ctx():
            return self.current_metrics.to_dict()

    def record_error(self):
        """Record an error during processing."""
        with self._lock:
            self.current_metrics.errors += 1

    async def record_error_async(self):
        """Record an error during processing (async version)."""
        async with self._async_lock_ctx():
            self.current_metrics.errors += 1

    def set_total_findings(self, total: int):
        """Set the total number of findings to process."""
        with self._lock:
            self.current_metrics.total_findings = total

    async def set_total_findings_async(self, total: int):
        """Set the total number of findings to process (async version)."""
        async with self._async_lock_ctx():
            self.current_metrics.total_findings = total
