"""Async progress tracking for validation operations."""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable, Awaitable, Any
from datetime import datetime
from enum import Enum


class ProgressStatus(str, Enum):
    """Status of a progress operation."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ProgressUpdate:
    """Represents a progress update."""

    total: int
    """Total number of items to process."""

    processed: int
    """Number of items processed so far."""

    status: ProgressStatus = ProgressStatus.RUNNING
    """Current status of the operation."""

    current_item: Optional[Dict[str, Any]] = None
    """Details about the currently processing item."""

    metrics: Dict[str, Any] = field(default_factory=dict)
    """Additional metrics like cache hits, errors, etc."""

    started_at: Optional[datetime] = None
    """When processing started."""

    error_message: Optional[str] = None
    """Error message if status is FAILED."""

    @property
    def percentage(self) -> float:
        """Get completion percentage."""
        if self.total == 0:
            return 0.0
        return (self.processed / self.total) * 100

    @property
    def is_complete(self) -> bool:
        """Check if processing is complete."""
        return self.status in (
            ProgressStatus.COMPLETED,
            ProgressStatus.FAILED,
            ProgressStatus.CANCELLED,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total": self.total,
            "processed": self.processed,
            "percentage": round(self.percentage, 1),
            "status": self.status.value,
            "current_item": self.current_item,
            "metrics": self.metrics,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "error_message": self.error_message,
        }


ProgressCallback = Callable[[ProgressUpdate], Awaitable[None]]


class AsyncProgressTracker:
    """
    Async progress tracker that supports multiple callback types.

    Supports:
    - Rich console progress (CLI)
    - WebSocket broadcast (API)
    - Custom callbacks

    Usage:
        tracker = AsyncProgressTracker(total=100)

        # Register a callback
        async def my_callback(update: ProgressUpdate):
            print(f"Progress: {update.percentage}%")

        tracker.add_callback(my_callback)

        # Update progress
        await tracker.update(processed=10, current_item={"rule_id": "xss-001"})

        # Complete
        await tracker.complete()
    """

    def __init__(self, total: int):
        self._total = total
        self._processed = 0
        self._status = ProgressStatus.PENDING
        self._current_item: Optional[Dict[str, Any]] = None
        self._metrics: Dict[str, Any] = {
            "cache_hits": 0,
            "cache_misses": 0,
            "true_positives": 0,
            "false_positives": 0,
            "needs_review": 0,
            "errors": 0,
        }
        self._started_at: Optional[datetime] = None
        self._error_message: Optional[str] = None
        self._callbacks: list[ProgressCallback] = []
        self._lock = asyncio.Lock()

    @property
    def current_update(self) -> ProgressUpdate:
        """Get current progress update."""
        return ProgressUpdate(
            total=self._total,
            processed=self._processed,
            status=self._status,
            current_item=self._current_item,
            metrics=self._metrics.copy(),
            started_at=self._started_at,
            error_message=self._error_message,
        )

    def add_callback(self, callback: ProgressCallback):
        """Add a progress callback."""
        self._callbacks.append(callback)

    def remove_callback(self, callback: ProgressCallback):
        """Remove a progress callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    async def _notify_callbacks(self):
        """Notify all callbacks of progress update."""
        update = self.current_update
        for callback in self._callbacks:
            try:
                await callback(update)
            except Exception:
                # Don't let callback errors stop processing
                pass

    async def start(self):
        """Mark processing as started."""
        async with self._lock:
            self._status = ProgressStatus.RUNNING
            self._started_at = datetime.utcnow()
        await self._notify_callbacks()

    async def update(
        self,
        processed: Optional[int] = None,
        increment: int = 0,
        current_item: Optional[Dict[str, Any]] = None,
        metrics_update: Optional[Dict[str, Any]] = None,
    ):
        """
        Update progress.

        Args:
            processed: Absolute number of processed items
            increment: Increment processed count by this amount
            current_item: Details about current item being processed
            metrics_update: Dictionary to update metrics with
        """
        async with self._lock:
            if processed is not None:
                self._processed = processed
            else:
                self._processed += increment

            if current_item is not None:
                self._current_item = current_item

            if metrics_update:
                self._metrics.update(metrics_update)

        await self._notify_callbacks()

    async def increment_metric(self, metric_name: str, amount: int = 1):
        """Increment a specific metric."""
        async with self._lock:
            if metric_name in self._metrics:
                self._metrics[metric_name] += amount
            else:
                self._metrics[metric_name] = amount
        await self._notify_callbacks()

    async def complete(self):
        """Mark processing as completed."""
        async with self._lock:
            self._status = ProgressStatus.COMPLETED
            self._processed = self._total
            self._current_item = None
        await self._notify_callbacks()

    async def fail(self, error_message: str):
        """Mark processing as failed."""
        async with self._lock:
            self._status = ProgressStatus.FAILED
            self._error_message = error_message
            self._current_item = None
        await self._notify_callbacks()

    async def cancel(self):
        """Mark processing as cancelled."""
        async with self._lock:
            self._status = ProgressStatus.CANCELLED
            self._current_item = None
        await self._notify_callbacks()


class MultiProgressTracker:
    """
    Manage multiple progress trackers for different scans.

    Usage:
        multi = MultiProgressTracker()

        # Create tracker for a scan
        tracker = multi.create_tracker("scan-123", total=50)

        # Get existing tracker
        tracker = multi.get_tracker("scan-123")

        # Remove when done
        multi.remove_tracker("scan-123")
    """

    def __init__(self):
        self._trackers: Dict[str, AsyncProgressTracker] = {}
        self._lock = asyncio.Lock()

    async def create_tracker(self, scan_id: str, total: int) -> AsyncProgressTracker:
        """Create a new tracker for a scan."""
        async with self._lock:
            tracker = AsyncProgressTracker(total)
            self._trackers[scan_id] = tracker
            return tracker

    def get_tracker(self, scan_id: str) -> Optional[AsyncProgressTracker]:
        """Get tracker for a scan."""
        return self._trackers.get(scan_id)

    async def remove_tracker(self, scan_id: str):
        """Remove tracker for a scan."""
        async with self._lock:
            self._trackers.pop(scan_id, None)

    def get_all_updates(self) -> Dict[str, ProgressUpdate]:
        """Get progress updates for all active scans."""
        return {
            scan_id: tracker.current_update
            for scan_id, tracker in self._trackers.items()
        }
