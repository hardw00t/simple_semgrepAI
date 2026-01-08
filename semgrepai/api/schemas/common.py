"""Common Pydantic schemas used across the API."""

from typing import Optional, Dict, Any, List, Generic, TypeVar
from pydantic import BaseModel, Field
from datetime import datetime

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Pagination parameters."""
    page: int = Field(default=1, ge=1, description="Page number")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")


class SortParams(BaseModel):
    """Sort parameters."""
    sort_by: str = Field(default="created_at", description="Field to sort by")
    sort_order: str = Field(
        default="desc",
        description="Sort order",
        pattern="^(asc|desc)$",
    )


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response."""
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int

    @classmethod
    def create(
        cls,
        items: List[T],
        total: int,
        pagination: PaginationParams,
    ) -> "PaginatedResponse[T]":
        """Create a paginated response."""
        total_pages = (total + pagination.page_size - 1) // pagination.page_size
        return cls(
            items=items,
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
            total_pages=total_pages,
        )


class SeverityDistribution(BaseModel):
    """Distribution of findings by severity."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0


class TriageDistribution(BaseModel):
    """Distribution of findings by triage status."""
    needs_review: int = 0
    true_positive: int = 0
    false_positive: int = 0
    accepted_risk: int = 0
    fixed: int = 0


class VerdictDistribution(BaseModel):
    """Distribution of findings by AI verdict."""
    true_positive: int = 0
    false_positive: int = 0
    needs_review: int = 0
    error: int = 0


class StatsResponse(BaseModel):
    """API statistics response."""
    total_scans: int = 0
    total_findings: int = 0
    pending_scans: int = 0
    running_scans: int = 0
    completed_scans: int = 0
    failed_scans: int = 0

    severity_distribution: SeverityDistribution = Field(
        default_factory=SeverityDistribution
    )
    triage_distribution: TriageDistribution = Field(
        default_factory=TriageDistribution
    )
    verdict_distribution: VerdictDistribution = Field(
        default_factory=VerdictDistribution
    )

    # Risk metrics
    average_risk_score: float = 0.0
    critical_findings_count: int = 0  # Risk score >= 8

    # Recent activity
    recent_scans_count: int = 0  # Last 7 days
    findings_needing_review: int = 0


class WebSocketMessage(BaseModel):
    """WebSocket message format."""
    type: str = Field(description="Message type: progress, complete, error")
    scan_id: str
    data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
