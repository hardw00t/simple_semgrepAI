"""Pydantic schemas for Scan endpoints."""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

from ..models.scan import ScanStatus


class ScanCreate(BaseModel):
    """Schema for creating a new scan."""
    target_path: str = Field(
        description="Path to the code directory to scan"
    )
    rules_path: Optional[str] = Field(
        default=None,
        description="Path to custom Semgrep rules file"
    )
    name: Optional[str] = Field(
        default=None,
        description="Optional name for the scan"
    )


class ScanResponse(BaseModel):
    """Schema for scan response."""
    id: str
    name: Optional[str]
    target_path: str
    rules_path: Optional[str]
    status: ScanStatus
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    total_findings: int
    validated_findings: int
    created_at: datetime
    updated_at: datetime

    # Computed properties
    progress_percentage: float = 0.0
    duration_seconds: Optional[float] = None

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Schema for list of scans."""
    items: List[ScanResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ScanDetailResponse(ScanResponse):
    """Schema for detailed scan response with additional stats."""
    error_message: Optional[str] = None
    config_snapshot: Optional[Dict[str, Any]] = None

    # Statistics
    true_positives: int = 0
    false_positives: int = 0
    needs_review: int = 0

    # Severity breakdown
    severity_critical: int = 0
    severity_high: int = 0
    severity_medium: int = 0
    severity_low: int = 0

    class Config:
        from_attributes = True


class ScanProgress(BaseModel):
    """Schema for scan progress updates via WebSocket."""
    scan_id: str
    status: ScanStatus
    total_findings: int
    validated_findings: int
    progress_percentage: float
    current_finding: Optional[Dict[str, Any]] = None
    metrics: Dict[str, Any] = Field(default_factory=dict)
