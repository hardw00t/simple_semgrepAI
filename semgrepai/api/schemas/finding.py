"""Pydantic schemas for Finding endpoints."""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

from ..models.finding import TriageStatus


class FindingResponse(BaseModel):
    """Schema for finding response in list views."""
    id: str
    scan_id: str
    rule_id: str
    severity: str
    message: Optional[str]
    path: str
    line: int

    # AI validation summary
    verdict: Optional[str]
    confidence: Optional[float]
    risk_score: Optional[int]

    # Triage info
    triage_status: TriageStatus
    assignee: Optional[str]

    created_at: datetime

    class Config:
        from_attributes = True


class FindingDetailResponse(FindingResponse):
    """Schema for detailed finding response."""
    code: Optional[str]
    justification: Optional[str]
    poc: Optional[str]
    attack_vectors: Optional[List[str]]
    trigger_steps: Optional[List[str]]
    recommended_fixes: Optional[List[str]]
    impact_assessment: Optional[Dict[str, Any]]
    vulnerability_category: Optional[Dict[str, Any]]
    technical_details: Optional[Dict[str, Any]]
    semgrep_metadata: Optional[Dict[str, Any]] = Field(default=None, alias="metadata")

    # Triage details
    triage_note: Optional[str]
    triage_updated_at: Optional[datetime]
    triage_updated_by: Optional[str]

    # Processing info
    processing_time: Optional[float]
    updated_at: datetime

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    """Schema for updating a finding's triage status."""
    triage_status: Optional[TriageStatus] = Field(
        default=None,
        description="New triage status"
    )
    triage_note: Optional[str] = Field(
        default=None,
        description="Note explaining the triage decision"
    )
    assignee: Optional[str] = Field(
        default=None,
        description="Person assigned to handle this finding"
    )


class FindingFilters(BaseModel):
    """Filters for finding queries."""
    severity: Optional[List[str]] = Field(
        default=None,
        description="Filter by severity levels"
    )
    triage_status: Optional[List[TriageStatus]] = Field(
        default=None,
        description="Filter by triage status"
    )
    verdict: Optional[List[str]] = Field(
        default=None,
        description="Filter by AI verdict"
    )
    rule_id: Optional[str] = Field(
        default=None,
        description="Filter by rule ID (partial match)"
    )
    path_contains: Optional[str] = Field(
        default=None,
        description="Filter by file path (partial match)"
    )
    min_risk_score: Optional[int] = Field(
        default=None,
        ge=0,
        le=10,
        description="Minimum risk score"
    )
    max_risk_score: Optional[int] = Field(
        default=None,
        ge=0,
        le=10,
        description="Maximum risk score"
    )
    assignee: Optional[str] = Field(
        default=None,
        description="Filter by assignee"
    )


class FindingListResponse(BaseModel):
    """Schema for list of findings."""
    items: List[FindingResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class BulkTriageUpdate(BaseModel):
    """Schema for bulk updating multiple findings."""
    finding_ids: List[str] = Field(
        description="List of finding IDs to update"
    )
    triage_status: TriageStatus = Field(
        description="New triage status for all findings"
    )
    triage_note: Optional[str] = Field(
        default=None,
        description="Note to apply to all findings"
    )
