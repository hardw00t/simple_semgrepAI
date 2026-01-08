"""Finding database model."""

import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional, List, Dict, Any, TYPE_CHECKING

from sqlalchemy import Column, String, Integer, Float, DateTime, Enum, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship, Mapped, mapped_column

from ..db.session import Base

if TYPE_CHECKING:
    from .scan import Scan


class TriageStatus(str, PyEnum):
    """Triage status for a finding."""
    NEEDS_REVIEW = "needs_review"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"


class Finding(Base):
    """Database model for security findings."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id"), nullable=False, index=True
    )

    # Semgrep fields
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=True)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    line: Mapped[int] = mapped_column(Integer, nullable=False)
    code: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # AI validation fields
    verdict: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    poc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # JSON fields for complex data
    attack_vectors: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    trigger_steps: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    recommended_fixes: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    impact_assessment: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    vulnerability_category: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    technical_details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Triage fields
    triage_status: Mapped[TriageStatus] = mapped_column(
        Enum(TriageStatus), default=TriageStatus.NEEDS_REVIEW, nullable=False, index=True
    )
    triage_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    triage_updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    triage_updated_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    assignee: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Metadata from Semgrep
    semgrep_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Processing info
    processing_time: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, rule_id={self.rule_id}, severity={self.severity})>"

    @property
    def is_true_positive(self) -> Optional[bool]:
        """Check if finding is a true positive."""
        if self.verdict:
            return "true positive" in self.verdict.lower()
        return None

    @classmethod
    def from_scan_finding(cls, scan_id: str, finding_dict: Dict[str, Any]) -> "Finding":
        """Create a Finding from a scan result dictionary."""
        ai_validation = finding_dict.get("ai_validation", {})

        return cls(
            scan_id=scan_id,
            # Semgrep fields
            rule_id=finding_dict.get("rule_id", "unknown"),
            severity=finding_dict.get("severity", "UNKNOWN"),
            message=finding_dict.get("message", ""),
            path=finding_dict.get("path", ""),
            line=finding_dict.get("line", 0),
            code=finding_dict.get("code"),
            # AI validation fields
            verdict=ai_validation.get("verdict"),
            confidence=ai_validation.get("confidence"),
            risk_score=ai_validation.get("risk_score"),
            justification=ai_validation.get("justification"),
            poc=ai_validation.get("poc"),
            attack_vectors=ai_validation.get("attack_vectors"),
            trigger_steps=ai_validation.get("trigger_steps"),
            recommended_fixes=ai_validation.get("recommended_fixes"),
            impact_assessment=ai_validation.get("impact"),
            vulnerability_category=ai_validation.get("vulnerability"),
            technical_details=ai_validation.get("technical"),
            # Metadata
            semgrep_metadata=finding_dict.get("metadata"),
            processing_time=finding_dict.get("processing_time"),
        )
