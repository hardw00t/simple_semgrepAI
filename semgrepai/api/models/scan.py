"""Scan database model."""

import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional, List, TYPE_CHECKING

from sqlalchemy import Column, String, Integer, DateTime, Enum, JSON, Text
from sqlalchemy.orm import relationship, Mapped, mapped_column

from ..db.session import Base

if TYPE_CHECKING:
    from .finding import Finding


class ScanStatus(str, PyEnum):
    """Status of a scan operation."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    """Database model for security scans."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    target_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    rules_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)

    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False
    )

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    validated_findings: Mapped[int] = mapped_column(Integer, default=0)

    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Store config snapshot at scan time for reproducibility
    config_snapshot: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, name={self.name}, status={self.status})>"

    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def progress_percentage(self) -> float:
        """Calculate progress percentage."""
        if self.total_findings == 0:
            return 0.0 if self.status == ScanStatus.PENDING else 100.0
        return (self.validated_findings / self.total_findings) * 100
