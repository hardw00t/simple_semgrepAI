"""Finding API routes."""

from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_

from ..db import get_db
from ..models import Scan, Finding, TriageStatus
from ..schemas.finding import (
    FindingResponse,
    FindingDetailResponse,
    FindingUpdate,
    FindingListResponse,
    BulkTriageUpdate,
)

router = APIRouter()


@router.get("/scans/{scan_id}/findings", response_model=FindingListResponse)
async def list_findings(
    scan_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: Optional[str] = Query(default=None, description="Comma-separated severity levels"),
    triage_status: Optional[str] = Query(default=None, description="Comma-separated triage statuses"),
    verdict: Optional[str] = Query(default=None, description="Comma-separated verdicts"),
    rule_id: Optional[str] = Query(default=None, description="Filter by rule ID (partial match)"),
    path_contains: Optional[str] = Query(default=None, description="Filter by file path (partial match)"),
    min_risk_score: Optional[int] = Query(default=None, ge=0, le=10),
    max_risk_score: Optional[int] = Query(default=None, ge=0, le=10),
    assignee: Optional[str] = Query(default=None),
    sort_by: str = Query(default="risk_score", description="Field to sort by"),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
):
    """List findings for a scan with filtering and sorting."""
    # Verify scan exists
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build query
    query = select(Finding).where(Finding.scan_id == scan_id)

    # Apply filters
    if severity:
        severities = [s.strip().upper() for s in severity.split(",")]
        query = query.where(Finding.severity.in_(severities))

    if triage_status:
        statuses = [s.strip() for s in triage_status.split(",")]
        triage_enums = []
        for s in statuses:
            try:
                triage_enums.append(TriageStatus(s))
            except ValueError:
                pass
        if triage_enums:
            query = query.where(Finding.triage_status.in_(triage_enums))

    if verdict:
        verdicts = [v.strip() for v in verdict.split(",")]
        verdict_conditions = [Finding.verdict.ilike(f"%{v}%") for v in verdicts]
        query = query.where(or_(*verdict_conditions))

    if rule_id:
        query = query.where(Finding.rule_id.ilike(f"%{rule_id}%"))

    if path_contains:
        query = query.where(Finding.path.ilike(f"%{path_contains}%"))

    if min_risk_score is not None:
        query = query.where(Finding.risk_score >= min_risk_score)

    if max_risk_score is not None:
        query = query.where(Finding.risk_score <= max_risk_score)

    if assignee:
        query = query.where(Finding.assignee == assignee)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query)

    # Apply sorting
    sort_column = getattr(Finding, sort_by, Finding.risk_score)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc().nullslast())
    else:
        query = query.order_by(sort_column.asc().nullsfirst())

    # Apply pagination
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    findings = result.scalars().all()

    total_pages = (total + page_size - 1) // page_size

    return FindingListResponse(
        items=[
            FindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                rule_id=f.rule_id,
                severity=f.severity,
                message=f.message,
                path=f.path,
                line=f.line,
                verdict=f.verdict,
                confidence=f.confidence,
                risk_score=f.risk_score,
                triage_status=f.triage_status,
                assignee=f.assignee,
                created_at=f.created_at,
            )
            for f in findings
        ],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/scans/{scan_id}/findings/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(
    scan_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get detailed information about a specific finding."""
    result = await db.execute(
        select(Finding).where(
            and_(Finding.scan_id == scan_id, Finding.id == finding_id)
        )
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingDetailResponse(
        id=finding.id,
        scan_id=finding.scan_id,
        rule_id=finding.rule_id,
        severity=finding.severity,
        message=finding.message,
        path=finding.path,
        line=finding.line,
        code=finding.code,
        verdict=finding.verdict,
        confidence=finding.confidence,
        risk_score=finding.risk_score,
        justification=finding.justification,
        poc=finding.poc,
        attack_vectors=finding.attack_vectors,
        trigger_steps=finding.trigger_steps,
        recommended_fixes=finding.recommended_fixes,
        impact_assessment=finding.impact_assessment,
        vulnerability_category=finding.vulnerability_category,
        technical_details=finding.technical_details,
        metadata=finding.semgrep_metadata,
        triage_status=finding.triage_status,
        triage_note=finding.triage_note,
        triage_updated_at=finding.triage_updated_at,
        triage_updated_by=finding.triage_updated_by,
        assignee=finding.assignee,
        processing_time=finding.processing_time,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


@router.patch("/scans/{scan_id}/findings/{finding_id}", response_model=FindingDetailResponse)
async def update_finding(
    scan_id: str,
    finding_id: str,
    update_data: FindingUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a finding's triage status."""
    result = await db.execute(
        select(Finding).where(
            and_(Finding.scan_id == scan_id, Finding.id == finding_id)
        )
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Update fields
    if update_data.triage_status is not None:
        finding.triage_status = update_data.triage_status
        finding.triage_updated_at = datetime.utcnow()

    if update_data.triage_note is not None:
        finding.triage_note = update_data.triage_note

    if update_data.assignee is not None:
        finding.assignee = update_data.assignee

    await db.commit()
    await db.refresh(finding)

    return FindingDetailResponse(
        id=finding.id,
        scan_id=finding.scan_id,
        rule_id=finding.rule_id,
        severity=finding.severity,
        message=finding.message,
        path=finding.path,
        line=finding.line,
        code=finding.code,
        verdict=finding.verdict,
        confidence=finding.confidence,
        risk_score=finding.risk_score,
        justification=finding.justification,
        poc=finding.poc,
        attack_vectors=finding.attack_vectors,
        trigger_steps=finding.trigger_steps,
        recommended_fixes=finding.recommended_fixes,
        impact_assessment=finding.impact_assessment,
        vulnerability_category=finding.vulnerability_category,
        technical_details=finding.technical_details,
        metadata=finding.semgrep_metadata,
        triage_status=finding.triage_status,
        triage_note=finding.triage_note,
        triage_updated_at=finding.triage_updated_at,
        triage_updated_by=finding.triage_updated_by,
        assignee=finding.assignee,
        processing_time=finding.processing_time,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


@router.post("/scans/{scan_id}/findings/bulk-triage", response_model=dict)
async def bulk_triage_findings(
    scan_id: str,
    update_data: BulkTriageUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update triage status for multiple findings at once."""
    # Verify scan exists
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get findings to update
    result = await db.execute(
        select(Finding).where(
            and_(
                Finding.scan_id == scan_id,
                Finding.id.in_(update_data.finding_ids),
            )
        )
    )
    findings = result.scalars().all()

    if not findings:
        raise HTTPException(status_code=404, detail="No findings found with provided IDs")

    # Update all findings
    updated_count = 0
    for finding in findings:
        finding.triage_status = update_data.triage_status
        finding.triage_updated_at = datetime.utcnow()
        if update_data.triage_note:
            finding.triage_note = update_data.triage_note
        updated_count += 1

    await db.commit()

    return {
        "updated_count": updated_count,
        "requested_count": len(update_data.finding_ids),
    }
