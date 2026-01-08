"""Scan API routes."""

import asyncio
from typing import Optional
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from ..db import get_db
from ..models import Scan, ScanStatus, Finding
from ..schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanListResponse,
    ScanDetailResponse,
)
from ..schemas.common import PaginationParams
from ..services.scan_service import ScanService

router = APIRouter()


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Create and start a new security scan.

    The scan runs asynchronously in the background. Use the WebSocket endpoint
    or poll the scan status to track progress.
    """
    # Validate target path exists
    target_path = Path(scan_data.target_path)
    if not target_path.exists():
        raise HTTPException(
            status_code=400,
            detail=f"Target path does not exist: {scan_data.target_path}",
        )

    # Validate rules path if provided
    if scan_data.rules_path:
        rules_path = Path(scan_data.rules_path)
        if not rules_path.exists():
            raise HTTPException(
                status_code=400,
                detail=f"Rules path does not exist: {scan_data.rules_path}",
            )

    # Create scan record
    scan = Scan(
        name=scan_data.name or f"Scan of {target_path.name}",
        target_path=str(target_path.absolute()),
        rules_path=str(Path(scan_data.rules_path).absolute()) if scan_data.rules_path else None,
        status=ScanStatus.PENDING,
    )

    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Start scan in background
    scan_service = ScanService(db)
    background_tasks.add_task(scan_service.run_scan, scan.id)

    return ScanResponse(
        id=scan.id,
        name=scan.name,
        target_path=scan.target_path,
        rules_path=scan.rules_path,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        total_findings=scan.total_findings,
        validated_findings=scan.validated_findings,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        progress_percentage=scan.progress_percentage,
        duration_seconds=scan.duration_seconds,
    )


@router.get("", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: Optional[ScanStatus] = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """List all scans with pagination and optional status filter."""
    # Build query
    query = select(Scan)

    if status:
        query = query.where(Scan.status == status)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query)

    # Apply pagination and ordering
    query = query.order_by(Scan.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    scans = result.scalars().all()

    total_pages = (total + page_size - 1) // page_size

    return ScanListResponse(
        items=[
            ScanResponse(
                id=s.id,
                name=s.name,
                target_path=s.target_path,
                rules_path=s.rules_path,
                status=s.status,
                started_at=s.started_at,
                completed_at=s.completed_at,
                total_findings=s.total_findings,
                validated_findings=s.validated_findings,
                created_at=s.created_at,
                updated_at=s.updated_at,
                progress_percentage=s.progress_percentage,
                duration_seconds=s.duration_seconds,
            )
            for s in scans
        ],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get detailed information about a specific scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get finding statistics
    stats_query = select(
        func.count().filter(Finding.verdict.ilike("%true positive%")).label("true_positives"),
        func.count().filter(Finding.verdict.ilike("%false positive%")).label("false_positives"),
        func.count().filter(
            ~Finding.verdict.ilike("%true positive%")
            & ~Finding.verdict.ilike("%false positive%")
        ).label("needs_review"),
        func.count().filter(Finding.severity.ilike("CRITICAL")).label("severity_critical"),
        func.count().filter(Finding.severity.ilike("HIGH")).label("severity_high"),
        func.count().filter(Finding.severity.ilike("MEDIUM")).label("severity_medium"),
        func.count().filter(Finding.severity.ilike("LOW")).label("severity_low"),
    ).where(Finding.scan_id == scan_id)

    stats_result = await db.execute(stats_query)
    stats = stats_result.one()

    return ScanDetailResponse(
        id=scan.id,
        name=scan.name,
        target_path=scan.target_path,
        rules_path=scan.rules_path,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        total_findings=scan.total_findings,
        validated_findings=scan.validated_findings,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        progress_percentage=scan.progress_percentage,
        duration_seconds=scan.duration_seconds,
        error_message=scan.error_message,
        config_snapshot=scan.config_snapshot,
        true_positives=stats.true_positives or 0,
        false_positives=stats.false_positives or 0,
        needs_review=stats.needs_review or 0,
        severity_critical=stats.severity_critical or 0,
        severity_high=stats.severity_high or 0,
        severity_medium=stats.severity_medium or 0,
        severity_low=stats.severity_low or 0,
    )


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan and all its findings."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Prevent deletion of running scans
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete a running scan. Cancel it first.",
        )

    await db.delete(scan)
    await db.commit()


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(
            status_code=400,
            detail=f"Can only cancel running scans. Current status: {scan.status}",
        )

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    await db.commit()
    await db.refresh(scan)

    return ScanResponse(
        id=scan.id,
        name=scan.name,
        target_path=scan.target_path,
        rules_path=scan.rules_path,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        total_findings=scan.total_findings,
        validated_findings=scan.validated_findings,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        progress_percentage=scan.progress_percentage,
        duration_seconds=scan.duration_seconds,
    )
