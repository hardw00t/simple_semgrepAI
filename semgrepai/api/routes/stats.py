"""Statistics API routes."""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from ..db import get_db
from ..models import Scan, ScanStatus, Finding, TriageStatus
from ..schemas.common import (
    StatsResponse,
    SeverityDistribution,
    TriageDistribution,
    VerdictDistribution,
)

router = APIRouter()


@router.get("", response_model=StatsResponse)
async def get_stats(
    db: AsyncSession = Depends(get_db),
):
    """Get overall statistics for the dashboard."""
    # Scan counts by status
    scan_counts_query = select(
        func.count().label("total"),
        func.count().filter(Scan.status == ScanStatus.PENDING).label("pending"),
        func.count().filter(Scan.status == ScanStatus.RUNNING).label("running"),
        func.count().filter(Scan.status == ScanStatus.COMPLETED).label("completed"),
        func.count().filter(Scan.status == ScanStatus.FAILED).label("failed"),
    )
    scan_counts = await db.execute(scan_counts_query)
    sc = scan_counts.one()

    # Total findings
    total_findings = await db.scalar(select(func.count()).select_from(Finding))

    # Severity distribution
    # Note: Semgrep uses ERROR/WARNING/INFO, map to HIGH/MEDIUM/LOW
    from sqlalchemy import or_, case
    severity_query = select(
        func.sum(case((Finding.severity.ilike("CRITICAL"), 1), else_=0)).label("critical"),
        func.sum(case((or_(Finding.severity.ilike("HIGH"), Finding.severity.ilike("ERROR")), 1), else_=0)).label("high"),
        func.sum(case((or_(Finding.severity.ilike("MEDIUM"), Finding.severity.ilike("WARNING")), 1), else_=0)).label("medium"),
        func.sum(case((Finding.severity.ilike("LOW"), 1), else_=0)).label("low"),
        func.sum(case((Finding.severity.ilike("INFO"), 1), else_=0)).label("info"),
    ).select_from(Finding)
    severity_result = await db.execute(severity_query)
    sev = severity_result.one()

    severity_distribution = SeverityDistribution(
        critical=sev.critical or 0,
        high=sev.high or 0,
        medium=sev.medium or 0,
        low=sev.low or 0,
        info=sev.info or 0,
        unknown=max(0, total_findings - (sev.critical + sev.high + sev.medium + sev.low + sev.info)),
    )

    # Triage distribution
    triage_query = select(
        func.count().filter(Finding.triage_status == TriageStatus.NEEDS_REVIEW).label("needs_review"),
        func.count().filter(Finding.triage_status == TriageStatus.TRUE_POSITIVE).label("true_positive"),
        func.count().filter(Finding.triage_status == TriageStatus.FALSE_POSITIVE).label("false_positive"),
        func.count().filter(Finding.triage_status == TriageStatus.ACCEPTED_RISK).label("accepted_risk"),
        func.count().filter(Finding.triage_status == TriageStatus.FIXED).label("fixed"),
    )
    triage_result = await db.execute(triage_query)
    tri = triage_result.one()

    triage_distribution = TriageDistribution(
        needs_review=tri.needs_review or 0,
        true_positive=tri.true_positive or 0,
        false_positive=tri.false_positive or 0,
        accepted_risk=tri.accepted_risk or 0,
        fixed=tri.fixed or 0,
    )

    # Verdict distribution (AI prediction)
    verdict_query = select(
        func.count().filter(Finding.verdict.ilike("%true positive%")).label("true_positive"),
        func.count().filter(Finding.verdict.ilike("%false positive%")).label("false_positive"),
        func.count().filter(Finding.verdict.ilike("%needs review%")).label("needs_review"),
        func.count().filter(Finding.verdict.ilike("%error%")).label("error"),
    )
    verdict_result = await db.execute(verdict_query)
    verd = verdict_result.one()

    verdict_distribution = VerdictDistribution(
        true_positive=verd.true_positive or 0,
        false_positive=verd.false_positive or 0,
        needs_review=verd.needs_review or 0,
        error=verd.error or 0,
    )

    # Risk metrics
    avg_risk = await db.scalar(
        select(func.avg(Finding.risk_score)).where(Finding.risk_score.isnot(None))
    )
    critical_findings = await db.scalar(
        select(func.count()).select_from(Finding).where(Finding.risk_score >= 8)
    )

    # Recent activity (last 7 days)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    recent_scans = await db.scalar(
        select(func.count()).select_from(Scan).where(Scan.created_at >= seven_days_ago)
    )

    # Findings needing review
    findings_needing_review = await db.scalar(
        select(func.count())
        .select_from(Finding)
        .where(Finding.triage_status == TriageStatus.NEEDS_REVIEW)
    )

    return StatsResponse(
        total_scans=sc.total or 0,
        total_findings=total_findings or 0,
        pending_scans=sc.pending or 0,
        running_scans=sc.running or 0,
        completed_scans=sc.completed or 0,
        failed_scans=sc.failed or 0,
        severity_distribution=severity_distribution,
        triage_distribution=triage_distribution,
        verdict_distribution=verdict_distribution,
        average_risk_score=float(avg_risk or 0),
        critical_findings_count=critical_findings or 0,
        recent_scans_count=recent_scans or 0,
        findings_needing_review=findings_needing_review or 0,
    )
