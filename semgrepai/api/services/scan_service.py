"""Scan service for orchestrating security scans."""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..models import Scan, ScanStatus, Finding
from ..routes.websocket import get_connection_manager
from ...scanner import SemgrepScanner
from ...validator import AIValidator
from ...async_utils import AsyncProgressTracker, ProgressUpdate
from ...logging import get_logger

logger = get_logger(__name__)


class ScanService:
    """Service for running and managing security scans."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ws_manager = get_connection_manager()

    async def run_scan(self, scan_id: str):
        """
        Run a security scan asynchronously.

        This method is designed to run as a background task.
        """
        try:
            # Get scan from database
            result = await self.db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()

            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return

            if scan.status != ScanStatus.PENDING:
                logger.warning(f"Scan {scan_id} is not in pending state: {scan.status}")
                return

            # Update status to running
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            await self.db.commit()

            await self._broadcast_progress(scan_id, {
                "type": "started",
                "status": "running",
                "message": "Scan started",
            })

            # Run Semgrep scan
            logger.info(f"Starting Semgrep scan for {scan.target_path}")
            scanner = SemgrepScanner()

            try:
                target_path = Path(scan.target_path)
                rules_path = Path(scan.rules_path) if scan.rules_path else None

                results = scanner.scan(target_path, rules_path)

                if not results or not results.get("json", {}).get("results"):
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.total_findings = 0
                    await self.db.commit()

                    await self._broadcast_progress(scan_id, {
                        "type": "complete",
                        "status": "completed",
                        "message": "No findings detected",
                        "total_findings": 0,
                    })
                    return

                # Process results
                findings_data = scanner._process_results(results)
                scan.total_findings = len(findings_data)
                await self.db.commit()

                await self._broadcast_progress(scan_id, {
                    "type": "progress",
                    "status": "running",
                    "message": f"Found {len(findings_data)} potential issues, starting AI validation",
                    "total": len(findings_data),
                    "processed": 0,
                })

            except Exception as e:
                logger.error(f"Semgrep scan failed: {e}")
                scan.status = ScanStatus.FAILED
                scan.completed_at = datetime.utcnow()
                scan.error_message = f"Semgrep scan failed: {str(e)}"
                await self.db.commit()

                await self._broadcast_progress(scan_id, {
                    "type": "error",
                    "status": "failed",
                    "message": f"Semgrep scan failed: {str(e)}",
                })
                return

            # Run AI validation
            logger.info(f"Starting AI validation for {len(findings_data)} findings")

            try:
                validator = AIValidator()

                # Create progress tracker with WebSocket callback
                progress_tracker = AsyncProgressTracker(len(findings_data))

                async def ws_callback(update: ProgressUpdate):
                    """Callback to send progress updates via WebSocket."""
                    await self._broadcast_progress(scan_id, {
                        "type": "progress",
                        "status": "running",
                        "total": update.total,
                        "processed": update.processed,
                        "percentage": update.percentage,
                        "current_finding": update.current_item,
                        "metrics": update.metrics,
                    })

                    # Update scan in database
                    scan.validated_findings = update.processed
                    await self.db.commit()

                progress_tracker.add_callback(ws_callback)

                # Run async validation
                validated_findings = await validator.validate_findings_async(
                    findings_data,
                    progress_tracker=progress_tracker,
                )

                # Store findings in database
                for finding_dict in validated_findings:
                    finding = Finding.from_scan_finding(scan_id, finding_dict)
                    self.db.add(finding)

                scan.validated_findings = len(validated_findings)
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                await self.db.commit()

                await self._broadcast_progress(scan_id, {
                    "type": "complete",
                    "status": "completed",
                    "message": "Scan completed successfully",
                    "total_findings": len(validated_findings),
                })

                logger.info(f"Scan {scan_id} completed with {len(validated_findings)} findings")

            except Exception as e:
                logger.error(f"AI validation failed: {e}", exc_info=True)
                scan.status = ScanStatus.FAILED
                scan.completed_at = datetime.utcnow()
                scan.error_message = f"AI validation failed: {str(e)}"
                await self.db.commit()

                await self._broadcast_progress(scan_id, {
                    "type": "error",
                    "status": "failed",
                    "message": f"AI validation failed: {str(e)}",
                })

        except Exception as e:
            logger.error(f"Scan {scan_id} failed with unexpected error: {e}", exc_info=True)
            try:
                result = await self.db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.utcnow()
                    scan.error_message = f"Unexpected error: {str(e)}"
                    await self.db.commit()
            except Exception:
                pass

            await self._broadcast_progress(scan_id, {
                "type": "error",
                "status": "failed",
                "message": f"Unexpected error: {str(e)}",
            })

    async def _broadcast_progress(self, scan_id: str, data: dict):
        """Broadcast progress update to WebSocket clients."""
        message = {
            **data,
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
        }
        await self.ws_manager.broadcast_to_scan(scan_id, message)
