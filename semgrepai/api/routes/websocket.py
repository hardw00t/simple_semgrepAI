"""WebSocket routes for real-time scan progress."""

import asyncio
from typing import Dict, List
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from datetime import datetime

router = APIRouter()


class ConnectionManager:
    """Manage WebSocket connections for scan progress updates."""

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, scan_id: str):
        """Accept a WebSocket connection and track it by scan ID."""
        await websocket.accept()
        async with self._lock:
            if scan_id not in self.active_connections:
                self.active_connections[scan_id] = []
            self.active_connections[scan_id].append(websocket)

    async def disconnect(self, websocket: WebSocket, scan_id: str):
        """Remove a WebSocket connection."""
        async with self._lock:
            if scan_id in self.active_connections:
                if websocket in self.active_connections[scan_id]:
                    self.active_connections[scan_id].remove(websocket)
                if not self.active_connections[scan_id]:
                    del self.active_connections[scan_id]

    async def broadcast_to_scan(self, scan_id: str, message: dict):
        """Broadcast a message to all connections watching a specific scan."""
        async with self._lock:
            connections = self.active_connections.get(scan_id, [])

        # Send to all connections outside the lock to avoid holding it too long
        disconnected = []
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                for conn in disconnected:
                    if scan_id in self.active_connections:
                        if conn in self.active_connections[scan_id]:
                            self.active_connections[scan_id].remove(conn)

    def get_connection_count(self, scan_id: str) -> int:
        """Get number of active connections for a scan."""
        return len(self.active_connections.get(scan_id, []))


# Global connection manager instance
manager = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    """Get the global connection manager instance."""
    return manager


@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_progress(
    websocket: WebSocket,
    scan_id: str,
):
    """
    WebSocket endpoint for real-time scan progress updates.

    Connect to receive live updates about a scan's progress.

    Message format:
    ```json
    {
        "type": "progress|complete|error",
        "scan_id": "uuid",
        "data": {
            "status": "running",
            "total": 100,
            "processed": 45,
            "percentage": 45.0,
            "current_finding": {
                "rule_id": "python.flask.security.xss",
                "path": "app/views.py"
            },
            "metrics": {
                "cache_hits": 10,
                "true_positives": 20,
                "false_positives": 15
            }
        },
        "timestamp": "2024-01-15T10:30:00Z"
    }
    ```
    """
    await manager.connect(websocket, scan_id)

    # Send initial connection confirmation
    await websocket.send_json({
        "type": "connected",
        "scan_id": scan_id,
        "data": {"message": "Connected to scan progress updates"},
        "timestamp": datetime.utcnow().isoformat(),
    })

    try:
        while True:
            # Keep connection alive and handle any client messages
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0  # Send ping every 30 seconds
                )

                # Handle client messages if needed
                try:
                    message = json.loads(data)
                    if message.get("type") == "ping":
                        await websocket.send_json({
                            "type": "pong",
                            "scan_id": scan_id,
                            "timestamp": datetime.utcnow().isoformat(),
                        })
                except json.JSONDecodeError:
                    pass

            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                try:
                    await websocket.send_json({
                        "type": "ping",
                        "scan_id": scan_id,
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                except Exception:
                    break

    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket, scan_id)
