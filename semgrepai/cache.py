from pathlib import Path
import json
import hashlib
from typing import Dict, Optional
from datetime import datetime, timedelta
import sqlite3
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

class ValidationCache:
    def __init__(self, cache_dir: Path, max_entries: int = 10000, auto_cleanup_interval: int = 100):
        """
        Initialize validation cache with size limits and auto-cleanup.

        Args:
            cache_dir: Directory for cache database
            max_entries: Maximum number of cache entries before cleanup (default: 10000)
            auto_cleanup_interval: Trigger cleanup every N puts (default: 100)
        """
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "validation_cache.db"
        self.hits = 0
        self.misses = 0
        self.max_entries = max_entries
        self.auto_cleanup_interval = auto_cleanup_interval
        self._put_count = 0
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database."""
        with self._get_db() as (conn, cursor):
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS validation_cache (
                    hash TEXT PRIMARY KEY,
                    finding_data TEXT,
                    validation_result TEXT,
                    created_at TIMESTAMP,
                    accessed_at TIMESTAMP,
                    access_count INTEGER DEFAULT 1
                )
            """)
            conn.commit()

    @contextmanager
    def _get_db(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            yield conn, cursor
        finally:
            conn.close()

    def _compute_hash(self, finding) -> str:
        """Compute a deterministic hash for a finding or use provided hash."""
        if isinstance(finding, str):
            return finding
            
        # Extract relevant fields for hash
        hash_data = {
            'rule_id': finding.get('rule_id'),
            'severity': finding.get('severity'),
            'message': finding.get('message'),
            'code': finding.get('code'),
        }
        
        # Create deterministic string representation
        hash_str = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_str.encode()).hexdigest()

    def get(self, finding) -> Optional[Dict]:
        """Retrieve cached validation result for a finding.
        
        Args:
            finding: Either a dictionary containing finding data or a pre-computed hash string
        """
        finding_hash = self._compute_hash(finding)
        
        with self._get_db() as (conn, cursor):
            cursor.execute("""
                SELECT validation_result, created_at 
                FROM validation_cache 
                WHERE hash = ?
            """, (finding_hash,))
            
            result = cursor.fetchone()
            if result:
                validation_result, created_at = result
                
                # Update access statistics
                cursor.execute("""
                    UPDATE validation_cache 
                    SET accessed_at = CURRENT_TIMESTAMP,
                        access_count = access_count + 1
                    WHERE hash = ?
                """, (finding_hash,))
                conn.commit()
                
                self.hits += 1
                return json.loads(validation_result)
        
        self.misses += 1
        return None

    def put(self, finding, validation_result: Dict):
        """Cache validation result for a finding."""
        finding_hash = self._compute_hash(finding)

        with self._get_db() as (conn, cursor):
            cursor.execute("""
                INSERT OR REPLACE INTO validation_cache
                (hash, finding_data, validation_result, created_at, accessed_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (
                finding_hash,
                json.dumps(finding) if not isinstance(finding, str) else finding,
                json.dumps(validation_result)
            ))
            conn.commit()

        # Increment put counter and check if auto-cleanup is needed
        self._put_count += 1
        if self._put_count >= self.auto_cleanup_interval:
            self._auto_cleanup()
            self._put_count = 0

    def _auto_cleanup(self):
        """Automatically cleanup cache when size exceeds limit."""
        try:
            with self._get_db() as (conn, cursor):
                # Check current size
                cursor.execute("SELECT COUNT(*) FROM validation_cache")
                current_size = cursor.fetchone()[0]

                if current_size > self.max_entries:
                    # Calculate how many to remove (remove 20% to avoid frequent cleanups)
                    entries_to_remove = int(current_size * 0.2)

                    # Remove least recently accessed entries
                    cursor.execute("""
                        DELETE FROM validation_cache
                        WHERE hash IN (
                            SELECT hash FROM validation_cache
                            ORDER BY accessed_at ASC, access_count ASC
                            LIMIT ?
                        )
                    """, (entries_to_remove,))

                    removed = cursor.rowcount
                    conn.commit()
                    logger.info(f"Auto-cleanup: Removed {removed} old cache entries (cache size was {current_size})")

        except Exception as e:
            logger.error(f"Error during auto-cleanup: {e}")

    def cleanup(self, max_age_days: int = 30, min_access_count: int = 1):
        """Clean up old or rarely accessed cache entries."""
        cutoff_date = datetime.now() - timedelta(days=max_age_days)

        with self._get_db() as (conn, cursor):
            cursor.execute("""
                DELETE FROM validation_cache
                WHERE (created_at < ? AND access_count <= ?)
            """, (cutoff_date.isoformat(), min_access_count))

            removed = cursor.rowcount
            conn.commit()
            logger.info(f"Cleanup: Removed {removed} entries older than {max_age_days} days with access count <= {min_access_count}")

    def get_statistics(self) -> Dict:
        """Get cache statistics."""
        with self._get_db() as (conn, cursor):
            cursor.execute("SELECT COUNT(*) FROM validation_cache")
            total_entries = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*) FROM validation_cache
                WHERE accessed_at > datetime('now', '-1 day')
            """)
            daily_hits = cursor.fetchone()[0]

            cursor.execute("""
                SELECT AVG(access_count) FROM validation_cache
            """)
            avg_access = cursor.fetchone()[0] or 0

            # Calculate hit rate
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

            # Get size info
            cursor.execute("""
                SELECT
                    MAX(created_at) as newest,
                    MIN(created_at) as oldest
                FROM validation_cache
            """)
            dates = cursor.fetchone()

            return {
                'total_entries': total_entries,
                'max_entries': self.max_entries,
                'capacity_used': f"{(total_entries / self.max_entries * 100):.1f}%" if self.max_entries > 0 else "N/A",
                'daily_hits': daily_hits,
                'average_access': round(avg_access, 2),
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': f"{hit_rate:.1f}%",
                'oldest_entry': dates[1] if dates else None,
                'newest_entry': dates[0] if dates else None
            }

    def clear(self):
        """Clear all cache entries."""
        with self._get_db() as (conn, cursor):
            cursor.execute("DELETE FROM validation_cache")
            conn.commit()
            logger.info("Cache cleared")
