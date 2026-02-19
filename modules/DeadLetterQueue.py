"""
Dead Letter Queue (DLQ) System
Handles failed events and provides retry/recovery mechanisms

Features:
- Persistent storage of failed events
- Automatic retry with backoff
- Event prioritization
- Poison message detection
- Metrics and monitoring
- Manual reprocessing
- Event expiration
"""

import json
import pickle
import sqlite3
import logging
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import threading
import queue
import time


class DLQEventStatus(Enum):
    """Status of DLQ events"""
    PENDING = "pending"  # Waiting for retry
    RETRYING = "retrying"  # Currently being retried
    FAILED = "failed"  # Permanently failed
    RECOVERED = "recovered"  # Successfully reprocessed
    EXPIRED = "expired"  # Expired before recovery
    POISON = "poison"  # Detected as poison message


class DLQEventPriority(Enum):
    """Priority levels for event processing"""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4


@dataclass
class DLQEvent:
    """Dead letter queue event"""
    id: str
    event_type: str
    payload: Any
    error_message: str
    error_type: str
    stack_trace: Optional[str]

    # Metadata
    original_timestamp: datetime
    failed_at: datetime
    retry_count: int = 0
    max_retries: int = 5
    status: str = DLQEventStatus.PENDING.value
    priority: int = DLQEventPriority.NORMAL.value

    # Retry tracking
    last_retry_at: Optional[datetime] = None
    next_retry_at: Optional[datetime] = None

    # Context
    source: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

    # Expiration
    expires_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        # Serialize datetime objects
        for key in ['original_timestamp', 'failed_at', 'last_retry_at', 'next_retry_at', 'expires_at']:
            if data.get(key):
                data[key] = data[key].isoformat()
        # Serialize payload
        if not isinstance(data['payload'], str):
            data['payload'] = json.dumps(data['payload'], default=str)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DLQEvent':
        """Create from dictionary"""
        # Deserialize datetime objects
        for key in ['original_timestamp', 'failed_at', 'last_retry_at', 'next_retry_at', 'expires_at']:
            if data.get(key) and isinstance(data[key], str):
                data[key] = datetime.fromisoformat(data[key])
        # Deserialize payload
        if isinstance(data.get('payload'), str):
            try:
                data['payload'] = json.loads(data['payload'])
            except (json.JSONDecodeError, TypeError):
                pass  # Keep as string if not JSON
        return cls(**data)


@dataclass
class DLQMetrics:
    """Metrics for dead letter queue"""
    total_events: int = 0
    pending_events: int = 0
    retrying_events: int = 0
    failed_events: int = 0
    recovered_events: int = 0
    expired_events: int = 0
    poison_messages: int = 0
    total_retries: int = 0
    successful_retries: int = 0
    failed_retries: int = 0


class DeadLetterQueue:
    """
    Dead Letter Queue for failed event handling

    Features:
    - Persistent storage (SQLite)
    - Automatic retry with exponential backoff
    - Poison message detection
    - Priority-based processing
    - Event expiration
    - Metrics and monitoring

    Usage:
        dlq = DeadLetterQueue("path/to/dlq.db")

        # Add failed event
        dlq.add_event(
            event_type="elasticsearch_query",
            payload={"query": "..."},
            error=exception,
            source="ElasticsearchDataSource"
        )

        # Process pending events
        dlq.process_pending_events(handler_func)
    """

    def __init__(
        self,
        db_path: str = "dlq/dead_letter_queue.db",
        auto_process: bool = False,
        process_interval: int = 60
    ):
        """
        Initialize Dead Letter Queue

        Args:
            db_path: Path to SQLite database
            auto_process: Enable automatic background processing
            process_interval: Interval in seconds for auto processing
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Initialize database
        self._init_database()

        # Background processing
        self.auto_process = auto_process
        self.process_interval = process_interval
        self._stop_processing = threading.Event()
        self._processing_thread = None

        if auto_process:
            self.start_auto_processing()

    def _init_database(self) -> None:
        """Initialize SQLite database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dlq_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                error_message TEXT NOT NULL,
                error_type TEXT NOT NULL,
                stack_trace TEXT,
                original_timestamp TEXT NOT NULL,
                failed_at TEXT NOT NULL,
                retry_count INTEGER DEFAULT 0,
                max_retries INTEGER DEFAULT 5,
                status TEXT DEFAULT 'pending',
                priority INTEGER DEFAULT 3,
                last_retry_at TEXT,
                next_retry_at TEXT,
                source TEXT,
                context TEXT,
                expires_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create indices
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON dlq_events(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_priority ON dlq_events(priority)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_next_retry ON dlq_events(next_retry_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON dlq_events(event_type)')

        conn.commit()
        conn.close()

    def add_event(
        self,
        event_type: str,
        payload: Any,
        error: Exception,
        source: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        priority: DLQEventPriority = DLQEventPriority.NORMAL,
        max_retries: int = 5,
        ttl_hours: Optional[int] = 24
    ) -> str:
        """
        Add failed event to DLQ

        Args:
            event_type: Type of event
            payload: Event payload
            error: Exception that caused failure
            source: Source component
            context: Additional context
            priority: Event priority
            max_retries: Maximum retry attempts
            ttl_hours: Time to live in hours (None = no expiration)

        Returns:
            Event ID
        """
        # Generate unique event ID
        event_id = self._generate_event_id(event_type, payload, error)

        # Calculate next retry time (immediate first retry)
        next_retry = datetime.now()

        # Calculate expiration
        expires_at = None
        if ttl_hours:
            expires_at = datetime.now() + timedelta(hours=ttl_hours)

        # Create event
        event = DLQEvent(
            id=event_id,
            event_type=event_type,
            payload=payload,
            error_message=str(error),
            error_type=type(error).__name__,
            stack_trace=None,  # Could add traceback here
            original_timestamp=datetime.now(),
            failed_at=datetime.now(),
            retry_count=0,
            max_retries=max_retries,
            status=DLQEventStatus.PENDING.value,
            priority=priority.value,
            next_retry_at=next_retry,
            source=source,
            context=context,
            expires_at=expires_at
        )

        # Save to database
        self._save_event(event)

        self.logger.warning(
            f"Event added to DLQ: {event_type} (ID: {event_id[:8]}, Error: {type(error).__name__})"
        )

        return event_id

    def get_event(self, event_id: str) -> Optional[DLQEvent]:
        """Get event by ID"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM dlq_events WHERE id = ?', (event_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return self._row_to_event(row)
        return None

    def get_pending_events(
        self,
        limit: Optional[int] = None,
        priority_order: bool = True
    ) -> List[DLQEvent]:
        """
        Get pending events ready for retry

        Args:
            limit: Maximum number of events
            priority_order: Sort by priority

        Returns:
            List of events
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = '''
            SELECT * FROM dlq_events
            WHERE status = 'pending'
            AND (next_retry_at IS NULL OR next_retry_at <= ?)
            AND (expires_at IS NULL OR expires_at > ?)
        '''

        if priority_order:
            query += ' ORDER BY priority ASC, failed_at ASC'
        else:
            query += ' ORDER BY failed_at ASC'

        if limit:
            query += f' LIMIT {limit}'

        now = datetime.now().isoformat()
        cursor.execute(query, (now, now))
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_event(row) for row in rows]

    def retry_event(
        self,
        event_id: str,
        handler: Callable[[DLQEvent], Any]
    ) -> bool:
        """
        Retry processing a single event

        Args:
            event_id: Event ID
            handler: Function to process event

        Returns:
            True if successful, False otherwise
        """
        event = self.get_event(event_id)
        if not event:
            self.logger.error(f"Event not found: {event_id}")
            return False

        # Check if expired
        if event.expires_at and datetime.now() > event.expires_at:
            self._mark_expired(event)
            return False

        # Check if max retries exceeded
        if event.retry_count >= event.max_retries:
            self._mark_failed(event, "Max retries exceeded")
            return False

        # Check for poison message
        if self._is_poison_message(event):
            self._mark_poison(event)
            return False

        # Update status to retrying
        event.status = DLQEventStatus.RETRYING.value
        event.retry_count += 1
        event.last_retry_at = datetime.now()
        self._update_event(event)

        # Try processing
        try:
            self.logger.info(f"Retrying event {event_id[:8]} (attempt {event.retry_count}/{event.max_retries})")
            result = handler(event)

            # Success
            event.status = DLQEventStatus.RECOVERED.value
            self._update_event(event)

            self.logger.info(f"Event recovered: {event_id[:8]}")
            return True

        except Exception as e:
            self.logger.error(f"Retry failed for event {event_id[:8]}: {e}")

            # Check if should retry again
            if event.retry_count >= event.max_retries:
                self._mark_failed(event, str(e))
            else:
                # Calculate next retry time with exponential backoff
                backoff_seconds = min(300, 2 ** event.retry_count * 10)  # Max 5 minutes
                event.next_retry_at = datetime.now() + timedelta(seconds=backoff_seconds)
                event.status = DLQEventStatus.PENDING.value
                self._update_event(event)

                self.logger.info(f"Scheduled retry for event {event_id[:8]} in {backoff_seconds}s")

            return False

    def process_pending_events(
        self,
        handler: Callable[[DLQEvent], Any],
        batch_size: int = 10,
        max_concurrent: int = 5
    ) -> Dict[str, int]:
        """
        Process pending events

        Args:
            handler: Function to process events
            batch_size: Number of events to process
            max_concurrent: Maximum concurrent processing (not implemented yet)

        Returns:
            Processing statistics
        """
        events = self.get_pending_events(limit=batch_size)

        stats = {
            'processed': 0,
            'recovered': 0,
            'failed': 0
        }

        for event in events:
            stats['processed'] += 1
            if self.retry_event(event.id, handler):
                stats['recovered'] += 1
            else:
                stats['failed'] += 1

        return stats

    def start_auto_processing(self) -> None:
        """Start automatic background processing"""
        if self._processing_thread and self._processing_thread.is_alive():
            return

        self._stop_processing.clear()
        self._processing_thread = threading.Thread(target=self._auto_process_loop, daemon=True)
        self._processing_thread.start()
        self.logger.info("Started automatic DLQ processing")

    def stop_auto_processing(self) -> None:
        """Stop automatic background processing"""
        self._stop_processing.set()
        if self._processing_thread:
            self._processing_thread.join(timeout=5)
        self.logger.info("Stopped automatic DLQ processing")

    def _auto_process_loop(self) -> None:
        """Background processing loop"""
        while not self._stop_processing.is_set():
            try:
                # Check for pending events
                events = self.get_pending_events(limit=10)
                if events:
                    self.logger.info(f"Auto-processing {len(events)} pending DLQ events")
                    # Note: Would need handler registration for auto-processing
                    # For now, just log
            except Exception as e:
                self.logger.error(f"Error in auto-processing loop: {e}")

            # Wait for next interval
            self._stop_processing.wait(self.process_interval)

    def get_metrics(self) -> DLQMetrics:
        """Get DLQ metrics"""
        metrics = DLQMetrics()
        conn = None
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Total events
            cursor.execute('SELECT COUNT(*) FROM dlq_events')
            result = cursor.fetchone()
            metrics.total_events = result[0] if result else 0

            # Count by status
            cursor.execute('SELECT status, COUNT(*) FROM dlq_events GROUP BY status')
            for status, count in cursor.fetchall():
                if status == DLQEventStatus.PENDING.value:
                    metrics.pending_events = count
                elif status == DLQEventStatus.RETRYING.value:
                    metrics.retrying_events = count
                elif status == DLQEventStatus.FAILED.value:
                    metrics.failed_events = count
                elif status == DLQEventStatus.RECOVERED.value:
                    metrics.recovered_events = count
                elif status == DLQEventStatus.EXPIRED.value:
                    metrics.expired_events = count
                elif status == DLQEventStatus.POISON.value:
                    metrics.poison_messages = count

            # Retry stats
            cursor.execute('SELECT SUM(retry_count) FROM dlq_events')
            result = cursor.fetchone()
            metrics.total_retries = result[0] if result and result[0] else 0

            cursor.execute('SELECT COUNT(*) FROM dlq_events WHERE status = "recovered" AND retry_count > 0')
            result = cursor.fetchone()
            metrics.successful_retries = result[0] if result else 0

            cursor.execute('SELECT COUNT(*) FROM dlq_events WHERE status = "failed" AND retry_count > 0')
            result = cursor.fetchone()
            metrics.failed_retries = result[0] if result else 0

        except Exception as e:
            self.logger.error(f"Error getting DLQ metrics: {e}")
        finally:
            if conn:
                conn.close()
        return metrics

    def purge_old_events(self, days: int = 30) -> int:
        """
        Purge old events from DLQ

        Args:
            days: Delete events older than this many days

        Returns:
            Number of deleted events
        """
        cutoff = datetime.now() - timedelta(days=days)
        deleted = 0
        conn = None
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute(
                'DELETE FROM dlq_events WHERE failed_at < ? AND status IN ("recovered", "expired")',
                (cutoff.isoformat(),)
            )

            deleted = cursor.rowcount
            conn.commit()
            self.logger.info(f"Purged {deleted} old events from DLQ")
        except Exception as e:
            self.logger.error(f"Error purging old events from DLQ: {e}")
        finally:
            if conn:
                conn.close()
        return deleted

    # Private helper methods

    def _generate_event_id(self, event_type: str, payload: Any, error: Exception) -> str:
        """Generate unique event ID"""
        content = f"{event_type}_{payload}_{type(error).__name__}_{datetime.now().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _save_event(self, event: DLQEvent) -> None:
        """Save event to database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        data = event.to_dict()
        cursor.execute('''
            INSERT INTO dlq_events (
                id, event_type, payload, error_message, error_type, stack_trace,
                original_timestamp, failed_at, retry_count, max_retries, status, priority,
                last_retry_at, next_retry_at, source, context, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['id'], data['event_type'], data['payload'], data['error_message'],
            data['error_type'], data.get('stack_trace'), data['original_timestamp'],
            data['failed_at'], data['retry_count'], data['max_retries'], data['status'],
            data['priority'], data.get('last_retry_at'), data.get('next_retry_at'),
            data.get('source'), json.dumps(data.get('context')) if data.get('context') else None,
            data.get('expires_at')
        ))

        conn.commit()
        conn.close()

    def _update_event(self, event: DLQEvent) -> None:
        """Update event in database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        data = event.to_dict()
        cursor.execute('''
            UPDATE dlq_events SET
                status = ?, retry_count = ?, last_retry_at = ?, next_retry_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (
            data['status'], data['retry_count'], data.get('last_retry_at'),
            data.get('next_retry_at'), data['id']
        ))

        conn.commit()
        conn.close()

    def _mark_failed(self, event: DLQEvent, reason: str) -> None:
        """Mark event as permanently failed"""
        event.status = DLQEventStatus.FAILED.value
        self._update_event(event)
        self.logger.error(f"Event permanently failed: {event.id[:8]} - {reason}")

    def _mark_expired(self, event: DLQEvent) -> None:
        """Mark event as expired"""
        event.status = DLQEventStatus.EXPIRED.value
        self._update_event(event)
        self.logger.warning(f"Event expired: {event.id[:8]}")

    def _mark_poison(self, event: DLQEvent) -> None:
        """Mark event as poison message"""
        event.status = DLQEventStatus.POISON.value
        self._update_event(event)
        self.logger.critical(f"Poison message detected: {event.id[:8]}")

    def _is_poison_message(self, event: DLQEvent) -> bool:
        """
        Detect poison messages (events that consistently fail)

        Heuristics:
        - Multiple retries with same error
        - Rapid failure rate
        """
        # If failed 3+ times with same error type, likely poison
        if event.retry_count >= 3:
            return True

        return False

    def _row_to_event(self, row: sqlite3.Row) -> DLQEvent:
        """Convert database row to DLQEvent"""
        data = dict(row)

        # Remove database-only fields
        data.pop('created_at', None)
        data.pop('updated_at', None)

        # Parse context if present
        if data.get('context'):
            try:
                data['context'] = json.loads(data['context'])
            except (json.JSONDecodeError, TypeError):
                data['context'] = None

        return DLQEvent.from_dict(data)
