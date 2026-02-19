"""
Real-Time Stream Processing Engine
Simulates Apache Flink/Spark Streaming capabilities for real-time data processing
Handles high-throughput event streams with windowing, aggregation, and pattern detection
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Callable, Optional
from collections import deque, defaultdict
from dataclasses import dataclass, field
import threading
from queue import Queue, Empty, Full
import json

@dataclass
class StreamEvent:
    """Represents a single event in the stream"""
    event_id: str
    timestamp: datetime
    event_type: str
    data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)

class StreamWindow:
    """
    Time-based or count-based window for stream aggregation
    """
    def __init__(self, window_type: str = "tumbling", size_seconds: int = 60):
        self.window_type = window_type  # tumbling, sliding, session
        self.size_seconds = size_seconds
        self.events = deque()
        self.start_time = datetime.utcnow()

    def add_event(self, event: StreamEvent):
        """Add event to window"""
        self.events.append(event)
        self._cleanup_expired()

    def _cleanup_expired(self):
        """Remove expired events from sliding window"""
        if self.window_type == "sliding":
            cutoff = datetime.utcnow() - timedelta(seconds=self.size_seconds)
            while self.events and self.events[0].timestamp < cutoff:
                self.events.popleft()

    def get_events(self) -> List[StreamEvent]:
        """Get all events in current window"""
        return list(self.events)

    def clear(self):
        """Clear window (for tumbling windows)"""
        self.events.clear()
        self.start_time = datetime.utcnow()

class StreamProcessor:
    """
    High-performance real-time stream processing engine
    Processes events with sub-second latency
    """

    def __init__(self,
                 buffer_size: int = 10000,
                 batch_size: int = 100,
                 window_size: int = 60):

        # Event buffers
        self.input_buffer = Queue(maxsize=buffer_size)
        self.output_buffer = Queue(maxsize=buffer_size)

        # Processing configuration
        self.batch_size = batch_size
        self.window_size = window_size

        # Thread safety locks
        self._metrics_lock = threading.Lock()
        self._windows_lock = threading.Lock()
        self._patterns_lock = threading.Lock()

        # Windows for aggregation
        self.windows = defaultdict(lambda: StreamWindow("tumbling", window_size))

        # Processors and filters
        self.processors: List[Callable] = []
        self.filters: List[Callable] = []
        self.aggregators: Dict[str, Callable] = {}

        # State management
        self.running = False
        self.worker_threads = []

        # Metrics
        self.metrics = {
            "events_processed": 0,
            "events_filtered": 0,
            "processing_latency_ms": deque(maxlen=1000),
            "throughput_events_per_sec": 0
        }

        # Pattern detection
        self.patterns = []

    def start(self, num_workers: int = 4):
        """
        Start stream processing with multiple worker threads

        Args:
            num_workers: Number of parallel processing threads
        """
        self.running = True

        # Start worker threads
        for i in range(num_workers):
            worker = threading.Thread(
                target=self._process_worker,
                name=f"StreamWorker-{i}",
                daemon=True
            )
            worker.start()
            self.worker_threads.append(worker)

        # Start metrics collector
        metrics_thread = threading.Thread(
            target=self._collect_metrics,
            daemon=True
        )
        metrics_thread.start()

    def stop(self):
        """Stop stream processing"""
        self.running = False
        for worker in self.worker_threads:
            worker.join(timeout=5)

    def ingest(self, event: StreamEvent):
        """
        Ingest event into stream (non-blocking)

        Args:
            event: StreamEvent to process
        """
        try:
            self.input_buffer.put_nowait(event)
        except Full:
            # Buffer full - drop event (backpressure)
            with self._metrics_lock:
                self.metrics["events_filtered"] += 1
        except Exception as e:
            # Log unexpected errors
            print(f"Stream ingest error: {e}")

    def add_processor(self, processor: Callable[[StreamEvent], StreamEvent]):
        """
        Add event processor to pipeline

        Args:
            processor: Function that transforms events
        """
        self.processors.append(processor)

    def add_filter(self, filter_func: Callable[[StreamEvent], bool]):
        """
        Add filter to pipeline

        Args:
            filter_func: Function that returns True to keep event
        """
        self.filters.append(filter_func)

    def add_aggregator(self, key: str, aggregator: Callable[[List[StreamEvent]], Any]):
        """
        Add aggregation function for windowed computation

        Args:
            key: Aggregation key
            aggregator: Function that aggregates window events
        """
        self.aggregators[key] = aggregator

    def add_pattern(self, pattern_name: str, pattern_func: Callable[[List[StreamEvent]], bool]):
        """
        Add pattern detection rule

        Args:
            pattern_name: Name of the pattern
            pattern_func: Function that detects pattern in event sequence
        """
        self.patterns.append({
            "name": pattern_name,
            "func": pattern_func,
            "matches": []
        })

    def _process_worker(self):
        """Worker thread for processing events"""
        batch = []

        while self.running:
            try:
                # Collect batch
                while len(batch) < self.batch_size:
                    try:
                        event = self.input_buffer.get(timeout=0.1)
                        batch.append(event)
                    except Empty:
                        break

                if not batch:
                    continue

                # Process batch
                for event in batch:
                    start_time = time.time()

                    # Apply filters
                    if not self._apply_filters(event):
                        with self._metrics_lock:
                            self.metrics["events_filtered"] += 1
                        continue

                    # Apply processors
                    processed_event = self._apply_processors(event)

                    # Add to windows (thread-safe)
                    self._add_to_windows(processed_event)

                    # Check patterns (thread-safe)
                    self._check_patterns(processed_event)

                    # Output
                    self.output_buffer.put(processed_event)

                    # Update metrics (thread-safe)
                    latency = (time.time() - start_time) * 1000
                    with self._metrics_lock:
                        self.metrics["processing_latency_ms"].append(latency)
                        self.metrics["events_processed"] += 1

                batch.clear()

            except Exception as e:
                print(f"Stream processing error: {e}")

    def _apply_filters(self, event: StreamEvent) -> bool:
        """Apply all filters to event"""
        for filter_func in self.filters:
            if not filter_func(event):
                return False
        return True

    def _apply_processors(self, event: StreamEvent) -> StreamEvent:
        """Apply all processors to event"""
        for processor in self.processors:
            event = processor(event)
        return event

    def _add_to_windows(self, event: StreamEvent):
        """Add event to appropriate windows (thread-safe)"""
        with self._windows_lock:
            # Add to default window
            self.windows["default"].add_event(event)

            # Add to type-specific window
            window_key = event.event_type
            self.windows[window_key].add_event(event)

    def _check_patterns(self, event: StreamEvent):
        """Check for pattern matches (thread-safe)"""
        with self._windows_lock:
            recent_events = list(self.windows["default"].events)[-10:]

        with self._patterns_lock:
            for pattern in self.patterns:
                if pattern["func"](recent_events):
                    pattern["matches"].append({
                        "timestamp": datetime.utcnow(),
                        "events": [e.event_id for e in recent_events]
                    })

    def _collect_metrics(self):
        """Collect throughput metrics (thread-safe)"""
        last_count = 0

        while self.running:
            time.sleep(1)

            with self._metrics_lock:
                current_count = self.metrics["events_processed"]
                self.metrics["throughput_events_per_sec"] = current_count - last_count
            last_count = current_count

    def get_windowed_aggregate(self, window_key: str = "default", aggregator_key: str = None) -> Any:
        """
        Get aggregated result from window (thread-safe)

        Args:
            window_key: Window identifier
            aggregator_key: Aggregator function key

        Returns:
            Aggregated result
        """
        with self._windows_lock:
            window = self.windows.get(window_key)
            if not window:
                return None

            events = window.get_events()

        if aggregator_key and aggregator_key in self.aggregators:
            return self.aggregators[aggregator_key](events)

        # Default aggregation: count
        return len(events)

    def get_metrics(self) -> Dict[str, Any]:
        """Get current processing metrics (thread-safe)"""
        with self._metrics_lock:
            latencies = list(self.metrics["processing_latency_ms"])
            events_processed = self.metrics["events_processed"]
            events_filtered = self.metrics["events_filtered"]
            throughput = self.metrics["throughput_events_per_sec"]

        # Calculate p95 safely - need at least 1 element
        p95_latency = 0
        if latencies:
            sorted_latencies = sorted(latencies)
            p95_index = min(int(len(latencies) * 0.95), len(latencies) - 1)
            p95_latency = sorted_latencies[p95_index]

        with self._windows_lock:
            active_windows = len(self.windows)

        return {
            "events_processed": events_processed,
            "events_filtered": events_filtered,
            "throughput_eps": throughput,
            "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0,
            "p95_latency_ms": p95_latency,
            "buffer_utilization": {
                "input": self.input_buffer.qsize() / self.input_buffer.maxsize * 100,
                "output": self.output_buffer.qsize() / self.output_buffer.maxsize * 100
            },
            "active_windows": active_windows
        }

    def get_pattern_matches(self) -> List[Dict[str, Any]]:
        """Get detected patterns (thread-safe)"""
        results = []
        with self._patterns_lock:
            for pattern in self.patterns:
                results.append({
                    "pattern_name": pattern["name"],
                    "match_count": len(pattern["matches"]),
                    "recent_matches": pattern["matches"][-10:]
                })
        return results

    async def process_stream_async(self, event_generator):
        """
        Async stream processing for high-throughput scenarios

        Args:
            event_generator: Async generator yielding events
        """
        async for event in event_generator:
            self.ingest(event)
            await asyncio.sleep(0)  # Yield control

# Example usage and convenience functions
class AttackStreamProcessor(StreamProcessor):
    """
    Specialized stream processor for attack events
    """

    def __init__(self):
        super().__init__(window_size=300)  # 5-minute windows

        # Add default attack processors
        self.add_processor(self._enrich_attack_event)
        self.add_filter(self._filter_low_severity)

        # Add aggregators
        self.add_aggregator("attack_count", lambda events: len(events))
        self.add_aggregator("unique_ips", lambda events: len(set(e.data.get("ip") for e in events)))
        self.add_aggregator("avg_severity", lambda events:
            sum(e.data.get("severity", 0) for e in events) / len(events) if events else 0)

        # Add attack patterns
        self.add_pattern("brute_force_burst", self._detect_brute_force)
        self.add_pattern("distributed_attack", self._detect_distributed_attack)

    def _enrich_attack_event(self, event: StreamEvent) -> StreamEvent:
        """Enrich attack event with additional data"""
        # Add hour of day
        event.metadata["hour"] = event.timestamp.hour

        # Add day of week
        event.metadata["day_of_week"] = event.timestamp.strftime("%A")

        # Calculate time since last event
        # (In real implementation, would use state store)

        return event

    def _filter_low_severity(self, event: StreamEvent) -> bool:
        """Filter out low-severity events"""
        # Safely handle None event.data
        data = event.data or {}
        return data.get("severity", 0) >= 3

    def _detect_brute_force(self, events: List[StreamEvent]) -> bool:
        """Detect brute force attack pattern"""
        if len(events) < 5:
            return False

        # Check for multiple failed auth attempts from same IP
        recent = events[-10:]
        auth_events = [e for e in recent if e.event_type == "authentication_failure"]

        if len(auth_events) >= 5:
            # Check if from same IP
            ips = [e.data.get("ip") for e in auth_events]
            if len(set(ips)) == 1:
                return True

        return False

    def _detect_distributed_attack(self, events: List[StreamEvent]) -> bool:
        """Detect distributed attack (multiple IPs, same target)"""
        if len(events) < 10:
            return False

        recent = events[-20:]

        # Get unique source IPs and target IPs
        source_ips = set(e.data.get("source_ip") for e in recent)
        target_ips = set(e.data.get("target_ip") for e in recent)

        # Distributed attack: many sources, few targets
        if len(source_ips) >= 5 and len(target_ips) <= 2:
            return True

        return False

    def get_attack_summary(self) -> Dict[str, Any]:
        """Get real-time attack summary"""
        return {
            "total_attacks": self.get_windowed_aggregate("default", "attack_count"),
            "unique_attackers": self.get_windowed_aggregate("default", "unique_ips"),
            "average_severity": self.get_windowed_aggregate("default", "avg_severity"),
            "detected_patterns": self.get_pattern_matches(),
            "metrics": self.get_metrics()
        }
