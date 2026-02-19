"""
Complex Event Processing (CEP) Engine
Rule-based event correlation and pattern matching
Detects complex attack patterns across multiple events
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass
from collections import deque
from enum import Enum
import re

class RuleOperator(Enum):
    """CEP rule operators"""
    AND = "AND"
    OR = "OR"
    THEN = "THEN"  # Sequence
    WITHIN = "WITHIN"  # Time window
    COUNT = "COUNT"
    NOT = "NOT"

@dataclass
class CEPRule:
    """Complex Event Processing Rule"""
    rule_id: str
    name: str
    description: str
    conditions: List[Dict[str, Any]]
    time_window_seconds: int = 300  # 5 minutes default
    severity: str = "medium"
    actions: List[str] = None
    enabled: bool = True

@dataclass
class CEPMatch:
    """Detected pattern match"""
    rule_id: str
    rule_name: str
    matched_events: List[Any]
    timestamp: datetime
    severity: str
    confidence: float
    metadata: Dict[str, Any] = None

class CEPEngine:
    """
    Complex Event Processing Engine
    Correlates events to detect sophisticated attack patterns
    """

    def __init__(self, max_event_history: int = 10000):
        self.rules: Dict[str, CEPRule] = {}
        self.event_history = deque(maxlen=max_event_history)
        self.matches: List[CEPMatch] = []

        # Performance metrics
        self.metrics = {
            "rules_evaluated": 0,
            "matches_found": 0,
            "events_processed": 0
        }

        # Register default security rules
        self._register_default_rules()

    def add_rule(self, rule: CEPRule):
        """
        Add CEP rule

        Args:
            rule: CEPRule object
        """
        self.rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str):
        """Remove rule"""
        if rule_id in self.rules:
            del self.rules[rule_id]

    def process_event(self, event: Dict[str, Any]) -> List[CEPMatch]:
        """
        Process incoming event against all rules

        Args:
            event: Event dictionary

        Returns:
            List of matched patterns
        """
        # Add to history
        self.event_history.append({
            **event,
            "processed_at": datetime.utcnow()
        })

        self.metrics["events_processed"] += 1

        # Evaluate all enabled rules
        new_matches = []

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            self.metrics["rules_evaluated"] += 1

            # Check if rule matches
            match = self._evaluate_rule(rule, event)

            if match:
                self.matches.append(match)
                new_matches.append(match)
                self.metrics["matches_found"] += 1

        return new_matches

    def _evaluate_rule(self, rule: CEPRule, current_event: Dict[str, Any]) -> Optional[CEPMatch]:
        """
        Evaluate rule against event history

        Args:
            rule: CEP rule to evaluate
            current_event: Most recent event

        Returns:
            CEPMatch if pattern detected, None otherwise
        """
        # Get events within time window
        cutoff_time = datetime.utcnow() - timedelta(seconds=rule.time_window_seconds)
        recent_events = [
            e for e in self.event_history
            if e.get("timestamp", e.get("processed_at")) > cutoff_time
        ]

        # Evaluate conditions
        matched_events = []

        for condition in rule.conditions:
            operator = condition.get("operator", "AND")

            if operator == "SEQUENCE":
                # Check for event sequence
                if self._check_sequence(condition, recent_events):
                    matched_events.extend(recent_events)
            elif operator == "COUNT":
                # Check for event count threshold
                if self._check_count(condition, recent_events):
                    matched_events.extend(recent_events)
            elif operator == "PATTERN":
                # Check for pattern match
                pattern_events = self._check_pattern(condition, recent_events)
                if pattern_events:
                    matched_events.extend(pattern_events)
            else:
                # Simple condition check
                if self._check_condition(condition, current_event):
                    matched_events.append(current_event)

        # If we have matches, create CEPMatch
        if matched_events:
            confidence = self._calculate_confidence(rule, matched_events)

            return CEPMatch(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                matched_events=matched_events,
                timestamp=datetime.utcnow(),
                severity=rule.severity,
                confidence=confidence,
                metadata={
                    "description": rule.description,
                    "event_count": len(matched_events),
                    "time_span_seconds": (
                        (matched_events[-1] or {}).get("timestamp", datetime.utcnow()) -
                        (matched_events[0] or {}).get("timestamp", datetime.utcnow())
                    ).total_seconds() if len(matched_events) > 1 else 0
                }
            )

        return None

    def _check_condition(self, condition: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Check if event matches condition"""
        field = condition.get("field")
        value = condition.get("value")
        operator = condition.get("op", "equals")

        event_value = event.get(field)

        if operator == "equals":
            return event_value == value
        elif operator == "contains":
            return value in str(event_value)
        elif operator == "gt":
            return event_value > value
        elif operator == "lt":
            return event_value < value
        elif operator == "in":
            return event_value in value
        elif operator == "regex":
            return re.match(value, str(event_value)) is not None

        return False

    def _check_sequence(self, condition: Dict[str, Any], events: List[Dict]) -> bool:
        """Check for event sequence"""
        sequence = condition.get("sequence", [])

        if len(events) < len(sequence):
            return False

        # Look for sequence pattern
        for i in range(len(events) - len(sequence) + 1):
            matches = True

            for j, seq_condition in enumerate(sequence):
                if not self._check_condition(seq_condition, events[i + j]):
                    matches = False
                    break

            if matches:
                return True

        return False

    def _check_count(self, condition: Dict[str, Any], events: List[Dict]) -> bool:
        """Check if event count meets threshold"""
        field = condition.get("field")
        threshold = condition.get("threshold")
        value = condition.get("value")

        # Count events matching value
        count = sum(1 for e in events if e.get(field) == value)

        return count >= threshold

    def _check_pattern(self, condition: Dict[str, Any], events: List[Dict]) -> List[Dict]:
        """Check for complex pattern"""
        pattern_type = condition.get("pattern_type")

        if pattern_type == "escalation":
            return self._detect_escalation(events)
        elif pattern_type == "spike":
            return self._detect_spike(events)
        elif pattern_type == "correlation":
            return self._detect_correlation(condition, events)

        return []

    def _detect_escalation(self, events: List[Dict]) -> List[Dict]:
        """Detect privilege escalation pattern"""
        # Look for increasing privilege levels
        priv_events = [e for e in events if "privilege_level" in e]

        if len(priv_events) >= 3:
            # Check if privilege levels are increasing
            levels = [e["privilege_level"] for e in priv_events]
            if levels == sorted(levels):
                return priv_events

        return []

    def _detect_spike(self, events: List[Dict]) -> List[Dict]:
        """Detect sudden spike in activity"""
        if len(events) < 10:
            return []

        # Calculate baseline and recent rate
        half = len(events) // 2
        baseline_rate = half
        recent_rate = len(events) - half

        # Spike if recent rate is 3x baseline
        if recent_rate > baseline_rate * 3:
            return events[half:]

        return []

    def _detect_correlation(self, condition: Dict, events: List[Dict]) -> List[Dict]:
        """Detect correlated events"""
        fields = condition.get("fields", [])

        if not fields:
            return []

        # Group events by correlation fields
        groups = {}

        for event in events:
            key = tuple(event.get(f) for f in fields)
            if key not in groups:
                groups[key] = []
            groups[key].append(event)

        # Return largest group if it meets threshold
        threshold = condition.get("threshold", 3)
        largest_group = max(groups.values(), key=len, default=[])

        return largest_group if len(largest_group) >= threshold else []

    def _calculate_confidence(self, rule: CEPRule, matched_events: List[Dict]) -> float:
        """Calculate confidence score for match"""
        # Base confidence
        confidence = 0.5

        # More events = higher confidence
        event_factor = min(len(matched_events) / 10.0, 0.3)
        confidence += event_factor

        # Recent events = higher confidence
        if matched_events:
            latest = matched_events[-1].get("timestamp", datetime.utcnow())
            recency = (datetime.utcnow() - latest).total_seconds()

            if recency < 60:  # Within 1 minute
                confidence += 0.2

        return min(confidence, 1.0)

    def _register_default_rules(self):
        """Register default security detection rules"""

        # Rule 1: Brute Force Attack
        self.add_rule(CEPRule(
            rule_id="SEC-001",
            name="Brute Force Attack",
            description="Multiple failed login attempts from same IP",
            conditions=[{
                "operator": "COUNT",
                "field": "event_type",
                "value": "authentication_failure",
                "threshold": 5
            }],
            time_window_seconds=300,
            severity="high",
            actions=["block_ip", "alert_soc"]
        ))

        # Rule 2: SQL Injection Campaign
        self.add_rule(CEPRule(
            rule_id="SEC-002",
            name="SQL Injection Campaign",
            description="Multiple SQL injection attempts",
            conditions=[{
                "operator": "COUNT",
                "field": "attack_type",
                "value": "SQL_INJECTION",
                "threshold": 10
            }],
            time_window_seconds=600,
            severity="critical",
            actions=["block_ip", "alert_soc", "create_incident"]
        ))

        # Rule 3: Privilege Escalation
        self.add_rule(CEPRule(
            rule_id="SEC-003",
            name="Privilege Escalation Attempt",
            description="Progressive increase in access privileges",
            conditions=[{
                "operator": "PATTERN",
                "pattern_type": "escalation"
            }],
            time_window_seconds=1800,
            severity="critical",
            actions=["alert_soc", "lock_account"]
        ))

        # Rule 4: Port Scanning
        self.add_rule(CEPRule(
            rule_id="SEC-004",
            name="Port Scanning Detected",
            description="Multiple connection attempts to different ports",
            conditions=[{
                "operator": "COUNT",
                "field": "event_type",
                "value": "connection_attempt",
                "threshold": 20
            }],
            time_window_seconds=60,
            severity="medium",
            actions=["alert_soc"]
        ))

        # Rule 5: Data Exfiltration
        self.add_rule(CEPRule(
            rule_id="SEC-005",
            name="Potential Data Exfiltration",
            description="Large data transfer to external IP",
            conditions=[{
                "field": "bytes_transferred",
                "op": "gt",
                "value": 100000000  # 100MB
            }, {
                "field": "destination_type",
                "op": "equals",
                "value": "external"
            }],
            time_window_seconds=300,
            severity="critical",
            actions=["block_ip", "alert_soc", "create_incident"]
        ))

    def get_matches(self, severity: str = None, hours: int = 24) -> List[CEPMatch]:
        """
        Get detected pattern matches

        Args:
            severity: Filter by severity (critical, high, medium, low)
            hours: Look back hours

        Returns:
            List of matches
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        matches = [
            m for m in self.matches
            if m.timestamp > cutoff
        ]

        if severity:
            matches = [m for m in matches if m.severity == severity]

        return matches

    def get_metrics(self) -> Dict[str, Any]:
        """Get CEP engine metrics"""
        return {
            **self.metrics,
            "active_rules": len([r for r in self.rules.values() if r.enabled]),
            "total_rules": len(self.rules),
            "event_history_size": len(self.event_history),
            "total_matches": len(self.matches),
            "critical_matches": len([m for m in self.matches if m.severity == "critical"]),
            "high_matches": len([m for m in self.matches if m.severity == "high"])
        }

    def export_matches(self, format: str = "json") -> str:
        """Export matches in specified format"""
        if format == "json":
            import json
            return json.dumps([{
                "rule_id": m.rule_id,
                "rule_name": m.rule_name,
                "timestamp": m.timestamp.isoformat(),
                "severity": m.severity,
                "confidence": m.confidence,
                "event_count": len(m.matched_events),
                "metadata": m.metadata
            } for m in self.matches], indent=2)

        return ""
