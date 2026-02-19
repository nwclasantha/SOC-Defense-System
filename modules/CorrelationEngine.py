"""
Correlation Analysis Engine
Advanced correlation detection between security events
Identifies related attacks, coordinated campaigns, and causal relationships
"""

import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
from collections import defaultdict, Counter
from dataclasses import dataclass
from scipy import stats
from scipy.spatial.distance import cosine, euclidean
import itertools

@dataclass
class CorrelationResult:
    """Correlation analysis result"""
    entity1: str
    entity2: str
    correlation_score: float
    correlation_type: str
    confidence: float
    evidence: List[Dict[str, Any]]
    temporal_relationship: str
    statistical_significance: float

class CorrelationEngine:
    """
    Advanced correlation engine for security events
    Detects relationships between attacks, attackers, and patterns
    """

    def __init__(self):
        self.events = []
        self.correlation_cache = {}
        self.correlation_history = []

    def add_event(self, event: Dict[str, Any]):
        """
        Add event for correlation analysis

        Args:
            event: Event dictionary with timestamp, type, source, target, etc.
        """
        self.events.append(event)

        # Keep only recent events (last 24 hours)
        cutoff = datetime.utcnow() - timedelta(hours=24)
        self.events = [e for e in self.events if e.get("timestamp", datetime.utcnow()) > cutoff]

    def correlate_by_ip(self, time_window_seconds: int = 300) -> List[CorrelationResult]:
        """
        Find correlations between events from same IP addresses

        Args:
            time_window_seconds: Time window for correlation

        Returns:
            List of correlation results
        """
        correlations = []

        # Group events by source IP
        ip_events = defaultdict(list)
        for event in self.events:
            source_ip = event.get("source_ip")
            if source_ip:
                ip_events[source_ip].append(event)

        # Analyze each IP's events
        for ip, events in ip_events.items():
            if len(events) < 2:
                continue

            # Sort by time
            events = sorted(events, key=lambda e: e.get("timestamp", datetime.utcnow()))

            # Find temporal patterns
            attack_types = [e.get("attack_type") for e in events]
            type_counts = Counter(attack_types)

            # Check for progression (attack chain)
            is_progressive = self._detect_attack_progression(events)

            if is_progressive:
                correlations.append(CorrelationResult(
                    entity1=ip,
                    entity2="attack_chain",
                    correlation_score=0.9,
                    correlation_type="temporal_progression",
                    confidence=0.85,
                    evidence=[{
                        "type": "attack_sequence",
                        "events": len(events),
                        "attack_types": list(type_counts.keys())
                    }],
                    temporal_relationship="sequential",
                    statistical_significance=0.01
                ))

        return correlations

    def correlate_by_target(self, min_attackers: int = 3) -> List[CorrelationResult]:
        """
        Find coordinated attacks targeting same entity

        Args:
            min_attackers: Minimum number of attackers for correlation

        Returns:
            List of correlation results
        """
        correlations = []

        # Group by target
        target_events = defaultdict(list)
        for event in self.events:
            target = event.get("target_ip") or event.get("target_host")
            if target:
                target_events[target].append(event)

        # Find coordinated attacks
        for target, events in target_events.items():
            source_ips = set(e.get("source_ip") for e in events)

            if len(source_ips) >= min_attackers:
                # Check temporal clustering
                timestamps = [e.get("timestamp", datetime.utcnow()) for e in events]
                # Skip if no timestamps (avoid ValueError on empty list)
                if not timestamps:
                    continue
                time_span = (max(timestamps) - min(timestamps)).total_seconds()

                # Coordinated if within short time window
                if time_span < 600:  # 10 minutes
                    correlation_score = min(len(source_ips) / 10, 1.0)

                    correlations.append(CorrelationResult(
                        entity1=target,
                        entity2="coordinated_attack",
                        correlation_score=correlation_score,
                        correlation_type="coordinated_targeting",
                        confidence=0.8,
                        evidence=[{
                            "type": "multiple_sources",
                            "attacker_count": len(source_ips),
                            "time_span_seconds": time_span,
                            "attack_count": len(events)
                        }],
                        temporal_relationship="concurrent",
                        statistical_significance=0.05
                    ))

        return correlations

    def correlate_by_pattern(self) -> List[CorrelationResult]:
        """
        Find correlations based on attack patterns and techniques

        Returns:
            List of correlation results
        """
        correlations = []

        # Group by attack pattern
        pattern_groups = defaultdict(list)

        for event in self.events:
            # Extract pattern signature
            signature = self._extract_pattern_signature(event)
            pattern_groups[signature].append(event)

        # Analyze patterns
        for signature, events in pattern_groups.items():
            if len(events) < 3:
                continue

            # Get unique sources
            sources = set(e.get("source_ip") for e in events)

            if len(sources) > 1:
                # Same pattern, different sources = campaign
                correlations.append(CorrelationResult(
                    entity1=signature,
                    entity2="attack_campaign",
                    correlation_score=0.85,
                    correlation_type="pattern_similarity",
                    confidence=0.75,
                    evidence=[{
                        "type": "shared_pattern",
                        "pattern": signature,
                        "source_count": len(sources),
                        "event_count": len(events)
                    }],
                    temporal_relationship="distributed",
                    statistical_significance=0.01
                ))

        return correlations

    def correlate_by_behavior(self) -> List[CorrelationResult]:
        """
        Correlate events based on behavioral similarity

        Returns:
            List of correlation results
        """
        correlations = []

        # Group events by source IP
        ip_behaviors = defaultdict(list)

        for event in self.events:
            source_ip = event.get("source_ip")
            if source_ip:
                behavior = self._extract_behavior_vector(event)
                ip_behaviors[source_ip].append(behavior)

        # Compare behaviors between IPs
        ips = list(ip_behaviors.keys())

        for i in range(len(ips)):
            for j in range(i + 1, len(ips)):
                ip1, ip2 = ips[i], ips[j]

                # Calculate behavioral similarity
                similarity = self._calculate_behavioral_similarity(
                    ip_behaviors[ip1],
                    ip_behaviors[ip2]
                )

                if similarity > 0.7:  # High similarity
                    correlations.append(CorrelationResult(
                        entity1=ip1,
                        entity2=ip2,
                        correlation_score=similarity,
                        correlation_type="behavioral_similarity",
                        confidence=0.7,
                        evidence=[{
                            "type": "similar_behavior",
                            "similarity_score": similarity
                        }],
                        temporal_relationship="independent",
                        statistical_significance=0.05
                    ))

        return correlations

    def detect_causal_relationships(self) -> List[CorrelationResult]:
        """
        Detect potential causal relationships between events

        Returns:
            List of correlation results with causal links
        """
        correlations = []

        # Sort events chronologically
        sorted_events = sorted(self.events, key=lambda e: e.get("timestamp", datetime.utcnow()))

        # Look for cause-effect patterns
        for i in range(len(sorted_events) - 1):
            event1 = sorted_events[i]

            for j in range(i + 1, min(i + 10, len(sorted_events))):
                event2 = sorted_events[j]

                # Check temporal proximity
                time_diff = (event2.get("timestamp", datetime.utcnow()) -
                           event1.get("timestamp", datetime.utcnow())).total_seconds()

                if time_diff > 300:  # More than 5 minutes
                    break

                # Check for causal patterns
                causal_score = self._assess_causality(event1, event2)

                if causal_score > 0.6:
                    correlations.append(CorrelationResult(
                        entity1=f"{event1.get('event_type')}_{event1.get('source_ip')}",
                        entity2=f"{event2.get('event_type')}_{event2.get('source_ip')}",
                        correlation_score=causal_score,
                        correlation_type="causal",
                        confidence=0.65,
                        evidence=[{
                            "type": "causal_link",
                            "time_difference": time_diff,
                            "event1_type": event1.get("event_type"),
                            "event2_type": event2.get("event_type")
                        }],
                        temporal_relationship="causal",
                        statistical_significance=0.1
                    ))

        return correlations

    def correlate_statistical(self,
                             field1: str,
                             field2: str,
                             method: str = "pearson") -> Optional[CorrelationResult]:
        """
        Statistical correlation between two event fields

        Args:
            field1: First field name
            field2: Second field name
            method: pearson, spearman, or kendall

        Returns:
            Correlation result
        """
        # Extract field values
        values1 = []
        values2 = []

        for event in self.events:
            v1 = event.get(field1)
            v2 = event.get(field2)

            if v1 is not None and v2 is not None:
                try:
                    values1.append(float(v1))
                    values2.append(float(v2))
                except (ValueError, TypeError):
                    continue

        if len(values1) < 3:
            return None

        # Calculate correlation
        if method == "pearson":
            corr, p_value = stats.pearsonr(values1, values2)
        elif method == "spearman":
            corr, p_value = stats.spearmanr(values1, values2)
        elif method == "kendall":
            corr, p_value = stats.kendalltau(values1, values2)
        else:
            return None

        return CorrelationResult(
            entity1=field1,
            entity2=field2,
            correlation_score=abs(corr),
            correlation_type=f"statistical_{method}",
            confidence=1 - p_value,
            evidence=[{
                "type": "statistical",
                "correlation": corr,
                "p_value": p_value,
                "sample_size": len(values1)
            }],
            temporal_relationship="statistical",
            statistical_significance=p_value
        )

    def find_all_correlations(self, min_confidence: float = 0.6) -> List[CorrelationResult]:
        """
        Run all correlation analyses

        Args:
            min_confidence: Minimum confidence threshold

        Returns:
            Combined list of all correlations
        """
        all_correlations = []

        # Run all correlation methods
        all_correlations.extend(self.correlate_by_ip())
        all_correlations.extend(self.correlate_by_target())
        all_correlations.extend(self.correlate_by_pattern())
        all_correlations.extend(self.correlate_by_behavior())
        all_correlations.extend(self.detect_causal_relationships())

        # Filter by confidence
        filtered = [c for c in all_correlations if c.confidence >= min_confidence]

        # Store in history
        self.correlation_history.extend(filtered)

        return filtered

    def _detect_attack_progression(self, events: List[Dict]) -> bool:
        """Detect if events show attack progression"""
        if len(events) < 2:
            return False

        # Known attack progressions
        progressions = [
            ["reconnaissance", "scanning", "exploitation"],
            ["brute_force", "authentication_success", "lateral_movement"],
            ["sql_injection", "command_injection", "data_exfiltration"],
            ["xss", "csrf", "session_hijacking"]
        ]

        attack_types = [e.get("attack_type", "").lower() for e in events]

        # Check if events match any progression
        for progression in progressions:
            matched = 0
            for attack_type in attack_types:
                for stage in progression:
                    if stage in attack_type:
                        matched += 1
                        break

            if matched >= 2:
                return True

        return False

    def _extract_pattern_signature(self, event: Dict[str, Any]) -> str:
        """Extract pattern signature from event"""
        attack_type = event.get("attack_type", "unknown")
        technique = event.get("technique", "")
        protocol = event.get("protocol", "")

        return f"{attack_type}_{technique}_{protocol}"

    def _extract_behavior_vector(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract behavioral feature vector from event"""
        features = [
            hash(event.get("attack_type", "")) % 1000 / 1000.0,
            event.get("severity", 0) / 10.0,
            event.get("port", 0) / 65535.0,
            len(event.get("payload", "")) / 1000.0,
            event.get("hour", 12) / 24.0
        ]

        return np.array(features)

    def _calculate_behavioral_similarity(self,
                                        behaviors1: List[np.ndarray],
                                        behaviors2: List[np.ndarray]) -> float:
        """Calculate behavioral similarity between two sets of behaviors"""
        if not behaviors1 or not behaviors2:
            return 0.0

        # Average behavior vectors
        avg1 = np.mean(behaviors1, axis=0)
        avg2 = np.mean(behaviors2, axis=0)

        # Cosine similarity
        similarity = 1 - cosine(avg1, avg2)

        return max(0, similarity)

    def _assess_causality(self, event1: Dict, event2: Dict) -> float:
        """Assess if event1 might have caused event2"""
        causal_score = 0.0

        # Same source IP = higher causality
        if event1.get("source_ip") == event2.get("source_ip"):
            causal_score += 0.3

        # Known causal patterns
        causal_pairs = [
            ("reconnaissance", "exploitation"),
            ("brute_force", "authentication_success"),
            ("sql_injection", "data_exfiltration"),
            ("privilege_escalation", "lateral_movement")
        ]

        type1 = event1.get("attack_type", "").lower()
        type2 = event2.get("attack_type", "").lower()

        for cause, effect in causal_pairs:
            if cause in type1 and effect in type2:
                causal_score += 0.5

        # Same target = higher causality
        if event1.get("target_ip") == event2.get("target_ip"):
            causal_score += 0.2

        return min(causal_score, 1.0)

    def get_correlation_summary(self) -> Dict[str, Any]:
        """Get summary of correlation analysis"""
        correlations = self.find_all_correlations()

        # Group by type
        type_counts = Counter(c.correlation_type for c in correlations)

        # Calculate average confidence
        avg_confidence = np.mean([c.confidence for c in correlations]) if correlations else 0

        return {
            "total_correlations": len(correlations),
            "by_type": dict(type_counts),
            "average_confidence": float(avg_confidence),
            "high_confidence_count": len([c for c in correlations if c.confidence > 0.8]),
            "causal_relationships": len([c for c in correlations if c.correlation_type == "causal"]),
            "coordinated_attacks": len([c for c in correlations if "coordinated" in c.correlation_type])
        }

    def export_correlation_graph(self) -> Dict[str, Any]:
        """Export correlations as graph structure"""
        correlations = self.find_all_correlations()

        nodes = set()
        edges = []

        for corr in correlations:
            nodes.add(corr.entity1)
            nodes.add(corr.entity2)

            edges.append({
                "source": corr.entity1,
                "target": corr.entity2,
                "weight": corr.correlation_score,
                "type": corr.correlation_type,
                "confidence": corr.confidence
            })

        return {
            "nodes": [{"id": node} for node in nodes],
            "edges": edges,
            "metadata": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "generated_at": datetime.utcnow().isoformat()
            }
        }
