"""
Attack Chain Reconstruction Engine
Reconstructs multi-stage attack sequences using graph algorithms
Maps attacks to MITRE ATT&CK kill chain phases
"""

import networkx as nx
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Set
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum

class KillChainPhase(Enum):
    """MITRE ATT&CK Kill Chain Phases"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

@dataclass
class AttackNode:
    """Node in attack chain"""
    node_id: str
    timestamp: datetime
    event_type: str
    source_ip: str
    target_ip: str
    kill_chain_phase: KillChainPhase
    technique: str
    severity: int
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AttackChain:
    """Reconstructed attack chain"""
    chain_id: str
    attacker_ip: str
    target_ip: str
    start_time: datetime
    end_time: datetime
    nodes: List[AttackNode]
    edges: List[Tuple[str, str]]
    kill_chain_phases: List[KillChainPhase]
    severity_score: float
    confidence: float
    is_complete: bool

class AttackChainReconstructor:
    """
    Reconstructs complete attack chains from individual events
    Uses graph algorithms and temporal analysis
    """

    def __init__(self, time_window_hours: int = 24):
        self.events = []
        self.chains = []
        self.time_window = timedelta(hours=time_window_hours)

        # Attack type to kill chain phase mapping
        self.attack_phase_map = self._init_phase_mapping()

        # Graph for relationship tracking
        self.attack_graph = nx.DiGraph()

    def add_event(self, event: Dict[str, Any]):
        """
        Add event for chain reconstruction

        Args:
            event: Security event dictionary
        """
        self.events.append(event)

        # Clean old events
        cutoff = datetime.utcnow() - self.time_window
        # Strip timezone info for comparison
        cutoff_naive = cutoff.replace(tzinfo=None) if cutoff.tzinfo else cutoff

        # Filter events safely with proper None handling
        filtered_events = []
        for e in self.events:
            ts = e.get("timestamp")
            if ts is None:
                ts = datetime.utcnow()
            # Strip timezone if present
            ts_naive = ts.replace(tzinfo=None) if hasattr(ts, 'tzinfo') and ts.tzinfo else ts
            if ts_naive > cutoff_naive:
                filtered_events.append(e)
        self.events = filtered_events

    def reconstruct_chains(self, min_chain_length: int = 2) -> List[AttackChain]:
        """
        Reconstruct attack chains from events

        Args:
            min_chain_length: Minimum events to form a chain

        Returns:
            List of reconstructed attack chains
        """
        # Build attack graph
        self._build_attack_graph()

        # Find connected attack sequences
        chains = []

        # Group events by attacker IP
        attacker_events = defaultdict(list)
        for event in self.events:
            source_ip = event.get("source_ip")
            if source_ip:
                attacker_events[source_ip].append(event)

        # Reconstruct chain for each attacker
        for attacker_ip, events in attacker_events.items():
            if len(events) < min_chain_length:
                continue

            # Sort by timestamp
            events = sorted(events, key=lambda e: e.get("timestamp", datetime.utcnow()))

            # Create nodes
            nodes = []
            for event in events:
                node = self._event_to_node(event)
                nodes.append(node)

            # Find edges (causal relationships)
            edges = self._find_edges(nodes)

            if len(nodes) >= min_chain_length:
                # Extract kill chain phases
                phases = [node.kill_chain_phase for node in nodes]
                unique_phases = list(dict.fromkeys(phases))  # Preserve order

                # Calculate severity
                severity = self._calculate_chain_severity(nodes)

                # Calculate confidence
                confidence = self._calculate_chain_confidence(nodes, edges)

                # Check if chain is complete
                is_complete = self._is_chain_complete(unique_phases)

                chain = AttackChain(
                    chain_id=f"chain_{attacker_ip}_{datetime.utcnow().timestamp()}",
                    attacker_ip=attacker_ip,
                    target_ip=nodes[0].target_ip if nodes else "unknown",
                    start_time=nodes[0].timestamp if nodes else datetime.utcnow(),
                    end_time=nodes[-1].timestamp if nodes else datetime.utcnow(),
                    nodes=nodes,
                    edges=edges,
                    kill_chain_phases=unique_phases,
                    severity_score=severity,
                    confidence=confidence,
                    is_complete=is_complete
                )

                chains.append(chain)

        self.chains = chains
        return chains

    def find_attack_paths(self, start_ip: str, target_ip: str) -> List[List[AttackNode]]:
        """
        Find all attack paths from source to target

        Args:
            start_ip: Attacker IP
            target_ip: Target IP

        Returns:
            List of attack paths
        """
        # Build graph
        self._build_attack_graph()

        paths = []

        # Find relevant nodes
        start_nodes = [n for n in self.attack_graph.nodes()
                      if self.attack_graph.nodes[n].get("source_ip") == start_ip]

        target_nodes = [n for n in self.attack_graph.nodes()
                       if self.attack_graph.nodes[n].get("target_ip") == target_ip]

        # Find paths between start and target nodes
        for start_node in start_nodes:
            for target_node in target_nodes:
                try:
                    if nx.has_path(self.attack_graph, start_node, target_node):
                        # Find all simple paths
                        simple_paths = nx.all_simple_paths(
                            self.attack_graph,
                            start_node,
                            target_node,
                            cutoff=10
                        )

                        for path in simple_paths:
                            path_nodes = [self.attack_graph.nodes[n]["node_obj"]
                                        for n in path]
                            paths.append(path_nodes)
                except (KeyError, StopIteration, nx.NetworkXNoPath):
                    continue

        return paths

    def analyze_attack_progression(self, chain: AttackChain) -> Dict[str, Any]:
        """
        Analyze attack progression and identify gaps

        Args:
            chain: Attack chain to analyze

        Returns:
            Analysis results
        """
        phases = chain.kill_chain_phases

        # Expected phase order
        expected_order = [
            KillChainPhase.RECONNAISSANCE,
            KillChainPhase.INITIAL_ACCESS,
            KillChainPhase.EXECUTION,
            KillChainPhase.PERSISTENCE,
            KillChainPhase.PRIVILEGE_ESCALATION,
            KillChainPhase.LATERAL_MOVEMENT,
            KillChainPhase.EXFILTRATION
        ]

        # Find missing phases
        present_phases = set(phases)
        all_phases = set(expected_order)
        missing_phases = all_phases - present_phases

        # Check for out-of-order phases
        phase_indices = []
        for phase in phases:
            try:
                idx = expected_order.index(phase)
                phase_indices.append(idx)
            except ValueError:
                pass

        out_of_order = False
        if len(phase_indices) > 1:
            out_of_order = phase_indices != sorted(phase_indices)

        # Calculate progression score (0-1)
        progression_score = len(present_phases) / len(expected_order)

        # Time analysis
        time_span = (chain.end_time - chain.start_time).total_seconds()

        return {
            "chain_id": chain.chain_id,
            "phases_present": [p.value for p in phases],
            "phases_missing": [p.value for p in missing_phases],
            "out_of_order": out_of_order,
            "progression_score": progression_score,
            "is_complete": chain.is_complete,
            "time_span_seconds": time_span,
            "event_count": len(chain.nodes),
            "severity": chain.severity_score,
            "recommendations": self._generate_recommendations(chain, missing_phases)
        }

    def predict_next_phase(self, chain: AttackChain) -> Dict[str, Any]:
        """
        Predict next phase in attack chain

        Args:
            chain: Current attack chain

        Returns:
            Prediction results
        """
        if not chain.nodes:
            return {"error": "Empty chain"}

        current_phase = chain.nodes[-1].kill_chain_phase

        # Phase transition probabilities (based on common attack patterns)
        transitions = {
            KillChainPhase.RECONNAISSANCE: [
                (KillChainPhase.INITIAL_ACCESS, 0.7),
                (KillChainPhase.RESOURCE_DEVELOPMENT, 0.3)
            ],
            KillChainPhase.INITIAL_ACCESS: [
                (KillChainPhase.EXECUTION, 0.8),
                (KillChainPhase.PERSISTENCE, 0.2)
            ],
            KillChainPhase.EXECUTION: [
                (KillChainPhase.PRIVILEGE_ESCALATION, 0.5),
                (KillChainPhase.PERSISTENCE, 0.3),
                (KillChainPhase.DISCOVERY, 0.2)
            ],
            KillChainPhase.PRIVILEGE_ESCALATION: [
                (KillChainPhase.CREDENTIAL_ACCESS, 0.4),
                (KillChainPhase.LATERAL_MOVEMENT, 0.4),
                (KillChainPhase.PERSISTENCE, 0.2)
            ],
            KillChainPhase.LATERAL_MOVEMENT: [
                (KillChainPhase.COLLECTION, 0.4),
                (KillChainPhase.EXFILTRATION, 0.3),
                (KillChainPhase.IMPACT, 0.3)
            ],
            KillChainPhase.COLLECTION: [
                (KillChainPhase.EXFILTRATION, 0.8),
                (KillChainPhase.IMPACT, 0.2)
            ]
        }

        predictions = transitions.get(current_phase, [])

        return {
            "current_phase": current_phase.value,
            "predictions": [
                {
                    "phase": phase.value,
                    "probability": prob,
                    "recommended_actions": self._get_mitigation_actions(phase)
                }
                for phase, prob in predictions
            ]
        }

    def export_chain_visualization(self, chain: AttackChain) -> Dict[str, Any]:
        """
        Export chain for visualization

        Args:
            chain: Attack chain

        Returns:
            Visualization data
        """
        nodes = []
        edges = []

        for i, node in enumerate(chain.nodes):
            nodes.append({
                "id": node.node_id,
                "label": node.event_type,
                "phase": node.kill_chain_phase.value,
                "timestamp": node.timestamp.isoformat(),
                "severity": node.severity,
                "technique": node.technique
            })

        for source, target in chain.edges:
            edges.append({
                "source": source,
                "target": target
            })

        return {
            "chain_id": chain.chain_id,
            "attacker": chain.attacker_ip,
            "target": chain.target_ip,
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "start_time": chain.start_time.isoformat(),
                "end_time": chain.end_time.isoformat(),
                "severity": chain.severity_score,
                "confidence": chain.confidence
            }
        }

    def _build_attack_graph(self):
        """Build graph from events"""
        self.attack_graph.clear()

        # Add nodes
        for i, event in enumerate(self.events):
            node_id = f"event_{i}_{event.get('source_ip')}"
            node = self._event_to_node(event)

            self.attack_graph.add_node(
                node_id,
                node_obj=node,
                timestamp=node.timestamp,
                source_ip=node.source_ip,
                target_ip=node.target_ip,
                phase=node.kill_chain_phase
            )

        # Add edges based on temporal and logical relationships
        node_list = list(self.attack_graph.nodes())

        for i in range(len(node_list)):
            for j in range(i + 1, len(node_list)):
                node1 = node_list[i]
                node2 = node_list[j]

                if self._should_connect(node1, node2):
                    self.attack_graph.add_edge(node1, node2)

    def _should_connect(self, node1_id: str, node2_id: str) -> bool:
        """Determine if two nodes should be connected"""
        node1 = self.attack_graph.nodes[node1_id]
        node2 = self.attack_graph.nodes[node2_id]

        # Same attacker
        if node1["source_ip"] != node2["source_ip"]:
            return False

        # Temporal proximity (within 30 minutes)
        time_diff = abs((node2["timestamp"] - node1["timestamp"]).total_seconds())
        if time_diff > 1800:
            return False

        # Logical phase progression
        phase1 = node1["phase"]
        phase2 = node2["phase"]

        # Check if phase2 can follow phase1
        valid_transitions = self._get_valid_transitions(phase1)

        return phase2 in valid_transitions

    def _get_valid_transitions(self, phase: KillChainPhase) -> Set[KillChainPhase]:
        """Get valid next phases"""
        transitions = {
            KillChainPhase.RECONNAISSANCE: {
                KillChainPhase.INITIAL_ACCESS,
                KillChainPhase.RESOURCE_DEVELOPMENT
            },
            KillChainPhase.INITIAL_ACCESS: {
                KillChainPhase.EXECUTION,
                KillChainPhase.PERSISTENCE
            },
            KillChainPhase.EXECUTION: {
                KillChainPhase.PERSISTENCE,
                KillChainPhase.PRIVILEGE_ESCALATION,
                KillChainPhase.DISCOVERY
            },
            KillChainPhase.PRIVILEGE_ESCALATION: {
                KillChainPhase.CREDENTIAL_ACCESS,
                KillChainPhase.LATERAL_MOVEMENT,
                KillChainPhase.PERSISTENCE
            },
            KillChainPhase.LATERAL_MOVEMENT: {
                KillChainPhase.COLLECTION,
                KillChainPhase.EXFILTRATION,
                KillChainPhase.IMPACT
            }
        }

        return transitions.get(phase, set())

    def _event_to_node(self, event: Dict[str, Any]) -> AttackNode:
        """Convert event to attack node"""
        event_type = event.get("attack_type", "unknown")
        phase = self._map_to_kill_chain_phase(event_type)

        return AttackNode(
            node_id=f"{event.get('source_ip')}_{event.get('timestamp')}",
            timestamp=event.get("timestamp", datetime.utcnow()),
            event_type=event_type,
            source_ip=event.get("source_ip", "unknown"),
            target_ip=event.get("target_ip", "unknown"),
            kill_chain_phase=phase,
            technique=event.get("technique", ""),
            severity=event.get("severity", 5),
            metadata=event
        )

    def _map_to_kill_chain_phase(self, attack_type: str) -> KillChainPhase:
        """Map attack type to kill chain phase"""
        attack_type_lower = attack_type.lower()

        for phase, keywords in self.attack_phase_map.items():
            for keyword in keywords:
                if keyword in attack_type_lower:
                    return phase

        return KillChainPhase.EXECUTION  # Default

    def _init_phase_mapping(self) -> Dict[KillChainPhase, List[str]]:
        """Initialize attack type to phase mapping"""
        return {
            KillChainPhase.RECONNAISSANCE: ["scan", "reconnaissance", "enumeration", "probe"],
            KillChainPhase.INITIAL_ACCESS: ["exploit", "phishing", "brute_force", "injection"],
            KillChainPhase.EXECUTION: ["command", "script", "payload", "execution"],
            KillChainPhase.PERSISTENCE: ["backdoor", "persistence", "scheduled_task"],
            KillChainPhase.PRIVILEGE_ESCALATION: ["privilege", "escalation", "root"],
            KillChainPhase.CREDENTIAL_ACCESS: ["credential", "password", "hash", "token"],
            KillChainPhase.DISCOVERY: ["discovery", "enumerate", "network_map"],
            KillChainPhase.LATERAL_MOVEMENT: ["lateral", "remote", "rdp", "ssh"],
            KillChainPhase.COLLECTION: ["collect", "gather", "archive"],
            KillChainPhase.EXFILTRATION: ["exfiltration", "data_transfer", "upload"],
            KillChainPhase.IMPACT: ["ransom", "delete", "wipe", "destroy", "dos"]
        }

    def _find_edges(self, nodes: List[AttackNode]) -> List[Tuple[str, str]]:
        """Find causal edges between nodes"""
        edges = []

        for i in range(len(nodes) - 1):
            edges.append((nodes[i].node_id, nodes[i + 1].node_id))

        return edges

    def _calculate_chain_severity(self, nodes: List[AttackNode]) -> float:
        """Calculate overall chain severity"""
        if not nodes:
            return 0.0

        # Average severity
        avg_severity = sum(n.severity for n in nodes) / len(nodes)

        # Bonus for complete chain
        unique_phases = len(set(n.kill_chain_phase for n in nodes))
        phase_bonus = unique_phases / 7.0  # 7 main phases

        return min((avg_severity / 10.0) + phase_bonus, 1.0)

    def _calculate_chain_confidence(self, nodes: List[AttackNode], edges: List[Tuple]) -> float:
        """Calculate confidence in chain reconstruction"""
        confidence = 0.5

        # More nodes = higher confidence
        confidence += min(len(nodes) / 10, 0.2)

        # Sequential phases = higher confidence
        phases = [n.kill_chain_phase for n in nodes]
        if len(phases) > 1:
            sequential = sum(1 for i in range(len(phases)-1)
                           if phases[i+1] in self._get_valid_transitions(phases[i]))
            confidence += (sequential / len(phases)) * 0.3

        return min(confidence, 1.0)

    def _is_chain_complete(self, phases: List[KillChainPhase]) -> bool:
        """Check if chain represents complete attack"""
        critical_phases = {
            KillChainPhase.INITIAL_ACCESS,
            KillChainPhase.EXECUTION,
            KillChainPhase.EXFILTRATION
        }

        return critical_phases.issubset(set(phases))

    def _generate_recommendations(self, chain: AttackChain, missing_phases: Set) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        if KillChainPhase.RECONNAISSANCE in chain.kill_chain_phases:
            recommendations.append("Deploy honeypots to detect reconnaissance")

        if KillChainPhase.EXFILTRATION in chain.kill_chain_phases:
            recommendations.append("URGENT: Block egress traffic from compromised systems")

        if chain.is_complete:
            recommendations.append("Full attack chain detected - initiate incident response")

        return recommendations

    def _get_mitigation_actions(self, phase: KillChainPhase) -> List[str]:
        """Get mitigation actions for phase"""
        mitigations = {
            KillChainPhase.INITIAL_ACCESS: ["Enable MFA", "Update firewall rules", "Patch vulnerabilities"],
            KillChainPhase.EXECUTION: ["Enable application whitelisting", "Monitor process execution"],
            KillChainPhase.PERSISTENCE: ["Audit scheduled tasks", "Monitor registry changes"],
            KillChainPhase.EXFILTRATION: ["Block suspicious egress traffic", "Monitor data transfers"]
        }

        return mitigations.get(phase, ["Monitor for suspicious activity"])
