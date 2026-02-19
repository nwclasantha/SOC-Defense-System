"""
MITRE Feature Extractor for Hybrid ML
Extracts MITRE-based features from attack events for ML training and prediction

Author: SOC Defense System
Version: 1.0.0
"""

import numpy as np
from typing import List, Dict, Set, Tuple, Optional
from collections import Counter, defaultdict
from datetime import datetime

from modules.AttackEvent import AttackEvent
from modules.AttackType import AttackType
from modules.MitreAttackMapper import MitreAttackMapper, MitreTactic


class MitreFeatureExtractor:
    """
    Extracts comprehensive MITRE ATT&CK-based features from attack events
    for use in hybrid ML models
    """

    # MITRE Technique Severity Scores (based on real-world impact)
    TECHNIQUE_SEVERITY = {
        'T1190': 100,  # Exploit Public-Facing Application (CRITICAL)
        'T1068': 95,   # Exploitation for Privilege Escalation
        'T1059': 90,   # Command and Scripting Interpreter
        'T1059.001': 92,  # PowerShell
        'T1059.003': 90,  # Windows Command Shell
        'T1486': 100,  # Data Encrypted for Impact (Ransomware)
        'T1078': 85,   # Valid Accounts
        'T1053': 85,   # Scheduled Task/Job
        'T1003': 95,   # OS Credential Dumping
        'T1048': 90,   # Exfiltration Over Alternative Protocol
        'T1071': 80,   # Application Layer Protocol (C2)
        'T1055': 88,   # Process Injection
        'T1105': 85,   # Ingress Tool Transfer
        'T1133': 82,   # External Remote Services
        'T1021': 80,   # Remote Services
        'T1566': 75,   # Phishing
        'T1203': 90,   # Exploitation for Client Execution
        'T1210': 88,   # Exploitation of Remote Services
        'T1570': 85,   # Lateral Tool Transfer
        'T1083': 60,   # File and Directory Discovery
        'T1057': 55,   # Process Discovery
        'T1018': 58,   # Remote System Discovery
        'T1082': 50,   # System Information Discovery
    }

    # Tactic Severity (1-100)
    TACTIC_SEVERITY = {
        MitreTactic.IMPACT: 100,
        MitreTactic.EXFILTRATION: 95,
        MitreTactic.CREDENTIAL_ACCESS: 90,
        MitreTactic.LATERAL_MOVEMENT: 85,
        MitreTactic.COMMAND_AND_CONTROL: 80,
        MitreTactic.PRIVILEGE_ESCALATION: 85,
        MitreTactic.PERSISTENCE: 80,
        MitreTactic.EXECUTION: 75,
        MitreTactic.INITIAL_ACCESS: 70,
        MitreTactic.DEFENSE_EVASION: 70,
        MitreTactic.COLLECTION: 75,
        MitreTactic.DISCOVERY: 50,
        MitreTactic.RECONNAISSANCE: 40,
        MitreTactic.RESOURCE_DEVELOPMENT: 45,
    }

    # Critical tactic sequences (indicate sophisticated attacks)
    CRITICAL_SEQUENCES = [
        (MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION, MitreTactic.PERSISTENCE),
        (MitreTactic.PRIVILEGE_ESCALATION, MitreTactic.CREDENTIAL_ACCESS),
        (MitreTactic.COLLECTION, MitreTactic.EXFILTRATION),
        (MitreTactic.LATERAL_MOVEMENT, MitreTactic.COMMAND_AND_CONTROL),
    ]

    def __init__(self, mitre_mapper: Optional[MitreAttackMapper] = None):
        """
        Initialize the MITRE feature extractor

        Args:
            mitre_mapper: Optional MitreAttackMapper instance (creates new if None)
        """
        self.mitre_mapper = mitre_mapper or MitreAttackMapper.get_instance(use_local_db=True)

    def extract_features(self, ip_address: str, attack_events: List[AttackEvent]) -> Dict[str, float]:
        """
        Extract comprehensive MITRE-based features from attack events

        Args:
            ip_address: The IP address being analyzed
            attack_events: List of attack events from this IP

        Returns:
            Dictionary of feature names to values
        """
        if not attack_events:
            return self._get_empty_features()

        # Map all attacks to MITRE
        techniques, tactics, attack_types = self._map_to_mitre(attack_events)

        # Extract temporal features
        temporal_features = self._extract_temporal_features(attack_events)

        # Extract MITRE-specific features
        mitre_features = self._extract_mitre_features(techniques, tactics)

        # Extract behavioral features
        behavioral_features = self._extract_behavioral_features(attack_events, attack_types)

        # Extract sequence features (kill chain analysis)
        sequence_features = self._extract_sequence_features(attack_events, tactics)

        # Combine all features
        features = {
            **temporal_features,
            **mitre_features,
            **behavioral_features,
            **sequence_features
        }

        return features

    def _map_to_mitre(self, attack_events: List[AttackEvent]) -> Tuple[Set[str], Set[MitreTactic], Set[AttackType]]:
        """Map attack events to MITRE techniques and tactics"""
        techniques = set()
        tactics = set()
        attack_types = set()

        # Map tactic string names to MitreTactic enum
        tactic_name_map = {
            'reconnaissance': MitreTactic.RECONNAISSANCE,
            'resource-development': MitreTactic.RESOURCE_DEVELOPMENT,
            'resource development': MitreTactic.RESOURCE_DEVELOPMENT,
            'initial-access': MitreTactic.INITIAL_ACCESS,
            'initial access': MitreTactic.INITIAL_ACCESS,
            'execution': MitreTactic.EXECUTION,
            'persistence': MitreTactic.PERSISTENCE,
            'privilege-escalation': MitreTactic.PRIVILEGE_ESCALATION,
            'privilege escalation': MitreTactic.PRIVILEGE_ESCALATION,
            'defense-evasion': MitreTactic.DEFENSE_EVASION,
            'defense evasion': MitreTactic.DEFENSE_EVASION,
            'credential-access': MitreTactic.CREDENTIAL_ACCESS,
            'credential access': MitreTactic.CREDENTIAL_ACCESS,
            'discovery': MitreTactic.DISCOVERY,
            'lateral-movement': MitreTactic.LATERAL_MOVEMENT,
            'lateral movement': MitreTactic.LATERAL_MOVEMENT,
            'collection': MitreTactic.COLLECTION,
            'command-and-control': MitreTactic.COMMAND_AND_CONTROL,
            'command and control': MitreTactic.COMMAND_AND_CONTROL,
            'exfiltration': MitreTactic.EXFILTRATION,
            'impact': MitreTactic.IMPACT,
        }

        for event in attack_events:
            attack_types.add(event.attack_type)
            # map_attack_to_mitre returns a list of MitreTechnique objects
            mapped_techniques = self.mitre_mapper.map_attack_to_mitre(
                event.attack_type,
                description=getattr(event, 'description', '')
            )

            for tech in mapped_techniques:
                # Get technique ID - handle both formats (external_id or id)
                tech_id = getattr(tech, 'external_id', None) or getattr(tech, 'id', '')
                if tech_id:
                    techniques.add(tech_id)

                # Handle both MitreTechnique formats:
                # 1. MitreDatabaseLoader format: tactics is List[str]
                # 2. MitreAttackMapper format: tactic is MitreTactic enum
                if hasattr(tech, 'tactics') and isinstance(tech.tactics, list):
                    # MitreDatabaseLoader format - convert string tactics to enums
                    for tactic_str in tech.tactics:
                        tactic_enum = tactic_name_map.get(tactic_str.lower())
                        if tactic_enum:
                            tactics.add(tactic_enum)
                elif hasattr(tech, 'tactic') and tech.tactic:
                    # MitreAttackMapper format - single tactic enum
                    tactics.add(tech.tactic)

        return techniques, tactics, attack_types

    def _extract_temporal_features(self, attack_events: List[AttackEvent]) -> Dict[str, float]:
        """Extract time-based features"""
        timestamps = [event.timestamp for event in attack_events if hasattr(event, 'timestamp')]

        if not timestamps:
            return {
                'attack_count': float(len(attack_events)),
                'time_span_hours': 0.0,
                'attack_velocity': 0.0,
                'attacks_per_hour': 0.0,
            }

        first_seen = min(timestamps)
        last_seen = max(timestamps)
        time_span = (last_seen - first_seen).total_seconds() / 3600  # hours

        # Velocity calculation
        if time_span > 0:
            velocity = len(attack_events) / time_span
        else:
            velocity = len(attack_events)  # All attacks in same moment

        return {
            'attack_count': float(len(attack_events)),
            'time_span_hours': float(time_span),
            'attack_velocity': float(velocity),
            'attacks_per_hour': float(velocity),
        }

    def _extract_mitre_features(self, techniques: Set[str], tactics: Set[MitreTactic]) -> Dict[str, float]:
        """Extract MITRE-specific features"""
        # Technique-based features
        technique_count = len(techniques)
        technique_severity_scores = [
            self.TECHNIQUE_SEVERITY.get(t, 50) for t in techniques
        ]
        avg_technique_severity = np.mean(technique_severity_scores) if technique_severity_scores else 0
        max_technique_severity = max(technique_severity_scores) if technique_severity_scores else 0

        # Count critical techniques
        critical_technique_count = sum(
            1 for t in techniques if self.TECHNIQUE_SEVERITY.get(t, 0) >= 85
        )

        # Tactic-based features
        tactic_count = len(tactics)
        tactic_severity_scores = [
            self.TACTIC_SEVERITY.get(t, 50) for t in tactics
        ]
        avg_tactic_severity = np.mean(tactic_severity_scores) if tactic_severity_scores else 0
        max_tactic_severity = max(tactic_severity_scores) if tactic_severity_scores else 0

        # Kill chain coverage (percentage of tactics covered)
        kill_chain_coverage = tactic_count / len(MitreTactic) * 100

        # Specific tactic presence (binary features)
        has_initial_access = 1.0 if MitreTactic.INITIAL_ACCESS in tactics else 0.0
        has_execution = 1.0 if MitreTactic.EXECUTION in tactics else 0.0
        has_persistence = 1.0 if MitreTactic.PERSISTENCE in tactics else 0.0
        has_privilege_escalation = 1.0 if MitreTactic.PRIVILEGE_ESCALATION in tactics else 0.0
        has_credential_access = 1.0 if MitreTactic.CREDENTIAL_ACCESS in tactics else 0.0
        has_lateral_movement = 1.0 if MitreTactic.LATERAL_MOVEMENT in tactics else 0.0
        has_exfiltration = 1.0 if MitreTactic.EXFILTRATION in tactics else 0.0
        has_impact = 1.0 if MitreTactic.IMPACT in tactics else 0.0
        has_c2 = 1.0 if MitreTactic.COMMAND_AND_CONTROL in tactics else 0.0

        # Specific technique presence (high-value indicators)
        has_t1190 = 1.0 if 'T1190' in techniques else 0.0  # Web exploit
        has_t1059 = 1.0 if 'T1059' in techniques else 0.0  # Command injection
        has_t1068 = 1.0 if 'T1068' in techniques else 0.0  # Privilege escalation exploit
        has_t1486 = 1.0 if 'T1486' in techniques else 0.0  # Ransomware
        has_t1003 = 1.0 if 'T1003' in techniques else 0.0  # Credential dumping

        return {
            # Technique features
            'technique_count': float(technique_count),
            'technique_diversity': float(technique_count),
            'avg_technique_severity': float(avg_technique_severity),
            'max_technique_severity': float(max_technique_severity),
            'critical_technique_count': float(critical_technique_count),

            # Tactic features
            'tactic_count': float(tactic_count),
            'tactic_diversity': float(tactic_count),
            'avg_tactic_severity': float(avg_tactic_severity),
            'max_tactic_severity': float(max_tactic_severity),
            'kill_chain_coverage': float(kill_chain_coverage),

            # Binary tactic presence
            'has_initial_access': has_initial_access,
            'has_execution': has_execution,
            'has_persistence': has_persistence,
            'has_privilege_escalation': has_privilege_escalation,
            'has_credential_access': has_credential_access,
            'has_lateral_movement': has_lateral_movement,
            'has_exfiltration': has_exfiltration,
            'has_impact': has_impact,
            'has_c2': has_c2,

            # Binary technique presence
            'has_t1190_web_exploit': has_t1190,
            'has_t1059_command_injection': has_t1059,
            'has_t1068_privilege_escalation': has_t1068,
            'has_t1486_ransomware': has_t1486,
            'has_t1003_credential_dumping': has_t1003,
        }

    def _extract_behavioral_features(self, attack_events: List[AttackEvent],
                                     attack_types: Set[AttackType]) -> Dict[str, float]:
        """Extract behavioral features"""
        # Target diversity
        targeted_agents = set()
        for event in attack_events:
            if hasattr(event, 'agent_name') and event.agent_name:
                targeted_agents.add(event.agent_name)

        target_diversity = len(targeted_agents)

        # Attack type diversity
        attack_type_diversity = len(attack_types)

        # CVE exploitation count
        cve_count = 0
        for event in attack_events:
            if hasattr(event, 'cve_list') and event.cve_list:
                cve_count += len(event.cve_list)

        # Severity analysis
        severity_scores = []
        for event in attack_events:
            if hasattr(event, 'rule_level'):
                severity_scores.append(event.rule_level)

        avg_severity = np.mean(severity_scores) if severity_scores else 0
        max_severity = max(severity_scores) if severity_scores else 0

        # High severity attack count (level >= 10)
        high_severity_count = sum(1 for s in severity_scores if s >= 10)

        return {
            'target_diversity': float(target_diversity),
            'attack_type_diversity': float(attack_type_diversity),
            'cve_exploitation_count': float(cve_count),
            'avg_severity': float(avg_severity),
            'max_severity': float(max_severity),
            'high_severity_count': float(high_severity_count),
            'has_cve_exploits': 1.0 if cve_count > 0 else 0.0,
        }

    def _extract_sequence_features(self, attack_events: List[AttackEvent],
                                   tactics: Set[MitreTactic]) -> Dict[str, float]:
        """Extract attack sequence and progression features"""
        # Check for critical tactic sequences
        has_critical_sequence = 0.0
        for sequence in self.CRITICAL_SEQUENCES:
            if all(tactic in tactics for tactic in sequence):
                has_critical_sequence = 1.0
                break

        # Multi-stage attack detection
        is_multi_stage = 1.0 if len(tactics) >= 3 else 0.0

        # Full kill chain (initial access -> execution -> persistence)
        has_full_chain = 1.0 if (
            MitreTactic.INITIAL_ACCESS in tactics and
            MitreTactic.EXECUTION in tactics and
            (MitreTactic.PERSISTENCE in tactics or MitreTactic.PRIVILEGE_ESCALATION in tactics)
        ) else 0.0

        # Advanced persistent threat indicators
        is_apt_like = 1.0 if (
            len(tactics) >= 4 and
            MitreTactic.PERSISTENCE in tactics and
            MitreTactic.COMMAND_AND_CONTROL in tactics
        ) else 0.0

        # Data theft indicators
        is_data_theft = 1.0 if (
            MitreTactic.COLLECTION in tactics and
            MitreTactic.EXFILTRATION in tactics
        ) else 0.0

        # Ransomware indicators
        is_ransomware_like = 1.0 if MitreTactic.IMPACT in tactics else 0.0

        return {
            'has_critical_sequence': has_critical_sequence,
            'is_multi_stage_attack': is_multi_stage,
            'has_full_kill_chain': has_full_chain,
            'is_apt_like': is_apt_like,
            'is_data_theft_attack': is_data_theft,
            'is_ransomware_like': is_ransomware_like,
        }

    def _get_empty_features(self) -> Dict[str, float]:
        """Return feature dict with all zeros for empty input"""
        return {
            # Temporal
            'attack_count': 0.0,
            'time_span_hours': 0.0,
            'attack_velocity': 0.0,
            'attacks_per_hour': 0.0,

            # MITRE technique features
            'technique_count': 0.0,
            'technique_diversity': 0.0,
            'avg_technique_severity': 0.0,
            'max_technique_severity': 0.0,
            'critical_technique_count': 0.0,

            # MITRE tactic features
            'tactic_count': 0.0,
            'tactic_diversity': 0.0,
            'avg_tactic_severity': 0.0,
            'max_tactic_severity': 0.0,
            'kill_chain_coverage': 0.0,

            # Binary tactic features
            'has_initial_access': 0.0,
            'has_execution': 0.0,
            'has_persistence': 0.0,
            'has_privilege_escalation': 0.0,
            'has_credential_access': 0.0,
            'has_lateral_movement': 0.0,
            'has_exfiltration': 0.0,
            'has_impact': 0.0,
            'has_c2': 0.0,

            # Binary technique features
            'has_t1190_web_exploit': 0.0,
            'has_t1059_command_injection': 0.0,
            'has_t1068_privilege_escalation': 0.0,
            'has_t1486_ransomware': 0.0,
            'has_t1003_credential_dumping': 0.0,

            # Behavioral
            'target_diversity': 0.0,
            'attack_type_diversity': 0.0,
            'cve_exploitation_count': 0.0,
            'avg_severity': 0.0,
            'max_severity': 0.0,
            'high_severity_count': 0.0,
            'has_cve_exploits': 0.0,

            # Sequence
            'has_critical_sequence': 0.0,
            'is_multi_stage_attack': 0.0,
            'has_full_kill_chain': 0.0,
            'is_apt_like': 0.0,
            'is_data_theft_attack': 0.0,
            'is_ransomware_like': 0.0,
        }

    def get_feature_names(self) -> List[str]:
        """Get ordered list of feature names"""
        return list(self._get_empty_features().keys())

    def extract_features_dict(self, ip_address: str, attack_events: List[AttackEvent]) -> Dict[str, float]:
        """
        Extract features and return as dictionary with MITRE threat score included

        This is used by other modules that need the dict format with threat score.

        Args:
            ip_address: The IP address being analyzed
            attack_events: List of attack events

        Returns:
            Dictionary of features including mitre_threat_score
        """
        features = self.extract_features(ip_address, attack_events)

        # Calculate MITRE threat score
        techniques, tactics, _ = self._map_to_mitre(attack_events)
        mitre_score = self.calculate_mitre_threat_score(techniques, tactics)

        # Add MITRE threat score to features
        features['mitre_threat_score'] = mitre_score

        return features

    def extract_features_array(self, ip_address: str, attack_events: List[AttackEvent]) -> np.ndarray:
        """
        Extract features and return as numpy array for ML training

        Args:
            ip_address: The IP address being analyzed
            attack_events: List of attack events

        Returns:
            Numpy array of feature values in consistent order
        """
        features = self.extract_features(ip_address, attack_events)
        feature_names = self.get_feature_names()
        return np.array([features[name] for name in feature_names])

    def calculate_mitre_threat_score(self, techniques: Set[str], tactics: Set[MitreTactic]) -> float:
        """
        Calculate a threat score (0-100) based purely on MITRE patterns
        This can be used as ground truth for training

        Args:
            techniques: Set of MITRE technique IDs
            tactics: Set of MITRE tactics

        Returns:
            Threat score from 0 (benign) to 100 (critical threat)
        """
        if not techniques and not tactics:
            return 0.0

        score = 0.0

        # Technique-based scoring (max 60 points)
        if techniques:
            technique_scores = [self.TECHNIQUE_SEVERITY.get(t, 50) for t in techniques]
            max_technique_score = max(technique_scores)
            avg_technique_score = np.mean(technique_scores)

            # Weight towards maximum severity technique
            technique_component = (max_technique_score * 0.7 + avg_technique_score * 0.3)
            score += technique_component * 0.6

        # Tactic-based scoring (max 30 points)
        if tactics:
            tactic_scores = [self.TACTIC_SEVERITY.get(t, 50) for t in tactics]
            max_tactic_score = max(tactic_scores)

            tactic_component = max_tactic_score
            score += tactic_component * 0.3

        # Bonus for critical sequences (max 10 points)
        for sequence in self.CRITICAL_SEQUENCES:
            if all(tactic in tactics for tactic in sequence):
                score += 10
                break

        return min(100.0, score)
