"""
NIST Cybersecurity Framework (CSF) Compliance Detector
Maps security incidents to NIST CSF functions, categories, and subcategories
Assesses cybersecurity maturity and generates improvement recommendations

Covers NIST CSF 5 Core Functions:
- IDENTIFY (ID): Asset Management, Risk Assessment, Governance
- PROTECT (PR): Access Control, Data Security, Protective Technology
- DETECT (DE): Anomalies and Events, Security Monitoring, Detection Processes
- RESPOND (RS): Response Planning, Communications, Analysis, Mitigation
- RECOVER (RC): Recovery Planning, Improvements, Communications

Implementation Tiers:
- Tier 1: Partial (Ad-hoc, reactive)
- Tier 2: Risk Informed (Risk-aware but not formalized)
- Tier 3: Repeatable (Formal policies and procedures)
- Tier 4: Adaptive (Continuous improvement, advanced)
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

class NISTFunction(Enum):
    """NIST CSF Core Functions"""
    IDENTIFY = "ID"
    PROTECT = "PR"
    DETECT = "DE"
    RESPOND = "RS"
    RECOVER = "RC"

class NISTTier(Enum):
    """NIST CSF Implementation Tiers"""
    TIER_1_PARTIAL = "Tier 1 - Partial"
    TIER_2_RISK_INFORMED = "Tier 2 - Risk Informed"
    TIER_3_REPEATABLE = "Tier 3 - Repeatable"
    TIER_4_ADAPTIVE = "Tier 4 - Adaptive"

@dataclass
class NISTViolation:
    """NIST CSF Compliance Gap"""
    violation_id: str
    function: NISTFunction
    category_id: str
    category_name: str
    subcategory_id: str
    subcategory_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    current_maturity: int  # 0-4
    target_maturity: int  # Typically 3-4
    gap: int  # target - current
    evidence: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    remediation: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)
    compliance_impact: str = ""

class NISTComplianceDetector:
    """
    Detects NIST CSF compliance gaps from security incidents
    Assesses maturity level and provides improvement roadmap
    """

    def __init__(self):
        # NIST CSF subcategories database
        self.subcategories = self._initialize_subcategories()

        # Attack type to NIST subcategory mapping
        self.attack_to_nist_map = self._initialize_attack_mapping()

        # Violation/gap database
        self.violations: List[NISTViolation] = []

    def _initialize_subcategories(self) -> Dict[str, Dict[str, Any]]:
        """Initialize NIST CSF subcategories"""
        return {
            # IDENTIFY (ID)
            "ID.AM-1": {
                "function": NISTFunction.IDENTIFY,
                "category_id": "ID.AM",
                "category_name": "Asset Management",
                "subcategory_name": "Physical devices and systems inventoried"
            },
            "ID.AM-2": {
                "function": NISTFunction.IDENTIFY,
                "category_id": "ID.AM",
                "category_name": "Asset Management",
                "subcategory_name": "Software platforms and applications inventoried"
            },
            "ID.RA-1": {
                "function": NISTFunction.IDENTIFY,
                "category_id": "ID.RA",
                "category_name": "Risk Assessment",
                "subcategory_name": "Asset vulnerabilities are identified and documented"
            },
            "ID.RA-5": {
                "function": NISTFunction.IDENTIFY,
                "category_id": "ID.RA",
                "category_name": "Risk Assessment",
                "subcategory_name": "Threats, vulnerabilities, likelihoods, and impacts used to determine risk"
            },

            # PROTECT (PR)
            "PR.AC-1": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.AC",
                "category_name": "Access Control",
                "subcategory_name": "Identities and credentials issued, managed, verified, revoked, audited"
            },
            "PR.AC-3": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.AC",
                "category_name": "Access Control",
                "subcategory_name": "Remote access is managed"
            },
            "PR.AC-4": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.AC",
                "category_name": "Access Control",
                "subcategory_name": "Access permissions and authorizations managed, incorporating least privilege"
            },
            "PR.AC-5": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.AC",
                "category_name": "Access Control",
                "subcategory_name": "Network integrity protected (network segregation, network segmentation)"
            },
            "PR.AC-7": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.AC",
                "category_name": "Access Control",
                "subcategory_name": "Users, devices, assets authenticated prior to connections"
            },
            "PR.DS-1": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.DS",
                "category_name": "Data Security",
                "subcategory_name": "Data-at-rest is protected"
            },
            "PR.DS-2": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.DS",
                "category_name": "Data Security",
                "subcategory_name": "Data-in-transit is protected"
            },
            "PR.DS-5": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.DS",
                "category_name": "Data Security",
                "subcategory_name": "Protections against data leaks implemented"
            },
            "PR.IP-1": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.IP",
                "category_name": "Information Protection Processes",
                "subcategory_name": "Baseline configuration of systems created and maintained"
            },
            "PR.IP-12": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.IP",
                "category_name": "Information Protection Processes",
                "subcategory_name": "Vulnerability management plan developed and implemented"
            },
            "PR.PT-1": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.PT",
                "category_name": "Protective Technology",
                "subcategory_name": "Audit/log records determined, documented, implemented, reviewed"
            },
            "PR.PT-3": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.PT",
                "category_name": "Protective Technology",
                "subcategory_name": "Principle of least functionality incorporated"
            },
            "PR.PT-4": {
                "function": NISTFunction.PROTECT,
                "category_id": "PR.PT",
                "category_name": "Protective Technology",
                "subcategory_name": "Communications and control networks protected"
            },

            # DETECT (DE)
            "DE.AE-1": {
                "function": NISTFunction.DETECT,
                "category_id": "DE.AE",
                "category_name": "Anomalies and Events",
                "subcategory_name": "Network baseline established, managed, and analyzed for anomalies"
            },
            "DE.AE-2": {
                "function": NISTFunction.DETECT,
                "category_id": "DE.AE",
                "category_name": "Anomalies and Events",
                "subcategory_name": "Detected events analyzed to understand attack targets and methods"
            },
            "DE.AE-3": {
                "function": NISTFunction.DETECT,
                "category_id": "DE.AE",
                "category_name": "Anomalies and Events",
                "subcategory_name": "Event data correlated from multiple sources and sensors"
            },
            "DE.CM-1": {
                "function": NISTFunction.DETECT,
                "category_id": "DE.CM",
                "category_name": "Security Continuous Monitoring",
                "subcategory_name": "Network monitored to detect potential cybersecurity events"
            },
            "DE.CM-4": {
                "function": NISTFunction.DETECT,
                "category_id": "DE.CM",
                "category_name": "Security Continuous Monitoring",
                "subcategory_name": "Malicious code detected"
            },
            "DE.CM-7": {
                "function": NISTFunction.DETECT,
                "category_id": "DE.CM",
                "category_name": "Security Continuous Monitoring",
                "subcategory_name": "Monitoring for unauthorized personnel, connections, devices, software"
            },
            "DE.CM-8": {
                "function": NISTFunction.DETECT,
                "category_id": "DE.CM",
                "category_name": "Security Continuous Monitoring",
                "subcategory_name": "Vulnerability scans performed"
            },
            "DE.DP-2": {
                "function": NISTFunction.DETECT,
                "category_id": "DE.DP",
                "category_name": "Detection Processes",
                "subcategory_name": "Detection activities comply with requirements"
            },

            # RESPOND (RS)
            "RS.RP-1": {
                "function": NISTFunction.RESPOND,
                "category_id": "RS.RP",
                "category_name": "Response Planning",
                "subcategory_name": "Response plan executed during or after an incident"
            },
            "RS.CO-2": {
                "function": NISTFunction.RESPOND,
                "category_id": "RS.CO",
                "category_name": "Communications",
                "subcategory_name": "Incidents reported consistent with established criteria"
            },
            "RS.AN-1": {
                "function": NISTFunction.RESPOND,
                "category_id": "RS.AN",
                "category_name": "Analysis",
                "subcategory_name": "Notifications from detection systems investigated"
            },
            "RS.AN-3": {
                "function": NISTFunction.RESPOND,
                "category_id": "RS.AN",
                "category_name": "Analysis",
                "subcategory_name": "Forensics performed"
            },
            "RS.MI-1": {
                "function": NISTFunction.RESPOND,
                "category_id": "RS.MI",
                "category_name": "Mitigation",
                "subcategory_name": "Incidents contained"
            },
            "RS.MI-2": {
                "function": NISTFunction.RESPOND,
                "category_id": "RS.MI",
                "category_name": "Mitigation",
                "subcategory_name": "Incidents mitigated"
            },
            "RS.MI-3": {
                "function": NISTFunction.RESPOND,
                "category_id": "RS.MI",
                "category_name": "Mitigation",
                "subcategory_name": "Newly identified vulnerabilities mitigated or documented as accepted risks"
            },

            # RECOVER (RC)
            "RC.RP-1": {
                "function": NISTFunction.RECOVER,
                "category_id": "RC.RP",
                "category_name": "Recovery Planning",
                "subcategory_name": "Recovery plan executed during or after a cybersecurity incident"
            },
            "RC.IM-1": {
                "function": NISTFunction.RECOVER,
                "category_id": "RC.IM",
                "category_name": "Improvements",
                "subcategory_name": "Recovery plans incorporate lessons learned"
            },
            "RC.IM-2": {
                "function": NISTFunction.RECOVER,
                "category_id": "RC.IM",
                "category_name": "Improvements",
                "subcategory_name": "Recovery strategies updated"
            },
        }

    def _initialize_attack_mapping(self) -> Dict[str, List[Dict[str, Any]]]:
        """Map attack types to NIST CSF subcategories"""
        return {
            "BRUTE_FORCE": [
                {"subcategory": "PR.AC-1", "severity": "HIGH"},
                {"subcategory": "PR.AC-7", "severity": "HIGH"},
                {"subcategory": "DE.CM-7", "severity": "MEDIUM"},
                {"subcategory": "RS.AN-1", "severity": "MEDIUM"}
            ],
            "SQL_INJECTION": [
                {"subcategory": "ID.RA-1", "severity": "CRITICAL"},
                {"subcategory": "PR.IP-12", "severity": "CRITICAL"},
                {"subcategory": "PR.DS-5", "severity": "HIGH"},
                {"subcategory": "DE.CM-1", "severity": "HIGH"}
            ],
            "XSS": [
                {"subcategory": "ID.RA-1", "severity": "HIGH"},
                {"subcategory": "PR.IP-12", "severity": "HIGH"},
                {"subcategory": "DE.CM-1", "severity": "MEDIUM"}
            ],
            "COMMAND_INJECTION": [
                {"subcategory": "PR.AC-4", "severity": "CRITICAL"},
                {"subcategory": "PR.IP-12", "severity": "CRITICAL"},
                {"subcategory": "DE.CM-7", "severity": "HIGH"}
            ],
            "UNAUTHORIZED_ACCESS": [
                {"subcategory": "PR.AC-1", "severity": "HIGH"},
                {"subcategory": "PR.AC-4", "severity": "HIGH"},
                {"subcategory": "PR.PT-1", "severity": "MEDIUM"},
                {"subcategory": "DE.CM-7", "severity": "MEDIUM"}
            ],
            "PRIVILEGE_ESCALATION": [
                {"subcategory": "PR.AC-4", "severity": "CRITICAL"},
                {"subcategory": "PR.PT-1", "severity": "HIGH"},
                {"subcategory": "DE.CM-7", "severity": "HIGH"}
            ],
            "MALWARE": [
                {"subcategory": "DE.CM-4", "severity": "HIGH"},
                {"subcategory": "RS.MI-1", "severity": "HIGH"},
                {"subcategory": "RS.MI-2", "severity": "MEDIUM"},
                {"subcategory": "RC.RP-1", "severity": "MEDIUM"}
            ],
            "PORT_SCAN": [
                {"subcategory": "PR.AC-5", "severity": "MEDIUM"},
                {"subcategory": "DE.CM-1", "severity": "MEDIUM"},
                {"subcategory": "DE.AE-1", "severity": "LOW"}
            ],
            "DATA_EXFILTRATION": [
                {"subcategory": "PR.DS-5", "severity": "CRITICAL"},
                {"subcategory": "DE.AE-2", "severity": "CRITICAL"},
                {"subcategory": "RS.AN-3", "severity": "HIGH"},
                {"subcategory": "RS.CO-2", "severity": "HIGH"}
            ],
            "DOS_ATTACK": [
                {"subcategory": "PR.PT-4", "severity": "HIGH"},
                {"subcategory": "DE.AE-1", "severity": "MEDIUM"},
                {"subcategory": "RS.MI-1", "severity": "MEDIUM"}
            ],
            "ENCRYPTION_BYPASS": [
                {"subcategory": "PR.DS-1", "severity": "CRITICAL"},
                {"subcategory": "PR.DS-2", "severity": "CRITICAL"},
                {"subcategory": "RS.AN-1", "severity": "HIGH"}
            ],
            "CREDENTIAL_THEFT": [
                {"subcategory": "PR.AC-1", "severity": "CRITICAL"},
                {"subcategory": "PR.DS-1", "severity": "CRITICAL"},
                {"subcategory": "RS.CO-2", "severity": "HIGH"}
            ],
            "UNPATCHED_VULNERABILITY": [
                {"subcategory": "ID.RA-1", "severity": "HIGH"},
                {"subcategory": "PR.IP-12", "severity": "HIGH"},
                {"subcategory": "DE.CM-8", "severity": "MEDIUM"},
                {"subcategory": "RS.MI-3", "severity": "MEDIUM"}
            ],
        }

    def detect_violations(self, attack_events: List[Any]) -> List[NISTViolation]:
        """
        Detect NIST CSF compliance gaps from attack events

        Args:
            attack_events: List of attack events

        Returns:
            List of detected gaps/violations
        """
        violations = []
        gap_candidates = {}

        for event in attack_events:
            attack_type = str(event.attack_type).replace("AttackType.", "")

            # Get NIST subcategories for this attack
            nist_mappings = self.attack_to_nist_map.get(attack_type, [])

            for mapping in nist_mappings:
                subcategory_id = mapping["subcategory"]
                severity = mapping["severity"]

                if subcategory_id not in self.subcategories:
                    continue

                subcat = self.subcategories[subcategory_id]

                # Create unique gap key
                gap_key = f"{subcategory_id}_{event.agent_name}"

                if gap_key not in gap_candidates:
                    gap_candidates[gap_key] = {
                        "subcategory_id": subcategory_id,
                        "subcategory": subcat,
                        "severity": severity,
                        "events": [],
                        "affected_systems": set()
                    }

                gap_candidates[gap_key]["events"].append(event)
                gap_candidates[gap_key]["affected_systems"].add(event.agent_name)

        # Generate violations from candidates
        for gap_key, data in gap_candidates.items():
            subcategory_id = data["subcategory_id"]
            subcat = data["subcategory"]
            events = data["events"]
            event_count = len(events)

            # Assess current maturity (0-4 scale)
            # More events = lower maturity
            if event_count >= 50:
                current_maturity = 0  # Partial/Ad-hoc
            elif event_count >= 20:
                current_maturity = 1  # Risk Informed
            elif event_count >= 5:
                current_maturity = 2  # Repeatable
            else:
                current_maturity = 3  # Adaptive

            # Target maturity (typically 3 for most organizations)
            target_maturity = 3

            gap = target_maturity - current_maturity

            # Create violation
            violation = NISTViolation(
                violation_id=f"NIST-{subcategory_id.replace('.', '-')}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                function=subcat["function"],
                category_id=subcat["category_id"],
                category_name=subcat["category_name"],
                subcategory_id=subcategory_id,
                subcategory_name=subcat["subcategory_name"],
                severity=data["severity"],
                description=f"{subcat['subcategory_name']} - {event_count} security events indicate gap",
                current_maturity=current_maturity,
                target_maturity=target_maturity,
                gap=gap,
                evidence=[f"{e.attack_type} from {e.ip_address} at {e.timestamp}" for e in events[:5]],
                affected_systems=list(data["affected_systems"]),
                remediation=self._generate_remediation(subcategory_id, current_maturity, target_maturity),
                compliance_impact=f"NIST CSF {subcategory_id} - Maturity gap of {gap} tier(s)"
            )

            violations.append(violation)

        self.violations.extend(violations)
        return violations

    def _generate_remediation(self, subcategory_id: str, current: int, target: int) -> str:
        """Generate remediation recommendations"""

        remediations = {
            "PR.AC-1": "Implement identity and access management (IAM) system, enforce MFA, regular access reviews",
            "PR.AC-3": "Deploy VPN with MFA, implement zero-trust network access (ZTNA), monitor remote sessions",
            "PR.AC-4": "Implement RBAC, principle of least privilege, quarterly access reviews, just-in-time access",
            "PR.AC-5": "Deploy network segmentation, microsegmentation, VLANs, firewall rules between zones",
            "PR.AC-7": "Implement 802.1X authentication, certificate-based authentication, NAC solutions",
            "PR.DS-1": "Encrypt data at rest (AES-256), implement full-disk encryption, database encryption",
            "PR.DS-2": "Enforce TLS 1.3 for all connections, implement VPN, encrypt email",
            "PR.DS-5": "Deploy DLP solution, monitor egress traffic, implement data classification",
            "PR.IP-1": "Document security baselines, implement configuration management, use CIS Benchmarks",
            "PR.IP-12": "Implement vulnerability management program, monthly scans, patch within SLA (7/30/90 days)",
            "PR.PT-1": "Enable comprehensive logging, implement SIEM, retain logs for 1 year minimum",
            "PR.PT-3": "Disable unnecessary services, harden systems per STIG/CIS, minimal attack surface",
            "PR.PT-4": "Segment OT/IT networks, deploy IDS/IPS, encrypted protocols only",
            "DE.AE-1": "Establish network baseline, deploy anomaly detection, behavioral analytics",
            "DE.AE-2": "Implement SIEM correlation rules, threat intelligence integration, automated analysis",
            "DE.AE-3": "Deploy SIEM with multi-source correlation, integrate EDR/NDR/cloud logs",
            "DE.CM-1": "Deploy NDR solution, enable NetFlow, implement full packet capture for critical segments",
            "DE.CM-4": "Deploy EDR on all endpoints, sandbox analysis, threat hunting program",
            "DE.CM-7": "Implement NAC, monitor for rogue devices, audit software inventory",
            "DE.CM-8": "Conduct monthly vulnerability scans, annual penetration tests, continuous scanning",
            "RS.RP-1": "Develop incident response plan, conduct tabletop exercises quarterly, 24/7 SOC coverage",
            "RS.CO-2": "Implement incident reporting procedure, integrate with ticketing, defined SLAs",
            "RS.AN-1": "Establish SOC with 24/7 coverage, automated alert triage, playbooks for common incidents",
            "RS.AN-3": "Train forensic investigators, acquire forensic tools (FTK, EnCase), retain evidence",
            "RS.MI-1": "Develop containment procedures, automated isolation capabilities, network quarantine",
            "RS.MI-2": "Implement automated remediation where possible, patching procedures, IOC blocking",
            "RS.MI-3": "Track vulnerabilities in risk register, implement compensating controls, accept/mitigate decision framework",
            "RC.RP-1": "Develop disaster recovery plan, test backups quarterly, document RTO/RPO",
            "RC.IM-1": "Conduct post-incident reviews, document lessons learned, update procedures",
            "RC.IM-2": "Review recovery strategies annually, update based on threat landscape, test annually",
        }

        base_remediation = remediations.get(subcategory_id, "Implement NIST CSF subcategory controls")

        gap = target - current
        if gap >= 3:
            return f"{base_remediation} | URGENT: Major maturity gap - implement immediately"
        elif gap == 2:
            return f"{base_remediation} | HIGH PRIORITY: Significant gap - implement within 90 days"
        elif gap == 1:
            return f"{base_remediation} | MEDIUM PRIORITY: Improve to target maturity within 180 days"
        else:
            return f"{base_remediation} | MAINTAIN: Continue current practices"

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate NIST CSF compliance report"""

        # Group by function
        by_function = {}
        for violation in self.violations:
            func = violation.function.value
            if func not in by_function:
                by_function[func] = []
            by_function[func].append(violation)

        # Calculate maturity by function
        function_maturity = {}
        for func in NISTFunction:
            func_violations = [v for v in self.violations if v.function == func]
            if func_violations:
                avg_maturity = sum(v.current_maturity for v in func_violations) / len(func_violations)
                function_maturity[func.value] = round(avg_maturity, 1)
            else:
                function_maturity[func.value] = 4.0  # No violations = excellent

        # Overall maturity
        if self.violations:
            overall_maturity = sum(v.current_maturity for v in self.violations) / len(self.violations)
        else:
            overall_maturity = 4.0

        # Count by severity
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for violation in self.violations:
            by_severity[violation.severity] += 1

        # Determine implementation tier
        if overall_maturity >= 3.5:
            current_tier = NISTTier.TIER_4_ADAPTIVE
        elif overall_maturity >= 2.5:
            current_tier = NISTTier.TIER_3_REPEATABLE
        elif overall_maturity >= 1.5:
            current_tier = NISTTier.TIER_2_RISK_INFORMED
        else:
            current_tier = NISTTier.TIER_1_PARTIAL

        report = {
            "report_type": "NIST Cybersecurity Framework Assessment",
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": {
                "overall_maturity": round(overall_maturity, 2),
                "current_tier": current_tier.value,
                "target_tier": "Tier 3 - Repeatable",
                "total_gaps": len(self.violations),
                "critical_gaps": by_severity["CRITICAL"],
                "high_gaps": by_severity["HIGH"]
            },
            "function_maturity": function_maturity,
            "gaps_by_function": {func: len(viols) for func, viols in by_function.items()},
            "gaps_by_severity": by_severity,
            "critical_gaps": [
                {
                    "violation_id": v.violation_id,
                    "function": v.function.value,
                    "category": v.category_name,
                    "subcategory_id": v.subcategory_id,
                    "subcategory_name": v.subcategory_name,
                    "current_maturity": v.current_maturity,
                    "target_maturity": v.target_maturity,
                    "gap": v.gap,
                    "remediation": v.remediation
                }
                for v in self.violations if v.severity == "CRITICAL"
            ],
            "maturity_roadmap": self._generate_maturity_roadmap(overall_maturity),
            "recommendations": self._generate_recommendations(overall_maturity, by_severity)
        }

        return report

    def _generate_maturity_roadmap(self, current_maturity: float) -> List[Dict[str, Any]]:
        """Generate roadmap to reach target maturity"""
        roadmap = []

        if current_maturity < 2.0:
            roadmap.append({
                "phase": "Phase 1 (0-6 months)",
                "target": "Tier 2 - Risk Informed",
                "actions": [
                    "Establish cybersecurity risk management processes",
                    "Implement basic security controls",
                    "Begin regular vulnerability assessments",
                    "Deploy SIEM for log collection"
                ]
            })

        if current_maturity < 3.0:
            roadmap.append({
                "phase": "Phase 2 (6-12 months)",
                "target": "Tier 3 - Repeatable",
                "actions": [
                    "Formalize security policies and procedures",
                    "Implement comprehensive access control",
                    "Deploy endpoint detection and response (EDR)",
                    "Establish 24/7 security monitoring",
                    "Conduct quarterly security assessments"
                ]
            })

        if current_maturity < 4.0:
            roadmap.append({
                "phase": "Phase 3 (12-24 months)",
                "target": "Tier 4 - Adaptive",
                "actions": [
                    "Implement continuous monitoring and improvement",
                    "Deploy advanced threat detection (behavioral analytics, ML)",
                    "Establish threat intelligence program",
                    "Automate incident response",
                    "Conduct annual penetration tests"
                ]
            })

        return roadmap

    def _generate_recommendations(self, maturity: float, by_severity: Dict[str, int]) -> List[str]:
        """Generate recommendations"""
        recommendations = []

        if by_severity["CRITICAL"] > 0:
            recommendations.append(
                f"URGENT: Address {by_severity['CRITICAL']} critical gaps immediately"
            )

        if maturity < 2.0:
            recommendations.append("Establish foundational cybersecurity risk management program")
            recommendations.append("Implement basic security controls across all five functions")

        elif maturity < 3.0:
            recommendations.append("Formalize security policies, procedures, and governance")
            recommendations.append("Achieve Tier 3 (Repeatable) maturity within 12 months")

        elif maturity < 4.0:
            recommendations.append("Implement continuous improvement processes")
            recommendations.append("Advance to Tier 4 (Adaptive) through automation and threat intelligence")

        recommendations.append("Conduct annual NIST CSF assessment")
        recommendations.append("Map controls to other frameworks (ISO 27001, NIST 800-53)")
        recommendations.append("Provide cybersecurity awareness training to all staff")

        return recommendations
