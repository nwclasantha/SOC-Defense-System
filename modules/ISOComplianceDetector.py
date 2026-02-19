"""
ISO 27001/27002 Compliance Violation Detector
Maps security incidents to ISO 27001:2013 Annex A controls
Detects compliance violations and generates remediation recommendations

Covers all 14 domains of ISO 27001 Annex A:
- A.5: Information Security Policies
- A.6: Organization of Information Security
- A.7: Human Resource Security
- A.8: Asset Management
- A.9: Access Control
- A.10: Cryptography
- A.11: Physical and Environmental Security
- A.12: Operations Security
- A.13: Communications Security
- A.14: System Acquisition, Development and Maintenance
- A.15: Supplier Relationships
- A.16: Information Security Incident Management
- A.17: Business Continuity Management
- A.18: Compliance
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

class ISODomain(Enum):
    """ISO 27001 Annex A Domains"""
    POLICIES = "A.5"
    ORGANIZATION = "A.6"
    HUMAN_RESOURCES = "A.7"
    ASSET_MANAGEMENT = "A.8"
    ACCESS_CONTROL = "A.9"
    CRYPTOGRAPHY = "A.10"
    PHYSICAL_SECURITY = "A.11"
    OPERATIONS_SECURITY = "A.12"
    COMMUNICATIONS_SECURITY = "A.13"
    SYSTEM_DEVELOPMENT = "A.14"
    SUPPLIER_RELATIONSHIPS = "A.15"
    INCIDENT_MANAGEMENT = "A.16"
    BUSINESS_CONTINUITY = "A.17"
    COMPLIANCE = "A.18"

@dataclass
class ISOViolation:
    """ISO 27001 Compliance Violation"""
    violation_id: str
    control_id: str
    control_name: str
    domain: ISODomain
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    evidence: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    remediation: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)
    compliance_impact: str = ""

class ISOComplianceDetector:
    """
    Detects ISO 27001 compliance violations from security incidents
    Maps attacks to violated controls and generates remediation
    """

    def __init__(self):
        # ISO 27001:2013 Annex A Controls Database
        self.controls = self._initialize_controls()

        # Attack type to ISO control mapping
        self.attack_to_control_map = self._initialize_attack_mapping()

        # Violation database
        self.violations: List[ISOViolation] = []

    def _initialize_controls(self) -> Dict[str, Dict[str, Any]]:
        """Initialize ISO 27001 controls database"""
        return {
            # A.5 - Information Security Policies
            "A.5.1.1": {
                "name": "Policies for information security",
                "domain": ISODomain.POLICIES,
                "description": "Set of policies approved by management, published and communicated"
            },

            # A.6 - Organization of Information Security
            "A.6.1.1": {
                "name": "Information security roles and responsibilities",
                "domain": ISODomain.ORGANIZATION,
                "description": "All information security responsibilities defined and allocated"
            },
            "A.6.1.5": {
                "name": "Information security in project management",
                "domain": ISODomain.ORGANIZATION,
                "description": "Information security addressed in project management"
            },

            # A.7 - Human Resource Security
            "A.7.1.1": {
                "name": "Screening",
                "domain": ISODomain.HUMAN_RESOURCES,
                "description": "Background verification checks on all candidates"
            },
            "A.7.2.2": {
                "name": "Information security awareness, education and training",
                "domain": ISODomain.HUMAN_RESOURCES,
                "description": "All employees receive appropriate awareness training"
            },

            # A.8 - Asset Management
            "A.8.1.1": {
                "name": "Inventory of assets",
                "domain": ISODomain.ASSET_MANAGEMENT,
                "description": "Assets associated with information and facilities identified"
            },
            "A.8.1.2": {
                "name": "Ownership of assets",
                "domain": ISODomain.ASSET_MANAGEMENT,
                "description": "Assets maintained in the inventory owned"
            },
            "A.8.2.3": {
                "name": "Handling of assets",
                "domain": ISODomain.ASSET_MANAGEMENT,
                "description": "Procedures for handling assets in accordance with classification"
            },

            # A.9 - Access Control
            "A.9.1.1": {
                "name": "Access control policy",
                "domain": ISODomain.ACCESS_CONTROL,
                "description": "Access control policy established, documented and reviewed"
            },
            "A.9.2.1": {
                "name": "User registration and de-registration",
                "domain": ISODomain.ACCESS_CONTROL,
                "description": "Formal user registration process to enable access"
            },
            "A.9.2.3": {
                "name": "Management of privileged access rights",
                "domain": ISODomain.ACCESS_CONTROL,
                "description": "Allocation and use of privileged access restricted and controlled"
            },
            "A.9.2.4": {
                "name": "Management of secret authentication information",
                "domain": ISODomain.ACCESS_CONTROL,
                "description": "Allocation of secret authentication information controlled"
            },
            "A.9.2.6": {
                "name": "Removal or adjustment of access rights",
                "domain": ISODomain.ACCESS_CONTROL,
                "description": "Access rights removed upon termination or change of employment"
            },
            "A.9.4.1": {
                "name": "Information access restriction",
                "domain": ISODomain.ACCESS_CONTROL,
                "description": "Access to information and systems restricted per access control policy"
            },
            "A.9.4.2": {
                "name": "Secure log-on procedures",
                "domain": ISODomain.ACCESS_CONTROL,
                "description": "Access to systems and applications controlled by secure log-on"
            },
            "A.9.4.3": {
                "name": "Password management system",
                "domain": ISODomain.ACCESS_CONTROL,
                "description": "Password management systems interactive and ensure quality passwords"
            },

            # A.10 - Cryptography
            "A.10.1.1": {
                "name": "Policy on the use of cryptographic controls",
                "domain": ISODomain.CRYPTOGRAPHY,
                "description": "Policy on use of cryptographic controls developed and implemented"
            },
            "A.10.1.2": {
                "name": "Key management",
                "domain": ISODomain.CRYPTOGRAPHY,
                "description": "Policy on use, protection and lifetime of cryptographic keys"
            },

            # A.11 - Physical and Environmental Security
            "A.11.1.1": {
                "name": "Physical security perimeter",
                "domain": ISODomain.PHYSICAL_SECURITY,
                "description": "Security perimeters defined to protect areas with information"
            },
            "A.11.2.1": {
                "name": "Equipment siting and protection",
                "domain": ISODomain.PHYSICAL_SECURITY,
                "description": "Equipment sited and protected to reduce environmental threats"
            },

            # A.12 - Operations Security
            "A.12.1.1": {
                "name": "Documented operating procedures",
                "domain": ISODomain.OPERATIONS_SECURITY,
                "description": "Operating procedures documented and made available to users"
            },
            "A.12.2.1": {
                "name": "Controls against malware",
                "domain": ISODomain.OPERATIONS_SECURITY,
                "description": "Detection, prevention and recovery controls to protect against malware"
            },
            "A.12.3.1": {
                "name": "Information backup",
                "domain": ISODomain.OPERATIONS_SECURITY,
                "description": "Backup copies of information, software and systems tested regularly"
            },
            "A.12.4.1": {
                "name": "Event logging",
                "domain": ISODomain.OPERATIONS_SECURITY,
                "description": "Event logs recording user activities, exceptions and security events"
            },
            "A.12.4.2": {
                "name": "Protection of log information",
                "domain": ISODomain.OPERATIONS_SECURITY,
                "description": "Logging facilities and log information protected against tampering"
            },
            "A.12.4.3": {
                "name": "Administrator and operator logs",
                "domain": ISODomain.OPERATIONS_SECURITY,
                "description": "System administrator and operator activities logged and reviewed"
            },
            "A.12.6.1": {
                "name": "Management of technical vulnerabilities",
                "domain": ISODomain.OPERATIONS_SECURITY,
                "description": "Timely information about technical vulnerabilities obtained"
            },
            "A.12.6.2": {
                "name": "Restrictions on software installation",
                "domain": ISODomain.OPERATIONS_SECURITY,
                "description": "Rules governing installation of software established and implemented"
            },

            # A.13 - Communications Security
            "A.13.1.1": {
                "name": "Network controls",
                "domain": ISODomain.COMMUNICATIONS_SECURITY,
                "description": "Networks managed and controlled to protect information"
            },
            "A.13.1.2": {
                "name": "Security of network services",
                "domain": ISODomain.COMMUNICATIONS_SECURITY,
                "description": "Security mechanisms, service levels and requirements identified"
            },
            "A.13.1.3": {
                "name": "Segregation in networks",
                "domain": ISODomain.COMMUNICATIONS_SECURITY,
                "description": "Groups of information services, users and systems segregated"
            },
            "A.13.2.1": {
                "name": "Information transfer policies and procedures",
                "domain": ISODomain.COMMUNICATIONS_SECURITY,
                "description": "Formal transfer policies, procedures and controls protect information"
            },

            # A.14 - System Acquisition, Development and Maintenance
            "A.14.2.1": {
                "name": "Secure development policy",
                "domain": ISODomain.SYSTEM_DEVELOPMENT,
                "description": "Rules for development of software and systems established"
            },
            "A.14.2.5": {
                "name": "Secure system engineering principles",
                "domain": ISODomain.SYSTEM_DEVELOPMENT,
                "description": "Principles for engineering secure systems established"
            },

            # A.15 - Supplier Relationships
            "A.15.1.1": {
                "name": "Information security policy for supplier relationships",
                "domain": ISODomain.SUPPLIER_RELATIONSHIPS,
                "description": "Security requirements for supplier relationships agreed"
            },

            # A.16 - Information Security Incident Management
            "A.16.1.1": {
                "name": "Responsibilities and procedures",
                "domain": ISODomain.INCIDENT_MANAGEMENT,
                "description": "Management responsibilities and procedures established"
            },
            "A.16.1.2": {
                "name": "Reporting information security events",
                "domain": ISODomain.INCIDENT_MANAGEMENT,
                "description": "Information security events reported through management channels"
            },
            "A.16.1.4": {
                "name": "Assessment of and decision on information security events",
                "domain": ISODomain.INCIDENT_MANAGEMENT,
                "description": "Security events assessed to determine if they are incidents"
            },
            "A.16.1.5": {
                "name": "Response to information security incidents",
                "domain": ISODomain.INCIDENT_MANAGEMENT,
                "description": "Information security incidents responded to per documented procedures"
            },
            "A.16.1.7": {
                "name": "Collection of evidence",
                "domain": ISODomain.INCIDENT_MANAGEMENT,
                "description": "Procedures for identification, collection, acquisition of evidence"
            },

            # A.17 - Business Continuity Management
            "A.17.1.1": {
                "name": "Planning information security continuity",
                "domain": ISODomain.BUSINESS_CONTINUITY,
                "description": "Requirements for information security and continuity determined"
            },

            # A.18 - Compliance
            "A.18.1.1": {
                "name": "Identification of applicable legislation and contractual requirements",
                "domain": ISODomain.COMPLIANCE,
                "description": "Statutory, regulatory and contractual requirements identified"
            },
            "A.18.1.5": {
                "name": "Regulation of cryptographic controls",
                "domain": ISODomain.COMPLIANCE,
                "description": "Cryptographic controls used in compliance with agreements and regulations"
            },
            "A.18.2.2": {
                "name": "Compliance with security policies and standards",
                "domain": ISODomain.COMPLIANCE,
                "description": "Managers regularly review compliance with security policies"
            },
            "A.18.2.3": {
                "name": "Technical compliance review",
                "domain": ISODomain.COMPLIANCE,
                "description": "Information systems regularly reviewed for compliance"
            },
        }

    def _initialize_attack_mapping(self) -> Dict[str, List[str]]:
        """Map attack types to violated ISO controls"""
        return {
            "BRUTE_FORCE": ["A.9.4.2", "A.9.4.3", "A.9.2.3", "A.12.4.1", "A.16.1.2"],
            "SQL_INJECTION": ["A.14.2.1", "A.14.2.5", "A.12.6.1", "A.13.1.1"],
            "XSS": ["A.14.2.1", "A.14.2.5", "A.12.6.1"],
            "COMMAND_INJECTION": ["A.14.2.1", "A.14.2.5", "A.9.4.1", "A.12.6.1"],
            "PATH_TRAVERSAL": ["A.9.4.1", "A.14.2.1", "A.12.6.1"],
            "AUTHENTICATION_FAILURE": ["A.9.2.4", "A.9.4.2", "A.9.4.3", "A.12.4.1"],
            "UNAUTHORIZED_ACCESS": ["A.9.1.1", "A.9.4.1", "A.12.4.1", "A.16.1.2"],
            "PRIVILEGE_ESCALATION": ["A.9.2.3", "A.9.2.6", "A.12.4.3", "A.16.1.2"],
            "DOS_ATTACK": ["A.13.1.1", "A.13.1.2", "A.17.1.1", "A.16.1.2"],
            "MALWARE": ["A.12.2.1", "A.12.6.2", "A.16.1.2", "A.16.1.5"],
            "PORT_SCAN": ["A.13.1.1", "A.12.4.1", "A.16.1.2"],
            "DATA_EXFILTRATION": ["A.9.4.1", "A.13.2.1", "A.16.1.2", "A.16.1.7"],
            "CREDENTIAL_THEFT": ["A.9.2.4", "A.10.1.1", "A.16.1.2", "A.16.1.7"],
            "ENCRYPTION_BYPASS": ["A.10.1.1", "A.10.1.2", "A.13.2.1", "A.18.1.5"],
            "LOG_TAMPERING": ["A.12.4.2", "A.12.4.3", "A.16.1.2"],
            "UNPATCHED_VULNERABILITY": ["A.12.6.1", "A.18.2.3"],
        }

    def detect_violations(self, attack_events: List[Any]) -> List[ISOViolation]:
        """
        Detect ISO 27001 violations from attack events

        Args:
            attack_events: List of attack events

        Returns:
            List of detected violations
        """
        violations = []
        violation_counter = {}

        for event in attack_events:
            attack_type = str(event.attack_type).replace("AttackType.", "")

            # Get violated controls for this attack type
            violated_controls = self.attack_to_control_map.get(attack_type, [])

            for control_id in violated_controls:
                if control_id not in self.controls:
                    continue

                control = self.controls[control_id]

                # Create unique violation key
                violation_key = f"{control_id}_{event.agent_name}"

                if violation_key not in violation_counter:
                    violation_counter[violation_key] = {
                        "control_id": control_id,
                        "control": control,
                        "events": [],
                        "affected_systems": set(),
                        "severity_scores": []
                    }

                violation_counter[violation_key]["events"].append(event)
                violation_counter[violation_key]["affected_systems"].add(event.agent_name)
                violation_counter[violation_key]["severity_scores"].append(event.rule_level)

        # Generate violations from aggregated data
        for violation_key, data in violation_counter.items():
            control_id = data["control_id"]
            control = data["control"]
            events = data["events"]

            # Calculate severity
            severity_scores = data["severity_scores"]
            avg_severity = sum(severity_scores) / len(severity_scores) if severity_scores else 0
            event_count = len(events)

            if avg_severity >= 15 or event_count >= 50:
                severity = "CRITICAL"
            elif avg_severity >= 12 or event_count >= 20:
                severity = "HIGH"
            elif avg_severity >= 10 or event_count >= 10:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Create violation
            violation = ISOViolation(
                violation_id=f"ISO-{control_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                control_id=control_id,
                control_name=control["name"],
                domain=control["domain"],
                severity=severity,
                description=f"{control['name']} violated by {event_count} attack events",
                evidence=[f"{e.attack_type} from {e.ip_address} at {e.timestamp}" for e in events[:5]],
                affected_systems=list(data["affected_systems"]),
                remediation=self._generate_remediation(control_id, events),
                compliance_impact=f"Non-compliance with ISO 27001:2013 {control_id}"
            )

            violations.append(violation)

        self.violations.extend(violations)
        return violations

    def _generate_remediation(self, control_id: str, events: List[Any]) -> str:
        """Generate remediation recommendations"""
        remediations = {
            "A.9.4.2": "Implement multi-factor authentication, enforce account lockout policies, deploy CAPTCHA",
            "A.9.4.3": "Enforce strong password policies (min 14 chars, complexity, rotation every 90 days)",
            "A.9.2.3": "Restrict privileged access, implement privileged access management (PAM), audit privileged actions",
            "A.12.4.1": "Enable comprehensive event logging, implement SIEM for log correlation",
            "A.16.1.2": "Activate incident response procedures, notify CISO and security team",
            "A.14.2.1": "Implement secure coding practices, conduct code reviews, use SAST/DAST tools",
            "A.14.2.5": "Apply security-by-design principles, conduct threat modeling",
            "A.12.6.1": "Implement vulnerability management program, apply patches within 30 days (critical: 7 days)",
            "A.13.1.1": "Deploy network segmentation, implement firewall rules, enable IDS/IPS",
            "A.12.2.1": "Deploy anti-malware on all endpoints, enable real-time protection, update signatures daily",
            "A.13.1.2": "Implement network service security baselines, disable unnecessary services",
            "A.9.4.1": "Enforce principle of least privilege, implement role-based access control (RBAC)",
            "A.10.1.1": "Implement encryption for data at rest and in transit (AES-256, TLS 1.3)",
            "A.10.1.2": "Deploy key management system (KMS), rotate keys annually",
            "A.12.4.2": "Protect logs with write-once-read-many (WORM) storage, implement log integrity monitoring",
            "A.12.4.3": "Enable privileged user activity logging, review logs monthly",
            "A.13.2.1": "Encrypt data transfers, implement secure file transfer protocols (SFTP, HTTPS)",
            "A.16.1.7": "Implement forensic evidence collection procedures, maintain chain of custody",
            "A.18.2.3": "Conduct quarterly technical compliance reviews and penetration tests",
        }

        return remediations.get(control_id, "Review and implement ISO 27001 control requirements")

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate ISO 27001 compliance report"""

        # Group violations by domain
        by_domain = {}
        for violation in self.violations:
            domain = violation.domain.value
            if domain not in by_domain:
                by_domain[domain] = []
            by_domain[domain].append(violation)

        # Count by severity
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for violation in self.violations:
            by_severity[violation.severity] += 1

        # Calculate compliance score
        total_controls = len(self.controls)
        violated_controls = len(set(v.control_id for v in self.violations))
        compliance_score = ((total_controls - violated_controls) / total_controls) * 100 if total_controls > 0 else 100

        # Certification readiness
        certification_ready = compliance_score >= 95 and by_severity["CRITICAL"] == 0

        report = {
            "report_type": "ISO 27001:2013 Compliance Assessment",
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": {
                "total_controls": total_controls,
                "violated_controls": violated_controls,
                "compliance_score": round(compliance_score, 2),
                "certification_ready": certification_ready,
                "total_violations": len(self.violations),
                "critical_violations": by_severity["CRITICAL"],
                "high_violations": by_severity["HIGH"],
                "medium_violations": by_severity["MEDIUM"],
                "low_violations": by_severity["LOW"]
            },
            "violations_by_domain": {
                domain: len(viols) for domain, viols in by_domain.items()
            },
            "violations_by_severity": by_severity,
            "critical_violations": [
                {
                    "violation_id": v.violation_id,
                    "control_id": v.control_id,
                    "control_name": v.control_name,
                    "domain": v.domain.value,
                    "description": v.description,
                    "affected_systems": v.affected_systems,
                    "remediation": v.remediation
                }
                for v in self.violations if v.severity == "CRITICAL"
            ],
            "recommendations": self._generate_recommendations(by_severity, certification_ready),
            "next_audit_date": (datetime.utcnow()).isoformat(),
            "isms_scope": "Security Operations Center (SOC) infrastructure and operations"
        }

        return report

    def _generate_recommendations(self, by_severity: Dict[str, int], cert_ready: bool) -> List[str]:
        """Generate recommendations"""
        recommendations = []

        if by_severity["CRITICAL"] > 0:
            recommendations.append(f"URGENT: Address {by_severity['CRITICAL']} critical violations within 7 days")

        if by_severity["HIGH"] > 0:
            recommendations.append(f"Address {by_severity['HIGH']} high severity violations within 30 days")

        if not cert_ready:
            recommendations.append("Achieve 95% compliance score and zero critical violations for certification")

        if by_severity["CRITICAL"] == 0 and by_severity["HIGH"] == 0:
            recommendations.append("Maintain current compliance posture through quarterly reviews")

        recommendations.append("Conduct annual ISO 27001 internal audit")
        recommendations.append("Review and update ISMS documentation quarterly")

        return recommendations

    def get_violations_by_system(self, system_name: str) -> List[ISOViolation]:
        """Get all violations affecting a specific system"""
        return [v for v in self.violations if system_name in v.affected_systems]

    def get_violations_by_severity(self, severity: str) -> List[ISOViolation]:
        """Get violations by severity level"""
        return [v for v in self.violations if v.severity == severity]

    def get_violations_by_domain(self, domain: ISODomain) -> List[ISOViolation]:
        """Get violations by ISO domain"""
        return [v for v in self.violations if v.domain == domain]
