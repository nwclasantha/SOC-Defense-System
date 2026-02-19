"""
GDPR Compliance Violation Detector
Maps security incidents to GDPR articles and principles
Detects data breaches, privacy violations, and compliance gaps

Covers GDPR Articles:
- Art. 5: Principles relating to processing of personal data
- Art. 6: Lawfulness of processing
- Art. 13-14: Information to be provided
- Art. 15-22: Data subject rights
- Art. 25: Data protection by design and by default
- Art. 30: Records of processing activities
- Art. 32: Security of processing
- Art. 33-34: Data breach notification
- Art. 35: Data protection impact assessment
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

class GDPRArticle(Enum):
    """GDPR Articles"""
    ART_5_PRINCIPLES = "Art. 5"
    ART_6_LAWFULNESS = "Art. 6"
    ART_13_INFORMATION = "Art. 13"
    ART_15_ACCESS = "Art. 15"
    ART_16_RECTIFICATION = "Art. 16"
    ART_17_ERASURE = "Art. 17"
    ART_18_RESTRICTION = "Art. 18"
    ART_20_PORTABILITY = "Art. 20"
    ART_21_OBJECTION = "Art. 21"
    ART_25_DATA_PROTECTION_BY_DESIGN = "Art. 25"
    ART_30_RECORDS = "Art. 30"
    ART_32_SECURITY = "Art. 32"
    ART_33_BREACH_NOTIFICATION_DPA = "Art. 33"
    ART_34_BREACH_NOTIFICATION_SUBJECTS = "Art. 34"
    ART_35_DPIA = "Art. 35"

class GDPRPrinciple(Enum):
    """GDPR Principles (Art. 5)"""
    LAWFULNESS = "lawfulness_fairness_transparency"
    PURPOSE_LIMITATION = "purpose_limitation"
    DATA_MINIMIZATION = "data_minimization"
    ACCURACY = "accuracy"
    STORAGE_LIMITATION = "storage_limitation"
    INTEGRITY_CONFIDENTIALITY = "integrity_confidentiality"
    ACCOUNTABILITY = "accountability"

@dataclass
class GDPRViolation:
    """GDPR Compliance Violation"""
    violation_id: str
    article: GDPRArticle
    principle: Optional[GDPRPrinciple] = None
    severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    description: str = ""
    data_subjects_affected: int = 0
    personal_data_categories: List[str] = field(default_factory=list)
    breach_type: str = ""  # confidentiality, integrity, availability
    evidence: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    remediation: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)
    notification_required: bool = False
    notification_deadline: Optional[datetime] = None
    potential_fine: str = ""  # EUR amount estimate
    compliance_impact: str = ""

class GDPRComplianceDetector:
    """
    Detects GDPR compliance violations from security incidents
    Identifies data breaches and triggers notification requirements
    """

    def __init__(self):
        # GDPR requirements database
        self.requirements = self._initialize_requirements()

        # Attack type to GDPR violation mapping
        self.attack_to_gdpr_map = self._initialize_attack_mapping()

        # Violation database
        self.violations: List[GDPRViolation] = []

        # Data breach tracking (Art. 33/34)
        self.data_breaches: List[Dict[str, Any]] = []

    def _initialize_requirements(self) -> Dict[str, Dict[str, Any]]:
        """Initialize GDPR requirements database"""
        return {
            "Art. 5.1(a)": {
                "article": GDPRArticle.ART_5_PRINCIPLES,
                "principle": GDPRPrinciple.LAWFULNESS,
                "requirement": "Process personal data lawfully, fairly and transparently"
            },
            "Art. 5.1(b)": {
                "article": GDPRArticle.ART_5_PRINCIPLES,
                "principle": GDPRPrinciple.PURPOSE_LIMITATION,
                "requirement": "Collect data for specified, explicit and legitimate purposes"
            },
            "Art. 5.1(c)": {
                "article": GDPRArticle.ART_5_PRINCIPLES,
                "principle": GDPRPrinciple.DATA_MINIMIZATION,
                "requirement": "Collect only adequate, relevant and limited data"
            },
            "Art. 5.1(d)": {
                "article": GDPRArticle.ART_5_PRINCIPLES,
                "principle": GDPRPrinciple.ACCURACY,
                "requirement": "Ensure personal data is accurate and kept up to date"
            },
            "Art. 5.1(e)": {
                "article": GDPRArticle.ART_5_PRINCIPLES,
                "principle": GDPRPrinciple.STORAGE_LIMITATION,
                "requirement": "Keep data only as long as necessary"
            },
            "Art. 5.1(f)": {
                "article": GDPRArticle.ART_5_PRINCIPLES,
                "principle": GDPRPrinciple.INTEGRITY_CONFIDENTIALITY,
                "requirement": "Process data securely with appropriate technical and organizational measures"
            },
            "Art. 5.2": {
                "article": GDPRArticle.ART_5_PRINCIPLES,
                "principle": GDPRPrinciple.ACCOUNTABILITY,
                "requirement": "Be able to demonstrate compliance with GDPR principles"
            },
            "Art. 25.1": {
                "article": GDPRArticle.ART_25_DATA_PROTECTION_BY_DESIGN,
                "principle": None,
                "requirement": "Implement data protection by design and by default"
            },
            "Art. 30": {
                "article": GDPRArticle.ART_30_RECORDS,
                "principle": None,
                "requirement": "Maintain records of processing activities"
            },
            "Art. 32.1": {
                "article": GDPRArticle.ART_32_SECURITY,
                "principle": None,
                "requirement": "Implement appropriate technical and organizational security measures"
            },
            "Art. 32.1(a)": {
                "article": GDPRArticle.ART_32_SECURITY,
                "principle": None,
                "requirement": "Pseudonymization and encryption of personal data"
            },
            "Art. 32.1(b)": {
                "article": GDPRArticle.ART_32_SECURITY,
                "principle": None,
                "requirement": "Ensure ongoing confidentiality, integrity, availability and resilience"
            },
            "Art. 32.1(c)": {
                "article": GDPRArticle.ART_32_SECURITY,
                "principle": None,
                "requirement": "Ability to restore availability and access to data after incident"
            },
            "Art. 32.1(d)": {
                "article": GDPRArticle.ART_32_SECURITY,
                "principle": None,
                "requirement": "Process for regularly testing, assessing and evaluating security"
            },
            "Art. 33.1": {
                "article": GDPRArticle.ART_33_BREACH_NOTIFICATION_DPA,
                "principle": None,
                "requirement": "Notify supervisory authority of breach within 72 hours"
            },
            "Art. 34.1": {
                "article": GDPRArticle.ART_34_BREACH_NOTIFICATION_SUBJECTS,
                "principle": None,
                "requirement": "Notify data subjects without undue delay if high risk"
            },
        }

    def _initialize_attack_mapping(self) -> Dict[str, List[Dict[str, Any]]]:
        """Map attack types to GDPR violations"""
        return {
            "BRUTE_FORCE": [
                {"article": "Art. 32.1", "breach_type": "confidentiality", "severity": "HIGH"},
                {"article": "Art. 32.1(b)", "breach_type": "integrity", "severity": "HIGH"}
            ],
            "SQL_INJECTION": [
                {"article": "Art. 32.1", "breach_type": "confidentiality", "severity": "CRITICAL"},
                {"article": "Art. 5.1(f)", "breach_type": "confidentiality", "severity": "CRITICAL"},
                {"article": "Art. 25.1", "breach_type": "integrity", "severity": "HIGH"}
            ],
            "XSS": [
                {"article": "Art. 32.1", "breach_type": "confidentiality", "severity": "HIGH"},
                {"article": "Art. 25.1", "breach_type": "integrity", "severity": "MEDIUM"}
            ],
            "COMMAND_INJECTION": [
                {"article": "Art. 32.1", "breach_type": "confidentiality", "severity": "CRITICAL"},
                {"article": "Art. 32.1(b)", "breach_type": "integrity", "severity": "CRITICAL"}
            ],
            "DATA_EXFILTRATION": [
                {"article": "Art. 32.1", "breach_type": "confidentiality", "severity": "CRITICAL"},
                {"article": "Art. 5.1(f)", "breach_type": "confidentiality", "severity": "CRITICAL"},
                {"article": "Art. 33.1", "breach_type": "confidentiality", "severity": "CRITICAL"},
                {"article": "Art. 34.1", "breach_type": "confidentiality", "severity": "CRITICAL"}
            ],
            "UNAUTHORIZED_ACCESS": [
                {"article": "Art. 32.1", "breach_type": "confidentiality", "severity": "HIGH"},
                {"article": "Art. 5.1(f)", "breach_type": "confidentiality", "severity": "HIGH"}
            ],
            "CREDENTIAL_THEFT": [
                {"article": "Art. 32.1", "breach_type": "confidentiality", "severity": "CRITICAL"},
                {"article": "Art. 32.1(a)", "breach_type": "confidentiality", "severity": "CRITICAL"},
                {"article": "Art. 33.1", "breach_type": "confidentiality", "severity": "CRITICAL"}
            ],
            "ENCRYPTION_BYPASS": [
                {"article": "Art. 32.1(a)", "breach_type": "confidentiality", "severity": "CRITICAL"},
                {"article": "Art. 5.1(f)", "breach_type": "confidentiality", "severity": "CRITICAL"}
            ],
            "MALWARE": [
                {"article": "Art. 32.1", "breach_type": "integrity", "severity": "HIGH"},
                {"article": "Art. 32.1(b)", "breach_type": "availability", "severity": "HIGH"}
            ],
            "RANSOMWARE": [
                {"article": "Art. 32.1(b)", "breach_type": "availability", "severity": "CRITICAL"},
                {"article": "Art. 32.1(c)", "breach_type": "availability", "severity": "CRITICAL"},
                {"article": "Art. 33.1", "breach_type": "availability", "severity": "CRITICAL"},
                {"article": "Art. 34.1", "breach_type": "availability", "severity": "CRITICAL"}
            ],
            "DOS_ATTACK": [
                {"article": "Art. 32.1(b)", "breach_type": "availability", "severity": "MEDIUM"},
            ],
            "LOG_TAMPERING": [
                {"article": "Art. 5.2", "breach_type": "integrity", "severity": "HIGH"},
                {"article": "Art. 32.1(d)", "breach_type": "integrity", "severity": "HIGH"}
            ],
        }

    def detect_violations(self, attack_events: List[Any]) -> List[GDPRViolation]:
        """
        Detect GDPR violations from attack events

        Args:
            attack_events: List of attack events

        Returns:
            List of detected violations
        """
        violations = []
        breach_candidates = {}

        for event in attack_events:
            attack_type = str(event.attack_type).replace("AttackType.", "")

            # Get GDPR violations for this attack type
            gdpr_mappings = self.attack_to_gdpr_map.get(attack_type, [])

            for mapping in gdpr_mappings:
                article_ref = mapping["article"]
                breach_type = mapping["breach_type"]
                severity = mapping["severity"]

                if article_ref not in self.requirements:
                    continue

                req = self.requirements[article_ref]

                # Create unique violation key
                violation_key = f"{article_ref}_{event.agent_name}_{breach_type}"

                if violation_key not in breach_candidates:
                    breach_candidates[violation_key] = {
                        "article_ref": article_ref,
                        "requirement": req,
                        "breach_type": breach_type,
                        "severity": severity,
                        "events": [],
                        "affected_systems": set(),
                        "ip_addresses": set()
                    }

                breach_candidates[violation_key]["events"].append(event)
                breach_candidates[violation_key]["affected_systems"].add(event.agent_name)
                breach_candidates[violation_key]["ip_addresses"].add(event.ip_address)

        # Generate violations from candidates
        for violation_key, data in breach_candidates.items():
            article_ref = data["article_ref"]
            req = data["requirement"]
            events = data["events"]
            event_count = len(events)

            # Estimate data subjects affected (conservative estimate)
            data_subjects_affected = event_count * 10  # Rough estimate

            # Check if notification required (Art. 33/34)
            notification_required = False
            notification_deadline = None

            if article_ref in ["Art. 33.1", "Art. 34.1"]:
                notification_required = True
                # 72 hours for supervisory authority (Art. 33)
                notification_deadline = datetime.utcnow() + timedelta(hours=72)

            # Estimate potential fine
            potential_fine = self._estimate_fine(data["severity"], data_subjects_affected, article_ref)

            # Create violation
            violation = GDPRViolation(
                violation_id=f"GDPR-{article_ref.replace('. ', '-').replace('(', '-').replace(')', '')}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                article=req["article"],
                principle=req.get("principle"),
                severity=data["severity"],
                description=f"{req['requirement']} - {event_count} security events detected",
                data_subjects_affected=data_subjects_affected,
                personal_data_categories=self._identify_data_categories(events),
                breach_type=data["breach_type"],
                evidence=[f"{e.attack_type} from {e.ip_address} at {e.timestamp}" for e in events[:5]],
                affected_systems=list(data["affected_systems"]),
                remediation=self._generate_remediation(article_ref, data["breach_type"]),
                notification_required=notification_required,
                notification_deadline=notification_deadline,
                potential_fine=potential_fine,
                compliance_impact=f"GDPR {article_ref} violation - {req['requirement']}"
            )

            violations.append(violation)

            # Track data breaches separately
            if notification_required:
                self.data_breaches.append({
                    "breach_id": violation.violation_id,
                    "detected_at": violation.detected_at,
                    "breach_type": data["breach_type"],
                    "data_subjects_affected": data_subjects_affected,
                    "notification_deadline": notification_deadline,
                    "notified_dpa": False,
                    "notified_subjects": False,
                    "severity": data["severity"]
                })

        self.violations.extend(violations)
        return violations

    def _identify_data_categories(self, events: List[Any]) -> List[str]:
        """Identify categories of personal data potentially affected"""
        categories = set()

        for event in events:
            # Check attack type
            attack_type = str(event.attack_type)

            if "CREDENTIAL" in attack_type or "AUTHENTICATION" in attack_type:
                categories.add("Authentication credentials")
                categories.add("User identifiers")

            if "SQL" in attack_type or "DATA" in attack_type:
                categories.add("Database records")
                categories.add("Personal identifiers")

            # Add common categories
            categories.add("IP addresses")
            categories.add("System access logs")

        return list(categories)

    def _estimate_fine(self, severity: str, data_subjects: int, article: str) -> str:
        """Estimate potential GDPR fine"""

        # GDPR fines: up to €20M or 4% of global annual turnover (Art. 83)
        # Higher tier: Art. 5, 6, 7, 9 violations
        # Lower tier: Art. 8, 11, 25-39, 42, 43 violations

        if severity == "CRITICAL":
            if data_subjects >= 1000:
                return "€500,000 - €5,000,000 (Large-scale breach)"
            elif data_subjects >= 100:
                return "€100,000 - €500,000 (Significant breach)"
            else:
                return "€50,000 - €100,000 (Moderate breach)"

        elif severity == "HIGH":
            if data_subjects >= 1000:
                return "€100,000 - €500,000"
            elif data_subjects >= 100:
                return "€50,000 - €100,000"
            else:
                return "€10,000 - €50,000"

        elif severity == "MEDIUM":
            return "€5,000 - €50,000"

        else:  # LOW
            return "€1,000 - €10,000"

    def _generate_remediation(self, article: str, breach_type: str) -> str:
        """Generate remediation recommendations"""

        remediations = {
            "Art. 32.1": "Implement comprehensive security measures: encryption, access controls, monitoring, incident response",
            "Art. 32.1(a)": "Deploy encryption for personal data at rest (AES-256) and in transit (TLS 1.3), implement pseudonymization where possible",
            "Art. 32.1(b)": "Ensure system resilience through redundancy, backup systems, failover mechanisms, and regular security testing",
            "Art. 32.1(c)": "Implement disaster recovery procedures, test backup restoration, document recovery time objectives (RTO < 24hrs)",
            "Art. 32.1(d)": "Conduct quarterly security assessments, annual penetration tests, monthly vulnerability scans",
            "Art. 5.1(f)": "Strengthen security controls: multi-factor authentication, network segmentation, endpoint protection",
            "Art. 33.1": "URGENT: Notify supervisory authority (DPA) within 72 hours, document breach details, nature, and consequences",
            "Art. 34.1": "URGENT: Notify affected data subjects without undue delay, provide clear information about breach and mitigation",
            "Art. 25.1": "Implement privacy by design: conduct DPIA, minimize data collection, default to privacy-friendly settings",
            "Art. 5.2": "Document all security measures, maintain audit logs, conduct regular compliance reviews",
        }

        return remediations.get(article, "Review GDPR requirements and implement necessary technical and organizational measures")

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate GDPR compliance report"""

        # Count by severity
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for violation in self.violations:
            by_severity[violation.severity] += 1

        # Count by article
        by_article = {}
        for violation in self.violations:
            article = violation.article.value
            by_article[article] = by_article.get(article, 0) + 1

        # Count by breach type
        by_breach_type = {"confidentiality": 0, "integrity": 0, "availability": 0}
        for violation in self.violations:
            by_breach_type[violation.breach_type] += 1

        # Total data subjects affected
        total_data_subjects = sum(v.data_subjects_affected for v in self.violations)

        # Notifications required
        notifications_required = [v for v in self.violations if v.notification_required]

        # Calculate compliance status
        gdpr_ready = (by_severity["CRITICAL"] == 0 and
                     by_severity["HIGH"] == 0 and
                     len(notifications_required) == 0)

        report = {
            "report_type": "GDPR Compliance Assessment",
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": {
                "gdpr_compliant": gdpr_ready,
                "total_violations": len(self.violations),
                "critical_violations": by_severity["CRITICAL"],
                "high_violations": by_severity["HIGH"],
                "data_breaches": len(self.data_breaches),
                "data_subjects_affected": total_data_subjects,
                "notifications_required": len(notifications_required),
                "compliance_score": self._calculate_compliance_score()
            },
            "violations_by_severity": by_severity,
            "violations_by_article": by_article,
            "violations_by_breach_type": by_breach_type,
            "data_breaches": [
                {
                    "breach_id": b["breach_id"],
                    "detected_at": b["detected_at"].isoformat(),
                    "breach_type": b["breach_type"],
                    "data_subjects_affected": b["data_subjects_affected"],
                    "notification_deadline": b["notification_deadline"].isoformat() if b["notification_deadline"] else None,
                    "severity": b["severity"]
                }
                for b in self.data_breaches
            ],
            "critical_violations": [
                {
                    "violation_id": v.violation_id,
                    "article": v.article.value,
                    "description": v.description,
                    "breach_type": v.breach_type,
                    "data_subjects_affected": v.data_subjects_affected,
                    "notification_required": v.notification_required,
                    "notification_deadline": v.notification_deadline.isoformat() if v.notification_deadline else None,
                    "potential_fine": v.potential_fine,
                    "remediation": v.remediation
                }
                for v in self.violations if v.severity == "CRITICAL"
            ],
            "gdpr_principles_status": self._assess_principles(),
            "data_subject_rights": {
                "right_to_access": "implemented",
                "right_to_rectification": "implemented",
                "right_to_erasure": "implemented",
                "right_to_portability": "implemented",
                "right_to_object": "implemented"
            },
            "recommendations": self._generate_recommendations(by_severity, notifications_required),
            "dpo_contact": "dpo@organization.com",
            "supervisory_authority": "National DPA"
        }

        return report

    def _calculate_compliance_score(self) -> float:
        """Calculate overall GDPR compliance score"""
        if len(self.violations) == 0:
            return 100.0

        # Penalty points by severity
        penalty_points = {
            "CRITICAL": 10,
            "HIGH": 5,
            "MEDIUM": 2,
            "LOW": 1
        }

        total_penalty = sum(penalty_points.get(v.severity, 0) for v in self.violations)

        # Max score is 100, deduct penalties
        score = max(0, 100 - total_penalty)

        return round(score, 2)

    def _assess_principles(self) -> Dict[str, str]:
        """Assess compliance with GDPR principles"""
        principles_status = {}

        for principle in GDPRPrinciple:
            violations_for_principle = [
                v for v in self.violations
                if v.principle == principle and v.severity in ["CRITICAL", "HIGH"]
            ]

            if len(violations_for_principle) == 0:
                principles_status[principle.value] = "compliant"
            elif any(v.severity == "CRITICAL" for v in violations_for_principle):
                principles_status[principle.value] = "non_compliant"
            else:
                principles_status[principle.value] = "needs_improvement"

        return principles_status

    def _generate_recommendations(self, by_severity: Dict[str, int],
                                 notifications: List[GDPRViolation]) -> List[str]:
        """Generate recommendations"""
        recommendations = []

        if len(notifications) > 0:
            recommendations.append(
                f"URGENT: {len(notifications)} data breaches require notification to DPA within 72 hours (Art. 33)"
            )

        if by_severity["CRITICAL"] > 0:
            recommendations.append(
                f"CRITICAL: Address {by_severity['CRITICAL']} critical violations immediately to avoid substantial fines"
            )

        if by_severity["HIGH"] > 0:
            recommendations.append(
                f"Address {by_severity['HIGH']} high-severity violations within 30 days"
            )

        recommendations.append("Conduct Data Protection Impact Assessment (DPIA) for high-risk processing")
        recommendations.append("Appoint or consult Data Protection Officer (DPO)")
        recommendations.append("Update privacy policy and data processing agreements")
        recommendations.append("Implement data subject rights procedures (access, erasure, portability)")
        recommendations.append("Conduct annual GDPR compliance audit")

        return recommendations

    def check_notification_deadlines(self) -> List[Dict[str, Any]]:
        """Check which breaches have approaching notification deadlines"""
        upcoming_deadlines = []

        for breach in self.data_breaches:
            if breach["notification_deadline"]:
                hours_remaining = (breach["notification_deadline"] - datetime.utcnow()).total_seconds() / 3600

                if hours_remaining > 0:
                    upcoming_deadlines.append({
                        "breach_id": breach["breach_id"],
                        "hours_remaining": round(hours_remaining, 2),
                        "deadline": breach["notification_deadline"].isoformat(),
                        "severity": breach["severity"],
                        "data_subjects_affected": breach["data_subjects_affected"]
                    })

        # Sort by deadline (most urgent first)
        upcoming_deadlines.sort(key=lambda x: x["hours_remaining"])

        return upcoming_deadlines
