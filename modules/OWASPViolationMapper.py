"""
OWASP Top 10 Violation Mapper
Maps security incidents to OWASP Top 10 2021 vulnerabilities
Identifies web application security gaps and generates remediation

OWASP Top 10 2021:
A01:2021 - Broken Access Control
A02:2021 - Cryptographic Failures
A03:2021 - Injection
A04:2021 - Insecure Design
A05:2021 - Security Misconfiguration
A06:2021 - Vulnerable and Outdated Components
A07:2021 - Identification and Authentication Failures
A08:2021 - Software and Data Integrity Failures
A09:2021 - Security Logging and Monitoring Failures
A10:2021 - Server-Side Request Forgery (SSRF)
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

class OWASPCategory(Enum):
    """OWASP Top 10 2021 Categories"""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021"
    A03_INJECTION = "A03:2021"
    A04_INSECURE_DESIGN = "A04:2021"
    A05_SECURITY_MISCONFIGURATION = "A05:2021"
    A06_VULNERABLE_COMPONENTS = "A06:2021"
    A07_AUTH_FAILURES = "A07:2021"
    A08_INTEGRITY_FAILURES = "A08:2021"
    A09_LOGGING_FAILURES = "A09:2021"
    A10_SSRF = "A10:2021"

@dataclass
class OWASPViolation:
    """OWASP Top 10 Violation"""
    violation_id: str
    category: OWASPCategory
    category_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cwe_ids: List[str]  # Common Weakness Enumeration IDs
    description: str
    attack_count: int = 0
    evidence: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    remediation: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)
    compliance_impact: str = ""
    exploitability: str = "Easy"  # Easy, Average, Difficult
    prevalence: str = "Common"  # Widespread, Common, Uncommon
    technical_impact: str = "Severe"  # Severe, Moderate, Minor

class OWASPViolationMapper:
    """
    Maps security incidents to OWASP Top 10 2021 vulnerabilities
    Provides web application security assessment
    """

    def __init__(self):
        # OWASP Top 10 database
        self.owasp_categories = self._initialize_categories()

        # Attack type to OWASP category mapping
        self.attack_to_owasp_map = self._initialize_attack_mapping()

        # Violation database
        self.violations: List[OWASPViolation] = []

    def _initialize_categories(self) -> Dict[str, Dict[str, Any]]:
        """Initialize OWASP Top 10 2021 categories"""
        return {
            "A01:2021": {
                "category": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                "name": "Broken Access Control",
                "description": "Restrictions on what authenticated users can do not properly enforced",
                "cwe_ids": ["CWE-200", "CWE-201", "CWE-352", "CWE-425", "CWE-522"],
                "exploitability": "Easy",
                "prevalence": "Widespread",
                "technical_impact": "Severe"
            },
            "A02:2021": {
                "category": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                "name": "Cryptographic Failures",
                "description": "Failures related to cryptography leading to exposure of sensitive data",
                "cwe_ids": ["CWE-259", "CWE-327", "CWE-311", "CWE-312", "CWE-319", "CWE-320", "CWE-321", "CWE-325"],
                "exploitability": "Average",
                "prevalence": "Common",
                "technical_impact": "Severe"
            },
            "A03:2021": {
                "category": OWASPCategory.A03_INJECTION,
                "name": "Injection",
                "description": "User-supplied data not validated, filtered, or sanitized",
                "cwe_ids": ["CWE-79", "CWE-89", "CWE-73", "CWE-77", "CWE-78", "CWE-94", "CWE-917"],
                "exploitability": "Easy",
                "prevalence": "Common",
                "technical_impact": "Severe"
            },
            "A04:2021": {
                "category": OWASPCategory.A04_INSECURE_DESIGN,
                "name": "Insecure Design",
                "description": "Missing or ineffective control design",
                "cwe_ids": ["CWE-209", "CWE-256", "CWE-501", "CWE-522"],
                "exploitability": "Average",
                "prevalence": "Common",
                "technical_impact": "Moderate"
            },
            "A05:2021": {
                "category": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                "name": "Security Misconfiguration",
                "description": "Missing security hardening or improperly configured permissions",
                "cwe_ids": ["CWE-16", "CWE-260", "CWE-311", "CWE-732", "CWE-656", "CWE-16"],
                "exploitability": "Easy",
                "prevalence": "Widespread",
                "technical_impact": "Moderate"
            },
            "A06:2021": {
                "category": OWASPCategory.A06_VULNERABLE_COMPONENTS,
                "name": "Vulnerable and Outdated Components",
                "description": "Using components with known vulnerabilities",
                "cwe_ids": ["CWE-1035", "CWE-1104", "CWE-937"],
                "exploitability": "Average",
                "prevalence": "Widespread",
                "technical_impact": "Moderate"
            },
            "A07:2021": {
                "category": OWASPCategory.A07_AUTH_FAILURES,
                "name": "Identification and Authentication Failures",
                "description": "Confirmation of user's identity, authentication, session management failures",
                "cwe_ids": ["CWE-297", "CWE-287", "CWE-384", "CWE-798", "CWE-640"],
                "exploitability": "Easy",
                "prevalence": "Common",
                "technical_impact": "Severe"
            },
            "A08:2021": {
                "category": OWASPCategory.A08_INTEGRITY_FAILURES,
                "name": "Software and Data Integrity Failures",
                "description": "Code and infrastructure not protected against integrity violations",
                "cwe_ids": ["CWE-502", "CWE-829", "CWE-494"],
                "exploitability": "Difficult",
                "prevalence": "Uncommon",
                "technical_impact": "Severe"
            },
            "A09:2021": {
                "category": OWASPCategory.A09_LOGGING_FAILURES,
                "name": "Security Logging and Monitoring Failures",
                "description": "Lack of logging, detection, monitoring, and active response",
                "cwe_ids": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
                "exploitability": "Difficult",
                "prevalence": "Widespread",
                "technical_impact": "Moderate"
            },
            "A10:2021": {
                "category": OWASPCategory.A10_SSRF,
                "name": "Server-Side Request Forgery (SSRF)",
                "description": "Web application fetching remote resource without validating user-supplied URL",
                "cwe_ids": ["CWE-918"],
                "exploitability": "Average",
                "prevalence": "Uncommon",
                "technical_impact": "Moderate"
            }
        }

    def _initialize_attack_mapping(self) -> Dict[str, List[Dict[str, Any]]]:
        """Map attack types to OWASP categories"""
        return {
            "SQL_INJECTION": [
                {"category": "A03:2021", "severity": "CRITICAL"}
            ],
            "XSS": [
                {"category": "A03:2021", "severity": "HIGH"}
            ],
            "COMMAND_INJECTION": [
                {"category": "A03:2021", "severity": "CRITICAL"}
            ],
            "PATH_TRAVERSAL": [
                {"category": "A01:2021", "severity": "HIGH"},
                {"category": "A03:2021", "severity": "HIGH"}
            ],
            "LDAP_INJECTION": [
                {"category": "A03:2021", "severity": "HIGH"}
            ],
            "XML_INJECTION": [
                {"category": "A03:2021", "severity": "HIGH"}
            ],
            "BRUTE_FORCE": [
                {"category": "A07:2021", "severity": "HIGH"}
            ],
            "AUTHENTICATION_FAILURE": [
                {"category": "A07:2021", "severity": "HIGH"}
            ],
            "SESSION_HIJACKING": [
                {"category": "A07:2021", "severity": "CRITICAL"}
            ],
            "CREDENTIAL_THEFT": [
                {"category": "A07:2021", "severity": "CRITICAL"},
                {"category": "A02:2021", "severity": "HIGH"}
            ],
            "UNAUTHORIZED_ACCESS": [
                {"category": "A01:2021", "severity": "HIGH"}
            ],
            "PRIVILEGE_ESCALATION": [
                {"category": "A01:2021", "severity": "CRITICAL"}
            ],
            "IDOR": [  # Insecure Direct Object Reference
                {"category": "A01:2021", "severity": "HIGH"}
            ],
            "ENCRYPTION_BYPASS": [
                {"category": "A02:2021", "severity": "CRITICAL"}
            ],
            "WEAK_CRYPTO": [
                {"category": "A02:2021", "severity": "HIGH"}
            ],
            "PLAINTEXT_TRANSMISSION": [
                {"category": "A02:2021", "severity": "HIGH"}
            ],
            "UNPATCHED_VULNERABILITY": [
                {"category": "A06:2021", "severity": "HIGH"}
            ],
            "OUTDATED_SOFTWARE": [
                {"category": "A06:2021", "severity": "MEDIUM"}
            ],
            "DEFAULT_CREDENTIALS": [
                {"category": "A05:2021", "severity": "CRITICAL"}
            ],
            "INFORMATION_DISCLOSURE": [
                {"category": "A05:2021", "severity": "MEDIUM"},
                {"category": "A04:2021", "severity": "MEDIUM"}
            ],
            "DIRECTORY_LISTING": [
                {"category": "A05:2021", "severity": "LOW"}
            ],
            "LOG_TAMPERING": [
                {"category": "A09:2021", "severity": "HIGH"}
            ],
            "INSUFFICIENT_LOGGING": [
                {"category": "A09:2021", "severity": "MEDIUM"}
            ],
            "MALWARE": [
                {"category": "A08:2021", "severity": "HIGH"}
            ],
            "DESERIALIZATION": [
                {"category": "A08:2021", "severity": "CRITICAL"}
            ],
            "SSRF": [
                {"category": "A10:2021", "severity": "HIGH"}
            ],
        }

    def map_violations(self, attack_events: List[Any]) -> List[OWASPViolation]:
        """
        Map attack events to OWASP Top 10 violations

        Args:
            attack_events: List of attack events

        Returns:
            List of OWASP violations
        """
        violations = []
        violation_candidates = {}

        for event in attack_events:
            attack_type = str(event.attack_type).replace("AttackType.", "")

            # Get OWASP categories for this attack
            owasp_mappings = self.attack_to_owasp_map.get(attack_type, [])

            for mapping in owasp_mappings:
                category_id = mapping["category"]
                severity = mapping["severity"]

                if category_id not in self.owasp_categories:
                    continue

                cat = self.owasp_categories[category_id]

                # Create unique violation key
                violation_key = f"{category_id}_{event.agent_name}"

                if violation_key not in violation_candidates:
                    violation_candidates[violation_key] = {
                        "category_id": category_id,
                        "category": cat,
                        "severity": severity,
                        "events": [],
                        "affected_systems": set()
                    }

                violation_candidates[violation_key]["events"].append(event)
                violation_candidates[violation_key]["affected_systems"].add(event.agent_name)

        # Generate violations from candidates
        for violation_key, data in violation_candidates.items():
            category_id = data["category_id"]
            cat = data["category"]
            events = data["events"]
            attack_count = len(events)

            # Create violation
            violation = OWASPViolation(
                violation_id=f"OWASP-{category_id.replace(':', '-')}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                category=cat["category"],
                category_name=cat["name"],
                severity=data["severity"],
                cwe_ids=cat["cwe_ids"],
                description=f"{cat['name']}: {cat['description']} - {attack_count} attacks detected",
                attack_count=attack_count,
                evidence=[f"{e.attack_type} from {e.ip_address} at {e.timestamp}" for e in events[:5]],
                affected_systems=list(data["affected_systems"]),
                remediation=self._generate_remediation(category_id),
                compliance_impact=f"OWASP Top 10 2021 {category_id} - {cat['name']}",
                exploitability=cat["exploitability"],
                prevalence=cat["prevalence"],
                technical_impact=cat["technical_impact"]
            )

            violations.append(violation)

        self.violations.extend(violations)
        return violations

    def _generate_remediation(self, category_id: str) -> str:
        """Generate remediation for OWASP category"""

        remediations = {
            "A01:2021": """Implement access control mechanisms:
                - Deny by default (least privilege)
                - Enforce record ownership
                - Disable directory listing
                - Log access control failures
                - Implement rate limiting for API/controller access
                - Invalidate JWT tokens on logout
                - Use CORS headers to limit access""",

            "A02:2021": """Fix cryptographic failures:
                - Classify data and apply protection per classification
                - Encrypt all sensitive data at rest (AES-256)
                - Encrypt data in transit (TLS 1.3)
                - Disable caching for sensitive data
                - Store passwords using adaptive salted hashing (Argon2, bcrypt, PBKDF2)
                - Use authenticated encryption (GCM, CCM)
                - Generate cryptographic keys properly (secure random)""",

            "A03:2021": """Prevent injection attacks:
                - Use safe APIs that avoid interpreters
                - Use parameterized queries (prepared statements)
                - Use ORM frameworks (with caution)
                - Validate input using positive (allow-list) validation
                - Escape special characters in queries
                - Use LIMIT and other SQL controls to prevent mass disclosure
                - Implement Web Application Firewall (WAF)""",

            "A04:2021": """Improve secure design:
                - Establish secure development lifecycle
                - Use threat modeling for critical flows
                - Write unit and integration tests for authentication/access control
                - Separate tier layers (presentation, business, data)
                - Limit resource consumption by user or service""",

            "A05:2021": """Fix security misconfiguration:
                - Implement repeatable hardening process
                - Remove unnecessary features, components, documentation
                - Review and update configurations with security patches
                - Implement segmented application architecture
                - Send security directives to clients (Security Headers)
                - Automated process to verify effectiveness of configurations""",

            "A06:2021": """Manage vulnerable components:
                - Remove unused dependencies, features, components, files
                - Continuously inventory versions (client/server components, dependencies)
                - Monitor CVE and NVD for vulnerabilities in components
                - Subscribe to email alerts for security vulnerabilities
                - Obtain components only from official sources over secure links
                - Monitor for unmaintained libraries/components
                - Implement Software Composition Analysis (SCA)""",

            "A07:2021": """Fix authentication failures:
                - Implement multi-factor authentication (MFA)
                - Do not ship with default credentials
                - Implement weak password checks
                - Align password length, complexity, and rotation policies with NIST 800-63b
                - Harden registration, credential recovery, API pathways against account enumeration
                - Limit or delay failed login attempts (rate limiting)
                - Use server-side session manager with high entropy session IDs
                - Invalidate session IDs after logout, idle timeout, absolute timeout""",

            "A08:2021": """Ensure software and data integrity:
                - Use digital signatures to verify software/data from expected source
                - Ensure libraries and dependencies consume trusted repositories
                - Use software supply chain security tools (OWASP Dependency Check, Snyk)
                - Ensure CI/CD pipeline has proper segregation, configuration, access control
                - Ensure unsigned or unencrypted data is not sent to untrusted clients
                - Implement integrity checks or digital signatures for serialized objects""",

            "A09:2021": """Fix logging and monitoring failures:
                - Ensure all login, access control, server-side validation failures logged
                - Log in format consumable by centralized log management (SIEM)
                - Ensure high-value transactions have audit trail with integrity controls
                - Establish effective monitoring and alerting
                - Establish incident response and recovery plan
                - Commercial/open-source application protection frameworks (RASP)""",

            "A10:2021": """Prevent SSRF:
                - Sanitize and validate all client-supplied input data
                - Enforce URL schema, port, and destination with positive allow list
                - Do not send raw responses to clients
                - Disable HTTP redirections
                - Be aware of URL consistency to avoid DNS rebinding and TOCTOU attacks
                - Segment remote resource access functionality in separate networks"""
        }

        return remediations.get(category_id, "Review OWASP Top 10 2021 guidance for this category")

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate OWASP Top 10 compliance report"""

        # Count by category
        by_category = {}
        for violation in self.violations:
            cat = violation.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        # Count by severity
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for violation in self.violations:
            by_severity[violation.severity] += 1

        # Total attacks
        total_attacks = sum(v.attack_count for v in self.violations)

        # Calculate security score
        # Start at 100, deduct points for violations
        security_score = 100
        for violation in self.violations:
            if violation.severity == "CRITICAL":
                security_score -= 10
            elif violation.severity == "HIGH":
                security_score -= 5
            elif violation.severity == "MEDIUM":
                security_score -= 2
            else:
                security_score -= 1

        security_score = max(0, security_score)

        # Security grade
        if security_score >= 90:
            security_grade = "A"
        elif security_score >= 80:
            security_grade = "B"
        elif security_score >= 70:
            security_grade = "C"
        elif security_score >= 60:
            security_grade = "D"
        else:
            security_grade = "F"

        report = {
            "report_type": "OWASP Top 10 2021 Security Assessment",
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": {
                "security_score": security_score,
                "security_grade": security_grade,
                "total_violations": len(self.violations),
                "total_attacks": total_attacks,
                "critical_violations": by_severity["CRITICAL"],
                "high_violations": by_severity["HIGH"],
                "categories_affected": len(by_category)
            },
            "violations_by_category": by_category,
            "violations_by_severity": by_severity,
            "owasp_top_10_coverage": {
                "A01:2021 - Broken Access Control": by_category.get("A01:2021", 0),
                "A02:2021 - Cryptographic Failures": by_category.get("A02:2021", 0),
                "A03:2021 - Injection": by_category.get("A03:2021", 0),
                "A04:2021 - Insecure Design": by_category.get("A04:2021", 0),
                "A05:2021 - Security Misconfiguration": by_category.get("A05:2021", 0),
                "A06:2021 - Vulnerable Components": by_category.get("A06:2021", 0),
                "A07:2021 - Auth Failures": by_category.get("A07:2021", 0),
                "A08:2021 - Integrity Failures": by_category.get("A08:2021", 0),
                "A09:2021 - Logging Failures": by_category.get("A09:2021", 0),
                "A10:2021 - SSRF": by_category.get("A10:2021", 0)
            },
            "critical_violations": [
                {
                    "violation_id": v.violation_id,
                    "category": v.category.value,
                    "category_name": v.category_name,
                    "attack_count": v.attack_count,
                    "cwe_ids": v.cwe_ids,
                    "exploitability": v.exploitability,
                    "technical_impact": v.technical_impact,
                    "affected_systems": v.affected_systems,
                    "remediation": v.remediation
                }
                for v in self.violations if v.severity == "CRITICAL"
            ],
            "recommendations": self._generate_recommendations(security_score, by_severity),
            "owasp_resources": {
                "owasp_top_10_2021": "https://owasp.org/Top10/",
                "owasp_cheat_sheet": "https://cheatsheetseries.owasp.org/",
                "owasp_testing_guide": "https://owasp.org/www-project-web-security-testing-guide/",
                "owasp_dependency_check": "https://owasp.org/www-project-dependency-check/"
            }
        }

        return report

    def _generate_recommendations(self, security_score: int, by_severity: Dict[str, int]) -> List[str]:
        """Generate recommendations"""
        recommendations = []

        if by_severity["CRITICAL"] > 0:
            recommendations.append(
                f"URGENT: Remediate {by_severity['CRITICAL']} critical OWASP Top 10 vulnerabilities immediately"
            )

        if security_score < 70:
            recommendations.append("Security score below acceptable threshold - implement comprehensive remediation plan")

        if by_severity["HIGH"] > 0:
            recommendations.append(
                f"Address {by_severity['HIGH']} high-severity vulnerabilities within 30 days"
            )

        recommendations.append("Implement Secure Development Lifecycle (SDL) practices")
        recommendations.append("Deploy Web Application Firewall (WAF) with OWASP ModSecurity Core Rule Set")
        recommendations.append("Conduct quarterly Dynamic Application Security Testing (DAST)")
        recommendations.append("Implement Static Application Security Testing (SAST) in CI/CD pipeline")
        recommendations.append("Provide OWASP Top 10 security training to developers")
        recommendations.append("Conduct annual penetration testing of web applications")

        return recommendations

    def get_violations_by_category(self, category: OWASPCategory) -> List[OWASPViolation]:
        """Get violations by OWASP category"""
        return [v for v in self.violations if v.category == category]

    def get_violations_by_severity(self, severity: str) -> List[OWASPViolation]:
        """Get violations by severity"""
        return [v for v in self.violations if v.severity == severity]

    def get_cwe_mapping(self) -> Dict[str, List[str]]:
        """Get CWE IDs mapped to OWASP categories"""
        cwe_map = {}
        for v in self.violations:
            for cwe_id in v.cwe_ids:
                if cwe_id not in cwe_map:
                    cwe_map[cwe_id] = []
                if v.category.value not in cwe_map[cwe_id]:
                    cwe_map[cwe_id].append(v.category.value)
        return cwe_map
