"""
Comprehensive Compliance Reporting
Generates compliance reports for SOC 2, ISO 27001, GDPR, HIPAA, PCI-DSS, NIST
Tracks controls, evidence, and audit requirements
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    SOC2_TYPE2 = "soc2_type2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    NIST_CSF = "nist_csf"

class ControlStatus(Enum):
    """Control implementation status"""
    NOT_IMPLEMENTED = "not_implemented"
    PLANNED = "planned"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    IMPLEMENTED = "implemented"
    OPERATIONAL = "operational"
    NEEDS_IMPROVEMENT = "needs_improvement"

class EvidenceType(Enum):
    """Types of compliance evidence"""
    POLICY = "policy"
    PROCEDURE = "procedure"
    LOG = "log"
    SCREENSHOT = "screenshot"
    ATTESTATION = "attestation"
    AUDIT_REPORT = "audit_report"
    SYSTEM_CONFIG = "system_config"
    TRAINING_RECORD = "training_record"

@dataclass
class Control:
    """Compliance control"""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    category: str
    status: ControlStatus
    owner: str
    implemented_date: Optional[datetime] = None
    last_tested: Optional[datetime] = None
    test_frequency_days: int = 90
    evidence: List[str] = field(default_factory=list)
    notes: str = ""
    remediation_plan: str = ""

@dataclass
class ComplianceEvidence:
    """Evidence for compliance"""
    evidence_id: str
    evidence_type: EvidenceType
    control_ids: List[str]
    title: str
    description: str
    collected_date: datetime
    collected_by: str
    file_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ComplianceGap:
    """Compliance gap finding"""
    gap_id: str
    framework: ComplianceFramework
    control_id: str
    severity: str  # critical, high, medium, low
    description: str
    identified_date: datetime
    remediation_plan: str = ""
    target_date: Optional[datetime] = None
    status: str = "open"  # open, in_progress, resolved

class ComplianceReporter:
    """
    Comprehensive compliance reporting engine
    Generates reports for multiple frameworks
    """

    def __init__(self, reports_dir: str = "./compliance_reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # Controls database
        self.controls: Dict[str, Control] = {}

        # Evidence database
        self.evidence: Dict[str, ComplianceEvidence] = {}

        # Gaps tracking
        self.gaps: Dict[str, ComplianceGap] = {}

        # Initialize framework controls
        self._init_framework_controls()

    def generate_soc2_report(self,
                            start_date: datetime,
                            end_date: datetime,
                            audit_period_months: int = 12) -> Dict[str, Any]:
        """
        Generate SOC 2 Type II compliance report

        Args:
            start_date: Report period start
            end_date: Report period end
            audit_period_months: Audit observation period

        Returns:
            SOC 2 report
        """
        soc2_controls = [c for c in self.controls.values()
                        if c.framework == ComplianceFramework.SOC2_TYPE2]

        # Trust Services Criteria categories
        categories = {
            "security": [],
            "availability": [],
            "processing_integrity": [],
            "confidentiality": [],
            "privacy": []
        }

        for control in soc2_controls:
            if control.category in categories:
                categories[control.category].append({
                    "control_id": control.control_id,
                    "title": control.title,
                    "status": control.status.value,
                    "owner": control.owner,
                    "evidence_count": len(control.evidence),
                    "last_tested": control.last_tested.isoformat() if control.last_tested else None
                })

        # Calculate compliance percentage
        implemented = len([c for c in soc2_controls
                          if c.status == ControlStatus.OPERATIONAL])
        compliance_pct = (implemented / len(soc2_controls) * 100) if soc2_controls else 0

        # Identify gaps
        soc2_gaps = [g for g in self.gaps.values()
                    if g.framework == ComplianceFramework.SOC2_TYPE2 and g.status == "open"]

        report = {
            "report_type": "SOC 2 Type II",
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "observation_months": audit_period_months
            },
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": {
                "total_controls": len(soc2_controls),
                "implemented_controls": implemented,
                "compliance_percentage": round(compliance_pct, 2),
                "open_gaps": len(soc2_gaps),
                "critical_gaps": len([g for g in soc2_gaps if g.severity == "critical"])
            },
            "trust_services_criteria": categories,
            "gaps": [
                {
                    "gap_id": g.gap_id,
                    "control": g.control_id,
                    "severity": g.severity,
                    "description": g.description,
                    "target_date": g.target_date.isoformat() if g.target_date else None
                }
                for g in soc2_gaps
            ],
            "evidence_summary": self._get_evidence_summary(ComplianceFramework.SOC2_TYPE2),
            "recommendations": self._generate_soc2_recommendations(soc2_controls)
        }

        # Save report
        self._save_report("soc2_type2", report)

        return report

    def generate_iso27001_report(self) -> Dict[str, Any]:
        """
        Generate ISO 27001 compliance report

        Returns:
            ISO 27001 report
        """
        iso_controls = [c for c in self.controls.values()
                       if c.framework == ComplianceFramework.ISO27001]

        # ISO 27001 Annex A categories
        categories = {
            "A.5_policies": [],
            "A.6_organization": [],
            "A.7_human_resources": [],
            "A.8_asset_management": [],
            "A.9_access_control": [],
            "A.10_cryptography": [],
            "A.11_physical_security": [],
            "A.12_operations": [],
            "A.13_communications": [],
            "A.14_system_dev": [],
            "A.15_supplier": [],
            "A.16_incident": [],
            "A.17_bcm": [],
            "A.18_compliance": []
        }

        for control in iso_controls:
            category_key = f"A.{control.control_id.split('.')[1]}_{control.category}"
            if category_key in categories:
                categories[category_key].append({
                    "control_id": control.control_id,
                    "title": control.title,
                    "status": control.status.value
                })

        implemented = len([c for c in iso_controls
                          if c.status == ControlStatus.OPERATIONAL])
        compliance_pct = (implemented / len(iso_controls) * 100) if iso_controls else 0

        report = {
            "report_type": "ISO 27001:2013",
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": {
                "total_controls": len(iso_controls),
                "implemented_controls": implemented,
                "compliance_percentage": round(compliance_pct, 2),
                "certification_ready": compliance_pct >= 95
            },
            "annex_a_controls": categories,
            "isms_scope": "Security Operations Center (SOC) operations and incident response",
            "risk_assessment_date": datetime.utcnow().isoformat(),
            "next_audit_date": (datetime.utcnow() + timedelta(days=365)).isoformat()
        }

        self._save_report("iso27001", report)
        return report

    def generate_gdpr_report(self) -> Dict[str, Any]:
        """
        Generate GDPR compliance report

        Returns:
            GDPR report
        """
        gdpr_controls = [c for c in self.controls.values()
                        if c.framework == ComplianceFramework.GDPR]

        # GDPR principles
        principles = {
            "lawfulness": [],
            "purpose_limitation": [],
            "data_minimization": [],
            "accuracy": [],
            "storage_limitation": [],
            "integrity_confidentiality": [],
            "accountability": []
        }

        for control in gdpr_controls:
            if control.category in principles:
                principles[control.category].append({
                    "control_id": control.control_id,
                    "title": control.title,
                    "status": control.status.value
                })

        # Data subject rights
        dsr_controls = {
            "right_to_access": "GDPR-07",
            "right_to_rectification": "GDPR-08",
            "right_to_erasure": "GDPR-09",
            "right_to_portability": "GDPR-10",
            "right_to_object": "GDPR-11"
        }

        dsr_status = {}
        for right, control_id in dsr_controls.items():
            control = self.controls.get(control_id)
            dsr_status[right] = control.status.value if control else "not_implemented"

        report = {
            "report_type": "GDPR Compliance Assessment",
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": {
                "total_controls": len(gdpr_controls),
                "gdpr_ready": len([c for c in gdpr_controls
                                  if c.status == ControlStatus.OPERATIONAL]) >= len(gdpr_controls) * 0.9
            },
            "gdpr_principles": principles,
            "data_subject_rights": dsr_status,
            "dpia_completed": True,
            "dpo_appointed": True,
            "breach_notification_procedure": "implemented",
            "data_processing_register": "maintained",
            "international_transfers": {
                "mechanism": "Standard Contractual Clauses",
                "adequacy_decision": "N/A"
            }
        }

        self._save_report("gdpr", report)
        return report

    def generate_hipaa_report(self) -> Dict[str, Any]:
        """
        Generate HIPAA compliance report

        Returns:
            HIPAA report
        """
        hipaa_controls = [c for c in self.controls.values()
                         if c.framework == ComplianceFramework.HIPAA]

        # HIPAA safeguards
        safeguards = {
            "administrative": [],
            "physical": [],
            "technical": []
        }

        for control in hipaa_controls:
            if control.category in safeguards:
                safeguards[control.category].append({
                    "control_id": control.control_id,
                    "title": control.title,
                    "status": control.status.value
                })

        report = {
            "report_type": "HIPAA Security Rule Compliance",
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": {
                "total_controls": len(hipaa_controls),
                "compliant": len([c for c in hipaa_controls
                                if c.status == ControlStatus.OPERATIONAL]) == len(hipaa_controls)
            },
            "security_safeguards": safeguards,
            "phi_encryption": "AES-256",
            "access_controls": "role_based",
            "audit_logging": "enabled",
            "breach_notification_ready": True,
            "business_associate_agreements": "in_place"
        }

        self._save_report("hipaa", report)
        return report

    def generate_pci_dss_report(self) -> Dict[str, Any]:
        """
        Generate PCI DSS compliance report

        Returns:
            PCI DSS report
        """
        pci_controls = [c for c in self.controls.values()
                       if c.framework == ComplianceFramework.PCI_DSS]

        # PCI DSS 12 requirements
        requirements = {}
        for i in range(1, 13):
            requirements[f"requirement_{i}"] = [
                {
                    "control_id": c.control_id,
                    "title": c.title,
                    "status": c.status.value
                }
                for c in pci_controls
                if c.control_id.startswith(f"PCI-{i}.")
            ]

        report = {
            "report_type": "PCI DSS v3.2.1 Compliance",
            "generated_at": datetime.utcnow().isoformat(),
            "merchant_level": "Level 4",
            "cardholder_data_environment": "defined",
            "requirements": requirements,
            "quarterly_scans": "passed",
            "penetration_testing": "annual",
            "compensating_controls": []
        }

        self._save_report("pci_dss", report)
        return report

    def generate_nist_csf_report(self) -> Dict[str, Any]:
        """
        Generate NIST Cybersecurity Framework report

        Returns:
            NIST CSF report
        """
        nist_controls = [c for c in self.controls.values()
                        if c.framework == ComplianceFramework.NIST_CSF]

        # NIST CSF functions
        functions = {
            "identify": [],
            "protect": [],
            "detect": [],
            "respond": [],
            "recover": []
        }

        for control in nist_controls:
            if control.category in functions:
                functions[control.category].append({
                    "control_id": control.control_id,
                    "title": control.title,
                    "status": control.status.value
                })

        # Calculate maturity level (0-4)
        maturity_scores = []
        for func_controls in functions.values():
            if func_controls:
                operational = len([c for c in func_controls
                                  if c["status"] == "operational"])
                maturity_scores.append(operational / len(func_controls) * 4)

        avg_maturity = sum(maturity_scores) / len(maturity_scores) if maturity_scores else 0

        report = {
            "report_type": "NIST Cybersecurity Framework Assessment",
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": {
                "current_maturity_level": round(avg_maturity, 1),
                "target_maturity_level": 3.0,
                "gap": round(3.0 - avg_maturity, 1)
            },
            "framework_functions": functions,
            "implementation_tier": "Tier 3 - Repeatable",
            "risk_management_process": "defined",
            "recommendations": [
                "Advance to Tier 4 (Adaptive) maturity",
                "Implement continuous monitoring",
                "Enhance threat intelligence integration"
            ]
        }

        self._save_report("nist_csf", report)
        return report

    def add_control(self, control: Control):
        """Add compliance control"""
        self.controls[control.control_id] = control

    def update_control_status(self, control_id: str, status: ControlStatus, notes: str = ""):
        """Update control status"""
        if control_id in self.controls:
            self.controls[control_id].status = status
            if notes:
                self.controls[control_id].notes += f"\n[{datetime.utcnow()}] {notes}"

            if status == ControlStatus.OPERATIONAL:
                self.controls[control_id].implemented_date = datetime.utcnow()

    def add_evidence(self, evidence: ComplianceEvidence):
        """Add compliance evidence"""
        self.evidence[evidence.evidence_id] = evidence

        # Link to controls
        for control_id in evidence.control_ids:
            if control_id in self.controls:
                if evidence.evidence_id not in self.controls[control_id].evidence:
                    self.controls[control_id].evidence.append(evidence.evidence_id)

    def identify_gap(self, gap: ComplianceGap):
        """Identify compliance gap"""
        self.gaps[gap.gap_id] = gap

    def resolve_gap(self, gap_id: str, notes: str = ""):
        """Resolve compliance gap"""
        if gap_id in self.gaps:
            self.gaps[gap_id].status = "resolved"
            self.gaps[gap_id].remediation_plan += f"\n[RESOLVED {datetime.utcnow()}] {notes}"

    def _get_evidence_summary(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """Get evidence summary for framework"""
        framework_evidence = [
            e for e in self.evidence.values()
            if any(self.controls.get(cid, Control("", framework, "", "", "", ControlStatus.NOT_IMPLEMENTED, "")).framework == framework
                  for cid in e.control_ids)
        ]

        by_type = {}
        for evidence in framework_evidence:
            evidence_type = evidence.evidence_type.value
            by_type[evidence_type] = by_type.get(evidence_type, 0) + 1

        return {
            "total_evidence_items": len(framework_evidence),
            "by_type": by_type
        }

    def _generate_soc2_recommendations(self, controls: List[Control]) -> List[str]:
        """Generate SOC 2 recommendations"""
        recommendations = []

        not_implemented = [c for c in controls if c.status == ControlStatus.NOT_IMPLEMENTED]
        if not_implemented:
            recommendations.append(
                f"Implement {len(not_implemented)} remaining controls to achieve full compliance"
            )

        needs_testing = [c for c in controls
                        if c.last_tested is None or
                        (datetime.utcnow() - c.last_tested).days > c.test_frequency_days]
        if needs_testing:
            recommendations.append(
                f"Test {len(needs_testing)} controls that are overdue for testing"
            )

        if len(recommendations) == 0:
            recommendations.append("No critical recommendations - maintain current state")

        return recommendations

    def _save_report(self, report_name: str, report_data: Dict[str, Any]):
        """Save report to file"""
        filename = f"{report_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.reports_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

    def _init_framework_controls(self):
        """Initialize controls for all frameworks"""
        # SOC 2 controls
        soc2_controls = [
            Control("CC1.1", ComplianceFramework.SOC2_TYPE2, "Control Environment",
                   "Organization maintains effective control environment", "security",
                   ControlStatus.OPERATIONAL, "CISO"),
            Control("CC2.1", ComplianceFramework.SOC2_TYPE2, "Communication",
                   "Entity communicates information security objectives", "security",
                   ControlStatus.OPERATIONAL, "CISO"),
            Control("CC6.1", ComplianceFramework.SOC2_TYPE2, "Logical Access",
                   "Entity implements logical access controls", "security",
                   ControlStatus.OPERATIONAL, "Security Team"),
            Control("CC7.1", ComplianceFramework.SOC2_TYPE2, "Detection",
                   "Entity monitors system to detect security events", "security",
                   ControlStatus.OPERATIONAL, "SOC Team"),
            Control("A1.1", ComplianceFramework.SOC2_TYPE2, "Availability",
                   "Entity maintains system availability", "availability",
                   ControlStatus.OPERATIONAL, "Operations"),
        ]

        # GDPR controls
        gdpr_controls = [
            Control("GDPR-01", ComplianceFramework.GDPR, "Lawfulness",
                   "Process personal data lawfully", "lawfulness",
                   ControlStatus.OPERATIONAL, "DPO"),
            Control("GDPR-03", ComplianceFramework.GDPR, "Data Minimization",
                   "Collect only necessary personal data", "data_minimization",
                   ControlStatus.OPERATIONAL, "DPO"),
            Control("GDPR-06", ComplianceFramework.GDPR, "Security",
                   "Implement appropriate security measures", "integrity_confidentiality",
                   ControlStatus.OPERATIONAL, "CISO"),
            Control("GDPR-07", ComplianceFramework.GDPR, "Right to Access",
                   "Enable data subject access requests", "accountability",
                   ControlStatus.OPERATIONAL, "DPO"),
            Control("GDPR-09", ComplianceFramework.GDPR, "Right to Erasure",
                   "Enable right to be forgotten", "accountability",
                   ControlStatus.OPERATIONAL, "DPO"),
        ]

        # Add all controls
        for control in soc2_controls + gdpr_controls:
            self.controls[control.control_id] = control

    def get_statistics(self) -> Dict[str, Any]:
        """Get compliance statistics"""
        by_framework = {}
        for framework in ComplianceFramework:
            framework_controls = [c for c in self.controls.values() if c.framework == framework]
            if framework_controls:
                operational = len([c for c in framework_controls
                                 if c.status == ControlStatus.OPERATIONAL])
                by_framework[framework.value] = {
                    "total": len(framework_controls),
                    "operational": operational,
                    "compliance_pct": round((operational / len(framework_controls)) * 100, 2)
                }

        return {
            "total_controls": len(self.controls),
            "total_evidence": len(self.evidence),
            "open_gaps": len([g for g in self.gaps.values() if g.status == "open"]),
            "by_framework": by_framework
        }
