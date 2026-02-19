"""
Enterprise Report Integration Module
Integrates all advanced reporting components and provides unified API

This module coordinates:
- AdvancedEnterpriseReportEngine (analytics and intelligence)
- EnterpriseVisualizationEngine (charts and dashboards)
- EnterpriseReportGenerator (multi-format output)
- ComplianceReporter (compliance assessments)

Provides single entry point for generating enterprise-grade reports
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import asyncio

# Import all report engines
from modules.AdvancedEnterpriseReportEngine import AdvancedEnterpriseReportEngine, RiskScore, MaturityLevel, ExecutiveInsight
from modules.EnterpriseVisualizationEngine import EnterpriseVisualizationEngine
from modules.EnterpriseReportGenerator import EnterpriseReportGenerator
from modules.ComplianceReporter import ComplianceReporter, ComplianceFramework
from modules.IPDataTablesInjector import IPDataTablesInjector

class EnterpriseReportIntegration:
    """
    Master integration class for all enterprise reporting
    Provides unified API for report generation
    """

    def __init__(self, output_dir: str = "./enterprise_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize all engines
        self.analytics_engine = AdvancedEnterpriseReportEngine(str(self.output_dir / "analytics"))
        self.viz_engine = EnterpriseVisualizationEngine()
        self.report_generator = EnterpriseReportGenerator(str(self.output_dir / "generated"))
        self.compliance_reporter = ComplianceReporter(str(self.output_dir / "compliance"))

        # Store attacker profiles for IP data injection
        self.current_attacker_profiles = []

    def _inject_ip_data_to_html_file(self, filepath: str, attacker_profiles: List[Any]) -> None:
        """
        Helper method to inject IP intelligence data into HTML files after generation

        Args:
            filepath: Path to the HTML file
            attacker_profiles: List of attacker profiles
        """
        try:
            # Read the HTML file
            with open(filepath, 'r', encoding='utf-8') as f:
                html_content = f.read()

            # Inject IP data
            html_content = IPDataTablesInjector.inject_ip_data_into_html(
                html_content,
                attacker_profiles,
                section_title=f"🔍 Detected Malicious IPs ({len(attacker_profiles)} Total)"
            )

            # Write back
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)

            print(f"[REPORT] [OK] IP intelligence data injected into: {filepath}")
        except Exception as e:
            print(f"[REPORT] [WARNING] Could not inject IP data: {e}")

    def generate_executive_report(
        self,
        attacker_profiles: List[Any],
        agent_profiles: Dict[str, Any],
        time_period_hours: int = 168,
        formats: List[str] = ['html', 'pdf']
    ) -> Dict[str, str]:
        """
        Generate comprehensive executive summary report

        Args:
            attacker_profiles: List of attacker profiles from analysis
            agent_profiles: Dictionary of agent profiles
            time_period_hours: Time period for analysis (default 7 days)
            formats: Output formats ['html', 'pdf', 'excel']

        Returns:
            Dictionary mapping format to file path
        """
        print(f"[REPORT] Generating Executive Summary Report...")

        # Store attacker profiles for IP injection
        self.current_attacker_profiles = attacker_profiles

        # Generate analytics data
        report_data = self.analytics_engine.generate_executive_summary_report(
            attacker_profiles,
            agent_profiles,
            time_period_hours
        )

        # Add visualizations to HTML version
        if 'html' in formats:
            report_data['visualizations'] = {
                'dashboard': self.viz_engine.generate_executive_dashboard_html(report_data),
                'geo_map': self.viz_engine.create_geo_threat_map(attacker_profiles)
            }

        # Generate reports in requested formats
        generated_files = {}

        for format_type in formats:
            if format_type == 'html':
                # Use visualization engine for HTML (with charts)
                filepath = self.output_dir / f"Executive_Summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                html_content = self.viz_engine.generate_executive_dashboard_html(report_data)

                # INJECT IP INTELLIGENCE DATA
                html_content = IPDataTablesInjector.inject_ip_data_into_html(
                    html_content,
                    attacker_profiles,
                    section_title=f"🔍 Detected Malicious IPs ({len(attacker_profiles)} Total)"
                )

                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                generated_files['html'] = str(filepath)
                print(f"[REPORT] [OK] HTML report generated with IP data: {filepath}")

            elif format_type == 'pdf':
                filepath = self.report_generator.generate_pdf_report(
                    "Executive_Summary",
                    self._flatten_for_pdf(report_data),
                    f"Executive_Summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                )
                generated_files['pdf'] = filepath
                print(f"[REPORT] [OK] PDF report generated: {filepath}")

            elif format_type == 'excel':
                filepath = self.report_generator.generate_excel_report(
                    "Executive_Summary",
                    self._flatten_for_excel(report_data),
                    f"Executive_Summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                )
                generated_files['excel'] = filepath
                print(f"[REPORT] [OK] Excel report generated: {filepath}")

        print(f"[REPORT] Executive Summary Report complete!")
        return generated_files

    def generate_threat_intelligence_report(
        self,
        attacker_profiles: List[Any],
        mitre_mapper: Any = None,
        formats: List[str] = ['html', 'pdf']
    ) -> Dict[str, str]:
        """
        Generate advanced threat intelligence report

        Args:
            attacker_profiles: List of attacker profiles
            mitre_mapper: MITRE ATT&CK mapper instance
            formats: Output formats

        Returns:
            Dictionary mapping format to file path
        """
        print(f"[REPORT] Generating Threat Intelligence Report...")

        # Store attacker profiles for IP injection
        self.current_attacker_profiles = attacker_profiles

        # Generate analytics
        report_data = self.analytics_engine.generate_advanced_threat_intelligence_report(
            attacker_profiles,
            mitre_mapper
        )

        # Add MITRE heatmap for HTML
        if 'html' in formats:
            technique_freq = report_data['mitre_attack_analysis']['technique_frequency']
            report_data['visualizations'] = {
                'mitre_heatmap': self.viz_engine.create_mitre_attack_heatmap(technique_freq),
                'attack_flow': self.viz_engine.create_attack_sankey_diagram(
                    report_data.get('attack_chains', {}).get('reconstructed_chains', [])
                )
            }

        # Generate reports
        generated_files = {}

        # Use the professional IP Intelligence generator which generates HTML, Excel, CSV together
        # This provides ONE beautiful table with ALL analytics including ML
        if 'html' in formats or 'excel' in formats:
            try:
                from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport

                ip_reporter = UltraAdvancedIPIntelligenceReport(
                    output_dir=str(self.output_dir / "generated")
                )

                # Generate professional report with ML analytics - generates HTML, Excel, CSV at once
                threat_files = ip_reporter.generate_full_ip_intelligence_report(
                    attacker_profiles=attacker_profiles,
                    agent_profiles={},  # Not needed for Threat Intelligence
                    output_name=f"Threat_Intelligence_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                )

                # Store all generated files
                if 'html' in formats and threat_files.get('html'):
                    generated_files['html'] = threat_files['html']
                    print(f"[REPORT] [OK] Threat Intelligence HTML with ML analytics: {threat_files['html']}")

                if 'excel' in formats and threat_files.get('excel'):
                    generated_files['excel'] = threat_files['excel']
                    print(f"[REPORT] [OK] Threat Intelligence Excel with ML analytics: {threat_files['excel']}")

            except Exception as e:
                print(f"[REPORT] [ERROR] Failed to generate TI reports via UltraAdvanced: {e}")
                import traceback
                traceback.print_exc()

        # Generate PDF if requested (separate generation since UltraAdvanced doesn't generate PDF)
        if 'pdf' in formats:
            try:
                filepath = self.report_generator.generate_pdf_report(
                    "Threat_Intelligence",
                    self._flatten_for_pdf(report_data),
                    f"Threat_Intelligence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                )
                generated_files['pdf'] = filepath
                print(f"[REPORT] [OK] PDF report generated: {filepath}")
            except Exception as e:
                print(f"[REPORT] [ERROR] Failed to generate TI PDF: {e}")

        print(f"[REPORT] Threat Intelligence Report complete!")
        return generated_files

    def generate_compliance_report(
        self,
        framework: str,
        compliance_data: Dict[str, Any],
        formats: List[str] = ['html', 'pdf', 'excel']
    ) -> Dict[str, str]:
        """
        Generate comprehensive compliance report

        Args:
            framework: Compliance framework (iso27001, soc2, gdpr, nist_csf, etc.)
            compliance_data: Compliance data from system
            formats: Output formats

        Returns:
            Dictionary mapping format to file path
        """
        print(f"[REPORT] Generating {framework.upper()} Compliance Report...")

        # Generate compliance assessment
        if framework == 'soc2':
            report_data = self.compliance_reporter.generate_soc2_report(
                datetime.now() - timedelta(days=365),
                datetime.now(),
                12
            )
        elif framework == 'iso27001':
            report_data = self.compliance_reporter.generate_iso27001_report()
        elif framework == 'gdpr':
            report_data = self.compliance_reporter.generate_gdpr_report()
        elif framework == 'nist_csf':
            report_data = self.compliance_reporter.generate_nist_csf_report()
        elif framework == 'hipaa':
            report_data = self.compliance_reporter.generate_hipaa_report()
        elif framework == 'pci_dss':
            report_data = self.compliance_reporter.generate_pci_dss_report()
        else:
            raise ValueError(f"Unknown framework: {framework}")

        # Generate maturity assessment
        maturity_report = self.analytics_engine.generate_compliance_maturity_report(
            {framework: report_data}
        )

        # Merge reports
        combined_data = {**report_data, **maturity_report}

        # Generate reports
        generated_files = {}

        for format_type in formats:
            if format_type == 'html':
                filepath = self.report_generator.generate_html_report(
                    f"{framework.upper()}_Compliance",
                    combined_data,
                    f"{framework.upper()}_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                )

                # Inject IP intelligence data into the HTML report
                if self.current_attacker_profiles:
                    self._inject_ip_data_to_html_file(filepath, self.current_attacker_profiles)

                generated_files['html'] = filepath
                print(f"[REPORT] [OK] HTML report generated: {filepath}")

            elif format_type == 'pdf':
                filepath = self.report_generator.generate_pdf_report(
                    f"{framework.upper()}_Compliance",
                    self._flatten_for_pdf(combined_data),
                    f"{framework.upper()}_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                )
                generated_files['pdf'] = filepath
                print(f"[REPORT] [OK] PDF report generated: {filepath}")

            elif format_type == 'excel':
                filepath = self.report_generator.generate_excel_report(
                    f"{framework.upper()}_Compliance",
                    self._flatten_for_excel(combined_data),
                    f"{framework.upper()}_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                )
                generated_files['excel'] = filepath
                print(f"[REPORT] [OK] Excel report generated: {filepath}")

        print(f"[REPORT] {framework.upper()} Compliance Report complete!")
        return generated_files

    def generate_all_compliance_reports(
        self,
        compliance_data: Dict[str, Any],
        formats: List[str] = ['html', 'pdf']
    ) -> Dict[str, Dict[str, str]]:
        """
        Generate all compliance reports in one shot

        Args:
            compliance_data: Complete compliance data
            formats: Output formats

        Returns:
            Dictionary mapping framework to file paths
        """
        print(f"[REPORT] Generating ALL Compliance Reports...")

        all_reports = {}
        frameworks = ['iso27001', 'soc2', 'gdpr', 'nist_csf', 'hipaa', 'pci_dss']

        for framework in frameworks:
            try:
                reports = self.generate_compliance_report(
                    framework,
                    compliance_data.get(framework, {}),
                    formats
                )
                all_reports[framework] = reports
            except Exception as e:
                print(f"[REPORT] [ERROR] Failed to generate {framework}: {e}")
                all_reports[framework] = {"error": str(e)}

        # Generate consolidated report
        consolidated_filepath = self._generate_consolidated_compliance_report(
            all_reports,
            formats
        )
        all_reports['consolidated'] = consolidated_filepath

        print(f"[REPORT] ALL Compliance Reports complete!")
        return all_reports

    def generate_risk_assessment_report(
        self,
        attacker_profiles: List[Any],
        agent_profiles: Dict[str, Any],
        formats: List[str] = ['html', 'pdf']
    ) -> Dict[str, str]:
        """
        Generate enterprise risk assessment report

        Args:
            attacker_profiles: List of attacker profiles
            agent_profiles: Dictionary of agent profiles
            formats: Output formats

        Returns:
            Dictionary mapping format to file path
        """
        print(f"[REPORT] Generating Risk Assessment Report...")

        # Generate risk assessment
        report_data = self.analytics_engine.generate_risk_assessment_report(
            attacker_profiles,
            agent_profiles
        )

        # Generate reports
        generated_files = {}

        for format_type in formats:
            if format_type == 'html':
                filepath = self.report_generator.generate_html_report(
                    "Risk_Assessment",
                    report_data,
                    f"Risk_Assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                )

                # Inject IP intelligence data
                if attacker_profiles:
                    self._inject_ip_data_to_html_file(filepath, attacker_profiles)

                generated_files['html'] = filepath
                print(f"[REPORT] [OK] HTML report generated: {filepath}")

            elif format_type == 'pdf':
                filepath = self.report_generator.generate_pdf_report(
                    "Risk_Assessment",
                    self._flatten_for_pdf(report_data),
                    f"Risk_Assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                )
                generated_files['pdf'] = filepath
                print(f"[REPORT] [OK] PDF report generated: {filepath}")

            elif format_type == 'excel':
                filepath = self.report_generator.generate_excel_report(
                    "Risk_Assessment",
                    self._flatten_for_excel(report_data),
                    f"Risk_Assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                )
                generated_files['excel'] = filepath
                print(f"[REPORT] [OK] Excel report generated: {filepath}")

        print(f"[REPORT] Risk Assessment Report complete!")
        return generated_files

    def generate_owasp_report(
        self,
        attacker_profiles: List[Any],
        formats: List[str] = ['html', 'pdf']
    ) -> Dict[str, str]:
        """
        Generate OWASP Top 10 compliance report

        Args:
            attacker_profiles: List of attacker profiles
            formats: Output formats

        Returns:
            Dictionary mapping format to file path
        """
        print(f"[REPORT] Generating OWASP Top 10 Report...")

        # Map attacks to OWASP Top 10 2021
        owasp_mapping = self._map_to_owasp_top10(attacker_profiles)

        report_data = {
            "report_type": "OWASP Top 10 2021 Assessment",
            "generated_at": datetime.now().isoformat(),
            "executive_summary": {
                "total_attacks_analyzed": len(attacker_profiles),
                "owasp_categories_detected": len([v for v in owasp_mapping.values() if v['count'] > 0]),
                "highest_risk_category": max(owasp_mapping.items(), key=lambda x: x[1]['count'])[0] if owasp_mapping else "None"
            },
            "owasp_top10_analysis": owasp_mapping,
            "recommendations": self._generate_owasp_recommendations(owasp_mapping)
        }

        # Generate reports
        generated_files = {}

        for format_type in formats:
            if format_type == 'html':
                filepath = self.report_generator.generate_html_report(
                    "OWASP_Top_10_2021",
                    report_data,
                    f"OWASP_Top10_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                )

                # Inject IP intelligence data
                if attacker_profiles:
                    self._inject_ip_data_to_html_file(filepath, attacker_profiles)

                generated_files['html'] = filepath
                print(f"[REPORT] [OK] HTML report generated: {filepath}")

            elif format_type == 'pdf':
                filepath = self.report_generator.generate_pdf_report(
                    "OWASP_Top_10_2021",
                    report_data,
                    f"OWASP_Top10_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                )
                generated_files['pdf'] = filepath
                print(f"[REPORT] [OK] PDF report generated: {filepath}")

            elif format_type == 'excel':
                filepath = self.report_generator.generate_excel_report(
                    "OWASP_Top_10_2021",
                    self._flatten_for_excel(report_data),
                    f"OWASP_Top10_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                )
                generated_files['excel'] = filepath
                print(f"[REPORT] [OK] Excel report generated: {filepath}")

        print(f"[REPORT] OWASP Top 10 Report complete!")
        return generated_files

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _flatten_for_pdf(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten complex nested structures for PDF rendering"""
        flattened = {}

        for key, value in data.items():
            if isinstance(value, dict):
                # Flatten nested dicts
                for subkey, subvalue in value.items():
                    if isinstance(subvalue, (str, int, float, bool)):
                        flattened[f"{key}_{subkey}"] = subvalue
                    elif isinstance(subvalue, list) and len(subvalue) <= 10:
                        flattened[f"{key}_{subkey}"] = str(subvalue)
            elif isinstance(value, list):
                if len(value) <= 10:
                    flattened[key] = value
            else:
                flattened[key] = value

        return flattened

    def _flatten_for_excel(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for Excel format"""
        # Excel can handle more complex structures
        return data

    def _generate_consolidated_compliance_report(
        self,
        all_reports: Dict[str, Dict[str, str]],
        formats: List[str]
    ) -> Dict[str, str]:
        """Generate consolidated compliance report across all frameworks"""

        consolidated = {
            "report_type": "Consolidated Compliance Assessment",
            "generated_at": datetime.now().isoformat(),
            "frameworks_assessed": list(all_reports.keys()),
            "summary": "Multi-framework compliance assessment covering ISO 27001, SOC 2, GDPR, NIST CSF, HIPAA, and PCI DSS"
        }

        # Save consolidated report
        filepath = self.output_dir / f"Consolidated_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(consolidated, f, indent=2)

        return {"json": str(filepath)}

    def _map_to_owasp_top10(self, attacker_profiles: List[Any]) -> Dict[str, Dict[str, Any]]:
        """Map attacks to OWASP Top 10 2021"""

        owasp_categories = {
            "A01:2021 - Broken Access Control": {"count": 0, "severity": "High", "examples": []},
            "A02:2021 - Cryptographic Failures": {"count": 0, "severity": "High", "examples": []},
            "A03:2021 - Injection": {"count": 0, "severity": "Critical", "examples": []},
            "A04:2021 - Insecure Design": {"count": 0, "severity": "Medium", "examples": []},
            "A05:2021 - Security Misconfiguration": {"count": 0, "severity": "Medium", "examples": []},
            "A06:2021 - Vulnerable Components": {"count": 0, "severity": "High", "examples": []},
            "A07:2021 - Authentication Failures": {"count": 0, "severity": "Critical", "examples": []},
            "A08:2021 - Software and Data Integrity": {"count": 0, "severity": "Medium", "examples": []},
            "A09:2021 - Security Logging Failures": {"count": 0, "severity": "Medium", "examples": []},
            "A10:2021 - Server-Side Request Forgery": {"count": 0, "severity": "Medium", "examples": []}
        }

        # Map attack types to OWASP categories
        for profile in attacker_profiles:
            for attack_type in profile.attack_types:
                attack_str = str(attack_type.value) if hasattr(attack_type, 'value') else str(attack_type)

                if 'SQL' in attack_str or 'COMMAND' in attack_str or 'XSS' in attack_str:
                    owasp_categories["A03:2021 - Injection"]["count"] += 1
                    owasp_categories["A03:2021 - Injection"]["examples"].append(profile.ip_address)

                elif 'BRUTE' in attack_str or 'AUTHENTICATION' in attack_str:
                    owasp_categories["A07:2021 - Authentication Failures"]["count"] += 1
                    owasp_categories["A07:2021 - Authentication Failures"]["examples"].append(profile.ip_address)

                elif 'PATH' in attack_str or 'TRAVERSAL' in attack_str:
                    owasp_categories["A01:2021 - Broken Access Control"]["count"] += 1
                    owasp_categories["A01:2021 - Broken Access Control"]["examples"].append(profile.ip_address)

            # Check for CVE exploits (vulnerable components)
            if len(profile.cve_exploits) > 0:
                owasp_categories["A06:2021 - Vulnerable Components"]["count"] += len(profile.cve_exploits)
                owasp_categories["A06:2021 - Vulnerable Components"]["examples"].append(
                    f"{profile.ip_address} (CVEs: {', '.join(list(profile.cve_exploits)[:3])})"
                )

        return owasp_categories

    def _generate_owasp_recommendations(self, owasp_mapping: Dict[str, Dict]) -> List[str]:
        """Generate recommendations based on OWASP findings"""

        recommendations = []

        for category, data in owasp_mapping.items():
            if data['count'] > 10:
                recommendations.append(
                    f"HIGH PRIORITY: Address {category} - {data['count']} instances detected. "
                    f"Severity: {data['severity']}. Implement input validation, output encoding, and security controls."
                )
            elif data['count'] > 5:
                recommendations.append(
                    f"MEDIUM PRIORITY: {category} - {data['count']} instances detected. "
                    f"Review and remediate within 30 days."
                )

        if not recommendations:
            recommendations.append("Good security posture - no critical OWASP Top 10 violations detected. Maintain current controls.")

        return recommendations
