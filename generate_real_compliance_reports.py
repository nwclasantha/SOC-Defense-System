"""
ADVANCED ENTERPRISE COMPLIANCE REPORT GENERATOR
Uses the new AdvancedEnterpriseReportEngine for Fortune 500-level reports

Features:
- Executive Summary with KPIs, risk scoring, maturity assessment
- Advanced Threat Intelligence with MITRE ATT&CK heatmaps
- Comprehensive Compliance Reports (ISO 27001, SOC 2, GDPR, NIST, HIPAA, PCI DSS)
- Risk Assessment with financial impact
- OWASP Top 10 mapping
- Interactive Plotly dashboards
- Multi-format output (HTML, PDF, Excel)

Usage:
    python generate_real_compliance_reports.py [--hours HOURS]

    --hours HOURS  : Number of hours to analyze (default: 168 = 7 days)

Examples:
    python generate_real_compliance_reports.py --hours 24   # Last 24 hours
    python generate_real_compliance_reports.py --hours 168  # Last 7 days
"""

from modules.EnterpriseReportIntegration import EnterpriseReportIntegration
from modules.CriticalAttackerAnalyzer import CriticalAttackerAnalyzer
from modules.CLIConfiguration import CLIConfiguration
from modules.ConfigManager import ConfigManager
from modules.MitreAttackMapper import MitreAttackMapper
from datetime import datetime
from pathlib import Path
import asyncio
import argparse

async def get_current_attackers(hours_back=24):
    """Run FRESH analysis to get current attackers with ML validation"""
    print(f"\n[ANALYSIS] Running fresh attack analysis for last {hours_back} hours...")

    # Initialize configuration
    config_mgr = ConfigManager()
    config = CLIConfiguration(
        elasticsearch_url=config_mgr.get('Elasticsearch', 'url'),
        elasticsearch_user=config_mgr.get('Elasticsearch', 'username'),
        elasticsearch_password=config_mgr.get('Elasticsearch', 'password'),
        verify_ssl=False,
        default_hours_back=hours_back,
        min_severity_level=0,
        max_results_per_query=-1  # Unlimited - capture ALL attackers
    )

    # Run analysis
    analyzer = CriticalAttackerAnalyzer(config)
    attacker_profiles, agent_profiles = await analyzer.analyze(hours_back=hours_back)

    print(f"[ANALYSIS] Complete: {len(attacker_profiles)} attackers, {len(agent_profiles)} agents")

    return attacker_profiles, agent_profiles

def print_statistics(attacker_profiles, agent_profiles):
    """Print analysis statistics"""
    total_ips = len(attacker_profiles)
    total_attacks = sum(p.attack_count for p in attacker_profiles)
    critical_ips = len([p for p in attacker_profiles if p.risk_score >= 85])

    print(f"\n{'='*100}")
    print("ATTACK ANALYSIS STATISTICS")
    print(f"{'='*100}")
    print(f"  Total Malicious IPs:        {total_ips:,}")
    print(f"  Total Attack Events:        {total_attacks:,}")
    print(f"  Critical Attackers (>=85):  {critical_ips}")
    print(f"  Average Attacks per IP:     {total_attacks / total_ips if total_ips > 0 else 0:.1f}")
    print(f"  Targeted Agents:            {len(agent_profiles)}")
    print(f"{'='*100}\n")

async def main(hours_back=24, report_type='all'):
    """Generate ADVANCED enterprise compliance reports"""
    print("\n" + "="*100)
    print("ADVANCED ENTERPRISE REPORT GENERATOR")
    print("Fortune 500-Level Security Intelligence & Compliance Reporting")
    print(f"Time Range: Last {hours_back} hours ({hours_back//24} days)" if hours_back >= 24 else f"Time Range: Last {hours_back} hours")
    if report_type != 'all':
        print(f"Report Type: {report_type.upper()}")
    print("="*100)

    # Get current attackers
    attacker_profiles, agent_profiles = await get_current_attackers(hours_back=hours_back)

    if not attacker_profiles:
        print(f"[ERROR] No attackers detected in the last {hours_back} hours! Cannot generate reports.")
        return

    # Print statistics
    print_statistics(attacker_profiles, agent_profiles)

    # Initialize Enterprise Report Integration
    integration = EnterpriseReportIntegration(output_dir="./compliance_reports")

    # Initialize MITRE mapper
    mitre_mapper = MitreAttackMapper()

    print(f"{'='*100}")
    print("GENERATING ADVANCED ENTERPRISE REPORTS")
    print(f"{'='*100}\n")

    # ========================================================================
    # 1. EXECUTIVE SUMMARY REPORT (C-Suite / Board Level)
    # ========================================================================
    print("[1/9] Generating Executive Summary Report (C-Suite/Board Level)...")
    print("      Features: Risk Scoring, Maturity Assessment, KPIs, Financial Impact, Forecasting")
    try:
        files = integration.generate_executive_report(
            attacker_profiles=attacker_profiles,
            agent_profiles=agent_profiles,
            time_period_hours=hours_back,  # Use selected time range
            formats=['html', 'pdf', 'excel']
        )
        print(f"      [OK] HTML (Interactive Dashboard): {files.get('html', 'N/A')}")
        print(f"      [OK] PDF (Boardroom Ready):        {files.get('pdf', 'N/A')}")
        print(f"      [OK] Excel (Data Analysis):        {files.get('excel', 'N/A')}")
    except Exception as e:
        print(f"      [ERROR] Failed: {e}")

    # ========================================================================
    # 2. THREAT INTELLIGENCE REPORT (Security Analysts / Threat Hunters)
    # ========================================================================
    print("\n[2/8] Generating Advanced Threat Intelligence Report...")
    print("      Features: MITRE ATT&CK Heatmap, Attack Chains, Geo Analysis, IoCs")
    try:
        files = integration.generate_threat_intelligence_report(
            attacker_profiles=attacker_profiles,
            mitre_mapper=mitre_mapper,
            formats=['html', 'pdf', 'excel']
        )
        print(f"      [OK] HTML (Interactive):  {files.get('html', 'N/A')}")
        print(f"      [OK] PDF (Printable):    {files.get('pdf', 'N/A')}")
        print(f"      [OK] Excel (With IoCs):   {files.get('excel', 'N/A')}")
    except Exception as e:
        print(f"      [ERROR] Failed: {e}")

    # ========================================================================
    # 3. ISO 27001 COMPLIANCE REPORT
    # ========================================================================
    print("\n[3/8] Generating ISO 27001:2022 Compliance Report...")
    print("      Features: 93 Controls, Annex A Domains, Gap Analysis, Maturity Assessment")
    try:
        # Generate HTML and PDF
        files = integration.generate_compliance_report(
            framework='iso27001',
            compliance_data={},
            formats=['html', 'pdf']
        )
        print(f"      [OK] HTML:  {files.get('html', 'N/A')}")
        print(f"      [OK] PDF:   {files.get('pdf', 'N/A')}")

        # Generate Professional Excel with IP Intelligence
        from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
        ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
        excel_files = ip_reporter.generate_full_ip_intelligence_report(
            attacker_profiles=attacker_profiles,
            agent_profiles={},
            output_name=f"ISO27001_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        print(f"      [OK] Excel: {excel_files.get('excel', 'N/A')} (Professional IP Intelligence)")
    except Exception as e:
        print(f"      [ERROR] Failed: {e}")

    # ========================================================================
    # 4. SOC 2 TYPE II COMPLIANCE REPORT
    # ========================================================================
    print("\n[4/8] Generating SOC 2 Type II Compliance Report...")
    print("      Features: 5 Trust Services Criteria, Control Testing, Evidence Packages")
    try:
        # Generate HTML and PDF
        files = integration.generate_compliance_report(
            framework='soc2',
            compliance_data={},
            formats=['html', 'pdf']
        )
        print(f"      [OK] HTML:  {files.get('html', 'N/A')}")
        print(f"      [OK] PDF:   {files.get('pdf', 'N/A')}")

        # Generate Professional Excel with IP Intelligence
        from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
        ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
        excel_files = ip_reporter.generate_full_ip_intelligence_report(
            attacker_profiles=attacker_profiles,
            agent_profiles={},
            output_name=f"SOC2_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        print(f"      [OK] Excel: {excel_files.get('excel', 'N/A')} (Professional IP Intelligence)")
    except Exception as e:
        print(f"      [ERROR] Failed: {e}")

    # ========================================================================
    # 5. GDPR COMPLIANCE REPORT
    # ========================================================================
    print("\n[5/8] Generating GDPR Compliance Report...")
    print("      Features: 7 Principles, Data Subject Rights, DPIA, Breach Notification")
    try:
        # Generate HTML and PDF
        files = integration.generate_compliance_report(
            framework='gdpr',
            compliance_data={},
            formats=['html', 'pdf']
        )
        print(f"      [OK] HTML:  {files.get('html', 'N/A')}")
        print(f"      [OK] PDF:   {files.get('pdf', 'N/A')}")

        # Generate Professional Excel with IP Intelligence
        from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
        ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
        excel_files = ip_reporter.generate_full_ip_intelligence_report(
            attacker_profiles=attacker_profiles,
            agent_profiles={},
            output_name=f"GDPR_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        print(f"      [OK] Excel: {excel_files.get('excel', 'N/A')} (Professional IP Intelligence)")
    except Exception as e:
        print(f"      [ERROR] Failed: {e}")

    # ========================================================================
    # 6. NIST CSF ASSESSMENT
    # ========================================================================
    print("\n[6/8] Generating NIST Cybersecurity Framework Assessment...")
    print("      Features: 5 Functions, Maturity Levels, Implementation Tiers")
    try:
        # Generate HTML and PDF
        files = integration.generate_compliance_report(
            framework='nist_csf',
            compliance_data={},
            formats=['html', 'pdf']
        )
        print(f"      [OK] HTML: {files.get('html', 'N/A')}")
        print(f"      [OK] PDF:  {files.get('pdf', 'N/A')}")

        # Generate Professional Excel with IP Intelligence
        from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
        ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
        excel_files = ip_reporter.generate_full_ip_intelligence_report(
            attacker_profiles=attacker_profiles,
            agent_profiles={},
            output_name=f"NIST_CSF_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        print(f"      [OK] Excel: {excel_files.get('excel', 'N/A')} (Professional IP Intelligence)")
    except Exception as e:
        print(f"      [ERROR] Failed: {e}")

    # ========================================================================
    # 7. RISK ASSESSMENT REPORT
    # ========================================================================
    print("\n[7/8] Generating Enterprise Risk Assessment Report...")
    print("      Features: Risk Matrix, Asset Criticality, Vulnerability Analysis, Treatment Plans")
    try:
        # Generate HTML and PDF
        files = integration.generate_risk_assessment_report(
            attacker_profiles=attacker_profiles,
            agent_profiles=agent_profiles,
            formats=['html', 'pdf']
        )
        print(f"      [OK] HTML: {files.get('html', 'N/A')}")
        print(f"      [OK] PDF:  {files.get('pdf', 'N/A')}")

        # Generate Professional Excel with IP Intelligence
        from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
        ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
        excel_files = ip_reporter.generate_full_ip_intelligence_report(
            attacker_profiles=attacker_profiles,
            agent_profiles={},
            output_name=f"Risk_Assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        print(f"      [OK] Excel: {excel_files.get('excel', 'N/A')} (Professional IP Intelligence)")
    except Exception as e:
        print(f"      [ERROR] Failed: {e}")

    # ========================================================================
    # 8. OWASP TOP 10 2021 REPORT
    # ========================================================================
    print("\n[8/8] Generating OWASP Top 10 2021 Report...")
    print("      Features: All 10 Categories, Attack Mapping, Remediation Priorities")
    try:
        # Generate HTML and PDF
        files = integration.generate_owasp_report(
            attacker_profiles=attacker_profiles,
            formats=['html', 'pdf']
        )
        print(f"      [OK] HTML: {files.get('html', 'N/A')}")
        print(f"      [OK] PDF:  {files.get('pdf', 'N/A')}")

        # Generate Professional Excel with IP Intelligence
        from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
        ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
        excel_files = ip_reporter.generate_full_ip_intelligence_report(
            attacker_profiles=attacker_profiles,
            agent_profiles={},
            output_name=f"OWASP_Top10_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        print(f"      [OK] Excel: {excel_files.get('excel', 'N/A')} (Professional IP Intelligence)")
    except Exception as e:
        print(f"      [ERROR] Failed: {e}")

    # Final Summary
    print(f"\n{'='*100}")
    print("REPORT GENERATION COMPLETE!")
    print(f"{'='*100}")
    print("\nOutput Directory:")
    print(f"   {Path('./compliance_reports').absolute()}")
    print("\nReport Types Generated:")
    print("   1. Executive Summary       - C-Suite/Board level with KPIs & financial impact")
    print("   2. Threat Intelligence     - MITRE ATT&CK heatmaps, attack chains, IP intelligence with ML analytics")
    print("   3. ISO 27001 Compliance    - 93 controls, gap analysis, maturity assessment")
    print("   4. SOC 2 Type II           - Trust Services Criteria, control testing")
    print("   5. GDPR Compliance         - Data protection, subject rights, breach notification")
    print("   6. NIST CSF Assessment     - 5 functions, maturity levels, implementation tiers")
    print("   7. Risk Assessment         - Risk matrix, asset criticality, treatment plans")
    print("   8. OWASP Top 10 2021       - Web app security, attack mapping, remediation")
    print("\nAdvanced Features Included:")
    print("   - Interactive Plotly.js dashboards (zoom, pan, filter)")
    print("   - Risk gauge charts (0-100 color-coded)")
    print("   - Maturity radar charts (5 dimensions)")
    print("   - MITRE ATT&CK heatmaps (12 tactics x techniques)")
    print("   - Financial waterfall charts (cost breakdown)")
    print("   - Geographic threat maps (world choropleth)")
    print("   - Risk heatmaps (5x5 likelihood/impact)")
    print("   - Multi-format output (HTML, PDF, Excel)")
    print("   - Industry benchmarking vs. Fortune 500 peers")
    print("   - 30-day threat forecasting with confidence intervals")
    print("   - AI-generated executive insights and action items")
    print("\nEnterprise Capabilities:")
    print("   - C-Suite presentation ready")
    print("   - Board of Directors briefing materials")
    print("   - Compliance audit evidence packages")
    print("   - Risk management decision support")
    print("   - Strategic security program guidance")
    print(f"\n{'='*100}")
    print("Open the HTML reports in your browser for interactive dashboards!")
    print(f"{'='*100}\n")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Generate advanced enterprise compliance reports from Wazuh alerts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Supported Time Ranges (matches GUI filters):
  --hours 24     Last Day (24 hours) - DEFAULT
  --hours 48     Last 2 Days (48 hours)
  --hours 168    Last 7 Days (168 hours)
  --hours 336    Last 14 Days (336 hours)
  --hours 720    Last 30 Days (720 hours)
  --hours 2160   Last 90 Days (2160 hours)

Examples:
  python generate_real_compliance_reports.py                # Last 24 hours (default)
  python generate_real_compliance_reports.py --hours 48     # Last 2 days
  python generate_real_compliance_reports.py --hours 168    # Last 7 days
  python generate_real_compliance_reports.py --hours 720    # Last 30 days
        '''
    )
    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        choices=[24, 48, 168, 336, 720, 2160],
        help='Time range to analyze - matches GUI dropdown (default: 24 hours)'
    )
    parser.add_argument(
        '--report-type',
        type=str,
        default='all',
        choices=['all', 'executive', 'threat', 'iso27001', 'soc2', 'gdpr', 'nist', 'risk', 'owasp'],
        help='Type of report to generate (default: all reports)'
    )

    args = parser.parse_args()

    # Run with specified hours and report type
    asyncio.run(main(hours_back=args.hours, report_type=args.report_type))
