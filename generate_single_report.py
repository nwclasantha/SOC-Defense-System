#!/usr/bin/env python3
"""
Single Report Generator
Generates a single compliance report based on command-line arguments

Usage:
    python generate_single_report.py --report-type executive --hours 24
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
import sys

async def get_current_attackers(hours_back=24):
    """Run FRESH analysis to get current attackers"""
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
        max_results_per_query=-1
    )

    # Run analysis
    analyzer = CriticalAttackerAnalyzer(config)
    attacker_profiles, agent_profiles = await analyzer.analyze(hours_back=hours_back)

    print(f"[ANALYSIS] Complete: {len(attacker_profiles)} attackers, {len(agent_profiles)} agents")

    return attacker_profiles, agent_profiles

async def main():
    parser = argparse.ArgumentParser(description='Generate a single compliance report')
    parser.add_argument(
        '--report-type',
        type=str,
        required=True,
        choices=['executive', 'threat', 'iso27001', 'soc2', 'gdpr', 'nist', 'risk', 'owasp'],
        help='Type of report to generate'
    )
    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        choices=[24, 48, 168, 336, 720, 2160],
        help='Time range to analyze (default: 24 hours)'
    )

    args = parser.parse_args()

    print(f"\n{'='*100}")
    print(f"GENERATING {args.report_type.upper()} REPORT")
    print(f"Time Range: Last {args.hours} hours")
    print(f"{'='*100}\n")

    # Get current attackers
    attacker_profiles, agent_profiles = await get_current_attackers(hours_back=args.hours)

    if not attacker_profiles:
        print(f"[ERROR] No attackers detected in the last {args.hours} hours!")
        return

    # Initialize Enterprise Report Integration
    integration = EnterpriseReportIntegration(output_dir="./compliance_reports")

    # Initialize MITRE mapper
    mitre_mapper = MitreAttackMapper()

    try:
        if args.report_type == 'executive':
            print("[REPORT] Generating Executive Summary...")
            files = integration.generate_executive_report(
                attacker_profiles=attacker_profiles,
                agent_profiles=agent_profiles,
                time_period_hours=args.hours,
                formats=['html', 'pdf', 'excel']
            )
            print(f"[OK] HTML: {files.get('html', 'N/A')}")
            print(f"[OK] PDF: {files.get('pdf', 'N/A')}")
            print(f"[OK] Excel: {files.get('excel', 'N/A')}")

        elif args.report_type == 'threat':
            print("[REPORT] Generating Threat Intelligence Report...")
            files = integration.generate_threat_intelligence_report(
                attacker_profiles=attacker_profiles,
                mitre_mapper=mitre_mapper,
                formats=['html', 'pdf', 'excel']
            )
            print(f"[OK] HTML: {files.get('html', 'N/A')}")
            print(f"[OK] PDF: {files.get('pdf', 'N/A')}")
            print(f"[OK] Excel: {files.get('excel', 'N/A')}")

        elif args.report_type == 'iso27001':
            print("[REPORT] Generating ISO 27001 Compliance Report...")
            # Generate HTML and PDF
            files = integration.generate_compliance_report(
                framework='iso27001',
                compliance_data={},
                formats=['html', 'pdf']
            )
            print(f"[OK] HTML: {files.get('html', 'N/A')}")
            print(f"[OK] PDF: {files.get('pdf', 'N/A')}")

            # Generate Professional Excel with IP Intelligence
            from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
            ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
            excel_files = ip_reporter.generate_full_ip_intelligence_report(
                attacker_profiles=attacker_profiles,
                agent_profiles={},
                output_name=f"ISO27001_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            print(f"[OK] Excel (Professional IP Data): {excel_files.get('excel', 'N/A')}")

        elif args.report_type == 'soc2':
            print("[REPORT] Generating SOC 2 Type II Report...")
            # Generate HTML and PDF
            files = integration.generate_compliance_report(
                framework='soc2',
                compliance_data={},
                formats=['html', 'pdf']
            )
            print(f"[OK] HTML: {files.get('html', 'N/A')}")
            print(f"[OK] PDF: {files.get('pdf', 'N/A')}")

            # Generate Professional Excel with IP Intelligence
            from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
            ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
            excel_files = ip_reporter.generate_full_ip_intelligence_report(
                attacker_profiles=attacker_profiles,
                agent_profiles={},
                output_name=f"SOC2_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            print(f"[OK] Excel (Professional IP Data): {excel_files.get('excel', 'N/A')}")

        elif args.report_type == 'gdpr':
            print("[REPORT] Generating GDPR Compliance Report...")
            # Generate HTML and PDF
            files = integration.generate_compliance_report(
                framework='gdpr',
                compliance_data={},
                formats=['html', 'pdf']
            )
            print(f"[OK] HTML: {files.get('html', 'N/A')}")
            print(f"[OK] PDF: {files.get('pdf', 'N/A')}")

            # Generate Professional Excel with IP Intelligence
            from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
            ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
            excel_files = ip_reporter.generate_full_ip_intelligence_report(
                attacker_profiles=attacker_profiles,
                agent_profiles={},
                output_name=f"GDPR_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            print(f"[OK] Excel (Professional IP Data): {excel_files.get('excel', 'N/A')}")

        elif args.report_type == 'nist':
            print("[REPORT] Generating NIST CSF Assessment...")
            # Generate HTML and PDF
            files = integration.generate_compliance_report(
                framework='nist_csf',
                compliance_data={},
                formats=['html', 'pdf']
            )
            print(f"[OK] HTML: {files.get('html', 'N/A')}")
            print(f"[OK] PDF: {files.get('pdf', 'N/A')}")

            # Generate Professional Excel with IP Intelligence
            from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
            ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
            excel_files = ip_reporter.generate_full_ip_intelligence_report(
                attacker_profiles=attacker_profiles,
                agent_profiles={},
                output_name=f"NIST_CSF_Compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            print(f"[OK] Excel (Professional IP Data): {excel_files.get('excel', 'N/A')}")

        elif args.report_type == 'risk':
            print("[REPORT] Generating Risk Assessment Report...")
            # Generate HTML and PDF
            files = integration.generate_risk_assessment_report(
                attacker_profiles=attacker_profiles,
                agent_profiles=agent_profiles,
                formats=['html', 'pdf']
            )
            print(f"[OK] HTML: {files.get('html', 'N/A')}")
            print(f"[OK] PDF: {files.get('pdf', 'N/A')}")

            # Generate Professional Excel with IP Intelligence
            from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
            ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
            excel_files = ip_reporter.generate_full_ip_intelligence_report(
                attacker_profiles=attacker_profiles,
                agent_profiles={},
                output_name=f"Risk_Assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            print(f"[OK] Excel (Professional IP Data): {excel_files.get('excel', 'N/A')}")

        elif args.report_type == 'owasp':
            print("[REPORT] Generating OWASP Top 10 Report...")
            # Generate HTML and PDF
            files = integration.generate_owasp_report(
                attacker_profiles=attacker_profiles,
                formats=['html', 'pdf']
            )
            print(f"[OK] HTML: {files.get('html', 'N/A')}")
            print(f"[OK] PDF: {files.get('pdf', 'N/A')}")

            # Generate Professional Excel with IP Intelligence
            from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
            ip_reporter = UltraAdvancedIPIntelligenceReport(output_dir="./compliance_reports/generated")
            excel_files = ip_reporter.generate_full_ip_intelligence_report(
                attacker_profiles=attacker_profiles,
                agent_profiles={},
                output_name=f"OWASP_Top10_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            print(f"[OK] Excel (Professional IP Data): {excel_files.get('excel', 'N/A')}")

        print(f"\n{'='*100}")
        print(f"{args.report_type.upper()} REPORT GENERATED SUCCESSFULLY!")
        print(f"Output Directory: {Path('./compliance_reports').absolute()}")
        print(f"{'='*100}\n")

    except Exception as e:
        print(f"[ERROR] Failed to generate {args.report_type} report: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
