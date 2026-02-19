"""
Generate Ultra-Professional IP Intelligence Report
With Excel, CSV, PDF exports and interactive HTML with filters
"""

import asyncio
from modules.UltraAdvancedIPIntelligenceReport import UltraAdvancedIPIntelligenceReport
from modules.CriticalAttackerAnalyzer import CriticalAttackerAnalyzer
from modules.CLIConfiguration import CLIConfiguration
from modules.ConfigManager import ConfigManager

async def main():
    print("\n" + "="*100)
    print("ULTRA-PROFESSIONAL IP INTELLIGENCE REPORT GENERATOR")
    print("Full Export: Excel, CSV, PDF | Interactive HTML with Filters")
    print("="*100 + "\n")

    # Get real attacker data from Wazuh/Elasticsearch
    print("[1/3] Fetching attacker data from Elasticsearch...")
    config_mgr = ConfigManager()
    config = CLIConfiguration(
        elasticsearch_url=config_mgr.get('Elasticsearch', 'url'),
        elasticsearch_user=config_mgr.get('Elasticsearch', 'username'),
        elasticsearch_password=config_mgr.get('Elasticsearch', 'password'),
        verify_ssl=False,
        default_hours_back=168,  # 7 days
        min_severity_level=0,
        max_results_per_query=-1
    )

    analyzer = CriticalAttackerAnalyzer(config)
    attacker_profiles, agent_profiles = await analyzer.analyze(hours_back=168)

    print(f"[OK] Retrieved {len(attacker_profiles)} malicious IPs with {sum(p.attack_count for p in attacker_profiles):,} attacks")

    # Generate IP Intelligence Report
    print("\n[2/3] Generating comprehensive IP intelligence report...")
    reporter = UltraAdvancedIPIntelligenceReport(output_dir="./ip_intelligence_reports")

    generated_files = reporter.generate_full_ip_intelligence_report(
        attacker_profiles=attacker_profiles,
        agent_profiles=agent_profiles,
        output_name="Attacker_IP_Intelligence"
    )

    print("\n[3/3] Report generation complete!")
    print("\n" + "="*100)
    print("GENERATED FILES:")
    print("="*100)
    for format_type, filepath in generated_files.items():
        print(f"  [{format_type.upper()}] {filepath}")

    print("\n" + "="*100)
    print("FEATURES:")
    print("="*100)
    print("  Excel Export:")
    print("    - Sheet 1: All Attackers (sorted by risk)")
    print("    - Sheet 2: Critical IPs only (Risk >= 80)")
    print("    - Sheet 3: High-volume attackers (Attack Count >= 100)")
    print("    - Sheet 4: Aggregated by Country")
    print("    - Sheet 5: Summary Statistics")
    print("    - Sheet 6: Top 50 Attackers")
    print("")
    print("  CSV Export:")
    print("    - All attacker data sorted by risk")
    print("    - UTF-8 encoding with BOM for Excel compatibility")
    print("")
    print("  Interactive HTML:")
    print("    - Advanced filters (IP search, risk level, country, attack count)")
    print("    - Sortable columns (click headers)")
    print("    - Real-time filtering")
    print("    - Export filtered data to CSV")
    print("    - 3 Analytics Charts:")
    print("      1. Risk Level Distribution (pie chart)")
    print("      2. Top 15 Countries by Attack Volume (bar chart)")
    print("      3. Attack Volume vs Risk Score (scatter plot)")
    print("    - Ultra-professional Bloomberg Terminal styling")
    print("    - Dark theme with glassmorphism effects")
    print("    - Responsive design")
    print("")
    print("="*100)
    print("\nOpen the HTML file in your browser to see the interactive dashboard!")
    print("="*100 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
