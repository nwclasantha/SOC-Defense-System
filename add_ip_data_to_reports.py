"""
Add IP Intelligence DataTables to ALL Existing Compliance Reports
Injects IP data with export buttons into all HTML reports retroactively
"""

from pathlib import Path
from modules.IPDataTablesInjector import IPDataTablesInjector
import asyncio
from modules.CriticalAttackerAnalyzer import CriticalAttackerAnalyzer
from modules.CLIConfiguration import CLIConfiguration
from modules.ConfigManager import ConfigManager

async def main():
    print("\n" + "="*100)
    print("ADDING IP INTELLIGENCE TO ALL COMPLIANCE REPORTS")
    print("="*100 + "\n")

    # Get real attacker data
    print("[1/2] Fetching attacker data from Elasticsearch...")
    config_mgr = ConfigManager()
    config = CLIConfiguration(
        elasticsearch_url=config_mgr.get('Elasticsearch', 'url'),
        elasticsearch_user=config_mgr.get('Elasticsearch', 'username'),
        elasticsearch_password=config_mgr.get('Elasticsearch', 'password'),
        verify_ssl=False,
        default_hours_back=24,
        min_severity_level=0,
        max_results_per_query=-1
    )

    analyzer = CriticalAttackerAnalyzer(config)
    attacker_profiles, agent_profiles = await analyzer.analyze(hours_back=24)

    print(f"[OK] Retrieved {len(attacker_profiles)} malicious IPs\n")

    # Find all HTML reports
    print("[2/2] Injecting IP data into all HTML reports...")

    report_dirs = [
        Path("./compliance_reports"),
        Path("./compliance_reports/generated"),
        Path("./ip_intelligence_reports")
    ]

    updated_count = 0
    for report_dir in report_dirs:
        if not report_dir.exists():
            continue

        for html_file in report_dir.glob("*.html"):
            try:
                # Skip IP intelligence reports (already have IP data)
                if "IP_Intelligence" in html_file.name or "FINAL_PROFESSIONAL" in html_file.name:
                    print(f"  [SKIP] {html_file.name} (already has IP data)")
                    continue

                print(f"  [PROCESSING] {html_file.name}...")

                # Read original HTML
                with open(html_file, 'r', encoding='utf-8') as f:
                    html_content = f.read()

                # Skip if already has IP section
                if 'ipIntelTable' in html_content:
                    print(f"  [SKIP] {html_file.name} (already has IP section)")
                    continue

                # Inject IP data
                modified_html = IPDataTablesInjector.inject_ip_data_into_html(
                    html_content,
                    attacker_profiles,
                    section_title=f"🔍 Detected Malicious IPs (Last 24 Hours)"
                )

                # Save modified HTML
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(modified_html)

                print(f"  [OK] {html_file.name} - IP data added!")
                updated_count += 1

            except Exception as e:
                print(f"  [ERROR] {html_file.name}: {e}")

    print(f"\n{'='*100}")
    print(f"COMPLETE! Updated {updated_count} compliance reports with IP intelligence data")
    print(f"{'='*100}\n")
    print("All HTML reports now include:")
    print("  - Full IP intelligence table with DataTables")
    print("  - Export buttons (Excel, CSV, PDF, Print)")
    print("  - Column-level search and filtering")
    print("  - Risk-based color coding")
    print("  - Quick statistics cards")
    print(f"{'='*100}\n")

if __name__ == "__main__":
    asyncio.run(main())
