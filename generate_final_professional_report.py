"""
FINAL ULTRA-PROFESSIONAL IP INTELLIGENCE REPORT
With DataTables, Export Buttons, Perfect Alignment, Professional Look

Usage:
    python generate_final_professional_report.py [--hours HOURS]

    --hours HOURS  : Number of hours to analyze (default: 168 = 7 days)

Examples:
    python generate_final_professional_report.py --hours 24   # Last 24 hours
    python generate_final_professional_report.py --hours 168  # Last 7 days
"""

import asyncio
import pandas as pd
import json
import argparse
from datetime import datetime
from pathlib import Path
from modules.CriticalAttackerAnalyzer import CriticalAttackerAnalyzer
from modules.CLIConfiguration import CLIConfiguration
from modules.ConfigManager import ConfigManager

async def main(hours_back=24):
    print("\n" + "="*100)
    print("FINAL ULTRA-PROFESSIONAL IP INTELLIGENCE REPORT")
    print("DataTables + Export Buttons + Perfect Alignment + Enterprise Look")
    print(f"Time Range: Last {hours_back} hours ({hours_back//24} days)" if hours_back >= 24 else f"Time Range: Last {hours_back} hours")
    print("="*100 + "\n")

    # Get real attacker data
    print(f"[1/2] Fetching attacker data from Elasticsearch (last {hours_back} hours)...")
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

    analyzer = CriticalAttackerAnalyzer(config)
    attacker_profiles, agent_profiles = await analyzer.analyze(hours_back=hours_back)

    print(f"[OK] Retrieved {len(attacker_profiles)} malicious IPs with {sum(p.attack_count for p in attacker_profiles):,} attacks")

    # Convert to DataFrame
    print("\n[2/2] Generating ultra-professional report with DataTables...")
    data = []
    for profile in attacker_profiles:
        row = {
            'IP': profile.ip_address,
            'Risk': round(profile.risk_score, 1),
            'Level': 'CRITICAL' if profile.risk_score >= 85 else 'HIGH' if profile.risk_score >= 70 else 'MEDIUM' if profile.risk_score >= 40 else 'LOW',
            'Attacks': profile.attack_count,
            'First_Seen': profile.first_seen.strftime('%Y-%m-%d %H:%M') if hasattr(profile, 'first_seen') and profile.first_seen else 'N/A',
            'Last_Seen': profile.last_seen.strftime('%Y-%m-%d %H:%M') if hasattr(profile, 'last_seen') and profile.last_seen else 'N/A',
            'Country': getattr(profile, 'country', 'Unknown'),
            'City': getattr(profile, 'city', 'Unknown'),
            'ISP': getattr(profile, 'isp', 'Unknown')[:50]
        }
        data.append(row)

    df = pd.DataFrame(data)

    # Generate HTML with DataTables
    html = generate_professional_html(df, len(attacker_profiles))

    # Save
    output_dir = Path("./ip_intelligence_reports")
    output_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = output_dir / f"FINAL_PROFESSIONAL_IP_Report_{timestamp}.html"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"\n[OK] Report generated: {output_file}")
    print("\n" + "="*100)
    print("FEATURES:")
    print("="*100)
    print("  ✓ DataTables with advanced search/filter")
    print("  ✓ Export buttons: Excel, CSV, PDF, Copy")
    print("  ✓ Print button")
    print("  ✓ Column visibility toggle")
    print("  ✓ Perfect graph alignment")
    print("  ✓ Ultra-professional dark theme")
    print("  ✓ Responsive design")
    print("  ✓ Pagination")
    print("  ✓ Individual column search")
    print("="*100 + "\n")

    # Open in browser
    import subprocess
    subprocess.Popen(['cmd', '/c', 'start', str(output_file)])

def generate_professional_html(df, total_ips):
    """Generate ultra-professional HTML with DataTables and export buttons"""

    # Convert to JSON
    table_data = df.to_dict('records')
    table_json = json.dumps(table_data, default=str)

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Professional IP Intelligence Report</title>

    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>

    <!-- DataTables CSS -->
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.1/css/buttons.dataTables.min.css">

    <!-- DataTables JS -->
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.1/js/dataTables.buttons.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.html5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.print.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.colVis.min.js"></script>

    <!-- Plotly -->
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>

    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #0a0e27;
            color: #e0e6ed;
            padding: 20px;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1800px;
            margin: 0 auto;
        }}

        .header {{
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 50%, #06b6d4 100%);
            padding: 50px;
            border-radius: 20px;
            text-align: center;
            margin-bottom: 40px;
            box-shadow: 0 25px 50px rgba(59, 130, 246, 0.3);
            position: relative;
            overflow: hidden;
        }}

        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
        }}

        @keyframes rotate {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}

        .header h1 {{
            font-size: 3.5em;
            font-weight: 900;
            margin-bottom: 15px;
            position: relative;
            z-index: 1;
            letter-spacing: -1px;
        }}

        .header .subtitle {{
            font-size: 1.5em;
            opacity: 0.95;
            position: relative;
            z-index: 1;
        }}

        .badge {{
            display: inline-block;
            background: #ef4444;
            padding: 10px 25px;
            border-radius: 25px;
            font-weight: 700;
            font-size: 0.9em;
            margin-top: 20px;
            letter-spacing: 2px;
            position: relative;
            z-index: 1;
        }}

        .stats-row {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }}

        .stat-card {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            padding: 35px;
            border-radius: 15px;
            text-align: center;
            border: 1px solid rgba(59, 130, 246, 0.2);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            transition: all 0.3s ease;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            border-color: rgba(59, 130, 246, 0.5);
            box-shadow: 0 15px 40px rgba(59, 130, 246, 0.3);
        }}

        .stat-value {{
            font-size: 3.5em;
            font-weight: 900;
            background: linear-gradient(135deg, #3b82f6, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}

        .stat-label {{
            font-size: 1.1em;
            color: #94a3b8;
            font-weight: 600;
        }}

        .section {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            padding: 40px;
            border-radius: 20px;
            margin-bottom: 30px;
            border: 1px solid rgba(59, 130, 246, 0.2);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }}

        .section-title {{
            font-size: 2em;
            font-weight: 800;
            margin-bottom: 30px;
            color: #3b82f6;
            border-left: 5px solid #3b82f6;
            padding-left: 20px;
        }}

        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }}

        .chart-box {{
            background: #0f172a;
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(59, 130, 246, 0.2);
        }}

        .chart-box.full {{
            grid-column: 1 / -1;
        }}

        /* DataTables Custom Styling */
        .dataTables_wrapper {{
            padding: 0;
        }}

        .dataTables_wrapper .dt-buttons {{
            float: left;
            margin-bottom: 20px;
        }}

        .dt-button {{
            background: linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%) !important;
            border: none !important;
            color: white !important;
            padding: 12px 25px !important;
            margin-right: 10px !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
            cursor: pointer !important;
            transition: all 0.3s ease !important;
        }}

        .dt-button:hover {{
            transform: translateY(-2px) !important;
            box-shadow: 0 8px 20px rgba(59, 130, 246, 0.4) !important;
        }}

        table.dataTable {{
            width: 100% !important;
            background: #0f172a !important;
            border: 1px solid rgba(59, 130, 246, 0.2) !important;
            border-radius: 10px !important;
        }}

        table.dataTable thead {{
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%) !important;
        }}

        table.dataTable thead th {{
            color: white !important;
            font-weight: 700 !important;
            padding: 18px 12px !important;
            border-bottom: 2px solid #3b82f6 !important;
        }}

        table.dataTable tbody td {{
            color: #e0e6ed !important;
            padding: 15px 12px !important;
            border-bottom: 1px solid rgba(59, 130, 246, 0.1) !important;
        }}

        table.dataTable tbody tr:hover {{
            background: rgba(59, 130, 246, 0.1) !important;
        }}

        .dataTables_filter input {{
            background: #0f172a !important;
            border: 1px solid rgba(59, 130, 246, 0.3) !important;
            color: white !important;
            padding: 10px 15px !important;
            border-radius: 8px !important;
            margin-left: 10px !important;
        }}

        .dataTables_length select {{
            background: #0f172a !important;
            border: 1px solid rgba(59, 130, 246, 0.3) !important;
            color: white !important;
            padding: 8px !important;
            border-radius: 8px !important;
            margin: 0 10px !important;
        }}

        .dataTables_info, .dataTables_length label, .dataTables_filter label {{
            color: #94a3b8 !important;
            font-weight: 600 !important;
        }}

        .dataTables_paginate .paginate_button {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%) !important;
            border: 1px solid rgba(59, 130, 246, 0.3) !important;
            color: white !important;
            padding: 8px 16px !important;
            margin: 0 5px !important;
            border-radius: 8px !important;
        }}

        .dataTables_paginate .paginate_button.current {{
            background: linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%) !important;
            border-color: #3b82f6 !important;
        }}

        .dataTables_paginate .paginate_button:hover {{
            background: #3b82f6 !important;
        }}

        .risk-critical {{
            color: #ef4444;
            font-weight: 800;
        }}

        .risk-high {{
            color: #f59e0b;
            font-weight: 700;
        }}

        .risk-medium {{
            color: #3b82f6;
            font-weight: 600;
        }}

        .risk-low {{
            color: #10b981;
        }}

        .level-badge {{
            display: inline-block;
            padding: 6px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 700;
            text-transform: uppercase;
        }}

        .badge-critical {{ background: #ef4444; color: white; }}
        .badge-high {{ background: #f59e0b; color: white; }}
        .badge-medium {{ background: #3b82f6; color: white; }}
        .badge-low {{ background: #10b981; color: white; }}

        @media print {{
            body {{ background: white; color: black; }}
            .section {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ ENTERPRISE IP THREAT INTELLIGENCE</h1>
            <div class="subtitle">Advanced Security Operations Center Report</div>
            <div class="badge">CONFIDENTIAL</div>
        </div>

        <!-- Stats -->
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value">{total_ips}</div>
                <div class="stat-label">Malicious IPs Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(df[df['Level'] == 'CRITICAL'])}</div>
                <div class="stat-label">Critical Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{df['Attacks'].sum():,}</div>
                <div class="stat-label">Total Attack Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{df['Country'].nunique()}</div>
                <div class="stat-label">Countries</div>
            </div>
        </div>

        <!-- Charts -->
        <div class="section">
            <div class="section-title">📊 Visual Analytics</div>
            <div class="charts-grid">
                <div class="chart-box">
                    <div id="riskChart"></div>
                </div>
                <div class="chart-box">
                    <div id="countryChart"></div>
                </div>
                <div class="chart-box full">
                    <div id="scatterChart"></div>
                </div>
            </div>
        </div>

        <!-- Table -->
        <div class="section">
            <div class="section-title">🔍 Attacker IP Database</div>
            <table id="ipTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                        <th>Attacks</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th>Country</th>
                        <th>City</th>
                        <th>ISP</th>
                    </tr>
                </thead>
            </table>
        </div>
    </div>

    <script>
        const rawData = {table_json};

        // Initialize DataTable
        $(document).ready(function() {{
            const table = $('#ipTable').DataTable({{
                data: rawData,
                columns: [
                    {{ data: 'IP' }},
                    {{
                        data: 'Risk',
                        render: function(data, type, row) {{
                            if (type === 'display') {{
                                let className = 'risk-' + row.Level.toLowerCase();
                                return '<span class="' + className + '">' + data + '</span>';
                            }}
                            return data;
                        }}
                    }},
                    {{
                        data: 'Level',
                        render: function(data) {{
                            return '<span class="level-badge badge-' + data.toLowerCase() + '">' + data + '</span>';
                        }}
                    }},
                    {{
                        data: 'Attacks',
                        render: function(data) {{
                            return data.toLocaleString();
                        }}
                    }},
                    {{ data: 'First_Seen' }},
                    {{ data: 'Last_Seen' }},
                    {{ data: 'Country' }},
                    {{ data: 'City' }},
                    {{ data: 'ISP' }}
                ],
                dom: 'Bfrtip',
                buttons: [
                    {{
                        extend: 'excelHtml5',
                        text: '📥 Export Excel',
                        titleAttr: 'Export to Excel',
                        className: 'dt-button'
                    }},
                    {{
                        extend: 'csvHtml5',
                        text: '📄 Export CSV',
                        titleAttr: 'Export to CSV',
                        className: 'dt-button'
                    }},
                    {{
                        extend: 'pdfHtml5',
                        text: '📑 Export PDF',
                        titleAttr: 'Export to PDF',
                        className: 'dt-button'
                    }},
                    {{
                        extend: 'print',
                        text: '🖨️ Print',
                        titleAttr: 'Print Table',
                        className: 'dt-button'
                    }},
                    {{
                        extend: 'colvis',
                        text: '👁️ Columns',
                        titleAttr: 'Column Visibility',
                        className: 'dt-button'
                    }}
                ],
                pageLength: 25,
                lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]],
                order: [[1, 'desc']],
                responsive: true
            }});

            // Add column search
            $('#ipTable thead tr').clone(true).appendTo('#ipTable thead');
            $('#ipTable thead tr:eq(1) th').each(function(i) {{
                const title = $(this).text();
                $(this).html('<input type="text" placeholder="Search ' + title + '" style="width:100%; padding:5px; background:#0f172a; border:1px solid rgba(59,130,246,0.3); color:white; border-radius:5px;" />');

                $('input', this).on('keyup change', function() {{
                    if (table.column(i).search() !== this.value) {{
                        table.column(i).search(this.value).draw();
                    }}
                }});
            }});
        }});

        // Charts
        const riskCounts = {{}};
        rawData.forEach(row => {{
            riskCounts[row.Level] = (riskCounts[row.Level] || 0) + 1;
        }});

        // Risk Distribution
        Plotly.newPlot('riskChart', [{{
            values: Object.values(riskCounts),
            labels: Object.keys(riskCounts),
            type: 'pie',
            hole: 0.4,
            marker: {{
                colors: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981']
            }},
            textinfo: 'label+percent+value',
            textfont: {{ color: 'white', size: 14 }}
        }}], {{
            paper_bgcolor: 'rgba(0,0,0,0)',
            plot_bgcolor: 'rgba(0,0,0,0)',
            font: {{ color: 'white', family: 'Arial' }},
            title: {{ text: 'Risk Level Distribution', font: {{ size: 18, color: '#3b82f6' }} }},
            showlegend: true,
            legend: {{ font: {{ color: 'white' }} }},
            height: 350
        }}, {{ responsive: true }});

        // Top Countries
        const countryCounts = {{}};
        rawData.forEach(row => {{
            countryCounts[row.Country] = (countryCounts[row.Country] || 0) + row.Attacks;
        }});
        const topCountries = Object.entries(countryCounts).sort((a,b) => b[1] - a[1]).slice(0, 10);

        Plotly.newPlot('countryChart', [{{
            x: topCountries.map(x => x[1]),
            y: topCountries.map(x => x[0]),
            type: 'bar',
            orientation: 'h',
            marker: {{
                color: topCountries.map(x => x[1]),
                colorscale: 'Reds',
                showscale: false
            }},
            text: topCountries.map(x => x[1].toLocaleString()),
            textposition: 'outside',
            textfont: {{ color: 'white' }}
        }}], {{
            paper_bgcolor: 'rgba(0,0,0,0)',
            plot_bgcolor: 'rgba(0,0,0,0)',
            font: {{ color: 'white' }},
            title: {{ text: 'Top 10 Countries by Attacks', font: {{ size: 18, color: '#3b82f6' }} }},
            xaxis: {{ gridcolor: 'rgba(59,130,246,0.2)', color: 'white' }},
            yaxis: {{ color: 'white' }},
            height: 350
        }}, {{ responsive: true }});

        // Scatter Plot
        Plotly.newPlot('scatterChart', [{{
            x: rawData.map(r => r.Attacks),
            y: rawData.map(r => r.Risk),
            mode: 'markers',
            type: 'scatter',
            marker: {{
                size: 10,
                color: rawData.map(r => r.Risk),
                colorscale: 'RdYlGn_r',
                showscale: true,
                colorbar: {{ title: {{ text: 'Risk', font: {{ color: 'white' }} }}, tickfont: {{ color: 'white' }} }},
                line: {{ width: 1, color: 'white' }}
            }},
            text: rawData.map(r => r.IP),
            hovertemplate: '<b>%{{text}}</b><br>Attacks: %{{x}}<br>Risk: %{{y}}<extra></extra>'
        }}], {{
            paper_bgcolor: 'rgba(0,0,0,0)',
            plot_bgcolor: 'rgba(0,0,0,0)',
            font: {{ color: 'white' }},
            title: {{ text: 'Attack Volume vs Risk Score', font: {{ size: 18, color: '#3b82f6' }} }},
            xaxis: {{ title: 'Attack Count', gridcolor: 'rgba(59,130,246,0.2)', color: 'white', type: 'log' }},
            yaxis: {{ title: 'Risk Score', gridcolor: 'rgba(59,130,246,0.2)', color: 'white' }},
            height: 400
        }}, {{ responsive: true }});
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Generate ultra-professional IP intelligence report with DataTables',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python generate_final_professional_report.py --hours 24    # Last 24 hours
  python generate_final_professional_report.py --hours 168   # Last 7 days (default)
  python generate_final_professional_report.py --hours 720   # Last 30 days
        '''
    )
    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        help='Number of hours to analyze (default: 24 = last 24 hours)'
    )

    args = parser.parse_args()

    # Run with specified hours
    asyncio.run(main(hours_back=args.hours))
