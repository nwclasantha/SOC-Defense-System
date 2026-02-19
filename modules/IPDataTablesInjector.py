"""
IP DataTables Injector
Adds professional IP intelligence tables with DataTables to ANY HTML report
"""

import json
from typing import List, Any
from datetime import datetime

class IPDataTablesInjector:
    """Injects IP intelligence tables with DataTables into HTML reports"""

    @staticmethod
    def generate_ip_section_html(attacker_profiles: List[Any], section_title: str = "Detected Malicious IPs") -> str:
        """
        Generate a complete IP intelligence section with DataTables

        Args:
            attacker_profiles: List of attacker profiles
            section_title: Title for the IP section

        Returns:
            HTML string with DataTables, export buttons, and charts
        """

        if not attacker_profiles:
            return ""

        # Convert profiles to table data
        table_data = []
        for profile in attacker_profiles:
            row = {
                'IP': profile.ip_address,
                'Risk': round(profile.risk_score, 1),
                'Level': 'CRITICAL' if profile.risk_score >= 85 else 'HIGH' if profile.risk_score >= 70 else 'MEDIUM' if profile.risk_score >= 40 else 'LOW',
                'Attacks': profile.attack_count,
                'FirstSeen': profile.first_seen.strftime('%Y-%m-%d %H:%M') if hasattr(profile, 'first_seen') and profile.first_seen else 'N/A',
                'LastSeen': profile.last_seen.strftime('%Y-%m-%d %H:%M') if hasattr(profile, 'last_seen') and profile.last_seen else 'N/A',
                'Country': getattr(profile, 'country', 'Unknown'),
                'City': getattr(profile, 'city', 'Unknown'),
                'AttackTypes': ', '.join([str(t) for t in profile.attack_types]) if hasattr(profile, 'attack_types') else 'N/A'
            }
            table_data.append(row)

        table_json = json.dumps(table_data, default=str)

        # Count by risk level (consistent with O365EmailSender thresholds)
        critical = len([p for p in attacker_profiles if p.risk_score >= 85])
        high = len([p for p in attacker_profiles if 70 <= p.risk_score < 85])
        medium = len([p for p in attacker_profiles if 40 <= p.risk_score < 70])
        low = len([p for p in attacker_profiles if p.risk_score < 40])

        return f"""
        <!-- IP Intelligence Section - Fully Isolated Styling -->
        <div class="ip-intelligence-section-container" style="all: initial; display: block; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #0c1222 0%, #1a1f35 100%); padding: 50px; border-radius: 20px; margin: 40px 0; border: 3px solid rgba(96, 165, 250, 0.4); box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);">
            <h2 style="all: initial; display: block; font-family: 'Segoe UI', sans-serif; font-size: 2.5em; font-weight: 900; margin: 0 0 40px 0; color: #60a5fa; border-left: 8px solid #3b82f6; padding-left: 25px; text-transform: uppercase; letter-spacing: 2px; text-shadow: 0 0 20px rgba(59, 130, 246, 0.5);">
                🔍 {section_title}
            </h2>

            <!-- Quick Stats -->
            <div style="all: initial; display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 25px; margin-bottom: 40px; font-family: 'Segoe UI', sans-serif;">
                <div style="all: initial; display: block; background: linear-gradient(135deg, rgba(220, 38, 38, 0.2), rgba(153, 27, 27, 0.15)); padding: 30px; border-radius: 15px; border-left: 6px solid #dc2626; box-shadow: 0 8px 25px rgba(220, 38, 38, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);">
                    <div style="all: initial; display: block; font-family: 'Segoe UI', sans-serif; font-size: 3.5em; font-weight: 900; color: #ef4444; text-shadow: 0 4px 8px rgba(0,0,0,0.5), 0 0 30px rgba(239, 68, 68, 0.4); margin: 0 0 12px 0;">{critical}</div>
                    <div style="all: initial; display: block; font-family: 'Segoe UI', sans-serif; color: #f1f5f9; font-weight: 800; font-size: 1.1em; margin: 0; text-transform: uppercase; letter-spacing: 0.5px;">CRITICAL (≥85)</div>
                </div>
                <div style="all: initial; display: block; background: linear-gradient(135deg, rgba(234, 88, 12, 0.2), rgba(194, 65, 12, 0.15)); padding: 30px; border-radius: 15px; border-left: 6px solid #ea580c; box-shadow: 0 8px 25px rgba(234, 88, 12, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);">
                    <div style="all: initial; display: block; font-family: 'Segoe UI', sans-serif; font-size: 3.5em; font-weight: 900; color: #f97316; text-shadow: 0 4px 8px rgba(0,0,0,0.5), 0 0 30px rgba(249, 115, 22, 0.4); margin: 0 0 12px 0;">{high}</div>
                    <div style="all: initial; display: block; font-family: 'Segoe UI', sans-serif; color: #f1f5f9; font-weight: 800; font-size: 1.1em; margin: 0; text-transform: uppercase; letter-spacing: 0.5px;">HIGH (70-84)</div>
                </div>
                <div style="all: initial; display: block; background: linear-gradient(135deg, rgba(245, 158, 11, 0.2), rgba(217, 119, 6, 0.15)); padding: 30px; border-radius: 15px; border-left: 6px solid #f59e0b; box-shadow: 0 8px 25px rgba(245, 158, 11, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);">
                    <div style="all: initial; display: block; font-family: 'Segoe UI', sans-serif; font-size: 3.5em; font-weight: 900; color: #fbbf24; text-shadow: 0 4px 8px rgba(0,0,0,0.5), 0 0 30px rgba(251, 191, 36, 0.4); margin: 0 0 12px 0;">{medium}</div>
                    <div style="all: initial; display: block; font-family: 'Segoe UI', sans-serif; color: #f1f5f9; font-weight: 800; font-size: 1.1em; margin: 0; text-transform: uppercase; letter-spacing: 0.5px;">MEDIUM (40-59)</div>
                </div>
                <div style="all: initial; display: block; background: linear-gradient(135deg, rgba(34, 197, 94, 0.2), rgba(22, 163, 74, 0.15)); padding: 30px; border-radius: 15px; border-left: 6px solid #22c55e; box-shadow: 0 8px 25px rgba(34, 197, 94, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);">
                    <div style="all: initial; display: block; font-family: 'Segoe UI', sans-serif; font-size: 3.5em; font-weight: 900; color: #34d399; text-shadow: 0 4px 8px rgba(0,0,0,0.5), 0 0 30px rgba(52, 211, 153, 0.4); margin: 0 0 12px 0;">{low}</div>
                    <div style="all: initial; display: block; font-family: 'Segoe UI', sans-serif; color: #f1f5f9; font-weight: 800; font-size: 1.1em; margin: 0; text-transform: uppercase; letter-spacing: 0.5px;">LOW (<40)</div>
                </div>
            </div>

            <!-- DataTable Container with Full Isolation -->
            <div style="all: initial; display: block; background: #050911; padding: 35px; border-radius: 16px; border: 2px solid rgba(96, 165, 250, 0.3); box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.6), 0 4px 15px rgba(0, 0, 0, 0.3);">
                <table id="ipIntelTable" class="display" style="width:100% !important; margin:0 !important; font-family: 'Segoe UI', sans-serif !important;">
                    <thead>
                        <tr>
                            <th style="font-family: 'Segoe UI', sans-serif !important;">IP Address</th>
                            <th style="font-family: 'Segoe UI', sans-serif !important;">Risk Score</th>
                            <th style="font-family: 'Segoe UI', sans-serif !important;">Risk Level</th>
                            <th style="font-family: 'Segoe UI', sans-serif !important;">Attacks</th>
                            <th style="font-family: 'Segoe UI', sans-serif !important;">First Seen</th>
                            <th style="font-family: 'Segoe UI', sans-serif !important;">Last Seen</th>
                            <th style="font-family: 'Segoe UI', sans-serif !important;">Country</th>
                            <th style="font-family: 'Segoe UI', sans-serif !important;">City</th>
                            <th style="font-family: 'Segoe UI', sans-serif !important;">Attack Types</th>
                        </tr>
                    </thead>
                </table>
            </div>
        </div>

        <script>
        (function() {{
            const ipData = {table_json};

            if (typeof $ !== 'undefined' && $.fn.DataTable) {{
                $(document).ready(function() {{
                    if ($('#ipIntelTable').length && !$.fn.DataTable.isDataTable('#ipIntelTable')) {{
                        const table = $('#ipIntelTable').DataTable({{
                            data: ipData,
                            columns: [
                                {{ data: 'IP' }},
                                {{
                                    data: 'Risk',
                                    render: function(data, type, row) {{
                                        if (type === 'display') {{
                                            let className = 'risk-' + row.Level.toLowerCase();
                                            return '<span class="' + className + '" style="font-weight: 700;">' + data + '</span>';
                                        }}
                                        return data;
                                    }}
                                }},
                                {{
                                    data: 'Level',
                                    render: function(data) {{
                                        const colors = {{
                                            'CRITICAL': '#dc2626',
                                            'HIGH': '#ea580c',
                                            'MEDIUM': '#f59e0b',
                                            'LOW': '#22c55e'
                                        }};
                                        return '<span style="display: inline-block; background: ' + colors[data] + '; color: white; padding: 8px 16px; border-radius: 6px; font-size: 0.85em; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 8px rgba(0,0,0,0.3);">' + data + '</span>';
                                    }}
                                }},
                                {{
                                    data: 'Attacks',
                                    render: function(data) {{
                                        return data.toLocaleString();
                                    }}
                                }},
                                {{ data: 'FirstSeen' }},
                                {{ data: 'LastSeen' }},
                                {{ data: 'Country' }},
                                {{ data: 'City' }},
                                {{ data: 'AttackTypes' }}
                            ],
                            dom: 'Bfrtip',
                            buttons: [
                                {{
                                    extend: 'excelHtml5',
                                    text: '📥 Export Excel',
                                    titleAttr: 'Export to Excel',
                                    className: 'dt-button',
                                    exportOptions: {{
                                        columns: ':visible'
                                    }}
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
                                    className: 'dt-button',
                                    orientation: 'landscape'
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
                            responsive: true,
                            language: {{
                                search: "Search IPs:",
                                lengthMenu: "Show _MENU_ IPs",
                                info: "Showing _START_ to _END_ of _TOTAL_ malicious IPs",
                                infoFiltered: "(filtered from _MAX_ total)",
                                zeroRecords: "No matching IPs found",
                                emptyTable: "No malicious IPs detected"
                            }}
                        }});

                        // Add column search
                        $('#ipIntelTable thead tr').clone(true).appendTo('#ipIntelTable thead');
                        $('#ipIntelTable thead tr:eq(1) th').each(function(i) {{
                            const title = $(this).text();
                            $(this).html('<input type="text" placeholder="Search ' + title + '" style="width:100%; padding:5px; background:#0f172a; border:1px solid rgba(59,130,246,0.3); color:white; border-radius:5px;" />');

                            $('input', this).on('keyup change', function() {{
                                if (table.column(i).search() !== this.value) {{
                                    table.column(i).search(this.value).draw();
                                }}
                            }});
                        }});
                    }}
                }});
            }}
        }})();
        </script>
        """

    @staticmethod
    def get_datatables_dependencies() -> str:
        """Get DataTables library dependencies (jQuery, DataTables, Buttons, etc.)"""
        return """
        <!-- DataTables Dependencies -->
        <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
        <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
        <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.1/css/buttons.dataTables.min.css">
        <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
        <script src="https://cdn.datatables.net/buttons/2.4.1/js/dataTables.buttons.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.js"></script>
        <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.html5.min.js"></script>
        <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.print.min.js"></script>
        <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.colVis.min.js"></script>
        """

    @staticmethod
    def get_datatables_styles() -> str:
        """Get custom DataTables styles with maximum specificity and isolation"""
        return """
        <style>
        /* DataTables Premium Styling - Maximum Isolation */
        .ip-intelligence-section-container .dataTables_wrapper {
            padding: 0 !important;
            font-family: 'Segoe UI', sans-serif !important;
            all: unset;
            display: block !important;
        }

        .ip-intelligence-section-container .dataTables_wrapper .dt-buttons {
            float: left !important;
            margin-bottom: 25px !important;
        }

        .ip-intelligence-section-container .dt-button {
            all: initial !important;
            display: inline-block !important;
            font-family: 'Segoe UI', sans-serif !important;
            background: linear-gradient(135deg, #3b82f6 0%, #1e40af 100%) !important;
            border: 2px solid #60a5fa !important;
            color: white !important;
            padding: 14px 30px !important;
            margin-right: 12px !important;
            border-radius: 10px !important;
            font-weight: 700 !important;
            font-size: 15px !important;
            cursor: pointer !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3) !important;
            text-transform: uppercase !important;
            letter-spacing: 0.5px !important;
        }

        .ip-intelligence-section-container .dt-button:hover {
            transform: translateY(-3px) !important;
            box-shadow: 0 12px 30px rgba(59, 130, 246, 0.5) !important;
            border-color: #93c5fd !important;
        }

        .ip-intelligence-section-container table.dataTable {
            width: 100% !important;
            background: #050911 !important;
            border: 2px solid rgba(96, 165, 250, 0.3) !important;
            border-radius: 12px !important;
            font-family: 'Segoe UI', sans-serif !important;
            border-collapse: separate !important;
            border-spacing: 0 !important;
            overflow: hidden !important;
        }

        .ip-intelligence-section-container table.dataTable thead {
            background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%) !important;
        }

        .ip-intelligence-section-container table.dataTable thead th {
            color: #ffffff !important;
            font-weight: 800 !important;
            padding: 20px 15px !important;
            border-bottom: 3px solid #3b82f6 !important;
            font-size: 14px !important;
            text-transform: uppercase !important;
            letter-spacing: 0.8px !important;
            font-family: 'Segoe UI', sans-serif !important;
            background: none !important;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3) !important;
        }

        .ip-intelligence-section-container table.dataTable tbody td {
            color: #e2e8f0 !important;
            padding: 18px 15px !important;
            border-bottom: 1px solid rgba(96, 165, 250, 0.15) !important;
            font-size: 14px !important;
            font-family: 'Segoe UI', sans-serif !important;
            font-weight: 500 !important;
        }

        .ip-intelligence-section-container table.dataTable tbody tr {
            transition: all 0.2s ease !important;
        }

        .ip-intelligence-section-container table.dataTable tbody tr:hover {
            background: rgba(59, 130, 246, 0.15) !important;
            transform: scale(1.002) !important;
        }

        .ip-intelligence-section-container .dataTables_filter input {
            background: #0c1222 !important;
            border: 2px solid rgba(96, 165, 250, 0.4) !important;
            color: white !important;
            padding: 12px 18px !important;
            border-radius: 10px !important;
            margin-left: 12px !important;
            font-family: 'Segoe UI', sans-serif !important;
            font-size: 14px !important;
            transition: all 0.3s ease !important;
        }

        .ip-intelligence-section-container .dataTables_filter input:focus {
            outline: none !important;
            border-color: #60a5fa !important;
            box-shadow: 0 0 20px rgba(96, 165, 250, 0.4) !important;
        }

        .ip-intelligence-section-container .dataTables_length select {
            background: #0c1222 !important;
            border: 2px solid rgba(96, 165, 250, 0.4) !important;
            color: white !important;
            padding: 10px 15px !important;
            border-radius: 10px !important;
            margin: 0 12px !important;
            font-family: 'Segoe UI', sans-serif !important;
            font-size: 14px !important;
        }

        .ip-intelligence-section-container .dataTables_info,
        .ip-intelligence-section-container .dataTables_length label,
        .ip-intelligence-section-container .dataTables_filter label {
            color: #cbd5e1 !important;
            font-weight: 700 !important;
            font-family: 'Segoe UI', sans-serif !important;
            font-size: 14px !important;
        }

        .ip-intelligence-section-container .dataTables_paginate .paginate_button {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%) !important;
            border: 2px solid rgba(96, 165, 250, 0.3) !important;
            color: white !important;
            padding: 10px 18px !important;
            margin: 0 6px !important;
            border-radius: 10px !important;
            font-family: 'Segoe UI', sans-serif !important;
            font-weight: 700 !important;
            transition: all 0.2s ease !important;
        }

        .ip-intelligence-section-container .dataTables_paginate .paginate_button.current {
            background: linear-gradient(135deg, #3b82f6 0%, #1e40af 100%) !important;
            border-color: #60a5fa !important;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4) !important;
        }

        .ip-intelligence-section-container .dataTables_paginate .paginate_button:hover {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%) !important;
            border-color: #60a5fa !important;
            transform: translateY(-2px) !important;
        }

        /* Risk level colors with enhanced styling */
        .ip-intelligence-section-container .risk-critical {
            color: #ef4444 !important;
            font-weight: 900 !important;
            text-shadow: 0 0 10px rgba(239, 68, 68, 0.5) !important;
        }

        .ip-intelligence-section-container .risk-high {
            color: #f97316 !important;
            font-weight: 800 !important;
            text-shadow: 0 0 10px rgba(249, 115, 22, 0.5) !important;
        }

        .ip-intelligence-section-container .risk-medium {
            color: #fbbf24 !important;
            font-weight: 700 !important;
            text-shadow: 0 0 10px rgba(251, 191, 36, 0.5) !important;
        }

        .ip-intelligence-section-container .risk-low {
            color: #34d399 !important;
            font-weight: 600 !important;
            text-shadow: 0 0 10px rgba(52, 211, 153, 0.5) !important;
        }
        </style>
        """

    @staticmethod
    def inject_ip_data_into_html(html_content: str, attacker_profiles: List[Any], section_title: str = "Detected Malicious IPs") -> str:
        """
        Inject IP intelligence section into existing HTML report

        Args:
            html_content: Original HTML content
            attacker_profiles: List of attacker profiles
            section_title: Title for the IP section

        Returns:
            Modified HTML with IP section injected
        """
        # Check if IP data has already been injected (to prevent duplicates)
        if 'ip-intelligence-section' in html_content or 'ipIntelTable' in html_content:
            print("[IP INJECTION] IP data already present in HTML, skipping injection")
            return html_content

        # Generate IP section
        ip_section = IPDataTablesInjector.generate_ip_section_html(attacker_profiles, section_title)

        # Add DataTables dependencies if not present
        if 'jquery' not in html_content.lower() and 'datatables' not in html_content.lower():
            dependencies = IPDataTablesInjector.get_datatables_dependencies()
            html_content = html_content.replace('</head>', f'{dependencies}\n{IPDataTablesInjector.get_datatables_styles()}\n</head>')
        elif '<style>' in html_content:
            # Just add styles
            html_content = html_content.replace('</style>', f'{IPDataTablesInjector.get_datatables_styles()}\n</style>', 1)

        # Hide the old IoCs section with Metric/Value format by adding CSS to hide it
        hide_old_iocs_css = """
        <style>
        /* Hide old IoCs section with Metric/Value format */
        .section[data-section="iocs"] {
            display: none !important;
        }
        </style>
        """
        html_content = html_content.replace('</head>', f'{hide_old_iocs_css}\n</head>')

        # Inject IP section before </body> tag
        html_content = html_content.replace('</body>', f'{ip_section}\n</body>')

        return html_content
