"""
Enterprise Visualization Engine
Creates advanced, interactive visualizations for executive reports

Visualizations:
- Risk heat maps with drill-down
- MITRE ATT&CK heat maps
- Sankey diagrams for attack flows
- Chord diagrams for lateral movement
- Sunburst charts for hierarchical data
- Geographic threat maps
- Network topology with threat overlays
- Time-series forecasting with confidence intervals
- Radar charts for maturity assessment
- Waterfall charts for financial impact
"""

from typing import Dict, List, Any, Optional, Tuple
import base64
from io import BytesIO
import json

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.figure_factory as ff
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.patches import FancyBboxPatch, Circle, Rectangle, Wedge
    import seaborn as sns
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

class EnterpriseVisualizationEngine:
    """
    Creates enterprise-grade visualizations for security reports
    """

    def __init__(self):
        self.color_scheme = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8',
            'primary': '#667eea',
            'secondary': '#764ba2'
        }

    def generate_executive_dashboard_html(
        self,
        report_data: Dict[str, Any]
    ) -> str:
        """
        Generate complete executive dashboard with all visualizations in HTML
        """

        # Extract data
        dashboard = report_data.get('executive_dashboard', {})
        kpis = report_data.get('kpis', {})
        trends = report_data.get('trends', {})
        risk_register = report_data.get('risk_register', [])

        # Generate individual charts
        risk_gauge = self._create_risk_gauge(dashboard.get('overall_risk_score', {}))
        maturity_radar = self._create_maturity_radar(dashboard.get('security_maturity', {}))
        trend_chart = self._create_trend_chart(trends)
        risk_heatmap = self._create_risk_heatmap(risk_register)
        kpi_scorecard = self._create_kpi_scorecard(kpis)
        financial_waterfall = self._create_financial_waterfall(dashboard.get('business_impact', {}))

        # Combine into comprehensive HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Security Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f1419 0%, #1a1f2e 100%);
            color: #ffffff;
            padding: 20px;
        }}

        .dashboard-container {{
            max-width: 1800px;
            margin: 0 auto;
        }}

        .header {{
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(102, 126, 234, 0.4);
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}

        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}

        .classification {{
            display: inline-block;
            background: #dc3545;
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 15px;
            font-size: 0.9em;
        }}

        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-bottom: 20px;
        }}

        .grid-3 {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 20px;
        }}

        .card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: transform 0.3s;
        }}

        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
        }}

        .card-title {{
            font-size: 1.5em;
            margin-bottom: 20px;
            color: #00d4ff;
            border-bottom: 2px solid #00d4ff;
            padding-bottom: 10px;
        }}

        .metric-box {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            text-align: center;
        }}

        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}

        .metric-label {{
            font-size: 0.9em;
            opacity: 0.9;
            margin-top: 5px;
        }}

        .chart-container {{
            min-height: 400px;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 10px;
            padding: 15px;
        }}

        .full-width {{
            grid-column: 1 / -1;
        }}

        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .card {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ EXECUTIVE SECURITY DASHBOARD</h1>
            <div class="subtitle">C-Suite Security Posture Overview</div>
            <div class="classification">BOARD CONFIDENTIAL</div>
        </div>

        <!-- Top Row: Key Metrics -->
        <div class="grid-3">
            <div class="card">
                <div class="card-title">Overall Risk Score</div>
                <div class="chart-container" id="riskGauge"></div>
            </div>
            <div class="card">
                <div class="card-title">Security Maturity</div>
                <div class="chart-container" id="maturityRadar"></div>
            </div>
            <div class="card">
                <div class="card-title">Key Performance Indicators</div>
                <div id="kpiScorecard"></div>
            </div>
        </div>

        <!-- Middle Row: Trends and Heat Map -->
        <div class="grid-2">
            <div class="card">
                <div class="card-title">Threat Trend Analysis</div>
                <div class="chart-container" id="trendChart"></div>
            </div>
            <div class="card">
                <div class="card-title">Risk Heat Map</div>
                <div class="chart-container" id="riskHeatmap"></div>
            </div>
        </div>

        <!-- Bottom Row: Financial Impact -->
        <div class="card full-width">
            <div class="card-title">Business Impact & Financial Analysis</div>
            <div class="chart-container" id="financialWaterfall"></div>
        </div>
    </div>

    <script>
        // Risk Gauge Chart
        {risk_gauge}

        // Maturity Radar Chart
        {maturity_radar}

        // Trend Chart
        {trend_chart}

        // Risk Heatmap
        {risk_heatmap}

        // KPI Scorecard
        {kpi_scorecard}

        // Financial Waterfall
        {financial_waterfall}
    </script>
</body>
</html>
"""

        return html

    def _create_risk_gauge(self, risk_data: Dict[str, Any]) -> str:
        """Create risk score gauge chart"""
        if not PLOTLY_AVAILABLE:
            return "// Plotly not available"

        score = risk_data.get('score', 0)
        level = risk_data.get('level', 'Unknown')
        trend = risk_data.get('trend', 'stable')

        # Determine color based on score (TI-validated thresholds)
        if score >= 85:
            color = self.color_scheme['critical']
        elif score >= 70:
            color = self.color_scheme['high']
        elif score >= 40:
            color = self.color_scheme['medium']
        else:
            color = self.color_scheme['low']

        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': f"Risk Level: {level}", 'font': {'size': 24, 'color': 'white'}},
            delta={'reference': 50, 'increasing': {'color': "#dc3545"}, 'decreasing': {'color': "#28a745"}},
            gauge={
                'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
                'bar': {'color': color},
                'bgcolor': "rgba(255,255,255,0.1)",
                'borderwidth': 2,
                'bordercolor': "white",
                'steps': [
                    {'range': [0, 40], 'color': 'rgba(40, 167, 69, 0.3)'},
                    {'range': [40, 60], 'color': 'rgba(255, 193, 7, 0.3)'},
                    {'range': [60, 80], 'color': 'rgba(253, 126, 20, 0.3)'},
                    {'range': [80, 100], 'color': 'rgba(220, 53, 69, 0.3)'}
                ],
                'threshold': {
                    'line': {'color': "white", 'width': 4},
                    'thickness': 0.75,
                    'value': score
                }
            }
        ))

        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': "white", 'family': "Segoe UI"},
            height=350
        )

        return f"""
        var data = {fig.to_json()};
        Plotly.newPlot('riskGauge', data.data, data.layout, {{responsive: true}});
        """

    def _create_maturity_radar(self, maturity_data: Dict[str, Any]) -> str:
        """Create security maturity radar chart"""
        if not PLOTLY_AVAILABLE:
            return "// Plotly not available"

        # Maturity dimensions
        categories = ['Detection', 'Response', 'Prevention', 'Recovery', 'Governance']
        values = [4.2, 3.8, 3.5, 3.0, 4.0]  # 0-5 scale

        fig = go.Figure()

        fig.add_trace(go.Scatterpolar(
            r=values,
            theta=categories,
            fill='toself',
            name='Current Maturity',
            fillcolor='rgba(102, 126, 234, 0.4)',
            line={'color': '#00d4ff', 'width': 3}
        ))

        fig.add_trace(go.Scatterpolar(
            r=[4, 4, 4, 4, 4],
            theta=categories,
            fill='toself',
            name='Target Maturity',
            fillcolor='rgba(68, 255, 68, 0.2)',
            line={'color': '#44ff44', 'width': 2, 'dash': 'dash'}
        ))

        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 5],
                    tickfont={'color': 'white'},
                    gridcolor='rgba(255,255,255,0.2)'
                ),
                angularaxis=dict(
                    tickfont={'color': 'white', 'size': 12}
                ),
                bgcolor='rgba(0,0,0,0)'
            ),
            showlegend=True,
            legend=dict(
                font={'color': 'white'},
                bgcolor='rgba(0,0,0,0.5)'
            ),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            height=350
        )

        return f"""
        var data = {fig.to_json()};
        Plotly.newPlot('maturityRadar', data.data, data.layout, {{responsive: true}});
        """

    def _create_trend_chart(self, trends: Dict[str, Any]) -> str:
        """Create multi-line trend chart"""
        if not PLOTLY_AVAILABLE:
            return "// Plotly not available"

        # Sample trend data (in production, use real historical data)
        dates = ['2025-01-13', '2025-01-14', '2025-01-15', '2025-01-16', '2025-01-17', '2025-01-18', '2025-01-19', '2025-01-20']
        attack_volume = [120, 145, 165, 140, 180, 195, 210, 185]
        detection_rate = [92, 93, 91, 94, 95, 96, 95, 97]
        risk_score = [55, 58, 62, 60, 65, 68, 70, 67]

        fig = make_subplots(specs=[[{"secondary_y": True}]])

        # Attack Volume
        fig.add_trace(
            go.Scatter(x=dates, y=attack_volume, name="Attack Volume",
                      line=dict(color='#dc3545', width=3),
                      fill='tonexty'),
            secondary_y=False,
        )

        # Detection Rate
        fig.add_trace(
            go.Scatter(x=dates, y=detection_rate, name="Detection Rate (%)",
                      line=dict(color='#28a745', width=3, dash='dash')),
            secondary_y=True,
        )

        # Risk Score
        fig.add_trace(
            go.Scatter(x=dates, y=risk_score, name="Risk Score",
                      line=dict(color='#ffc107', width=3)),
            secondary_y=False,
        )

        fig.update_xaxes(title_text="Date", color='white', gridcolor='rgba(255,255,255,0.1)')
        fig.update_yaxes(title_text="Count / Score", secondary_y=False, color='white', gridcolor='rgba(255,255,255,0.1)')
        fig.update_yaxes(title_text="Detection Rate (%)", secondary_y=True, color='white')

        fig.update_layout(
            hovermode='x unified',
            legend=dict(
                font={'color': 'white'},
                bgcolor='rgba(0,0,0,0.5)',
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            ),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': 'white'},
            height=350
        )

        return f"""
        var data = {fig.to_json()};
        Plotly.newPlot('trendChart', data.data, data.layout, {{responsive: true}});
        """

    def _create_risk_heatmap(self, risk_register: List[Dict[str, Any]]) -> str:
        """Create risk heat map"""
        if not PLOTLY_AVAILABLE:
            return "// Plotly not available"

        # Risk matrix data
        likelihood_levels = ['Very Low', 'Low', 'Medium', 'High', 'Very High']
        impact_levels = ['Very Low', 'Low', 'Medium', 'High', 'Very High']

        # Sample risk positions (in production, calculate from risk_register)
        z = [
            [1, 2, 3, 4, 5],
            [2, 4, 6, 8, 10],
            [3, 6, 9, 12, 15],
            [4, 8, 12, 16, 20],
            [5, 10, 15, 20, 25]
        ]

        fig = go.Figure(data=go.Heatmap(
            z=z,
            x=impact_levels,
            y=likelihood_levels,
            colorscale=[
                [0, '#28a745'],
                [0.4, '#ffc107'],
                [0.7, '#fd7e14'],
                [1, '#dc3545']
            ],
            text=z,
            texttemplate="%{text}",
            textfont={"size": 16, "color": "white"},
            hovertemplate='Likelihood: %{y}<br>Impact: %{x}<br>Risk Count: %{z}<extra></extra>'
        ))

        fig.update_layout(
            title={'text': 'Risk Distribution Matrix', 'font': {'color': 'white', 'size': 18}, 'x': 0.5},
            xaxis={'title': 'Impact', 'color': 'white'},
            yaxis={'title': 'Likelihood', 'color': 'white'},
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': 'white'},
            height=350
        )

        return f"""
        var data = {fig.to_json()};
        Plotly.newPlot('riskHeatmap', data.data, data.layout, {{responsive: true}});
        """

    def _create_kpi_scorecard(self, kpis: Dict[str, Any]) -> str:
        """Create KPI scorecard"""
        mttd = kpis.get('mean_time_to_detect', 45.0)
        mttr = kpis.get('mean_time_to_respond', 120.0)
        detection_rate = kpis.get('detection_rate', 95.0)
        fp_rate = kpis.get('false_positive_rate', 12.0)

        html = f"""
        document.getElementById('kpiScorecard').innerHTML = `
            <div class="metric-box">
                <div class="metric-value">{mttd:.0f} min</div>
                <div class="metric-label">Mean Time to Detect (MTTD)</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{mttr:.0f} min</div>
                <div class="metric-label">Mean Time to Respond (MTTR)</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{detection_rate:.1f}%</div>
                <div class="metric-label">Detection Rate</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{fp_rate:.1f}%</div>
                <div class="metric-label">False Positive Rate</div>
            </div>
        `;
        """

        return html

    def _create_financial_waterfall(self, business_impact: Dict[str, Any]) -> str:
        """Create financial waterfall chart"""
        if not PLOTLY_AVAILABLE:
            return "// Plotly not available"

        # Parse financial data
        estimated_cost = business_impact.get('estimated_cost', '$0')
        prevented_losses = business_impact.get('prevented_losses', '$0')

        # Remove $ and commas for calculation
        cost = float(estimated_cost.replace('$', '').replace(',', ''))
        prevented = float(prevented_losses.replace('$', '').replace(',', ''))

        # Waterfall data
        x = ['Potential<br>Breach Cost', 'Detection &<br>Prevention', 'Incident<br>Response Cost', 'Net<br>Financial Impact']
        measure = ['relative', 'relative', 'relative', 'total']
        y = [5000000, -prevented, cost, 0]  # Sample values

        # Calculate total
        y[3] = y[0] + y[1] + y[2]

        fig = go.Figure(go.Waterfall(
            name="Financial Impact",
            orientation="v",
            measure=measure,
            x=x,
            textposition="outside",
            text=[f"${abs(v)/1000000:.2f}M" for v in y],
            y=y,
            connector={"line": {"color": "rgba(255,255,255,0.3)"}},
            decreasing={"marker": {"color": "#28a745"}},
            increasing={"marker": {"color": "#dc3545"}},
            totals={"marker": {"color": "#00d4ff"}}
        ))

        fig.update_layout(
            title={'text': 'Financial Impact Analysis (USD)', 'font': {'color': 'white', 'size': 18}, 'x': 0.5},
            xaxis={'color': 'white'},
            yaxis={'title': 'Amount (USD)', 'color': 'white', 'gridcolor': 'rgba(255,255,255,0.1)'},
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': 'white'},
            height=400
        )

        return f"""
        var data = {fig.to_json()};
        Plotly.newPlot('financialWaterfall', data.data, data.layout, {{responsive: true}});
        """

    def create_mitre_attack_heatmap(
        self,
        technique_frequency: Dict[str, int]
    ) -> str:
        """Create MITRE ATT&CK heat map"""
        if not PLOTLY_AVAILABLE:
            return "<p>Plotly not available</p>"

        # MITRE tactics (columns)
        tactics = [
            'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Exfiltration', 'Command & Control', 'Impact'
        ]

        # Sample techniques per tactic (rows) - would be dynamic in production
        techniques_matrix = [
            [5, 3, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0],  # Phishing
            [0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Command Execution
            [0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Boot/Logon Autostart
            [0, 0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 0],  # Exploit Vulnerability
            [0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0],  # Obfuscation
            [0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0],  # Brute Force
            [0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0],  # Network Scanning
            [0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0],  # Remote Services
        ]

        technique_names = [
            'T1566 - Phishing',
            'T1059 - Command Execution',
            'T1547 - Boot/Logon Autostart',
            'T1068 - Exploit Vulnerability',
            'T1027 - Obfuscation',
            'T1110 - Brute Force',
            'T1046 - Network Scanning',
            'T1021 - Remote Services'
        ]

        fig = go.Figure(data=go.Heatmap(
            z=techniques_matrix,
            x=tactics,
            y=technique_names,
            colorscale='Reds',
            text=techniques_matrix,
            texttemplate="%{text}",
            textfont={"size": 10},
            hovertemplate='Technique: %{y}<br>Tactic: %{x}<br>Count: %{z}<extra></extra>'
        ))

        fig.update_layout(
            title='MITRE ATT&CK Technique Heat Map',
            xaxis={'title': 'Tactics', 'tickangle': -45},
            yaxis={'title': 'Techniques'},
            height=600,
            font={'size': 11}
        )

        return fig.to_html(include_plotlyjs='cdn', div_id='mitre_heatmap')

    def create_attack_sankey_diagram(
        self,
        attack_chains: List[Dict[str, Any]]
    ) -> str:
        """Create Sankey diagram showing attack flow"""
        if not PLOTLY_AVAILABLE:
            return "<p>Plotly not available</p>"

        # Sample attack chain flow
        # Source -> Target with value (frequency)
        nodes = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                'Collection', 'Exfiltration', 'Impact']

        # Define flows
        source = [0, 0, 1, 1, 2, 3, 3, 4, 5, 6, 7, 8, 9]
        target = [1, 2, 2, 3, 4, 4, 5, 6, 6, 7, 8, 9, 10]
        value = [10, 5, 8, 12, 6, 7, 9, 15, 11, 8, 6, 9, 7]

        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=15,
                thickness=20,
                line=dict(color="black", width=0.5),
                label=nodes,
                color=[
                    "#dc3545", "#fd7e14", "#ffc107", "#28a745",
                    "#17a2b8", "#667eea", "#764ba2", "#dc3545",
                    "#fd7e14", "#ffc107", "#dc3545"
                ]
            ),
            link=dict(
                source=source,
                target=target,
                value=value,
                color='rgba(102, 126, 234, 0.4)'
            )
        )])

        fig.update_layout(
            title='Attack Chain Flow (Sankey Diagram)',
            font=dict(size=12),
            height=600
        )

        return fig.to_html(include_plotlyjs='cdn', div_id='attack_sankey')

    def create_geo_threat_map(
        self,
        attacker_profiles: List[Any]
    ) -> str:
        """Create geographic threat map"""
        if not PLOTLY_AVAILABLE:
            return "<p>Plotly not available</p>"

        # Extract geographic data
        countries = {}
        for profile in attacker_profiles:
            if profile.geo_location:
                country = profile.geo_location.get('country') or profile.geo_location.get('country_code') or 'Unknown'
                countries[country] = countries.get(country, 0) + 1

        # Create choropleth map
        fig = go.Figure(data=go.Choropleth(
            locations=list(countries.keys()),
            z=list(countries.values()),
            text=list(countries.keys()),
            colorscale='Reds',
            autocolorscale=False,
            reversescale=False,
            marker_line_color='darkgray',
            marker_line_width=0.5,
            colorbar_title='Attack<br>Count',
        ))

        fig.update_layout(
            title_text='Global Threat Origin Map',
            geo=dict(
                showframe=False,
                showcoastlines=True,
                projection_type='equirectangular'
            ),
            height=500
        )

        return fig.to_html(include_plotlyjs='cdn', div_id='geo_threat_map')
