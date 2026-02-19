"""
Threat Intelligence and MITRE ATT&CK GUI Extension
Adds threat intelligence and MITRE ATT&CK framework visualization to the SOC GUI
"""

import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
import matplotlib.patches as mpatches

# Dark and Light color schemes for theme support
DARK_COLORS = {
    'bg_primary': '#0f1419',
    'bg_secondary': '#1a1f2e',
    'bg_tertiary': '#252d3f',
    'accent': '#00d4ff',
    'danger': '#ff4444',
    'warning': '#ffaa44',
    'success': '#44ff44',
    'text_primary': '#ffffff',
    'text_secondary': '#a0a0a0',
    'chart_colors': ['#00d4ff', '#ff4444', '#44ff44', '#ffaa44', '#ff44ff', '#44ffff']
}

LIGHT_COLORS = {
    'bg_primary': '#f0f0f0',
    'bg_secondary': '#ffffff',
    'bg_tertiary': '#e0e0e0',
    'accent': '#0078d4',
    'danger': '#d13438',
    'warning': '#ffb900',
    'success': '#107c10',
    'text_primary': '#000000',
    'text_secondary': '#505050',
    'chart_colors': ['#0078d4', '#d13438', '#107c10', '#ffb900', '#8764b8', '#00b7c3']
}

def get_theme_colors():
    """Get colors based on current CTk theme"""
    current_theme = ctk.get_appearance_mode().lower()
    return LIGHT_COLORS if current_theme == 'light' else DARK_COLORS

def mpl_color(key):
    """Get single color string for matplotlib (doesn't support CTk tuples)"""
    return get_theme_colors().get(key, '#ffffff')

# CTk-compatible dual-mode colors (light_color, dark_color) - AUTO-SWITCHES with theme!
COLORS = {
    'bg_primary': ('#f0f0f0', '#0f1419'),
    'bg_secondary': ('#ffffff', '#1a1f2e'),
    'bg_tertiary': ('#e0e0e0', '#252d3f'),
    'accent': ('#0078d4', '#00d4ff'),
    'danger': ('#d13438', '#ff4444'),
    'warning': ('#ffb900', '#ffaa44'),
    'success': ('#107c10', '#44ff44'),
    'text_primary': ('#000000', '#ffffff'),
    'text_secondary': ('#505050', '#a0a0a0'),
    'chart_colors': ['#0078d4', '#d13438', '#107c10', '#ffb900', '#8764b8', '#00b7c3']
}

def create_threat_intel_view(gui):
    """Create Threat Intelligence & MITRE ATT&CK view"""
    threat_intel = ctk.CTkScrollableFrame(gui.display_container)
    gui.views['threat_intel'] = threat_intel

    # Title
    title = ctk.CTkLabel(threat_intel, text="Threat Intelligence & MITRE ATT&CK",
                        font=ctk.CTkFont(size=28, weight="bold"))
    title.pack(pady=20)

    # Quick Stats
    stats_container = ctk.CTkFrame(threat_intel, fg_color='transparent')
    stats_container.pack(fill='x', padx=20, pady=10)

    gui.threat_intel_stats = {}
    stats = [
        ('Total Threats', '0', '#ff4444'),
        ('MITRE Techniques', '0', '#ffaa44'),
        ('Threat Actors', '0', '#00d4ff'),
        ('IOCs Detected', '0', '#44ff44')
    ]

    for i, (label, value, color) in enumerate(stats):
        stat_card_widget = create_stat_card(stats_container, label, value, color)
        # Store just the value widget for updates
        gui.threat_intel_stats[label.lower().replace(' ', '_')] = stat_card_widget

    # Charts Container
    charts_container = ctk.CTkFrame(threat_intel, fg_color='transparent')
    charts_container.pack(fill='both', expand=True, padx=20, pady=10)

    # MITRE ATT&CK Tactics
    mitre_frame = ctk.CTkFrame(charts_container, fg_color=COLORS['bg_tertiary'])
    mitre_frame.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')

    mitre_title = ctk.CTkLabel(mitre_frame, text="MITRE ATT&CK Tactics",
                               font=ctk.CTkFont(size=16, weight="bold"))
    mitre_title.pack(pady=10)

    gui.mitre_tactics_canvas = create_mitre_tactics_chart(mitre_frame, gui)

    # Threat Categories
    threat_cat_frame = ctk.CTkFrame(charts_container, fg_color=COLORS['bg_tertiary'])
    threat_cat_frame.grid(row=0, column=1, padx=10, pady=10, sticky='nsew')

    threat_cat_title = ctk.CTkLabel(threat_cat_frame, text="Threat Categories",
                                   font=ctk.CTkFont(size=16, weight="bold"))
    threat_cat_title.pack(pady=10)

    gui.threat_categories_canvas = create_threat_categories_chart(threat_cat_frame, gui)

    # MITRE Techniques Heatmap
    techniques_frame = ctk.CTkFrame(charts_container, fg_color=COLORS['bg_tertiary'])
    techniques_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky='nsew')

    techniques_title = ctk.CTkLabel(techniques_frame, text="Top MITRE ATT&CK Techniques",
                                   font=ctk.CTkFont(size=16, weight="bold"))
    techniques_title.pack(pady=10)

    gui.mitre_techniques_canvas = create_mitre_techniques_chart(techniques_frame, gui)

    # Threat Actor Table
    actor_frame = ctk.CTkFrame(threat_intel, fg_color=COLORS['bg_tertiary'])
    actor_frame.pack(fill='both', expand=True, padx=20, pady=10)

    actor_title = ctk.CTkLabel(actor_frame, text="Potential Threat Actors",
                               font=ctk.CTkFont(size=16, weight="bold"))
    actor_title.pack(pady=10)

    gui.threat_actors_tree = create_threat_actors_table(actor_frame)

    # Configure grid
    charts_container.grid_columnconfigure(0, weight=1)
    charts_container.grid_columnconfigure(1, weight=1)
    charts_container.grid_rowconfigure(0, weight=1)
    charts_container.grid_rowconfigure(1, weight=1)

def create_stat_card(parent, label, value, color):
    """Create stat card for threat intel metrics"""
    card = ctk.CTkFrame(parent, fg_color=COLORS['bg_secondary'])
    card.pack(side='left', fill='both', expand=True, padx=5, pady=5)

    label_widget = ctk.CTkLabel(card, text=label,
                               font=ctk.CTkFont(size=12),
                               text_color=COLORS['text_secondary'])
    label_widget.pack(pady=(15, 5))

    value_widget = ctk.CTkLabel(card, text=value,
                               font=ctk.CTkFont(size=28, weight="bold"),
                               text_color=color)
    value_widget.pack(pady=(0, 15))

    return value_widget

def create_mitre_tactics_chart(parent, gui):
    """Create MITRE ATT&CK tactics bar chart"""
    fig = Figure(figsize=(6, 4), dpi=100, facecolor=get_theme_colors()['bg_tertiary'])
    ax = fig.add_subplot(111)

    # Placeholder data
    tactics = ['Initial\nAccess', 'Execution', 'Persistence', 'Privilege\nEscalation',
               'Defense\nEvasion', 'Credential\nAccess']
    counts = [0, 0, 0, 0, 0, 0]

    bars = ax.barh(tactics, counts, color=mpl_color('accent'), alpha=0.8)

    ax.set_facecolor(get_theme_colors()['bg_tertiary'])
    ax.set_xlabel('Event Count', color=mpl_color('text_primary'), fontsize=10)
    ax.set_title('Detected MITRE Tactics', color=mpl_color('text_primary'), fontsize=12, pad=10)
    ax.tick_params(colors=mpl_color('text_primary'), labelsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color(mpl_color('text_secondary'))
    ax.spines['bottom'].set_color(mpl_color('text_secondary'))
    ax.grid(axis='x', alpha=0.2, linestyle='--', color=mpl_color('text_secondary'))

    fig.tight_layout()

    canvas = FigureCanvasTkAgg(fig, parent)
    canvas.draw()
    canvas.get_tk_widget().pack(fill='both', expand=True, padx=20, pady=(0, 20))

    gui.mitre_tactics_fig = fig
    gui.mitre_tactics_ax = ax

    return canvas

def create_threat_categories_chart(parent, gui):
    """Create threat categories pie chart"""
    fig = Figure(figsize=(6, 4), dpi=100, facecolor=get_theme_colors()['bg_tertiary'])
    ax = fig.add_subplot(111)

    # Placeholder data
    ax.text(0.5, 0.5, 'No Data', ha='center', va='center',
           transform=ax.transAxes, fontsize=16, color=mpl_color('text_secondary'))

    ax.set_facecolor(get_theme_colors()['bg_tertiary'])
    ax.axis('off')
    fig.tight_layout()

    canvas = FigureCanvasTkAgg(fig, parent)
    canvas.draw()
    canvas.get_tk_widget().pack(fill='both', expand=True, padx=20, pady=(0, 20))

    gui.threat_categories_fig = fig
    gui.threat_categories_ax = ax

    return canvas

def create_mitre_techniques_chart(parent, gui):
    """Create top MITRE techniques horizontal bar chart"""
    fig = Figure(figsize=(10, 3), dpi=100, facecolor=get_theme_colors()['bg_tertiary'])
    ax = fig.add_subplot(111)

    # Placeholder
    ax.text(0.5, 0.5, 'No Techniques Detected', ha='center', va='center',
           transform=ax.transAxes, fontsize=14, color=mpl_color('text_secondary'))

    ax.set_facecolor(get_theme_colors()['bg_tertiary'])
    ax.axis('off')
    fig.tight_layout()

    canvas = FigureCanvasTkAgg(fig, parent)
    canvas.draw()
    canvas.get_tk_widget().pack(fill='both', expand=True, padx=20, pady=(0, 20))

    gui.mitre_techniques_fig = fig
    gui.mitre_techniques_ax = ax

    return canvas

def create_threat_actors_table(parent):
    """Create threat actors table"""
    style = ttk.Style()
    style.theme_use('clam')

    theme_colors = get_theme_colors()
    style.configure("ThreatActors.Treeview",
                   background=theme_colors['bg_secondary'],
                   foreground=theme_colors['text_primary'],
                   fieldbackground=theme_colors['bg_secondary'],
                   borderwidth=0,
                   font=('Segoe UI', 10))
    style.map('ThreatActors.Treeview', background=[('selected', theme_colors['accent'])])

    columns = ('Threat Actor', 'Match Score', 'Origin', 'Confidence', 'Targets')
    tree = ttk.Treeview(parent, columns=columns, show='headings', height=6,
                       style="ThreatActors.Treeview")

    # Configure columns
    widths = [150, 100, 100, 100, 250]
    for col, width in zip(columns, widths):
        tree.heading(col, text=col)
        tree.column(col, width=width)

    # Add scrollbar
    scrollbar = ttk.Scrollbar(parent, orient='vertical', command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)

    tree.pack(side='left', fill='both', expand=True, padx=(20, 0), pady=(0, 20))
    scrollbar.pack(side='right', fill='y', padx=(0, 20), pady=(0, 20))

    return tree

def update_threat_intel_view(gui, results):
    """Update threat intelligence view with analysis results"""
    if not hasattr(gui, 'threat_intel_stats'):
        return

    attackers = results.get('attackers', [])
    if not attackers:
        return

    # Import the aggregator
    from modules.ThreatIntelligenceAggregator import ThreatIntelligenceAggregator

    aggregator = ThreatIntelligenceAggregator()

    # Collect all events
    all_events = []
    for attacker in attackers:
        if hasattr(attacker, 'events'):
            all_events.extend(attacker.events)

    if not all_events:
        return

    # Generate comprehensive threat report
    threat_report = aggregator.generate_threat_report(all_events)

    # Update stats
    if 'summary' in threat_report:
        summary = threat_report['summary']
        gui.threat_intel_stats['total_threats'].configure(
            text=str(summary.get('unique_ips', 0))
        )

    if 'mitre_attack' in threat_report:
        techniques_count = len(threat_report['mitre_attack'].get('techniques', {}))
        gui.threat_intel_stats['mitre_techniques'].configure(text=str(techniques_count))

    if 'attacker_classification' in threat_report:
        actors = threat_report['attacker_classification'].get('potential_threat_actors', [])
        gui.threat_intel_stats['threat_actors'].configure(text=str(len(actors)))

    # Count IOCs (unique IPs + malware families)
    ioc_count = summary.get('unique_ips', 0)
    for ip_intel in threat_report.get('ip_threat_intelligence', {}).values():
        ioc_count += len(ip_intel.get('malware_families', []))
    gui.threat_intel_stats['iocs_detected'].configure(text=str(ioc_count))

    # Update MITRE Tactics Chart
    update_mitre_tactics_chart(gui, threat_report)

    # Update Threat Categories Chart
    update_threat_categories_chart(gui, threat_report)

    # Update MITRE Techniques Chart
    update_mitre_techniques_chart(gui, threat_report)

    # Update Threat Actors Table
    update_threat_actors_table(gui, threat_report)

def update_mitre_tactics_chart(gui, threat_report):
    """Update MITRE tactics chart"""
    if not hasattr(gui, 'mitre_tactics_ax'):
        return

    gui.mitre_tactics_ax.clear()

    # Safely handle None threat_report
    threat_report = threat_report or {}
    tactics_data = threat_report.get('mitre_attack', {}).get('tactics', {})

    if tactics_data:
        # Get top 6 tactics
        sorted_tactics = sorted(tactics_data.items(), key=lambda x: x[1], reverse=True)[:6]
        tactics = [t[0].replace('_', '\n') for t in sorted_tactics]
        counts = [t[1] for t in sorted_tactics]

        bars = gui.mitre_tactics_ax.barh(tactics, counts, color=mpl_color('accent'), alpha=0.8)

        # Add count labels
        for bar in bars:
            width = bar.get_width()
            if width > 0:
                gui.mitre_tactics_ax.text(width, bar.get_y() + bar.get_height()/2,
                                         f' {int(width)}',
                                         ha='left', va='center',
                                         color=mpl_color('text_primary'),
                                         fontsize=9, weight='bold')

        gui.mitre_tactics_ax.set_facecolor(get_theme_colors()['bg_tertiary'])
        gui.mitre_tactics_ax.set_xlabel('Event Count', color=mpl_color('text_primary'), fontsize=10)
        gui.mitre_tactics_ax.set_title('Detected MITRE Tactics',
                                       color=mpl_color('text_primary'), fontsize=12, pad=10)
        gui.mitre_tactics_ax.tick_params(colors=mpl_color('text_primary'), labelsize=9)
        gui.mitre_tactics_ax.spines['top'].set_visible(False)
        gui.mitre_tactics_ax.spines['right'].set_visible(False)
        gui.mitre_tactics_ax.spines['left'].set_color(mpl_color('text_secondary'))
        gui.mitre_tactics_ax.spines['bottom'].set_color(mpl_color('text_secondary'))
        gui.mitre_tactics_ax.grid(axis='x', alpha=0.2, linestyle='--', color=mpl_color('text_secondary'))

    gui.mitre_tactics_fig.tight_layout()
    gui.mitre_tactics_canvas.draw()

def update_threat_categories_chart(gui, threat_report):
    """Update threat categories pie chart"""
    if not hasattr(gui, 'threat_categories_ax'):
        return

    gui.threat_categories_ax.clear()

    # Aggregate categories
    all_categories = []
    for ip_intel in threat_report.get('ip_threat_intelligence', {}).values():
        all_categories.extend(ip_intel.get('categories', []))

    if all_categories:
        category_counts = Counter(all_categories)
        labels = list(category_counts.keys())
        sizes = list(category_counts.values())
        colors = COLORS['chart_colors'][:len(labels)]

        wedges, texts, autotexts = gui.threat_categories_ax.pie(
            sizes, labels=labels, colors=colors, autopct='%1.1f%%',
            startangle=90, textprops={'color': get_theme_colors()['text_primary'], 'fontsize': 10}
        )

        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_weight('bold')
            autotext.set_fontsize(9)

        gui.threat_categories_ax.set_facecolor(get_theme_colors()['bg_tertiary'])
    else:
        gui.threat_categories_ax.text(0.5, 0.5, 'No Categories', ha='center', va='center',
                                     transform=gui.threat_categories_ax.transAxes,
                                     fontsize=14, color=mpl_color('text_secondary'))
        gui.threat_categories_ax.axis('off')

    gui.threat_categories_fig.tight_layout()
    gui.threat_categories_canvas.draw()

def update_mitre_techniques_chart(gui, threat_report):
    """Update top MITRE techniques chart"""
    if not hasattr(gui, 'mitre_techniques_ax'):
        return

    gui.mitre_techniques_ax.clear()

    # Safely handle None threat_report
    threat_report = threat_report or {}
    techniques_data = threat_report.get('mitre_attack', {}).get('techniques', {})

    if techniques_data:
        # Get top 10 techniques
        sorted_techniques = sorted(
            techniques_data.items(),
            key=lambda x: x[1].get('count', 0),
            reverse=True
        )[:10]

        technique_labels = [f"{t[0]}\n{t[1]['name'][:30]}" for t in sorted_techniques]
        counts = [t[1]['count'] for t in sorted_techniques]

        bars = gui.mitre_techniques_ax.barh(technique_labels, counts,
                                           color=mpl_color('warning'), alpha=0.8)

        # Add count labels
        for bar in bars:
            width = bar.get_width()
            if width > 0:
                gui.mitre_techniques_ax.text(width, bar.get_y() + bar.get_height()/2,
                                            f' {int(width)}',
                                            ha='left', va='center',
                                            color=mpl_color('text_primary'),
                                            fontsize=9, weight='bold')

        gui.mitre_techniques_ax.set_facecolor(get_theme_colors()['bg_tertiary'])
        gui.mitre_techniques_ax.set_xlabel('Detection Count', color=mpl_color('text_primary'), fontsize=10)
        gui.mitre_techniques_ax.set_title('Most Detected Techniques',
                                         color=mpl_color('text_primary'), fontsize=12, pad=10)
        gui.mitre_techniques_ax.tick_params(colors=mpl_color('text_primary'), labelsize=8)
        gui.mitre_techniques_ax.spines['top'].set_visible(False)
        gui.mitre_techniques_ax.spines['right'].set_visible(False)
        gui.mitre_techniques_ax.spines['left'].set_color(mpl_color('text_secondary'))
        gui.mitre_techniques_ax.spines['bottom'].set_color(mpl_color('text_secondary'))
        gui.mitre_techniques_ax.grid(axis='x', alpha=0.2, linestyle='--', color=mpl_color('text_secondary'))

    else:
        gui.mitre_techniques_ax.text(0.5, 0.5, 'No Techniques Detected',
                                    ha='center', va='center',
                                    transform=gui.mitre_techniques_ax.transAxes,
                                    fontsize=14, color=mpl_color('text_secondary'))
        gui.mitre_techniques_ax.axis('off')

    gui.mitre_techniques_fig.tight_layout()
    gui.mitre_techniques_canvas.draw()

def update_threat_actors_table(gui, threat_report):
    """Update threat actors table"""
    if not hasattr(gui, 'threat_actors_tree'):
        return

    # Clear existing items
    for item in gui.threat_actors_tree.get_children():
        gui.threat_actors_tree.delete(item)

    # Safely handle None threat_report
    threat_report = threat_report or {}
    actors = threat_report.get('attacker_classification', {}).get('potential_threat_actors', [])

    for actor in actors:
        gui.threat_actors_tree.insert('', 'end', values=(
            actor.get('name', 'Unknown'),
            f"{actor.get('match_score', 0):.1f}%",
            actor.get('origin', 'Unknown'),
            actor.get('confidence', 'low').capitalize(),
            ', '.join(actor.get('aliases', [])[:3])
        ))
