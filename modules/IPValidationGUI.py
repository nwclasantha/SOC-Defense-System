"""
IP Validation GUI Components
Displays IP validation and reputation results in the SOC interface
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from typing import List, Dict
from modules.IPValidationEngine import IPValidationEngine, IPValidationResult

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
}

def get_theme_colors():
    """Get colors based on current CTk theme"""
    current_theme = ctk.get_appearance_mode().lower()
    return LIGHT_COLORS if current_theme == 'light' else DARK_COLORS

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
}

def create_ip_validation_view(gui):
    """Create IP Validation view in GUI"""
    ip_validation = ctk.CTkScrollableFrame(gui.display_container)
    gui.views['ip_validation'] = ip_validation

    # Title
    title = ctk.CTkLabel(ip_validation, text="IP Address Validation & Reputation",
                        font=ctk.CTkFont(size=28, weight="bold"))
    title.pack(pady=20)

    # Input section
    input_frame = ctk.CTkFrame(ip_validation, fg_color=COLORS['bg_tertiary'])
    input_frame.pack(fill='x', padx=20, pady=10)

    input_title = ctk.CTkLabel(input_frame, text="Validate IP Addresses",
                               font=ctk.CTkFont(size=18, weight="bold"))
    input_title.pack(pady=10)

    # IP input
    input_container = ctk.CTkFrame(input_frame, fg_color='transparent')
    input_container.pack(fill='x', padx=20, pady=10)

    ctk.CTkLabel(input_container, text="Enter IPs (one per line or comma-separated):").pack(anchor='w', pady=5)

    gui.ip_input_text = ctk.CTkTextbox(input_container, height=100,
                                       font=ctk.CTkFont(family="Courier", size=12))
    gui.ip_input_text.pack(fill='x', pady=5)

    # Buttons
    btn_container = ctk.CTkFrame(input_frame, fg_color='transparent')
    btn_container.pack(fill='x', padx=20, pady=10)

    validate_btn = ctk.CTkButton(btn_container, text="Validate IPs",
                                 command=lambda: validate_ips(gui),
                                 fg_color=COLORS['accent'], width=150)
    validate_btn.pack(side='left', padx=5)

    validate_all_btn = ctk.CTkButton(btn_container, text="Validate All Detected IPs",
                                    command=lambda: validate_all_detected_ips(gui),
                                    fg_color=COLORS['success'], width=200)
    validate_all_btn.pack(side='left', padx=5)

    export_btn = ctk.CTkButton(btn_container, text="Export Results",
                              command=lambda: export_validation_results(gui),
                              fg_color=COLORS['warning'], width=150)
    export_btn.pack(side='left', padx=5)

    # Results section
    results_frame = ctk.CTkFrame(ip_validation, fg_color=COLORS['bg_tertiary'])
    results_frame.pack(fill='both', expand=True, padx=20, pady=10)

    results_title = ctk.CTkLabel(results_frame, text="Validation Results",
                                 font=ctk.CTkFont(size=18, weight="bold"))
    results_title.pack(pady=10)

    # Summary stats
    gui.ip_validation_stats = {}
    stats_container = ctk.CTkFrame(results_frame, fg_color='transparent')
    stats_container.pack(fill='x', padx=20, pady=10)

    stats = [
        ('Total IPs', '0', COLORS['accent']),
        ('Public IPs', '0', '#00aaff'),
        ('Private IPs', '0', '#ffaa00'),
        ('Blacklisted', '0', COLORS['danger']),
        ('High Risk', '0', COLORS['warning']),
        ('Attackers', '0', '#ff6600')
    ]

    for label, value, color in stats:
        card = create_stat_card_inline(stats_container, label, value, color)
        gui.ip_validation_stats[label.lower().replace(' ', '_')] = card

    # Results table
    gui.ip_validation_tree = create_ip_validation_table(results_frame)

    # Detail panel
    detail_frame = ctk.CTkFrame(results_frame, fg_color=COLORS['bg_secondary'])
    detail_frame.pack(fill='x', padx=20, pady=10)

    detail_title = ctk.CTkLabel(detail_frame, text="IP Details",
                                font=ctk.CTkFont(size=16, weight="bold"))
    detail_title.pack(pady=10)

    gui.ip_detail_text = ctk.CTkTextbox(detail_frame, height=200,
                                        font=ctk.CTkFont(family="Courier", size=11))
    gui.ip_detail_text.pack(fill='both', expand=True, padx=20, pady=(0, 20))

    # Bind selection event
    gui.ip_validation_tree.bind('<<TreeviewSelect>>', lambda e: show_ip_details(gui, e))

def create_stat_card_inline(parent, label, value, color):
    """Create inline stat card"""
    card = ctk.CTkFrame(parent, fg_color=COLORS['bg_secondary'])
    card.pack(side='left', fill='both', expand=True, padx=5, pady=5)

    label_widget = ctk.CTkLabel(card, text=label,
                               font=ctk.CTkFont(size=11),
                               text_color=COLORS['text_secondary'])
    label_widget.pack(pady=(10, 5))

    value_widget = ctk.CTkLabel(card, text=value,
                               font=ctk.CTkFont(size=20, weight="bold"),
                               text_color=color)
    value_widget.pack(pady=(0, 10))

    return value_widget

def create_ip_validation_table(parent):
    """Create IP validation results table"""
    style = ttk.Style()
    style.theme_use('clam')

    # Use get_theme_colors() for single values (ttk doesn't support CTk tuples)
    theme_colors = get_theme_colors()
    style.configure("IPValidation.Treeview",
                   background=theme_colors['bg_secondary'],
                   foreground=theme_colors['text_primary'],
                   fieldbackground=theme_colors['bg_secondary'],
                   borderwidth=0,
                   font=('Segoe UI', 10))
    style.map('IPValidation.Treeview', background=[('selected', theme_colors['accent'])])

    columns = ('IP Address', 'Type', 'Reputation', 'Threat Level', 'Blacklisted', 'Flags')
    tree = ttk.Treeview(parent, columns=columns, show='headings', height=12,
                       style="IPValidation.Treeview")

    widths = [150, 80, 100, 100, 100, 250]
    for col, width in zip(columns, widths):
        tree.heading(col, text=col)
        tree.column(col, width=width)

    # Tag configurations for threat levels
    tree.tag_configure('critical', background='#661111')
    tree.tag_configure('high', background='#664411')
    tree.tag_configure('medium', background='#665511')
    tree.tag_configure('low', background='#446622')
    tree.tag_configure('clean', background='#226611')

    scrollbar = ttk.Scrollbar(parent, orient='vertical', command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)

    tree.pack(side='left', fill='both', expand=True, padx=(20, 0), pady=(0, 20))
    scrollbar.pack(side='right', fill='y', padx=(0, 20), pady=(0, 20))

    return tree

def validate_ips(gui):
    """Validate IPs from input box"""
    ip_text = gui.ip_input_text.get("1.0", "end-1c").strip()

    if not ip_text:
        messagebox.showwarning("No Input", "Please enter IP addresses to validate")
        return

    # Parse IPs (handle newlines and commas)
    ip_list = []
    for line in ip_text.split('\n'):
        for ip in line.split(','):
            ip = ip.strip()
            if ip:
                ip_list.append(ip)

    if not ip_list:
        messagebox.showwarning("No IPs", "No valid IP addresses found in input")
        return

    # Perform validation
    engine = IPValidationEngine()
    results = engine.validate_multiple_ips(ip_list)

    # Store results
    gui.current_ip_validation_results = results

    # Update GUI
    update_validation_display(gui, results)

    messagebox.showinfo("Validation Complete",
                       f"Validated {len(results)} IP addresses")

def validate_all_detected_ips(gui):
    """Validate all IPs detected in current analysis"""
    if not hasattr(gui, 'current_profiles') or not gui.current_profiles:
        messagebox.showwarning("No Data", "No attack data available. Run analysis first.")
        return

    # Extract all unique IPs
    ip_list = list(set(profile.ip_address for profile in gui.current_profiles))

    if not ip_list:
        messagebox.showwarning("No IPs", "No IP addresses found in current analysis")
        return

    # Perform validation
    engine = IPValidationEngine()
    results = engine.validate_multiple_ips(ip_list)

    # Store results
    gui.current_ip_validation_results = results

    # Update attacker profiles with validation results
    for profile in gui.current_profiles:
        if profile.ip_address in results:
            validation_result = results[profile.ip_address]
            profile.ip_validation = {
                'reputation_score': validation_result.reputation_score,
                'threat_level': validation_result.threat_level,
                'is_blacklisted': validation_result.is_blacklisted,
                'is_tor_exit': validation_result.is_tor_exit,
                'is_vpn': validation_result.is_vpn,
                'is_proxy': validation_result.is_proxy,
                'is_known_attacker': validation_result.is_known_attacker,
                'abuse_confidence': validation_result.abuse_confidence
            }

    # Update GUI
    update_validation_display(gui, results)

    messagebox.showinfo("Validation Complete",
                       f"Validated {len(results)} detected IP addresses")

def update_validation_display(gui, results: Dict[str, IPValidationResult]):
    """Update GUI with validation results"""
    # Update stats
    engine = IPValidationEngine()
    summary = engine.get_validation_summary(results)

    gui.ip_validation_stats['total_ips'].configure(text=str(summary['total_ips']))
    gui.ip_validation_stats['public_ips'].configure(text=str(summary['public_ips']))
    gui.ip_validation_stats['private_ips'].configure(text=str(summary['private_ips']))
    gui.ip_validation_stats['blacklisted'].configure(text=str(summary['blacklisted']))

    high_risk = summary['threat_levels']['high'] + summary['threat_levels']['critical']
    gui.ip_validation_stats['high_risk'].configure(text=str(high_risk))

    # Count attacker IPs
    attacker_count = len(engine.get_attacker_ips(results))
    gui.ip_validation_stats['attackers'].configure(text=str(attacker_count))

    # Clear existing table
    for item in gui.ip_validation_tree.get_children():
        gui.ip_validation_tree.delete(item)

    # Populate table
    for ip, result in sorted(results.items(), key=lambda x: x[1].reputation_score, reverse=True):
        flags = []
        if result.is_blacklisted:
            flags.append("Blacklisted")
        if result.is_tor_exit:
            flags.append("Tor")
        if result.is_vpn:
            flags.append("VPN")
        if result.is_proxy:
            flags.append("Proxy")
        if result.is_known_attacker:
            flags.append("Known Attacker")
        if result.is_known_scanner:
            flags.append("Scanner")

        flags_str = ", ".join(flags) if flags else "-"

        gui.ip_validation_tree.insert('', 'end',
                                      values=(
                                          result.ip_address,
                                          result.ip_type.upper(),
                                          f"{result.reputation_score}/100",
                                          result.threat_level.upper(),
                                          "YES" if result.is_blacklisted else "NO",
                                          flags_str
                                      ),
                                      tags=(result.threat_level,))

def show_ip_details(gui, event):
    """Show detailed information for selected IP"""
    selection = gui.ip_validation_tree.selection()
    if not selection:
        return

    item = gui.ip_validation_tree.item(selection[0])
    ip_address = item['values'][0]

    if not hasattr(gui, 'current_ip_validation_results'):
        return

    result = gui.current_ip_validation_results.get(ip_address)
    if not result:
        return

    # Format detailed information
    # Prepare formatted lists (workaround for f-string backslash limitation)
    blacklist_sources_str = "\n  • ".join(result.blacklist_sources) if result.blacklist_sources else "None"
    validation_sources_str = "\n  • ".join(result.validation_sources) if result.validation_sources else "None"
    errors_str = "\n  • ".join(result.errors) if result.errors else "None"

    details = f"""
╔══════════════════════════════════════════════════════════════╗
║  IP Address Validation Details
╚══════════════════════════════════════════════════════════════╝

IP ADDRESS: {result.ip_address}
Type: {result.ip_type.upper()}
Valid: {"YES" if result.is_valid else "NO"}

CLASSIFICATION:
  • Public IP: {"YES" if result.is_public else "NO"}
  • Private IP: {"YES" if result.is_private else "NO"}
  • Loopback: {"YES" if result.is_loopback else "NO"}
  • Reserved: {"YES" if result.is_reserved else "NO"}

REPUTATION SCORE: {result.reputation_score}/100
THREAT LEVEL: {result.threat_level.upper()}

THREAT INDICATORS:
  • Blacklisted: {"YES" if result.is_blacklisted else "NO"}
  • Known Attacker: {"YES" if result.is_known_attacker else "NO"}
  • Known Scanner: {"YES" if result.is_known_scanner else "NO"}
  • Tor Exit Node: {"YES" if result.is_tor_exit else "NO"}
  • VPN: {"YES" if result.is_vpn else "NO"}
  • Proxy: {"YES" if result.is_proxy else "NO"}

ABUSE CONFIDENCE: {result.abuse_confidence}%

BLACKLIST SOURCES:
  • {blacklist_sources_str}

VALIDATION SOURCES:
  • {validation_sources_str}

VALIDATED: {result.validation_time}

ERRORS:
  • {errors_str}
"""

    gui.ip_detail_text.delete("1.0", "end")
    gui.ip_detail_text.insert("1.0", details)

def export_validation_results(gui):
    """Export validation results to JSON"""
    if not hasattr(gui, 'current_ip_validation_results'):
        messagebox.showwarning("No Results", "No validation results to export")
        return

    engine = IPValidationEngine()
    success = engine.export_results(gui.current_ip_validation_results,
                                    "output/ip_validation_results.json")

    if success:
        messagebox.showinfo("Export Complete",
                           "Results exported to output/ip_validation_results.json")
    else:
        messagebox.showerror("Export Failed",
                            "Failed to export results. Check logs for details.")
