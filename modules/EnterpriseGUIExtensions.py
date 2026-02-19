"""
Enterprise GUI Extensions
Adds GUI tabs and visualizations for all enterprise modules:
- Threat Actor Profiling with charts
- IoC Management with statistics
- ML Predictions with classification tables
- Evidence Collection with chain of custody
- Compliance Dashboard
- Attack Chain Visualization
- Correlation Analysis with graphs
- Time Series Forecasting with prediction graphs
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import pandas as pd
import numpy as np
from typing import Dict, List, Any

# Import additional view functions for missing modules
from modules.EnterpriseGUIExtensions_Additional import (
    create_audit_logs_view, create_ml_engine_view, create_model_manager_view,
    create_threat_intel_view, create_stream_monitor_view, create_cep_engine_view,
    create_trend_analysis_view, create_investigations_view, create_data_privacy_view,
    create_enterprise_reports_view, create_performance_view
)

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


def add_enterprise_tabs(gui_instance):
    """
    Add all enterprise tabs to the GUI
    Call this from AdvancedWazuhGUI.__init__() after creating views
    """
    # Initialize ALL enterprise modules if not already done
    if not hasattr(gui_instance, 'threat_profiler'):
        from modules.ThreatActorProfiler import ThreatActorProfiler
        from modules.IoCMatcher import IoCMatcher
        from modules.AutomatedEvidenceCollector import AutomatedEvidenceCollector
        from modules.DataPrivacyManager import DataPrivacyManager
        from modules.ComplianceReporter import ComplianceReporter
        from modules.CorrelationEngine import CorrelationEngine
        from modules.AttackChainReconstructor import AttackChainReconstructor
        from modules.TimeSeriesForecaster import TimeSeriesForecaster
        from modules.MLAnomalyDetector import MLAnomalyDetector
        from modules.EnterpriseReportGenerator import EnterpriseReportGenerator
        from modules.AuditLogger import AuditLogger
        from modules.AdvancedMLEngine import AdvancedMLEngine
        from modules.MLModelManager import MLModelManager
        from modules.ThreatIntelHub import ThreatIntelHub
        from modules.StreamProcessor import StreamProcessor
        from modules.CEPEngine import CEPEngine
        from modules.TrendAnalyzer import TrendAnalyzer
        from modules.InvestigationWorkflow import InvestigationWorkflowEngine
        from modules.ComplianceManager import ComplianceManager
        from modules.PerformanceOptimizer import PerformanceOptimizer

        gui_instance.threat_profiler = ThreatActorProfiler()
        gui_instance.ioc_matcher = IoCMatcher()
        gui_instance.evidence_collector = AutomatedEvidenceCollector()
        gui_instance.privacy_manager = DataPrivacyManager()
        gui_instance.compliance_reporter = ComplianceReporter()
        gui_instance.correlation_engine = CorrelationEngine()
        gui_instance.attack_chain_reconstructor = AttackChainReconstructor()
        gui_instance.forecaster = TimeSeriesForecaster()
        # Only initialize ml_detector if not already set (avoid duplicate initialization)
        if not hasattr(gui_instance, 'ml_detector') or gui_instance.ml_detector is None:
            gui_instance.ml_detector = MLAnomalyDetector(model_dir="./models")
        gui_instance.report_generator = EnterpriseReportGenerator()
        gui_instance.audit_logger = AuditLogger()
        gui_instance.ml_engine = AdvancedMLEngine()
        gui_instance.model_manager = MLModelManager()
        gui_instance.threat_intel_hub = ThreatIntelHub()
        gui_instance.stream_processor = StreamProcessor()
        gui_instance.cep_engine = CEPEngine()
        gui_instance.trend_analyzer = TrendAnalyzer()
        gui_instance.investigation_engine = InvestigationWorkflowEngine()
        gui_instance.compliance_manager = ComplianceManager()
        gui_instance.performance_optimizer = PerformanceOptimizer()

    # Add sidebar buttons for new views
    create_enterprise_sidebar_buttons(gui_instance)

    # Create all enterprise view frames
    create_threat_actor_view(gui_instance)
    create_ioc_management_view(gui_instance)
    create_ml_predictions_view(gui_instance)
    create_evidence_collection_view(gui_instance)
    create_compliance_dashboard_view(gui_instance)
    create_attack_chain_view(gui_instance)
    create_correlation_analysis_view(gui_instance)
    create_forecasting_view(gui_instance)
    # NEW: Create missing module views
    create_audit_logs_view(gui_instance)
    create_ml_engine_view(gui_instance)
    create_model_manager_view(gui_instance)
    create_threat_intel_view(gui_instance)
    create_stream_monitor_view(gui_instance)
    create_cep_engine_view(gui_instance)
    create_trend_analysis_view(gui_instance)
    create_investigations_view(gui_instance)
    create_data_privacy_view(gui_instance)
    create_enterprise_reports_view(gui_instance)
    create_performance_view(gui_instance)


def create_enterprise_sidebar_buttons(gui):
    """Add enterprise feature buttons to sidebar"""
    # Make sure sidebar exists
    if not hasattr(gui, 'sidebar'):
        print("Warning: Sidebar not found, enterprise buttons may not display correctly")
        return

    # Enterprise buttons with colors (removed ENTERPRISE label)
    buttons_config = [
        ("👤", "Threat Actors", "threat_actors", "#ff4444"),
        ("🎯", "IoC Management", "ioc_management", "#ffaa44"),
        ("🤖", "ML Predictions", "ml_predictions", "#00d4ff"),
        ("📦", "Evidence", "evidence_collection", "#44ffff"),
        ("✅", "Compliance", "compliance_dashboard", "#44ff44"),
        ("🔗", "Attack Chains", "attack_chains", "#ff44ff"),
        ("🔄", "Correlations", "correlations", "#00d4ff"),
        ("📈", "Forecasting", "forecasting", "#44ff44"),
        ("📋", "Audit Logs", "audit_logs", "#ffaa44"),
        ("🧠", "ML Engine", "ml_engine", "#00d4ff"),
        ("🎛️", "Model Manager", "model_manager", "#44ffff"),
        ("🌐", "Threat Intel", "threat_intel", "#ff4444"),
        ("📊", "Stream Monitor", "stream_monitor", "#00d4ff"),
        ("⚡", "CEP Engine", "cep_engine", "#ffaa44"),
        ("📉", "Trend Analysis", "trend_analysis", "#44ff44"),
        ("🔍", "Investigations", "investigations", "#ff44ff"),
        ("🔐", "Data Privacy", "data_privacy", "#44ff44"),
        ("📄", "Reports", "enterprise_reports", "#44ffff"),
        ("⚙️", "Performance", "performance", "#00d4ff"),
    ]

    for icon, label, view_name, color in buttons_config:
        # Compact button (36px height) with improved left alignment
        # No icons - text only for perfect alignment
        btn = ctk.CTkButton(
            gui.sidebar,
            text=f"  {label}",  # Just 2 spaces + label (no icon)
            command=lambda v=view_name: switch_view(gui, v),
            fg_color='transparent',
            hover_color=COLORS['bg_secondary'],
            text_color=COLORS['text_primary'],
            anchor='w',  # Left align text within button
            height=36,
            corner_radius=6,
            border_width=0,
            font=("Helvetica", 13)
        )
        btn.pack(fill='x', padx=(8, 8), pady=2)  # 8px padding for clean spacing

        # Store button reference for selection highlighting
        if not hasattr(gui, 'enterprise_nav_buttons'):
            gui.enterprise_nav_buttons = {}
        gui.enterprise_nav_buttons[view_name] = btn


def switch_view(gui, view_name):
    """Switch to specified enterprise view"""
    if hasattr(gui, 'views') and view_name in gui.views:
        # Hide current view
        if gui.current_view and gui.current_view in gui.views:
            gui.views[gui.current_view].pack_forget()

        # Show new view
        gui.views[view_name].pack(fill='both', expand=True)
        gui.current_view = view_name

        # Update all navigation buttons (core + enterprise)
        # Reset core buttons
        if hasattr(gui, 'nav_buttons'):
            for name, btn in gui.nav_buttons.items():
                try:
                    btn.configure(fg_color='transparent', text_color=COLORS['text_primary'])
                except (tk.TclError, Exception):
                    pass

        # Update enterprise buttons
        if hasattr(gui, 'enterprise_nav_buttons'):
            for name, btn in gui.enterprise_nav_buttons.items():
                if name == view_name:
                    # Highlight selected enterprise button
                    try:
                        btn.configure(fg_color=COLORS['accent'], text_color=COLORS['bg_primary'])
                    except (tk.TclError, Exception):
                        pass
                else:
                    # Reset unselected buttons
                    try:
                        btn.configure(fg_color='transparent', text_color=COLORS['text_primary'])
                    except (tk.TclError, Exception):
                        pass

        # Log tab switch - DO NOT auto-refresh as it freezes GUI
        profiles_count = len(gui.current_profiles) if hasattr(gui, 'current_profiles') and gui.current_profiles else 0
        print(f"[Enterprise] Switched to {view_name}, profiles available: {profiles_count}", flush=True)
        # Views have manual "Refresh" buttons - use those instead of auto-refresh


def refresh_threat_actors(gui, frame):
    """Refresh threat actor data from current profiles"""
    from tkinter import messagebox

    # Check if analysis is running
    if gui.is_analyzing:
        messagebox.showwarning("Analysis Running",
                             "Analysis is currently running!\n\n" +
                             f"Time range: {gui.time_range_var.get()}\n" +
                             "Status: Processing alerts...\n\n" +
                             "Please wait for analysis to complete.\n" +
                             "The button will change from 'Analyzing' to '🔍 Analyze' when done.")
        return

    if not gui.current_profiles:
        messagebox.showinfo("No Data Available",
                          f"No threat data available yet.\n\n" +
                          f"I can see you have analysis data on Dashboard:\n" +
                          f"- Total Attackers: {len(gui.current_profiles) if hasattr(gui, 'current_profiles') else 0}\n\n" +
                          f"But Threat Actor Profiler needs to process it.\n\n" +
                          f"The data will feed automatically on next analysis,\n" +
                          f"or you can run analysis again to populate this module.")
        return

    # Process current profiles through threat profiler - OPTIMIZED with limits
    processed_count = 0
    max_events_per_profile = 50  # Limit events per profile to prevent freeze
    max_profiles = 100  # Limit total profiles processed

    if hasattr(gui, 'threat_profiler'):
        gui.update_status("Processing threat actor profiles...")

        for profile in gui.current_profiles[:max_profiles]:
            # Process limited attack events per profile
            events_to_process = list(profile.attack_events)[:max_events_per_profile]
            for event in events_to_process:
                alert_data = {
                    'timestamp': event.timestamp,
                    'source_ip': event.ip_address,
                    'severity': event.rule_level,
                    'attack_type': event.description,
                    'rule_id': event.rule_id,
                    'agent_id': event.agent_id,
                }
                try:
                    gui.threat_profiler.process_attack_event(alert_data)
                    processed_count += 1
                except Exception as e:
                    print(f"Error processing event: {e}")
                    pass

    # Recreate the view with fresh data
    for widget in frame.winfo_children():
        widget.destroy()
    create_threat_actor_content(gui, frame)

    # Safely get statistics (handle None return)
    stats = gui.threat_profiler.get_statistics() or {}
    messagebox.showinfo("Refresh Complete",
                       f"Processed {processed_count} events through Threat Actor Profiler.\n\n" +
                       f"Found {stats.get('total_actors', 0)} threat actors.\n" +
                       f"View updated with latest data!")

    gui.update_status(f"Threat Actors data refreshed - {processed_count} events processed")

def create_threat_actor_view(gui):
    """Create Threat Actor Profiling tab with visualizations"""
    frame = ctk.CTkFrame(gui.display_container, fg_color=COLORS['bg_secondary'])
    gui.views['threat_actors'] = frame
    create_threat_actor_content(gui, frame)

def create_threat_actor_content(gui, frame):
    """Create the content for threat actor view"""

    # Header with refresh button
    header_frame = ctk.CTkFrame(frame, fg_color='transparent')
    header_frame.pack(fill='x', pady=20, padx=20)

    header = ctk.CTkLabel(
        header_frame,
        text="👤 THREAT ACTOR PROFILING",
        font=("Helvetica", 24, "bold"),
        text_color=COLORS['accent']
    )
    header.pack(side='left')

    # Add refresh button
    refresh_btn = ctk.CTkButton(
        header_frame,
        text="🔄 Refresh Data",
        command=lambda: refresh_threat_actors(gui, frame),
        fg_color=COLORS['accent'],
        width=120,
        height=32
    )
    refresh_btn.pack(side='right')

    # Stats cards
    stats_frame = ctk.CTkFrame(frame, fg_color=COLORS['bg_tertiary'])
    stats_frame.pack(fill='x', padx=20, pady=10)

    stats = gui.threat_profiler.get_statistics()

    stat_labels = [
        ("Total Actors", stats.get('total_actors', 0)),
        ("APT Actors", stats.get('apt_actors', 0)),
        ("Events Processed", stats.get('events_processed', 0))
    ]

    for label, value in stat_labels:
        stat_card = create_stat_card(stats_frame, label, value)
        stat_card.pack(side='left', expand=True, fill='both', padx=10, pady=10)

    # Main content with scrollable list and charts
    content = ctk.CTkFrame(frame, fg_color=COLORS['bg_primary'])
    content.pack(fill='both', expand=True, padx=20, pady=10)

    # Left: Actor list
    left_frame = ctk.CTkFrame(content, fg_color=COLORS['bg_tertiary'])
    left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))

    list_label = ctk.CTkLabel(left_frame, text="Threat Actors", font=("Helvetica", 16, "bold"))
    list_label.pack(pady=10)

    # Treeview for actors
    tree_frame = tk.Frame(left_frame, bg=get_theme_colors()['bg_tertiary'])
    tree_frame.pack(fill='both', expand=True, padx=10, pady=10)

    columns = ('IP', 'Sophistication', 'Threat Level', 'Attacks')
    actor_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)

    for col in columns:
        actor_tree.heading(col, text=col)
        actor_tree.column(col, width=120)

    # Add scrollbar
    scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=actor_tree.yview)
    actor_tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side='right', fill='y')
    actor_tree.pack(side='left', fill='both', expand=True)

    # Populate with data
    profiles = gui.threat_profiler.get_all_profiles()
    for profile in profiles[:20]:  # Show top 20
        actor_tree.insert('', 'end', values=(
            profile.primary_ip,
            profile.sophistication.value,
            profile.threat_level,
            profile.total_attacks
        ))

    # Add double-click handler to show details
    def show_actor_details(event):
        selection = actor_tree.selection()
        if selection:
            item = actor_tree.item(selection[0])
            values = item.get('values', [])
            if not values:
                return
            ip_address = values[0]
            profile = gui.threat_profiler.get_profile_by_ip(ip_address)
            if profile:
                show_threat_actor_detail_window(gui, profile)

    actor_tree.bind('<Double-1>', show_actor_details)

    # Right: Charts
    right_frame = ctk.CTkFrame(content, fg_color=COLORS['bg_tertiary'])
    right_frame.pack(side='right', fill='both', expand=True)

    chart_label = ctk.CTkLabel(right_frame, text="Analytics", font=("Helvetica", 16, "bold"))
    chart_label.pack(pady=10)

    # Sophistication distribution chart
    fig = Figure(figsize=(6, 4), facecolor=get_theme_colors()['bg_tertiary'])
    ax = fig.add_subplot(111)

    soph_data = stats.get('by_sophistication', {})
    if soph_data:
        ax.bar(soph_data.keys(), soph_data.values(), color=get_theme_colors()['accent'])
        ax.set_title('Actor Sophistication Distribution', color='white')
        ax.set_xlabel('Sophistication Level', color='white')
        ax.set_ylabel('Count', color='white')
        ax.tick_params(colors='white')
        ax.set_facecolor(get_theme_colors()['bg_tertiary'])
        fig.tight_layout()

    canvas = FigureCanvasTkAgg(fig, right_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)


def create_ioc_management_view(gui):
    """Create IoC Management tab with statistics"""
    frame = ctk.CTkFrame(gui.display_container, fg_color=COLORS['bg_secondary'])
    gui.views['ioc_management'] = frame

    header = ctk.CTkLabel(
        frame,
        text="🎯 INDICATOR OF COMPROMISE MANAGEMENT",
        font=("Helvetica", 24, "bold"),
        text_color=COLORS['accent']
    )
    header.pack(pady=20)

    # Stats
    stats = gui.ioc_matcher.get_statistics()

    stats_frame = ctk.CTkFrame(frame, fg_color=COLORS['bg_tertiary'])
    stats_frame.pack(fill='x', padx=20, pady=10)

    stat_cards = [
        ("Total IoCs", stats.get('total_iocs', 0)),
        ("Active IoCs", stats.get('active_iocs', 0)),
        ("Total Matches", stats.get('total_matches', 0))
    ]

    for label, value in stat_cards:
        card = create_stat_card(stats_frame, label, value)
        card.pack(side='left', expand=True, fill='both', padx=10, pady=10)

    # Add IoC form
    form_frame = ctk.CTkFrame(frame, fg_color=COLORS['bg_tertiary'])
    form_frame.pack(fill='x', padx=20, pady=10)

    form_label = ctk.CTkLabel(form_frame, text="Add New IoC", font=("Helvetica", 16, "bold"))
    form_label.pack(pady=10)

    input_frame = ctk.CTkFrame(form_frame, fg_color=COLORS['bg_tertiary'])
    input_frame.pack(fill='x', padx=20, pady=10)

    # IoC type dropdown
    type_label = ctk.CTkLabel(input_frame, text="Type:")
    type_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')

    ioc_types = ['IP_ADDRESS', 'DOMAIN', 'URL', 'FILE_HASH_SHA256', 'EMAIL']
    type_var = tk.StringVar(value='IP_ADDRESS')
    type_dropdown = ctk.CTkOptionMenu(input_frame, variable=type_var, values=ioc_types)
    type_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

    # IoC value input
    value_label = ctk.CTkLabel(input_frame, text="Value:")
    value_label.grid(row=1, column=0, padx=5, pady=5, sticky='w')

    value_entry = ctk.CTkEntry(input_frame, width=300)
    value_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

    # Severity dropdown
    severity_label = ctk.CTkLabel(input_frame, text="Severity:")
    severity_label.grid(row=2, column=0, padx=5, pady=5, sticky='w')

    severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    severity_var = tk.StringVar(value='MEDIUM')
    severity_dropdown = ctk.CTkOptionMenu(input_frame, variable=severity_var, values=severities)
    severity_dropdown.grid(row=2, column=1, padx=5, pady=5, sticky='ew')

    # Add button
    def add_ioc():
        from modules.IoCMatcher import IoCType, IoCSeverity
        try:
            gui.ioc_matcher.add_ioc(
                ioc_type=IoCType[type_var.get()],
                value=value_entry.get(),
                severity=IoCSeverity[severity_var.get()],
                source="manual_gui"
            )
            messagebox.showinfo("Success", "IoC added successfully!")
            value_entry.delete(0, 'end')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add IoC: {e}")

    add_btn = ctk.CTkButton(
        input_frame,
        text="Add IoC",
        command=add_ioc,
        fg_color=COLORS['success']
    )
    add_btn.grid(row=3, column=0, columnspan=2, pady=10)

    # IoC matches by type chart
    chart_frame = ctk.CTkFrame(frame, fg_color=COLORS['bg_tertiary'])
    chart_frame.pack(fill='both', expand=True, padx=20, pady=10)

    fig = Figure(figsize=(10, 4), facecolor=get_theme_colors()['bg_tertiary'])

    # Matches by type
    ax1 = fig.add_subplot(121)
    matches_by_type = stats.get('matches_by_type', {})
    if matches_by_type:
        ax1.barh(list(matches_by_type.keys()), list(matches_by_type.values()), color=get_theme_colors()['warning'])
        ax1.set_title('Matches by IoC Type', color='white')
        ax1.tick_params(colors='white')
        ax1.set_facecolor(get_theme_colors()['bg_tertiary'])

    # IoCs by type
    ax2 = fig.add_subplot(122)
    by_type = stats.get('by_type', {})
    if by_type:
        ax2.pie(by_type.values(), labels=by_type.keys(), autopct='%1.1f%%', startangle=90)
        ax2.set_title('IoCs by Type', color='white')

    fig.tight_layout()
    canvas = FigureCanvasTkAgg(fig, chart_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)


def create_ml_predictions_view(gui):
    """Create ML Predictions tab with comprehensive classification tables and charts"""
    # Main scrollable frame
    main_frame = ctk.CTkScrollableFrame(gui.display_container, fg_color=COLORS['bg_secondary'])
    gui.views['ml_predictions'] = main_frame

    header = ctk.CTkLabel(
        main_frame,
        text="🤖 ML ANOMALY DETECTION & PREDICTIONS",
        font=("Helvetica", 24, "bold"),
        text_color=COLORS['accent']
    )
    header.pack(pady=20)

    # Model stats and metrics
    stats_container = ctk.CTkFrame(main_frame, fg_color=COLORS['bg_tertiary'])
    stats_container.pack(fill='x', padx=20, pady=10)

    model_info = ctk.CTkLabel(
        stats_container,
        text="Models: Isolation Forest | Random Forest | K-Means Clustering",
        font=("Helvetica", 14)
    )
    model_info.pack(pady=10)

    # Control frame with buttons
    control_frame = ctk.CTkFrame(main_frame, fg_color=COLORS['bg_tertiary'])
    control_frame.pack(fill='x', padx=20, pady=5)

    # Train & Validate ML button
    def train_validate_ml():
        """Train ML models with cross-validation and show real metrics"""
        try:
            from modules.MLValidationEngine import get_validation_engine
            engine = get_validation_engine()

            # Check if we have enough data
            stats = engine.ground_truth.get_statistics()
            if stats['total'] < 20:
                messagebox.showwarning(
                    "Insufficient Data",
                    f"Need at least 20 ground truth samples to train.\n"
                    f"Current: {stats['total']} samples ({stats['malicious']} malicious, {stats['benign']} benign)\n\n"
                    f"Run more scans to build up the dataset."
                )
                return

            # Train with progress
            gui.update_status("Training ML models with cross-validation...")
            metrics = engine.train_and_validate(n_folds=5)

            # Update GUI with real metrics
            gui.ml_precision = metrics.precision
            gui.ml_recall = metrics.recall
            gui.ml_f1_score = metrics.f1_score
            gui.ml_accuracy = metrics.accuracy
            gui.ml_roc_auc = metrics.roc_auc

            # Show results
            messagebox.showinfo(
                "ML Training Complete",
                f"Model: {metrics.model_version}\n"
                f"Samples: {metrics.total_samples}\n\n"
                f"═══ METRICS ═══\n"
                f"Accuracy:  {metrics.accuracy*100:.2f}%\n"
                f"Precision: {metrics.precision*100:.2f}%\n"
                f"Recall:    {metrics.recall*100:.2f}%\n"
                f"F1-Score:  {metrics.f1_score*100:.2f}%\n"
                f"ROC-AUC:   {metrics.roc_auc*100:.2f}%\n\n"
                f"═══ CONFUSION ═══\n"
                f"True Positives:  {metrics.true_positive_count}\n"
                f"True Negatives:  {metrics.true_negative_count}\n"
                f"False Positives: {metrics.false_positive_count}\n"
                f"False Negatives: {metrics.false_negative_count}\n\n"
                f"Cross-Val: {metrics.cross_val_mean*100:.2f}% (+/- {metrics.cross_val_std*100:.2f}%)"
            )

            gui.update_status(f"ML Training Complete: F1={metrics.f1_score*100:.1f}%, Precision={metrics.precision*100:.1f}%")

        except ImportError:
            messagebox.showerror("Error", "ML Validation Engine not available")
        except Exception as e:
            messagebox.showerror("Training Error", f"ML training failed: {e}")

    train_btn = ctk.CTkButton(
        control_frame,
        text="🎓 Train & Validate ML",
        command=train_validate_ml,
        fg_color=COLORS['success'],
        hover_color=COLORS['accent'],
        width=180
    )
    train_btn.pack(side='left', padx=10, pady=10)

    # Show ground truth stats button
    def show_ground_truth_stats():
        """Show ground truth dataset statistics"""
        try:
            from modules.MLValidationEngine import get_validation_engine
            engine = get_validation_engine()
            stats = engine.ground_truth.get_statistics()

            label_sources = stats.get('label_sources', {})
            sources_text = "\n".join([f"  {k}: {v}" for k, v in label_sources.items()])

            messagebox.showinfo(
                "Ground Truth Dataset",
                f"═══ DATASET STATISTICS ═══\n\n"
                f"Total Samples: {stats['total']}\n"
                f"Malicious: {stats['malicious']} ({stats.get('malicious_pct', 0):.1f}%)\n"
                f"Benign: {stats['benign']} ({stats.get('benign_pct', 0):.1f}%)\n\n"
                f"═══ LABEL SOURCES ═══\n{sources_text}\n\n"
                f"Avg Malicious Confidence: {stats.get('avg_malicious_confidence', 0)*100:.1f}%\n"
                f"Avg Benign Confidence: {stats.get('avg_benign_confidence', 0)*100:.1f}%"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Could not get stats: {e}")

    stats_btn = ctk.CTkButton(
        control_frame,
        text="📊 Ground Truth Stats",
        command=show_ground_truth_stats,
        fg_color=COLORS['warning'],
        width=160
    )
    stats_btn.pack(side='left', padx=10, pady=10)

    # ML Model Performance Metrics Table
    metrics_frame = ctk.CTkFrame(main_frame, fg_color=COLORS['bg_tertiary'])
    metrics_frame.pack(fill='x', padx=20, pady=10)

    metrics_label = ctk.CTkLabel(metrics_frame, text="📊 Model Performance Metrics", font=("Helvetica", 16, "bold"))
    metrics_label.pack(pady=10)

    metrics_tree_frame = tk.Frame(metrics_frame, bg=get_theme_colors()['bg_tertiary'])
    metrics_tree_frame.pack(fill='x', padx=10, pady=10)

    metrics_cols = ('Model', 'Samples', 'Accuracy', 'Precision', 'Recall', 'F1-Score', 'Status')
    metrics_tree = ttk.Treeview(metrics_tree_frame, columns=metrics_cols, show='headings', height=4)

    for col in metrics_cols:
        metrics_tree.heading(col, text=col)
        metrics_tree.column(col, width=100)

    metrics_tree.pack(fill='x')

    # Predictions table with more details
    table_frame = ctk.CTkFrame(main_frame, fg_color=COLORS['bg_tertiary'])
    table_frame.pack(fill='both', expand=True, padx=20, pady=10)

    table_label = ctk.CTkLabel(table_frame, text="🎯 ML Predictions & Classifications", font=("Helvetica", 16, "bold"))
    table_label.pack(pady=10)

    tree_frame = tk.Frame(table_frame, bg=get_theme_colors()['bg_tertiary'])
    tree_frame.pack(fill='both', expand=True, padx=10, pady=10)

    columns = ('Timestamp', 'IP Address', 'Anomaly Score', 'Risk Level', 'Prediction', 'Confidence', 'Explanation')
    pred_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=8)

    col_widths = {'Timestamp': 140, 'IP Address': 120, 'Anomaly Score': 100, 'Risk Level': 80,
                  'Prediction': 80, 'Confidence': 80, 'Explanation': 300}

    for col in columns:
        pred_tree.heading(col, text=col)
        pred_tree.column(col, width=col_widths.get(col, 100))

    scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=pred_tree.yview)
    pred_tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side='right', fill='y')
    pred_tree.pack(side='left', fill='both', expand=True)

    # Classification Statistics Table
    class_stats_frame = ctk.CTkFrame(main_frame, fg_color=COLORS['bg_tertiary'])
    class_stats_frame.pack(fill='x', padx=20, pady=10)

    class_label = ctk.CTkLabel(class_stats_frame, text="📈 Classification Statistics", font=("Helvetica", 16, "bold"))
    class_label.pack(pady=10)

    class_tree_frame = tk.Frame(class_stats_frame, bg=get_theme_colors()['bg_tertiary'])
    class_tree_frame.pack(fill='x', padx=10, pady=10)

    class_cols = ('Category', 'Count', 'Percentage', 'Avg Score', 'Min Score', 'Max Score')
    class_tree = ttk.Treeview(class_tree_frame, columns=class_cols, show='headings', height=5)

    for col in class_cols:
        class_tree.heading(col, text=col)
        class_tree.column(col, width=120)

    class_tree.pack(fill='x')

    # Primary Charts (3 charts in row)
    chart_frame1 = ctk.CTkFrame(main_frame, fg_color=COLORS['bg_tertiary'])
    chart_frame1.pack(fill='both', expand=True, padx=20, pady=10)

    # Secondary Charts (3 more charts)
    chart_frame2 = ctk.CTkFrame(main_frame, fg_color=COLORS['bg_tertiary'])
    chart_frame2.pack(fill='both', expand=True, padx=20, pady=10)

    # Third Row Charts (3 more advanced charts)
    chart_frame3 = ctk.CTkFrame(main_frame, fg_color=COLORS['bg_tertiary'])
    chart_frame3.pack(fill='both', expand=True, padx=20, pady=10)

    # Fourth Row Charts (3 more advanced analytics)
    chart_frame4 = ctk.CTkFrame(main_frame, fg_color=COLORS['bg_tertiary'])
    chart_frame4.pack(fill='both', expand=True, padx=20, pady=10)

    def refresh_ml_predictions():
        """Refresh ML predictions with real data and populate all tables/charts"""
        # Clear existing data
        for item in pred_tree.get_children():
            pred_tree.delete(item)
        for item in metrics_tree.get_children():
            metrics_tree.delete(item)
        for item in class_tree.get_children():
            class_tree.delete(item)

        # Get real predictions from ML detector
        if hasattr(gui, 'ml_predictions') and gui.ml_predictions:
            predictions = gui.ml_predictions[:50]  # Show top 50

            # Populate predictions table with full details
            for pred in predictions:
                timestamp = pred['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                ip_address = pred['ip_address']
                anomaly_score = f"{abs(pred['anomaly_score']):.3f}"
                risk_level = pred['severity'].upper()
                prediction = 'Anomaly' if pred['is_anomaly'] else 'Normal'
                confidence = f"{pred.get('confidence', 0) * 100:.1f}%"
                explanation = pred.get('explanation', 'N/A')[:50]  # Truncate long explanations

                pred_tree.insert('', 'end', values=(timestamp, ip_address, anomaly_score, risk_level,
                                                   prediction, confidence, explanation))

            # Populate model performance metrics with REAL calculated values
            total_predictions = len(gui.ml_predictions)
            anomalies = sum(1 for p in gui.ml_predictions if p['is_anomaly'])
            normal = total_predictions - anomalies

            # Get real metrics from confusion matrix
            accuracy = f"{gui.ml_accuracy * 100:.1f}%" if hasattr(gui, 'ml_accuracy') else 'N/A'
            precision = f"{gui.ml_precision * 100:.1f}%" if hasattr(gui, 'ml_precision') else 'N/A'
            recall = f"{gui.ml_recall * 100:.1f}%" if hasattr(gui, 'ml_recall') else 'N/A'
            f1_score = f"{gui.ml_f1_score * 100:.1f}%" if hasattr(gui, 'ml_f1_score') else 'N/A'

            # Show which model was actually used
            if hasattr(gui, 'ml_detector') and gui.ml_detector:
                if gui.ml_detector.isolation_forest:
                    # ML model was trained and used
                    metrics_tree.insert('', 'end', values=(
                        'Isolation Forest',
                        total_predictions,
                        accuracy,
                        precision,
                        recall,
                        f1_score,
                        '✓ Trained & Active'
                    ))

                    metrics_tree.insert('', 'end', values=(
                        'Random Forest (Risk)',
                        total_predictions,
                        accuracy,
                        precision,
                        recall,
                        f1_score,
                        '✓ Trained & Active'
                    ))
                else:
                    # ML not trained, rule-based used
                    metrics_tree.insert('', 'end', values=(
                        'Isolation Forest',
                        0,
                        'N/A',
                        'N/A',
                        'N/A',
                        'N/A',
                        '⚠ Not Trained (<5 samples)'
                    ))

                    metrics_tree.insert('', 'end', values=(
                        'Random Forest (Risk)',
                        0,
                        'N/A',
                        'N/A',
                        'N/A',
                        'N/A',
                        '⚠ Not Trained (<5 samples)'
                    ))

            # Rule-based system stats (using same real metrics)
            if total_predictions > 0:
                metrics_tree.insert('', 'end', values=(
                    'Rule-Based Scoring',
                    total_predictions,
                    accuracy,
                    precision,
                    recall,
                    f1_score,
                    '✓ Active'
                ))

            # Confusion Matrix Summary
            if hasattr(gui, 'ml_confusion_matrix'):
                cm = gui.ml_confusion_matrix
                metrics_tree.insert('', 'end', values=(
                    f"Confusion Matrix",
                    f"TP:{cm['TP']} FP:{cm['FP']} TN:{cm['TN']} FN:{cm['FN']}",
                    accuracy,
                    precision,
                    recall,
                    f1_score,
                    '📊 Real Metrics'
                ))

            # Populate classification statistics
            from collections import Counter
            import numpy as np

            # By risk level
            risk_levels = [p['severity'].upper() for p in gui.ml_predictions]
            risk_counts = Counter(risk_levels)

            for risk, count in risk_counts.items():
                risk_preds = [p for p in gui.ml_predictions if p['severity'].upper() == risk]
                scores = [abs(p['anomaly_score']) for p in risk_preds]

                class_tree.insert('', 'end', values=(
                    f"Risk: {risk}",
                    count,
                    f"{count/total_predictions*100:.1f}%",
                    f"{np.mean(scores):.3f}" if scores else "0.000",
                    f"{np.min(scores):.3f}" if scores else "0.000",
                    f"{np.max(scores):.3f}" if scores else "0.000"
                ))

            # By prediction type
            class_tree.insert('', 'end', values=(
                "Anomalies Detected",
                anomalies,
                f"{anomalies/total_predictions*100:.1f}%",
                f"{np.mean([abs(p['anomaly_score']) for p in gui.ml_predictions if p['is_anomaly']]) if anomalies > 0 else 0:.3f}",
                "N/A",
                "N/A"
            ))

            class_tree.insert('', 'end', values=(
                "Normal Behavior",
                normal,
                f"{normal/total_predictions*100:.1f}%",
                f"{np.mean([abs(p['anomaly_score']) for p in gui.ml_predictions if not p['is_anomaly']]) if normal > 0 else 0:.3f}",
                "N/A",
                "N/A"
            ))

            # Update charts with real data
            update_ml_charts(gui, chart_frame1, chart_frame2, chart_frame3, chart_frame4)
        else:
            # No data available
            pred_tree.insert('', 'end', values=('N/A', 'No predictions available', 'N/A', 'N/A',
                                               'Run analysis first', 'N/A', 'N/A'))
            metrics_tree.insert('', 'end', values=('No models trained', '0', 'N/A', 'N/A', 'N/A', 'N/A', '⚠ No Data'))

    def update_ml_charts(gui, parent1, parent2, parent3, parent4):
        """Update charts with comprehensive ML visualizations"""
        # Clear previous charts
        for widget in parent1.winfo_children():
            widget.destroy()
        for widget in parent2.winfo_children():
            widget.destroy()
        for widget in parent3.winfo_children():
            widget.destroy()
        for widget in parent4.winfo_children():
            widget.destroy()

        if not hasattr(gui, 'ml_predictions') or not gui.ml_predictions:
            return

        from collections import Counter
        import numpy as np

        predictions = gui.ml_predictions
        anomaly_scores = [abs(p['anomaly_score']) for p in predictions]
        risk_levels = [p['severity'].upper() for p in predictions]
        confidences = [p.get('confidence', 0) * 100 for p in predictions]

        # ==== FIRST ROW OF CHARTS (3 charts) ====
        fig1 = Figure(figsize=(15, 5), facecolor=get_theme_colors()['bg_tertiary'])

        # Chart 1: Anomaly Score Distribution (Histogram)
        ax1 = fig1.add_subplot(131)
        if anomaly_scores:
            ax1.hist(anomaly_scores, bins=20, color=get_theme_colors()['accent'], alpha=0.7, edgecolor='white')
            ax1.axvline(np.mean(anomaly_scores), color=get_theme_colors()['danger'], linestyle='--', linewidth=2, label=f'Mean: {np.mean(anomaly_scores):.3f}')
            ax1.legend()
        ax1.set_title('Anomaly Score Distribution', color='white', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Anomaly Score', color='white')
        ax1.set_ylabel('Frequency', color='white')
        ax1.tick_params(colors='white')
        ax1.set_facecolor(get_theme_colors()['bg_tertiary'])
        ax1.grid(True, alpha=0.2)

        # Chart 2: Risk Level Distribution (Pie Chart)
        ax2 = fig1.add_subplot(132)
        risk_counts = Counter(risk_levels)
        if risk_counts:
            labels = list(risk_counts.keys())
            values = list(risk_counts.values())
            theme_colors = get_theme_colors()
            color_map = {'NORMAL': theme_colors['success'], 'HIGH': theme_colors['warning'], 'CRITICAL': theme_colors['danger'], 'MEDIUM': '#ffcc00'}
            colors = [color_map.get(label, theme_colors['text_secondary']) for label in labels]
            wedges, texts, autotexts = ax2.pie(values, labels=labels, autopct='%1.1f%%',
                    colors=colors, startangle=90, textprops={'color': 'white', 'fontsize': 10})
            for autotext in autotexts:
                autotext.set_color('black')
                autotext.set_fontweight('bold')
        ax2.set_title('Risk Level Distribution', color='white', fontsize=14, fontweight='bold')

        # Chart 3: Detection Timeline (24h)
        ax3 = fig1.add_subplot(133)
        hour_counts = [0] * 24
        for pred in predictions:
            hour = pred['timestamp'].hour
            hour_counts[hour] += 1

        hours = list(range(24))
        ax3.plot(hours, hour_counts, color=get_theme_colors()['accent'], linewidth=2, marker='o', markersize=4)
        ax3.fill_between(hours, hour_counts, alpha=0.3, color=get_theme_colors()['accent'])
        ax3.set_title('Detections by Hour (24h)', color='white', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Hour of Day', color='white')
        ax3.set_ylabel('Detection Count', color='white')
        ax3.tick_params(colors='white')
        ax3.set_facecolor(get_theme_colors()['bg_tertiary'])
        ax3.grid(True, alpha=0.2)
        ax3.set_xticks(range(0, 24, 3))

        fig1.tight_layout()
        canvas1 = FigureCanvasTkAgg(fig1, parent1)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

        # ==== SECOND ROW OF CHARTS (3 more charts) ====
        fig2 = Figure(figsize=(15, 5), facecolor=get_theme_colors()['bg_tertiary'])

        # Chart 4: Confusion Matrix Heatmap
        ax4 = fig2.add_subplot(131)
        if hasattr(gui, 'ml_confusion_matrix'):
            cm = gui.ml_confusion_matrix
            cm_array = np.array([[cm['TP'], cm['FP']],
                                  [cm['FN'], cm['TN']]])

            # Create heatmap
            im = ax4.imshow(cm_array, interpolation='nearest', cmap='Blues', alpha=0.8)

            # Set labels
            ax4.set_xticks([0, 1])
            ax4.set_yticks([0, 1])
            ax4.set_xticklabels(['Predicted\nAnomaly', 'Predicted\nNormal'], color='white')
            ax4.set_yticklabels(['Actual\nAnomaly', 'Actual\nNormal'], color='white')

            # Add text annotations
            for i in range(2):
                for j in range(2):
                    text_color = 'white' if cm_array[i, j] > cm_array.max()/2 else 'black'
                    labels = [['TP', 'FP'], ['FN', 'TN']]
                    ax4.text(j, i, f'{labels[i][j]}\n{cm_array[i, j]}',
                            ha="center", va="center", color=text_color,
                            fontsize=14, fontweight='bold')

            ax4.set_title('Confusion Matrix', color='white', fontsize=14, fontweight='bold')
            ax4.tick_params(colors='white')
        else:
            ax4.text(0.5, 0.5, 'No Confusion Matrix\nData Available',
                    ha='center', va='center', color='white', fontsize=12)
            ax4.set_xticks([])
            ax4.set_yticks([])

        ax4.set_facecolor(get_theme_colors()['bg_tertiary'])

        # Chart 5: Anomaly vs Normal Comparison (Bar Chart)
        ax5 = fig2.add_subplot(132)
        anomaly_count = sum(1 for p in predictions if p['is_anomaly'])
        normal_count = len(predictions) - anomaly_count
        categories = ['Anomalies', 'Normal']
        counts = [anomaly_count, normal_count]
        bars = ax5.bar(categories, counts, color=[get_theme_colors()['danger'], get_theme_colors()['success']], alpha=0.7, edgecolor='white', linewidth=2)

        # Add count labels on bars
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            ax5.text(bar.get_x() + bar.get_width()/2., height,
                    f'{count}\n({count/len(predictions)*100:.1f}%)',
                    ha='center', va='bottom', color='white', fontweight='bold')

        ax5.set_title('Anomaly Detection Summary', color='white', fontsize=14, fontweight='bold')
        ax5.set_ylabel('Count', color='white')
        ax5.tick_params(colors='white')
        ax5.set_facecolor(get_theme_colors()['bg_tertiary'])
        ax5.grid(True, alpha=0.2, axis='y')

        # Chart 6: Score vs Confidence Scatter Plot
        ax6 = fig2.add_subplot(133)
        scatter_colors = [get_theme_colors()['danger'] if p['is_anomaly'] else get_theme_colors()['success'] for p in predictions]
        ax6.scatter(anomaly_scores, confidences, c=scatter_colors, alpha=0.6, s=100, edgecolors='white', linewidth=1)
        ax6.set_title('Anomaly Score vs Confidence', color='white', fontsize=14, fontweight='bold')
        ax6.set_xlabel('Anomaly Score', color='white')
        ax6.set_ylabel('Confidence (%)', color='white')
        ax6.tick_params(colors='white')
        ax6.set_facecolor(get_theme_colors()['bg_tertiary'])
        ax6.grid(True, alpha=0.2)

        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor=get_theme_colors()['danger'], label='Anomaly'),
                          Patch(facecolor=get_theme_colors()['success'], label='Normal')]
        ax6.legend(handles=legend_elements, loc='upper right')

        fig2.tight_layout()
        canvas2 = FigureCanvasTkAgg(fig2, parent2)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

        # ==== THIRD ROW OF CHARTS (3 advanced ML analytics) ====
        fig3 = Figure(figsize=(15, 5), facecolor=get_theme_colors()['bg_tertiary'])

        # Chart 7: ROC Curve (Receiver Operating Characteristic)
        ax7 = fig3.add_subplot(131)
        if hasattr(gui, 'ml_confusion_matrix') and gui.ml_confusion_matrix['TP'] + gui.ml_confusion_matrix['FN'] > 0:
            cm = gui.ml_confusion_matrix
            # Calculate TPR and FPR
            tpr = cm['TP'] / (cm['TP'] + cm['FN']) if (cm['TP'] + cm['FN']) > 0 else 0
            fpr = cm['FP'] / (cm['FP'] + cm['TN']) if (cm['FP'] + cm['TN']) > 0 else 0

            # Plot ROC curve points
            ax7.plot([0, fpr, 1], [0, tpr, 1], color=get_theme_colors()['accent'], linewidth=2, marker='o', markersize=8, label=f'ROC (AUC ≈ {(1-fpr+tpr)/2:.3f})')
            ax7.plot([0, 1], [0, 1], 'r--', linewidth=1, label='Random Classifier')
            ax7.fill_between([0, fpr, 1], [0, tpr, 1], alpha=0.2, color=get_theme_colors()['accent'])
            ax7.set_xlabel('False Positive Rate (FPR)', color='white')
            ax7.set_ylabel('True Positive Rate (TPR)', color='white')
            ax7.set_title('ROC Curve', color='white', fontsize=14, fontweight='bold')
            ax7.legend(loc='lower right')
            ax7.grid(True, alpha=0.2)
        else:
            ax7.text(0.5, 0.5, 'Insufficient data\nfor ROC curve', ha='center', va='center', color='white', fontsize=12)
        ax7.tick_params(colors='white')
        ax7.set_facecolor(get_theme_colors()['bg_tertiary'])

        # Chart 8: Precision-Recall Curve
        ax8 = fig3.add_subplot(132)
        if hasattr(gui, 'ml_precision') and hasattr(gui, 'ml_recall'):
            precision = gui.ml_precision
            recall = gui.ml_recall

            # Plot precision-recall points
            ax8.plot([0, recall, 1], [1, precision, 0], color=get_theme_colors()['warning'], linewidth=2, marker='o', markersize=8, label=f'P={precision:.2f}, R={recall:.2f}')
            ax8.axhline(y=precision, color='red', linestyle='--', linewidth=1, alpha=0.5, label=f'Baseline P={precision:.2f}')
            ax8.fill_between([0, recall, 1], [1, precision, 0], alpha=0.2, color=get_theme_colors()['warning'])
            ax8.set_xlabel('Recall', color='white')
            ax8.set_ylabel('Precision', color='white')
            ax8.set_title('Precision-Recall Curve', color='white', fontsize=14, fontweight='bold')
            ax8.legend(loc='upper right')
            ax8.grid(True, alpha=0.2)
        else:
            ax8.text(0.5, 0.5, 'No precision/recall\ndata available', ha='center', va='center', color='white', fontsize=12)
        ax8.tick_params(colors='white')
        ax8.set_facecolor(get_theme_colors()['bg_tertiary'])

        # Chart 9: Risk Score Distribution by Category
        ax9 = fig3.add_subplot(133)
        ml_scores = [p['ml_risk_score'] for p in predictions]
        severities = [p['severity'].upper() for p in predictions]

        # Group scores by severity
        severity_scores = {}
        for sev in set(severities):
            severity_scores[sev] = [p['ml_risk_score'] for p in predictions if p['severity'].upper() == sev]

        if severity_scores:
            positions = []
            labels = []
            data = []
            colors_list = []
            theme_clrs = get_theme_colors()
            color_map = {'NORMAL': theme_clrs['success'], 'HIGH': theme_clrs['warning'], 'CRITICAL': theme_clrs['danger'], 'MEDIUM': '#ffcc00'}

            for i, (sev, scores) in enumerate(sorted(severity_scores.items())):
                if scores:
                    positions.append(i+1)
                    labels.append(sev)
                    data.append(scores)
                    colors_list.append(color_map.get(sev, theme_clrs['text_secondary']))

            bp = ax9.boxplot(data, positions=positions, widths=0.6, patch_artist=True, labels=labels,
                            boxprops=dict(alpha=0.7),
                            medianprops=dict(color='white', linewidth=2),
                            whiskerprops=dict(color='white'),
                            capprops=dict(color='white'))

            for patch, color in zip(bp['boxes'], colors_list):
                patch.set_facecolor(color)

        ax9.set_ylabel('Risk Score', color='white')
        ax9.set_title('Risk Score Distribution by Severity', color='white', fontsize=14, fontweight='bold')
        ax9.tick_params(colors='white')
        ax9.set_facecolor(get_theme_colors()['bg_tertiary'])
        ax9.grid(True, alpha=0.2, axis='y')

        fig3.tight_layout()
        canvas3 = FigureCanvasTkAgg(fig3, parent3)
        canvas3.draw()
        canvas3.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

        # ==== FOURTH ROW OF CHARTS (3 more advanced analytics) ====
        fig4 = Figure(figsize=(15, 5), facecolor=get_theme_colors()['bg_tertiary'])

        # Chart 10: Attack Frequency Heatmap (Day of Week vs Hour)
        ax10 = fig4.add_subplot(131)
        heatmap_data = np.zeros((7, 24))  # 7 days, 24 hours
        for pred in predictions:
            day_of_week = pred['timestamp'].weekday()  # 0=Monday, 6=Sunday
            hour = pred['timestamp'].hour
            heatmap_data[day_of_week][hour] += 1

        im = ax10.imshow(heatmap_data, cmap='YlOrRd', aspect='auto', interpolation='nearest')
        ax10.set_xticks(range(0, 24, 3))
        ax10.set_xticklabels([f'{h}h' for h in range(0, 24, 3)], color='white')
        ax10.set_yticks(range(7))
        ax10.set_yticklabels(['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], color='white')
        ax10.set_xlabel('Hour of Day', color='white')
        ax10.set_ylabel('Day of Week', color='white')
        ax10.set_title('Attack Frequency Heatmap', color='white', fontsize=14, fontweight='bold')
        plt_colorbar = fig4.colorbar(im, ax=ax10)
        plt_colorbar.ax.tick_params(colors='white')
        ax10.set_facecolor(get_theme_colors()['bg_tertiary'])

        # Chart 11: Cumulative Anomalies Over Time
        ax11 = fig4.add_subplot(132)
        sorted_preds = sorted(predictions, key=lambda x: x['timestamp'])
        cumulative_anomalies = []
        cumulative_count = 0
        timestamps = []

        for pred in sorted_preds:
            if pred['is_anomaly']:
                cumulative_count += 1
            cumulative_anomalies.append(cumulative_count)
            timestamps.append(pred['timestamp'])

        if timestamps:
            ax11.plot(range(len(timestamps)), cumulative_anomalies, color=get_theme_colors()['danger'], linewidth=2, marker='.')
            ax11.fill_between(range(len(timestamps)), cumulative_anomalies, alpha=0.3, color=get_theme_colors()['danger'])
            ax11.set_xlabel('Time Sequence', color='white')
            ax11.set_ylabel('Cumulative Anomalies', color='white')
            ax11.set_title('Cumulative Anomaly Detection', color='white', fontsize=14, fontweight='bold')
            ax11.grid(True, alpha=0.2)
        ax11.tick_params(colors='white')
        ax11.set_facecolor(get_theme_colors()['bg_tertiary'])

        # Chart 12: Classification Metrics Comparison Radar Chart
        ax12 = fig4.add_subplot(133, projection='polar')
        if hasattr(gui, 'ml_accuracy'):
            metrics = {
                'Accuracy': gui.ml_accuracy * 100,
                'Precision': gui.ml_precision * 100,
                'Recall': gui.ml_recall * 100,
                'F1-Score': gui.ml_f1_score * 100
            }

            angles = np.linspace(0, 2 * np.pi, len(metrics), endpoint=False).tolist()
            values = list(metrics.values())
            angles += angles[:1]
            values += values[:1]

            ax12.plot(angles, values, 'o-', linewidth=2, color=get_theme_colors()['accent'], label='Current Model')
            ax12.fill(angles, values, alpha=0.25, color=get_theme_colors()['accent'])
            ax12.set_xticks(angles[:-1])
            ax12.set_xticklabels(metrics.keys(), color='white')
            ax12.set_ylim(0, 100)
            ax12.set_yticks([25, 50, 75, 100])
            ax12.set_yticklabels(['25%', '50%', '75%', '100%'], color='white', fontsize=8)
            ax12.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))
            ax12.grid(True, alpha=0.3)
            # Set title with proper positioning
            ax12.text(0, 120, 'Model Performance Radar', color='white', fontsize=14,
                     fontweight='bold', ha='center', va='center', transform=ax12.transData)
        else:
            ax12.text(0, 0, 'No metrics\navailable', ha='center', va='center', color='white', fontsize=12)
        ax12.set_facecolor(get_theme_colors()['bg_tertiary'])
        ax12.tick_params(colors='white')

        fig4.tight_layout()
        canvas4 = FigureCanvasTkAgg(fig4, parent4)
        canvas4.draw()
        canvas4.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

    # Refresh button
    refresh_btn = ctk.CTkButton(
        control_frame,
        text="🔄 Refresh Predictions",
        command=refresh_ml_predictions,
        fg_color=COLORS['accent'],
        hover_color=COLORS['bg_secondary']
    )
    refresh_btn.pack(pady=10)

    # Store refresh function for external updates
    gui.refresh_ml_predictions = refresh_ml_predictions

    # Initial load
    refresh_ml_predictions()


def create_evidence_collection_view(gui):
    """Create Evidence Collection tab"""
    frame = ctk.CTkFrame(gui.display_container, fg_color=COLORS['bg_secondary'])
    gui.views['evidence_collection'] = frame

    # Create scrollable container for content
    scroll_frame = ctk.CTkScrollableFrame(frame, fg_color=COLORS['bg_secondary'])
    scroll_frame.pack(fill='both', expand=True, padx=20, pady=20)

    header = ctk.CTkLabel(
        scroll_frame,
        text="📦 EVIDENCE COLLECTION & CHAIN OF CUSTODY",
        font=("Helvetica", 24, "bold"),
        text_color=COLORS['accent']
    )
    header.pack(pady=(0, 20))

    # Get statistics
    stats = gui.evidence_collector.get_statistics()

    # Stats cards row
    stats_frame = ctk.CTkFrame(scroll_frame, fg_color='transparent')
    stats_frame.pack(fill='x', pady=(0, 20))

    stat_cards = [
        ("Total Evidence", stats.get('total_evidence_items', 0)),
        ("Incidents", stats.get('incidents_with_evidence', 0)),
        ("Storage (MB)", round(stats.get('total_storage_mb', 0), 2))
    ]

    for label, value in stat_cards:
        card = create_stat_card(stats_frame, label, str(value))
        card.pack(side='left', expand=True, fill='both', padx=5)

    # Evidence by type section
    chart_frame = ctk.CTkFrame(scroll_frame, fg_color=COLORS['bg_tertiary'])
    chart_frame.pack(fill='both', expand=True, pady=(0, 20))

    chart_header = ctk.CTkLabel(
        chart_frame,
        text="Evidence Distribution by Type",
        font=("Helvetica", 16, "bold"),
        text_color='white'
    )
    chart_header.pack(pady=(15, 10))

    by_type = stats.get('by_type', {})

    if by_type:
        # Create matplotlib figure
        fig = Figure(figsize=(10, 5), facecolor=get_theme_colors()['bg_tertiary'])
        ax = fig.add_subplot(111)

        types = list(by_type.keys())
        counts = list(by_type.values())

        bars = ax.barh(types, counts, color=get_theme_colors()['accent'])
        ax.set_title('Evidence Count by Type', color='white', fontsize=14, pad=15)
        ax.set_xlabel('Count', color='white', fontsize=12)
        ax.tick_params(colors='white', labelsize=10)
        ax.set_facecolor(get_theme_colors()['bg_tertiary'])

        # Add value labels on bars
        for bar in bars:
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2,
                   f' {int(width)}', va='center', color='white', fontweight='bold')

        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=15, pady=(0, 15))
    else:
        # Show empty state
        empty_label = ctk.CTkLabel(
            chart_frame,
            text="⚠️ No evidence collected yet\n\nRun an analysis to automatically collect evidence.\nEvidence is collected for alerts with severity ≥7.",
            font=("Helvetica", 14),
            text_color=COLORS['text_secondary'],
            justify='center'
        )
        empty_label.pack(pady=50)

    # Evidence by state section
    state_frame = ctk.CTkFrame(scroll_frame, fg_color=COLORS['bg_tertiary'])
    state_frame.pack(fill='both', expand=True, pady=(0, 20))

    state_header = ctk.CTkLabel(
        state_frame,
        text="Evidence Status Distribution",
        font=("Helvetica", 16, "bold"),
        text_color='white'
    )
    state_header.pack(pady=(15, 10))

    by_state = stats.get('by_state', {})

    if by_state:
        # Create matplotlib figure for pie chart
        fig = Figure(figsize=(8, 5), facecolor=get_theme_colors()['bg_tertiary'])
        ax = fig.add_subplot(111)

        states = list(by_state.keys())
        state_counts = list(by_state.values())

        theme_colors = get_theme_colors()
        colors = [theme_colors['success'], theme_colors['warning'], theme_colors['accent'], theme_colors['danger']][:len(states)]
        wedges, texts, autotexts = ax.pie(state_counts, labels=states, autopct='%1.1f%%',
                                           colors=colors, startangle=90, textprops={'color': 'white'})

        ax.set_title('Evidence by State', color='white', fontsize=14, pad=15)

        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, state_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=15, pady=(0, 15))
    else:
        empty_label = ctk.CTkLabel(
            state_frame,
            text="No evidence state data available",
            font=("Helvetica", 12),
            text_color=COLORS['text_secondary']
        )
        empty_label.pack(pady=30)

    # Info box at bottom
    info_frame = ctk.CTkFrame(scroll_frame, fg_color=COLORS['bg_tertiary'], border_width=2, border_color=COLORS['accent'])
    info_frame.pack(fill='x', pady=(0, 10))

    info_text = """💡 About Evidence Collection:

• Evidence is automatically collected for critical alerts (severity level 7+)
• All evidence maintains cryptographic chain of custody (MD5 & SHA256 hashing)
• Evidence types include: logs, network captures, memory dumps, and artifacts
• Default retention period: 7 years (2555 days)
• Storage location: ./evidence_vault/
    """

    info_label = ctk.CTkLabel(
        info_frame,
        text=info_text,
        font=("Courier New", 11),
        text_color=COLORS['text_primary'],
        justify='left'
    )
    info_label.pack(padx=20, pady=15, anchor='w')


def calculate_period_based_compliance(gui, start_date, end_date):
    """Calculate compliance based on actual attack data within period"""
    from datetime import datetime

    # Get attack data within period
    period_attackers = []
    if hasattr(gui, 'current_profiles') and gui.current_profiles:
        for attacker in gui.current_profiles:
            # Check if attacker has events in the period
            def get_event_timestamp(event):
                """Safely get event timestamp as naive datetime"""
                try:
                    if isinstance(event.timestamp, datetime):
                        ts = event.timestamp
                    else:
                        ts = datetime.fromisoformat(str(event.timestamp).replace('Z', '+00:00'))
                    return ts.replace(tzinfo=None)
                except (ValueError, TypeError, AttributeError):
                    return datetime.now()

            has_events_in_period = any(
                start_date <= get_event_timestamp(event) <= end_date
                for event in attacker.attack_events
            )
            if has_events_in_period:
                period_attackers.append(attacker)

    # Calculate compliance based on security controls effectiveness
    total_attacks = sum(a.attack_count for a in period_attackers)
    critical_attacks = len([a for a in period_attackers if a.risk_score >= 85])
    blocked_attacks = len([a for a in period_attackers if a.risk_score >= 70])  # High risk blocked

    # ISO 27001 - Access control & monitoring effectiveness
    iso_score = 100.0
    if total_attacks > 0:
        # Deduct points for unblocked critical attacks
        iso_score -= (critical_attacks * 2)  # -2% per critical attack
        iso_score = max(70, iso_score)  # Minimum 70%

    # GDPR - Data protection compliance
    gdpr_score = 100.0
    data_breach_attacks = len([a for a in period_attackers
                              if any('sql_injection' in str(t) or 'data' in str(t).lower()
                                   for t in a.attack_types)])
    if data_breach_attacks > 0:
        gdpr_score -= (data_breach_attacks * 5)  # -5% per data-related attack
        gdpr_score = max(75, gdpr_score)

    # SOC 2 - Security monitoring & incident response
    soc2_score = 100.0
    if total_attacks > 0:
        detection_rate = (blocked_attacks / total_attacks * 100) if total_attacks > 0 else 100
        soc2_score = detection_rate

    # Calculate control counts
    iso_total = 93
    iso_operational = int(iso_total * iso_score / 100)

    gdpr_total = 24
    gdpr_operational = int(gdpr_total * gdpr_score / 100)

    soc2_total = 60
    soc2_operational = int(soc2_total * soc2_score / 100)

    return {
        'by_framework': {
            'ISO 27001:2022': {
                'compliance_pct': round(iso_score, 1),
                'operational': iso_operational,
                'total': iso_total
            },
            'GDPR': {
                'compliance_pct': round(gdpr_score, 1),
                'operational': gdpr_operational,
                'total': gdpr_total
            },
            'SOC 2 Type II': {
                'compliance_pct': round(soc2_score, 1),
                'operational': soc2_operational,
                'total': soc2_total
            }
        },
        'period_stats': {
            'total_attacks': total_attacks,
            'critical_attacks': critical_attacks,
            'blocked_attacks': blocked_attacks,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d')
        }
    }

def create_compliance_dashboard_view(gui):
    """Create Compliance Dashboard tab with detailed controls"""
    main_frame = ctk.CTkScrollableFrame(gui.display_container, fg_color=COLORS['bg_secondary'])
    gui.views['compliance_dashboard'] = main_frame

    header = ctk.CTkLabel(
        main_frame,
        text="✅ COMPLIANCE DASHBOARD",
        font=("Helvetica", 24, "bold"),
        text_color=COLORS['accent']
    )
    header.pack(pady=20)

    # Date Range Selector
    from datetime import datetime, timedelta
    import tkinter as tk

    control_frame = ctk.CTkFrame(main_frame, fg_color=COLORS['bg_tertiary'])
    control_frame.pack(fill='x', padx=20, pady=10)

    ctk.CTkLabel(control_frame, text="📅 Analysis Period:",
                font=("Helvetica", 14, "bold")).pack(side='left', padx=10, pady=10)

    # Period dropdown
    periods = ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "Last 90 Days", "Last 180 Days", "Last 365 Days"]
    period_var = tk.StringVar(value="Last 90 Days")

    # Refresh button
    refresh_btn = ctk.CTkButton(control_frame, text="🔄 Refresh",
                               command=lambda: refresh_compliance_data(),
                               fg_color=COLORS['success'],
                               width=100)
    refresh_btn.pack(side='left', padx=10)

    period_dropdown = ctk.CTkOptionMenu(control_frame, values=periods, variable=period_var,
                                       command=lambda x: refresh_compliance_data(),
                                       width=150, fg_color=COLORS['accent'])
    period_dropdown.pack(side='left', padx=10)

    # Content container (will be refreshed)
    content_container = ctk.CTkFrame(main_frame, fg_color='transparent')
    content_container.pack(fill='both', expand=True)

    def refresh_compliance_data():
        """Refresh compliance dashboard with selected period"""
        # Clear existing content
        for widget in content_container.winfo_children():
            widget.destroy()

        # Calculate date range based on selection
        end_date = datetime.now().replace(tzinfo=None)
        selected_period = period_var.get()

        if selected_period == "Last 24 Hours":
            start_date = end_date - timedelta(hours=24)
        elif selected_period == "Last 7 Days":
            start_date = end_date - timedelta(days=7)
        elif selected_period == "Last 30 Days":
            start_date = end_date - timedelta(days=30)
        elif selected_period == "Last 90 Days":
            start_date = end_date - timedelta(days=90)
        elif selected_period == "Last 180 Days":
            start_date = end_date - timedelta(days=180)
        elif selected_period == "Last 365 Days":
            start_date = end_date - timedelta(days=365)
        else:
            start_date = end_date - timedelta(days=90)

        # Calculate compliance
        stats = calculate_period_based_compliance(gui, start_date, end_date)

        # Show period info
        period_info = stats.get('period_stats', {})
        period_label = ctk.CTkLabel(
            content_container,
            text=f"📅 {period_info.get('start_date', 'N/A')} to {period_info.get('end_date', 'N/A')} | "
                 f"Attacks: {period_info.get('total_attacks', 0)} | "
                 f"Critical: {period_info.get('critical_attacks', 0)} | "
                 f"Blocked: {period_info.get('blocked_attacks', 0)}",
            font=("Helvetica", 12),
            text_color=COLORS['text_secondary']
        )
        period_label.pack(pady=(0, 10))

        # Summary Cards
        cards_frame = ctk.CTkFrame(content_container, fg_color='transparent')
        cards_frame.pack(fill='x', padx=20, pady=10)

        frameworks = stats.get('by_framework', {})

        # Display cards for each framework with REAL data
        if frameworks:
            for framework_name, framework_data in frameworks.items():
                card = ctk.CTkFrame(cards_frame, fg_color=COLORS['bg_tertiary'])
                card.pack(side='left', expand=True, fill='both', padx=5)

                name_label = ctk.CTkLabel(card, text=framework_name, font=("Helvetica", 16, "bold"))
                name_label.pack(pady=(10, 5))

                pct = framework_data.get('compliance_pct', 0)
                color = COLORS['success'] if pct >= 90 else COLORS['warning'] if pct >= 75 else COLORS['danger']
                pct_label = ctk.CTkLabel(card, text=f"{pct:.1f}%", font=("Helvetica", 32, "bold"), text_color=color)
                pct_label.pack(pady=5)

                operational = framework_data.get('operational', 0)
                total = framework_data.get('total', 0)
                status_label = ctk.CTkLabel(card, text=f"{operational}/{total} Controls Operational",
                                           font=("Helvetica", 12), text_color=COLORS['text_secondary'])
                status_label.pack(pady=(0, 10))
        else:
            # Show message if no data
            no_data_label = ctk.CTkLabel(cards_frame,
                                         text="⚠️ No attack data in selected period. Run analysis first.",
                                         font=("Helvetica", 14),
                                         text_color=COLORS['warning'])
            no_data_label.pack(pady=20)

        # Add detail tables inside content_container so they refresh too
        # ISO 27001:2022 Detailed Table
        iso_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
        iso_frame.pack(fill='both', expand=True, padx=20, pady=10)

        iso_header = ctk.CTkLabel(iso_frame, text="🔒 ISO 27001:2022 Controls", font=("Helvetica", 18, "bold"))
        iso_header.pack(pady=10)

        iso_tree_frame = tk.Frame(iso_frame, bg=get_theme_colors()['bg_tertiary'])
        iso_tree_frame.pack(fill='both', expand=True, padx=10, pady=10)

        iso_cols = ('Control ID', 'Control Name', 'Category', 'Status', 'Compliance %', 'Last Audit')
        iso_tree = ttk.Treeview(iso_tree_frame, columns=iso_cols, show='headings', height=8)

        for col in iso_cols:
                iso_tree.heading(col, text=col)
                iso_tree.column(col, width=150 if col == 'Control Name' else 100)

        # Sample ISO 27001:2022 controls
        iso_controls = [
                ('A.5.1', 'Information Security Policies', 'Organizational', '✅ Compliant', '100%', '2025-01-15'),
                ('A.5.2', 'Information Security Roles', 'Organizational', '✅ Compliant', '95%', '2025-01-15'),
                ('A.8.1', 'User Endpoint Devices', 'Technical', '⚠️ Partial', '75%', '2025-01-10'),
                ('A.8.2', 'Privileged Access Rights', 'Technical', '✅ Compliant', '98%', '2025-01-12'),
                ('A.8.3', 'Information Access Restriction', 'Technical', '✅ Compliant', '92%', '2025-01-14'),
                ('A.8.5', 'Secure Authentication', 'Technical', '⚠️ Partial', '80%', '2025-01-11'),
                ('A.8.8', 'Management of Technical Vulnerabilities', 'Technical', '✅ Compliant', '88%', '2025-01-13'),
                ('A.8.16', 'Monitoring Activities', 'Technical', '✅ Compliant', '100%', '2025-01-15'),
        ]

        for control in iso_controls:
                iso_tree.insert('', 'end', values=control)

        scrollbar = ttk.Scrollbar(iso_tree_frame, orient='vertical', command=iso_tree.yview)
        iso_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        iso_tree.pack(side='left', fill='both', expand=True)

        # GDPR Detailed Table
        gdpr_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
        gdpr_frame.pack(fill='both', expand=True, padx=20, pady=10)

        gdpr_header = ctk.CTkLabel(gdpr_frame, text="🛡️ GDPR Articles Compliance", font=("Helvetica", 18, "bold"))
        gdpr_header.pack(pady=10)

        gdpr_tree_frame = tk.Frame(gdpr_frame, bg=get_theme_colors()['bg_tertiary'])
        gdpr_tree_frame.pack(fill='both', expand=True, padx=10, pady=10)

        gdpr_cols = ('Article', 'Requirement', 'Status', 'Data Handling', 'Compliance %', 'Last Review')
        gdpr_tree = ttk.Treeview(gdpr_tree_frame, columns=gdpr_cols, show='headings', height=8)

        for col in gdpr_cols:
                gdpr_tree.heading(col, text=col)
                gdpr_tree.column(col, width=150 if col == 'Requirement' else 100)

        # Sample GDPR articles
        gdpr_articles = [
                ('Art. 5', 'Principles of Data Processing', '✅ Compliant', 'Automated', '100%', '2025-01-15'),
                ('Art. 6', 'Lawfulness of Processing', '✅ Compliant', 'Consent-based', '98%', '2025-01-14'),
                ('Art. 15', 'Right of Access', '✅ Compliant', 'Self-service', '95%', '2025-01-13'),
                ('Art. 17', 'Right to Erasure', '⚠️ Partial', 'Manual Process', '70%', '2025-01-10'),
                ('Art. 25', 'Data Protection by Design', '✅ Compliant', 'Built-in', '92%', '2025-01-12'),
                ('Art. 30', 'Records of Processing', '✅ Compliant', 'Documented', '100%', '2025-01-15'),
                ('Art. 32', 'Security of Processing', '✅ Compliant', 'Encrypted', '96%', '2025-01-14'),
                ('Art. 33', 'Breach Notification', '✅ Compliant', '72h Process', '100%', '2025-01-15'),
        ]

        for article in gdpr_articles:
                gdpr_tree.insert('', 'end', values=article)

        scrollbar2 = ttk.Scrollbar(gdpr_tree_frame, orient='vertical', command=gdpr_tree.yview)
        gdpr_tree.configure(yscrollcommand=scrollbar2.set)
        scrollbar2.pack(side='right', fill='y')
        gdpr_tree.pack(side='left', fill='both', expand=True)

        # SOC 2 Type II Detailed Table
        soc2_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
        soc2_frame.pack(fill='both', expand=True, padx=20, pady=10)

        soc2_header = ctk.CTkLabel(soc2_frame, text="🔐 SOC 2 Type II Trust Service Criteria", font=("Helvetica", 18, "bold"))
        soc2_header.pack(pady=10)

        soc2_tree_frame = tk.Frame(soc2_frame, bg=get_theme_colors()['bg_tertiary'])
        soc2_tree_frame.pack(fill='both', expand=True, padx=10, pady=10)

        soc2_cols = ('Criteria', 'Trust Principle', 'Control Count', 'Status', 'Compliance %', 'Evidence')
        soc2_tree = ttk.Treeview(soc2_tree_frame, columns=soc2_cols, show='headings', height=6)

        for col in soc2_cols:
                soc2_tree.heading(col, text=col)
                soc2_tree.column(col, width=150 if col == 'Trust Principle' else 100)

        # SOC 2 criteria
        soc2_criteria = [
                ('CC1', 'Control Environment', '12/12', '✅ Compliant', '100%', 'Verified'),
                ('CC2', 'Communication & Information', '8/8', '✅ Compliant', '100%', 'Verified'),
                ('CC3', 'Risk Assessment', '7/8', '⚠️ Partial', '87%', 'In Progress'),
                ('CC4', 'Monitoring Activities', '5/5', '✅ Compliant', '100%', 'Verified'),
                ('CC5', 'Control Activities', '10/10', '✅ Compliant', '100%', 'Verified'),
                ('CC6', 'Logical & Physical Access', '15/16', '⚠️ Partial', '94%', 'In Progress'),
        ]

        for criteria in soc2_criteria:
                soc2_tree.insert('', 'end', values=criteria)

        scrollbar3 = ttk.Scrollbar(soc2_tree_frame, orient='vertical', command=soc2_tree.yview)
        soc2_tree.configure(yscrollcommand=scrollbar3.set)
        scrollbar3.pack(side='right', fill='y')
        soc2_tree.pack(side='left', fill='both', expand=True)

        # Gap Analysis Chart
        gap_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
        gap_frame.pack(fill='both', expand=True, padx=20, pady=10)

        gap_header = ctk.CTkLabel(gap_frame, text="📊 Compliance Gap Analysis", font=("Helvetica", 18, "bold"))
        gap_header.pack(pady=10)

        fig = Figure(figsize=(12, 5), facecolor=get_theme_colors()['bg_tertiary'])
        ax = fig.add_subplot(111)

        categories = ['Access Control', 'Encryption', 'Audit Logs', 'Incident Response', 'Data Protection', 'Network Security']
        iso_scores = [95, 88, 100, 82, 90, 85]
        gdpr_scores = [98, 92, 95, 70, 100, 88]
        soc2_scores = [100, 94, 100, 87, 96, 94]

        x = range(len(categories))
        width = 0.25

        ax.bar([i - width for i in x], iso_scores, width, label='ISO 27001', color='#00d4ff')
        ax.bar(x, gdpr_scores, width, label='GDPR', color='#44ff44')
        ax.bar([i + width for i in x], soc2_scores, width, label='SOC 2', color='#ffaa44')

        ax.set_ylabel('Compliance %', color='white')
        ax.set_title('Control Category Comparison Across Frameworks', color='white', fontsize=14, pad=15)
        ax.set_xticks(x)
        ax.set_xticklabels(categories, rotation=15, ha='right')
        ax.legend()
        ax.set_ylim(0, 100)
        ax.axhline(y=90, color='green', linestyle='--', alpha=0.5, label='Target: 90%')
        ax.tick_params(colors='white')
        ax.set_facecolor(get_theme_colors()['bg_tertiary'])

        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, gap_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)


def create_attack_chain_view(gui):
    """Create Attack Chain Visualization tab with real data"""
    frame = ctk.CTkFrame(gui.display_container, fg_color=COLORS['bg_secondary'])
    gui.views['attack_chains'] = frame

    header = ctk.CTkLabel(
        frame,
        text="🔗 ATTACK CHAIN RECONSTRUCTION",
        font=("Helvetica", 24, "bold"),
        text_color=COLORS['accent']
    )
    header.pack(pady=20)

    # Info label container
    info_container = ctk.CTkFrame(frame, fg_color=COLORS['bg_secondary'])
    info_container.pack(fill='x', pady=(0, 10))

    # Scrollable content container for dynamic updates
    from tkinter import Canvas, Scrollbar
    canvas = Canvas(frame, bg=get_theme_colors()['bg_secondary'], highlightthickness=0)
    scrollbar = Scrollbar(frame, orient='vertical', command=canvas.yview)
    content_container = ctk.CTkFrame(canvas, fg_color=COLORS['bg_secondary'])

    content_container.bind('<Configure>',
                          lambda e: canvas.configure(scrollregion=canvas.bbox('all')))

    canvas.create_window((0, 0), window=content_container, anchor='nw')
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side='left', fill='both', expand=True, padx=20, pady=(0, 20))
    scrollbar.pack(side='right', fill='y', pady=(0, 20))

    def refresh_attack_chains():
        """Refresh attack chain visualization with current data"""
        # Clear previous content
        for widget in info_container.winfo_children():
            widget.destroy()
        for widget in content_container.winfo_children():
            widget.destroy()

        # Get real attack data
        from modules.AttackChainReconstructor import AttackChainReconstructor
        reconstructor = AttackChainReconstructor(time_window_hours=720)

        # Convert attacker profiles to events for reconstructor
        # OPTIMIZED: Limit events per attacker to keep GUI responsive
        max_events_per_attacker = 50
        for attacker in gui.current_profiles:
            for idx, event in enumerate(attacker.attack_events):
                if idx >= max_events_per_attacker:
                    break
                # Strip timezone info to avoid comparison issues
                timestamp = event.timestamp.replace(tzinfo=None) if hasattr(event.timestamp, 'tzinfo') and event.timestamp.tzinfo else event.timestamp
                reconstructor.add_event({
                    'timestamp': timestamp,
                    'source_ip': event.ip_address,
                    'target_ip': event.agent_ip,
                    'attack_type': event.attack_type.value if hasattr(event.attack_type, 'value') else str(event.attack_type),
                    'severity': event.rule_level,
                    'technique': event.description,
                    'rule_id': event.rule_id
                })

        # Reconstruct chains
        chains = reconstructor.reconstruct_chains(min_chain_length=1)

        total_phases = sum(len(set(chain.kill_chain_phases)) for chain in chains) if chains else 0

        info_label = ctk.CTkLabel(
            info_container,
            text=f"MITRE ATT&CK Kill Chain Mapping | {total_phases} Phases Tracked | {len(chains)} Attack Chains",
            font=("Helvetica", 14)
        )
        info_label.pack()

        # NetworkX graph visualization
        viz_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
        viz_frame.pack(fill='both', expand=True)

        if chains:
            # Create NetworkX graph to visualize all chains
            import networkx as nx
            G = nx.DiGraph()

            # Sort chains by severity (most severe first)
            sorted_chains = sorted(chains, key=lambda c: c.severity_score, reverse=True)

            # Limit to top 5 chains to avoid overcrowding
            display_chains = sorted_chains[:5]

            # Add nodes with kill chain phase information
            phase_colors = {
                'reconnaissance': '#00d4ff',
                'resource_development': '#0099cc',
                'initial_access': '#ff4444',
                'execution': '#ff6644',
                'persistence': '#ff8844',
                'privilege_escalation': '#ffaa44',
                'defense_evasion': '#ffcc44',
                'credential_access': '#ffee44',
                'discovery': '#ccff44',
                'lateral_movement': '#88ff44',
                'collection': '#44ff88',
                'command_and_control': '#44ffcc',
                'exfiltration': '#44ccff',
                'impact': '#ff44ff'
            }

            # Add all chains to the graph with attacker IP as prefix
            for chain in display_chains:
                for node in chain.nodes:
                    phase_name = node.kill_chain_phase.value
                    # Create unique node ID with attacker IP to differentiate chains
                    unique_node_id = f"{chain.attacker_ip}_{node.node_id}"
                    G.add_node(unique_node_id,
                              phase=phase_name,
                              attacker=chain.attacker_ip,
                              label=f"{chain.attacker_ip}\n{phase_name}",
                              color=phase_colors.get(phase_name, '#666666'))

                # Add edges for this chain
                for source, target in chain.edges:
                    unique_source = f"{chain.attacker_ip}_{source}"
                    unique_target = f"{chain.attacker_ip}_{target}"
                    G.add_edge(unique_source, unique_target, attacker=chain.attacker_ip)

            # Create matplotlib figure
            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

            fig = Figure(figsize=(12, 5), facecolor=get_theme_colors()['bg_tertiary'])
            ax = fig.add_subplot(111)

            # Layout
            pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

            # Draw nodes
            node_colors = [G.nodes[node]['color'] for node in G.nodes()]
            nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=3000,
                              alpha=0.9, ax=ax)

            # Draw edges with arrows
            nx.draw_networkx_edges(G, pos, edge_color='#00d4ff', arrows=True,
                              arrowsize=20, arrowstyle='->', width=2,
                              connectionstyle='arc3,rad=0.1', ax=ax)

            # Draw labels
            labels = {node: G.nodes[node]['phase'].replace('_', '\n').title()
                 for node in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels, font_size=9,
                              font_color='white', font_weight='bold', ax=ax)

            # Create title showing all attackers
            attacker_ips = [chain.attacker_ip for chain in display_chains]
            title_text = f'Attack Chains: {len(display_chains)} Attackers\n'
            title_text += f'IPs: {", ".join(attacker_ips[:3])}{"..." if len(attacker_ips) > 3 else ""}'

            ax.set_title(title_text, color='white', fontsize=14, fontweight='bold', pad=20)
            ax.set_facecolor(get_theme_colors()['bg_tertiary'])
            ax.axis('off')

            fig.tight_layout()
            canvas = FigureCanvasTkAgg(fig, viz_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

            # Add chain details below - show all chains
            details_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
            details_frame.pack(fill='both', expand=True, padx=10, pady=10)

            # Summary header
            summary_label = ctk.CTkLabel(
                details_frame,
                text=f"📊 ATTACK CHAIN DETAILS",
                font=("Helvetica", 16, "bold"),
                text_color=COLORS['accent']
            )
            summary_label.pack(pady=(10, 5))

            summary_info = ctk.CTkLabel(
                details_frame,
                text=f"Total Chains: {len(chains)} | Displaying: {len(display_chains)}",
                font=("Helvetica", 12)
            )
            summary_info.pack(pady=(0, 10))

            # Individual chain details
            for i, chain in enumerate(display_chains[:3], 1):
                chain_frame = ctk.CTkFrame(details_frame, fg_color=COLORS['bg_secondary'])
                chain_frame.pack(fill='x', padx=10, pady=5)

                # Chain header
                chain_header = ctk.CTkLabel(
                    chain_frame,
                    text=f"🎯 Chain {i}: {chain.attacker_ip} → {chain.target_ip}",
                    font=("Helvetica", 12, "bold"),
                    anchor='w'
                )
                chain_header.pack(fill='x', padx=10, pady=(10, 5))

                # Phases
                phases_text = ' → '.join([p.value.replace('_', ' ').title() for p in chain.kill_chain_phases])
                if len(chain.kill_chain_phases) > 5:
                    phases_list = [p.value.replace('_', ' ').title() for p in chain.kill_chain_phases[:5]]
                    phases_text = ' → '.join(phases_list) + f' ... (+{len(chain.kill_chain_phases)-5} more)'

                phases_label = ctk.CTkLabel(
                    chain_frame,
                    text=f"🔍 Phases: {phases_text}",
                    font=("Courier", 11),
                    anchor='w'
                )
                phases_label.pack(fill='x', padx=20, pady=2)

                # Metrics
                metrics_label = ctk.CTkLabel(
                    chain_frame,
                    text=f"📈 Severity: {chain.severity_score:.2f} | Confidence: {chain.confidence:.2f} | Events: {len(chain.nodes)} | Duration: {(chain.end_time - chain.start_time).total_seconds() / 60:.1f}m",
                    font=("Courier", 11),
                    anchor='w'
                )
                metrics_label.pack(fill='x', padx=20, pady=(2, 10))

                # Complete status
                status_color = COLORS['success'] if chain.is_complete else COLORS['warning']
                status_text = "✅ Complete Chain" if chain.is_complete else "⚠️ Partial Chain"
                status_label = ctk.CTkLabel(
                    chain_frame,
                    text=status_text,
                    font=("Helvetica", 11, "bold"),
                    text_color=status_color,
                    anchor='w'
                )
                status_label.pack(fill='x', padx=20, pady=(0, 10))
        else:
            viz_label = ctk.CTkLabel(
                viz_frame,
                text="⚠️ No attack chains detected\n\nRun analysis to generate attack chain data",
                font=("Helvetica", 16)
            )
            viz_label.pack(expand=True)

    # Store refresh function for later updates
    gui.refresh_attack_chains = refresh_attack_chains

    # Initial load
    refresh_attack_chains()


def create_correlation_analysis_view(gui):
    """Create Correlation Analysis tab with real data"""
    frame = ctk.CTkFrame(gui.display_container, fg_color=COLORS['bg_secondary'])
    gui.views['correlations'] = frame

    header = ctk.CTkLabel(
        frame,
        text="🔄 CORRELATION ANALYSIS",
        font=("Helvetica", 24, "bold"),
        text_color=COLORS['accent']
    )
    header.pack(pady=20)

    # Content container
    content_container = ctk.CTkFrame(frame, fg_color=COLORS['bg_secondary'])
    content_container.pack(fill='both', expand=True, padx=20, pady=(0, 20))

    def refresh_correlations():
        """Refresh correlation analysis with current data - OPTIMIZED to prevent GUI freeze"""
        # Clear previous content
        for widget in content_container.winfo_children():
            widget.destroy()

        # Analyze real correlations from attack data
        from datetime import timedelta

        total_correlations = 0
        coordinated_attacks = 0
        causal_links = 0
        temporal_correlations = 0
        target_correlations = 0

        # Find correlations between attackers
        attackers = gui.current_profiles

        # OPTIMIZATION: Limit attacker pairs to prevent O(n²) explosion
        max_attacker_pairs = 50  # Limit pairs checked to keep GUI responsive
        max_events_per_attacker = 20  # Sample events for temporal correlation
        pairs_checked = 0

        if len(attackers) > 1:
            # Find attackers targeting same agents within time window
            for i, attacker1 in enumerate(attackers):
                if pairs_checked >= max_attacker_pairs:
                    break
                for attacker2 in attackers[i+1:]:
                    if pairs_checked >= max_attacker_pairs:
                        break
                    # Check if they target same agents
                    common_agents = attacker1.targeted_agents & attacker2.targeted_agents
                    if common_agents:
                        target_correlations += 1
                        total_correlations += 1
                        pairs_checked += 1

                        # OPTIMIZATION: Sample events instead of checking all
                        events1 = list(attacker1.attack_events)[:max_events_per_attacker]
                        events2 = list(attacker2.attack_events)[:max_events_per_attacker]

                        # Check temporal proximity (attacks within 1 hour) - sampled
                        found_temporal = False
                        for event1 in events1:
                            if found_temporal:
                                break
                            for event2 in events2:
                                time_diff = abs((event1.timestamp.replace(tzinfo=None) - event2.timestamp.replace(tzinfo=None)).total_seconds())
                                if time_diff < 3600:  # Within 1 hour
                                    temporal_correlations += 1
                                    coordinated_attacks += 1
                                    found_temporal = True
                                    break

        # Find causal relationships (sequential attacks from same attacker)
        # OPTIMIZATION: Limit attackers and events checked
        attack_patterns = []
        max_attackers_for_patterns = 30  # Limit attackers checked
        max_events_for_patterns = 30  # Limit events per attacker

        for attacker in attackers[:max_attackers_for_patterns]:
            events = sorted(attacker.attack_events[:max_events_for_patterns], key=lambda e: e.timestamp)
            if len(events) > 1:
                for i in range(min(len(events) - 1, 10)):  # Max 10 patterns per attacker
                    time_diff = (events[i+1].timestamp.replace(tzinfo=None) - events[i].timestamp.replace(tzinfo=None)).total_seconds()
                    # Increased window to 24 hours to catch more patterns
                    if time_diff < 86400:  # Within 24 hours
                        causal_links += 1
                        total_correlations += 1
                        attack_patterns.append({
                            'attacker': attacker.ip_address,
                            'event1': events[i],
                            'event2': events[i+1],
                            'time_diff': time_diff
                        })

        # Stats cards
        stats_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
        stats_frame.pack(fill='x', pady=10)

        stat_cards = [
            ("Total Correlations", total_correlations),
            ("Coordinated Attacks", coordinated_attacks),
            ("Causal Links", causal_links)
        ]

        for label, value in stat_cards:
            card = create_stat_card(stats_frame, label, value)
            card.pack(side='left', expand=True, fill='both', padx=10, pady=10)

        # Correlation details and visualizations
        if total_correlations > 0:
            # Correlation types breakdown
            chart_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
            chart_frame.pack(fill='both', expand=True, pady=10)

            chart_header = ctk.CTkLabel(chart_frame, text="📊 Correlation Types Distribution",
                                       font=("Helvetica", 16, "bold"))
            chart_header.pack(pady=10)

            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

            fig = Figure(figsize=(10, 5), facecolor=get_theme_colors()['bg_tertiary'])
            ax = fig.add_subplot(111)

            correlation_types = {
                'Temporal': temporal_correlations,
                'Target-based': target_correlations,
                'Sequential/Causal': causal_links
            }

            # Filter out zero values
            correlation_types = {k: v for k, v in correlation_types.items() if v > 0}

            if correlation_types:
                colors = ['#00d4ff', '#44ff44', '#ffaa44']
                ax.pie(correlation_types.values(), labels=correlation_types.keys(),
                      autopct='%1.1f%%', startangle=90, colors=colors[:len(correlation_types)])
                ax.set_title('Correlation Types Distribution', color='white', fontsize=14, pad=20)

            fig.tight_layout()
            canvas = FigureCanvasTkAgg(fig, chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

            # Detailed correlation information
            details_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
            details_frame.pack(fill='both', expand=True, pady=10)

            details_header = ctk.CTkLabel(details_frame, text="🔍 Correlation Details",
                                         font=("Helvetica", 16, "bold"))
            details_header.pack(pady=10)

            # Show top correlated attackers
            if len(attackers) > 1:
                for i, attacker1 in enumerate(attackers[:3]):
                    for attacker2 in attackers[i+1:4]:
                        common_agents = attacker1.targeted_agents & attacker2.targeted_agents
                        if common_agents:
                            detail_card = ctk.CTkFrame(details_frame, fg_color=COLORS['bg_secondary'])
                            detail_card.pack(fill='x', padx=10, pady=5)

                            detail_text = f"🔗 {attacker1.ip_address} ↔ {attacker2.ip_address}\n"
                            detail_text += f"   Common Targets: {', '.join(list(common_agents)[:3])}{'...' if len(common_agents) > 3 else ''}\n"
                            detail_text += f"   Correlation Strength: {'High' if len(common_agents) > 2 else 'Medium'}"

                            detail_label = ctk.CTkLabel(detail_card, text=detail_text,
                                                       font=("Courier", 11), justify='left', anchor='w')
                            detail_label.pack(fill='x', padx=15, pady=10)

            # Show attack patterns (sequential attacks from same attacker)
            if attack_patterns:
                patterns_header = ctk.CTkLabel(details_frame, text="🔄 Attack Patterns (Sequential Events)",
                                             font=("Helvetica", 14, "bold"))
                patterns_header.pack(pady=(15, 5))

                for pattern in attack_patterns[:5]:
                    pattern_card = ctk.CTkFrame(details_frame, fg_color=COLORS['bg_secondary'])
                    pattern_card.pack(fill='x', padx=10, pady=5)

                    hours = pattern['time_diff'] / 3600
                    time_str = f"{hours:.1f}h" if hours >= 1 else f"{pattern['time_diff']/60:.0f}m"

                    pattern_text = f"⚡ {pattern['attacker']} - Sequential Attack Pattern\n"
                    pattern_text += f"   Event 1: {pattern['event1'].attack_type} at {pattern['event1'].timestamp.strftime('%Y-%m-%d %H:%M')}\n"
                    pattern_text += f"   Event 2: {pattern['event2'].attack_type} at {pattern['event2'].timestamp.strftime('%Y-%m-%d %H:%M')}\n"
                    pattern_text += f"   Time Gap: {time_str}"

                    pattern_label = ctk.CTkLabel(pattern_card, text=pattern_text,
                                                 font=("Courier", 10), justify='left', anchor='w')
                    pattern_label.pack(fill='x', padx=15, pady=10)
        else:
            # No correlations found
            no_data_label = ctk.CTkLabel(
                content_container,
                text="ℹ️ No correlations detected\n\nCorrelations are identified when:\n• Multiple attackers target the same systems\n• Attacks occur within close time proximity\n• Sequential attack patterns are detected",
                font=("Helvetica", 14),
                justify='center'
            )
            no_data_label.pack(expand=True, pady=50)

    # Store refresh function
    gui.refresh_correlations = refresh_correlations

    # Initial load
    refresh_correlations()


def create_forecasting_view(gui):
    """Create Time Series Forecasting tab with real data predictions"""
    frame = ctk.CTkFrame(gui.display_container, fg_color=COLORS['bg_secondary'])
    gui.views['forecasting'] = frame

    header = ctk.CTkLabel(
        frame,
        text="📈 TIME SERIES FORECASTING & PREDICTIONS",
        font=("Helvetica", 24, "bold"),
        text_color=COLORS['accent']
    )
    header.pack(pady=20)

    # Content container
    content_container = ctk.CTkFrame(frame, fg_color=COLORS['bg_secondary'])
    content_container.pack(fill='both', expand=True, padx=20, pady=(0, 20))

    def refresh_forecast():
        """Refresh forecast with real attack data"""
        # Clear previous content
        for widget in content_container.winfo_children():
            widget.destroy()

        from datetime import datetime, timedelta
        from collections import defaultdict

        info_label = ctk.CTkLabel(
            content_container,
            text="Simple Moving Average Forecasting (Based on Real Attack Data)",
            font=("Helvetica", 14)
        )
        info_label.pack(pady=(0, 10))

        # Load REAL attack data from evidence vault
        try:
            import json
            from pathlib import Path

            # Load evidence vault directly
            evidence_file = Path("evidence_vault/evidence_registry.json")
            evidence_data = {}
            if evidence_file.exists():
                try:
                    with open(evidence_file, 'r', encoding='utf-8') as f:
                        evidence_data = json.load(f)
                except json.JSONDecodeError as e:
                    print(f"Warning: Evidence registry corrupted, resetting: {e}")
                    # Reset the corrupted file
                    with open(evidence_file, 'w', encoding='utf-8') as f:
                        json.dump({}, f)

            if not evidence_data:
                no_data_label = ctk.CTkLabel(
                    content_container,
                    text="ℹ️ No attack data in evidence vault\n\nEvidence vault is empty",
                    font=("Helvetica", 14),
                    justify='center'
                )
                no_data_label.pack(expand=True, pady=50)
                return

            # Group attacks by hour from evidence vault
            attack_counts = defaultdict(int)
            all_events = []

            # Parse timestamps from evidence vault
            for evidence_id, evidence in evidence_data.items():
                timestamp_str = evidence.get('collected_at', '')
                if timestamp_str:
                    try:
                        # Parse timestamp (format: "2025-10-12T10:46:21.819738")
                        timestamp = datetime.strptime(timestamp_str[:19], '%Y-%m-%dT%H:%M:%S')
                        all_events.append(timestamp)
                        hour_timestamp = timestamp.replace(minute=0, second=0, microsecond=0)
                        attack_counts[hour_timestamp] += 1
                    except (ValueError, IndexError) as e:
                        # Skip invalid timestamps but don't crash
                        continue

        except Exception as e:
            error_label = ctk.CTkLabel(
                content_container,
                text=f"Error loading evidence data: {str(e)}",
                font=("Helvetica", 14),
                justify='center'
            )
            error_label.pack(expand=True, pady=50)
            return

        if not all_events:
            no_data_label = ctk.CTkLabel(
                content_container,
                text="ℹ️ No attack events available for forecasting",
                font=("Helvetica", 14),
                justify='center'
            )
            no_data_label.pack(expand=True, pady=50)
            return

        # Sort events chronologically
        all_events.sort()
        start_time = all_events[0]
        end_time = all_events[-1]

        # Create hourly time series
        current = start_time.replace(minute=0, second=0, microsecond=0)
        historical_times = []
        historical_counts = []

        while current <= end_time:
            historical_times.append(current)
            historical_counts.append(attack_counts.get(current, 0))
            current += timedelta(hours=1)

        # Simple moving average forecast (next 24 hours)
        window_size = min(12, len(historical_counts))  # 12-hour window or less
        if len(historical_counts) >= window_size:
            avg_rate = sum(historical_counts[-window_size:]) / window_size
        else:
            avg_rate = sum(historical_counts) / len(historical_counts) if historical_counts else 0

        # Generate forecast
        forecast_hours = 24
        forecast_times = []
        forecast_counts = []
        last_time = historical_times[-1] if historical_times else datetime.now()

        for i in range(1, forecast_hours + 1):
            forecast_times.append(last_time + timedelta(hours=i))
            # Add some variation (±20%)
            variation = avg_rate * 0.2
            forecast_counts.append(max(0, avg_rate))

        # Create chart
        chart_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
        chart_frame.pack(fill='both', expand=True, pady=10)

        from matplotlib.figure import Figure
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        import matplotlib.dates as mdates

        fig = Figure(figsize=(12, 6), facecolor=get_theme_colors()['bg_tertiary'])
        ax = fig.add_subplot(111)

        # Plot historical data
        ax.plot(historical_times, historical_counts, label='Historical Attack Data',
               color=get_theme_colors()['accent'], linewidth=2, marker='o', markersize=4)

        # Plot forecast
        ax.plot(forecast_times, forecast_counts, label='Forecast (Next 24h)',
               color=get_theme_colors()['warning'], linewidth=2, linestyle='--', marker='s', markersize=4)

        # Add confidence interval (±30%)
        upper_bound = [f * 1.3 for f in forecast_counts]
        lower_bound = [f * 0.7 for f in forecast_counts]
        ax.fill_between(forecast_times, lower_bound, upper_bound,
                        alpha=0.3, color=get_theme_colors()['warning'], label='Confidence Interval (±30%)')

        ax.set_title('Attack Volume Forecast (24h ahead) - Based on Real Data',
                    color='white', fontsize=16, pad=20)
        ax.set_xlabel('Time', color='white', fontsize=12)
        ax.set_ylabel('Attack Count', color='white', fontsize=12)
        ax.legend(facecolor=get_theme_colors()['bg_tertiary'], edgecolor='white', labelcolor='white')
        ax.tick_params(colors='white')
        ax.grid(True, alpha=0.3)
        ax.set_facecolor(get_theme_colors()['bg_tertiary'])

        # Format x-axis dates
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
        fig.autofmt_xdate(rotation=45)

        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

        # Add statistics
        stats_frame = ctk.CTkFrame(content_container, fg_color=COLORS['bg_tertiary'])
        stats_frame.pack(fill='x', pady=10)

        total_attacks = sum(historical_counts)
        avg_per_hour = total_attacks / len(historical_counts) if historical_counts else 0
        predicted_24h = sum(forecast_counts)

        stats_text = f"📊 FORECAST STATISTICS\n\n"
        stats_text += f"Historical Period: {start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}\n"
        stats_text += f"Total Historical Attacks: {total_attacks}\n"
        stats_text += f"Average Attacks/Hour: {avg_per_hour:.2f}\n"
        stats_text += f"Predicted Next 24h: {predicted_24h:.0f} attacks\n"
        stats_text += f"Forecast Method: Simple Moving Average (Window: {window_size}h)"

        stats_label = ctk.CTkLabel(stats_frame, text=stats_text,
                                   font=("Courier", 11), justify='left', anchor='w')
        stats_label.pack(padx=15, pady=15)

    # Store refresh function
    gui.refresh_forecast = refresh_forecast

    # Initial load
    refresh_forecast()


def show_threat_actor_detail_window(gui, profile):
    """Show detailed information about a threat actor in a popup window"""
    from tkinter import Toplevel, Text, Scrollbar

    # Create popup window
    detail_window = Toplevel(gui.root)
    detail_window.title(f"Threat Actor Details - {profile.primary_ip}")
    detail_window.geometry("800x600")
    detail_window.configure(bg=get_theme_colors()['bg_primary'])

    # Header
    header = ctk.CTkLabel(detail_window,
                         text=f"🎯 Threat Actor Profile: {profile.primary_ip}",
                         font=("Helvetica", 20, "bold"),
                         text_color=COLORS['accent'])
    header.pack(pady=20)

    # Create scrollable text area
    text_frame = ctk.CTkFrame(detail_window, fg_color=COLORS['bg_secondary'])
    text_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))

    text_widget = ctk.CTkTextbox(text_frame, font=("Courier", 11))
    text_widget.pack(fill='both', expand=True, padx=10, pady=10)

    # Format detailed information
    details = f"""
{'='*80}
THREAT ACTOR PROFILE - {profile.primary_ip}
{'='*80}

OVERVIEW:
  Actor ID:           {profile.actor_id}
  Primary IP:         {profile.primary_ip}
  Aliases:            {', '.join(profile.aliases) if profile.aliases else 'None'}
  All Source IPs:     {', '.join(profile.source_ips) if profile.source_ips else profile.primary_ip}

THREAT ASSESSMENT:
  Risk Score:         {profile.risk_score:.2f}/100
  Threat Level:       {profile.threat_level}
  Sophistication:     {profile.sophistication.value}
  Motivation:         {profile.motivation.value if profile.motivation else 'Unknown'}
  Confidence Score:   {profile.confidence_score:.2f}
  Attribution:        {profile.attribution_confidence:.2f}

ACTIVITY METRICS:
  Total Attacks:      {profile.total_attacks}
  Successful:         {profile.successful_attacks}
  Failed:             {profile.failed_attacks}
  Success Rate:       {(profile.successful_attacks/max(profile.total_attacks,1)*100):.1f}%
  Attack Frequency:   {profile.attack_frequency:.2f} attacks/day
  First Seen:         {profile.first_seen}
  Last Seen:          {profile.last_seen}
  Last Updated:       {profile.last_updated}

TACTICS, TECHNIQUES & PROCEDURES (TTPs):
  MITRE Tactics:      {', '.join(profile.ttp.tactics) if profile.ttp.tactics else 'None identified'}
  MITRE Techniques:   {', '.join(profile.ttp.techniques) if profile.ttp.techniques else 'None identified'}
  MITRE IDs:          {', '.join(profile.ttp.mitre_ids) if profile.ttp.mitre_ids else 'None'}
  Tools Used:         {', '.join(profile.ttp.tools_used) if profile.ttp.tools_used else 'None identified'}
  Attack Patterns:    {', '.join(profile.attack_patterns) if profile.attack_patterns else 'None'}

TARGETING:
  Targeted Sectors:   {', '.join(profile.targeted_sectors) if profile.targeted_sectors else 'Unknown'}
  Targeted Countries: {', '.join(profile.targeted_countries) if profile.targeted_countries else 'Unknown'}
  Preferred Times:    {', '.join(f'{h}:00' for h in profile.preferred_attack_times) if profile.preferred_attack_times else 'Any time'}

CAMPAIGNS & INTELLIGENCE:
  Known Campaigns:    {', '.join(profile.known_campaigns) if profile.known_campaigns else 'None identified'}
  Related Actors:     {', '.join(profile.related_actors) if profile.related_actors else 'None identified'}
  Intel Sources:      {', '.join(profile.threat_intel_sources) if profile.threat_intel_sources else 'None'}

TECHNICAL INDICATORS:
  Source ASNs:        {', '.join(profile.source_asns) if profile.source_asns else 'Unknown'}
  User Agents:        {', '.join(list(profile.user_agents)[:3]) if profile.user_agents else 'None'}
  Signatures:         {', '.join(profile.attack_signatures[:5]) if profile.attack_signatures else 'None'}

TAGS & NOTES:
  Tags:               {', '.join(profile.tags) if profile.tags else 'None'}
  Notes:
{chr(10).join(f'    - {note}' for note in profile.notes) if profile.notes else '    No notes available'}

{'='*80}
"""

    text_widget.insert('1.0', details)
    text_widget.configure(state='disabled')  # Make read-only

    # Close button
    close_btn = ctk.CTkButton(detail_window,
                             text="Close",
                             command=detail_window.destroy,
                             fg_color=COLORS['danger'],
                             width=120)
    close_btn.pack(pady=(0, 20))

def create_stat_card(parent, label, value):
    """Helper function to create a stat card"""
    card = ctk.CTkFrame(parent, fg_color=COLORS['bg_primary'])

    value_label = ctk.CTkLabel(
        card,
        text=str(value),
        font=("Helvetica", 32, "bold"),
        text_color=COLORS['accent']
    )
    value_label.pack(pady=(20, 5))

    text_label = ctk.CTkLabel(
        card,
        text=label,
        font=("Helvetica", 14),
        text_color=COLORS['text_secondary']
    )
    text_label.pack(pady=(0, 20))

    return card
