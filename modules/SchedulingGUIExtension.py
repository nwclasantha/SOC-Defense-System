"""
Scheduling GUI Extension for SOC Defense System
Adds scheduled scanning interface and email configuration to the GUI
"""

import customtkinter as ctk
from tkinter import messagebox
import tkinter as tk
import threading
import uuid
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

# Dark and Light color schemes for theme support
DARK_COLORS = {
    'bg_primary': '#0f1419',
    'bg_secondary': '#1a1f2e',
    'bg_tertiary': '#252d3f',
    'accent': '#00d4ff',
    'accent_hover': '#00a8cc',
    'success': '#44ff44',
    'warning': '#ffaa44',
    'danger': '#ff4444',
    'text_primary': '#ffffff',
    'text_secondary': '#a0a0a0',
    'border': '#333366'
}

LIGHT_COLORS = {
    'bg_primary': '#f0f0f0',
    'bg_secondary': '#ffffff',
    'bg_tertiary': '#e0e0e0',
    'accent': '#0078d4',
    'accent_hover': '#005a9e',
    'success': '#107c10',
    'warning': '#ffb900',
    'danger': '#d13438',
    'text_primary': '#000000',
    'text_secondary': '#505050',
    'border': '#cccccc'
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
    'accent_hover': ('#005a9e', '#00a8cc'),
    'success': ('#107c10', '#44ff44'),
    'warning': ('#ffb900', '#ffaa44'),
    'danger': ('#d13438', '#ff4444'),
    'text_primary': ('#000000', '#ffffff'),
    'text_secondary': ('#505050', '#a0a0a0'),
    'border': ('#cccccc', '#333366')
}


class EmailTagInput(ctk.CTkFrame):
    """
    Tag-based email input widget.
    Shows emails as removable tags/chips with easy add/remove functionality.
    """

    def __init__(self, parent, initial_emails: str = "", on_change=None, **kwargs):
        super().__init__(parent, fg_color=COLORS['bg_tertiary'], corner_radius=8, **kwargs)

        self.emails: List[str] = []
        self.on_change = on_change  # Callback when emails change
        self.tag_widgets: Dict[str, ctk.CTkFrame] = {}

        # Main container
        self.container = ctk.CTkFrame(self, fg_color='transparent')
        self.container.pack(fill='both', expand=True, padx=5, pady=5)

        # Tags display area (scrollable if many emails)
        self.tags_frame = ctk.CTkFrame(self.container, fg_color='transparent')
        self.tags_frame.pack(fill='x', pady=(0, 5))

        # Input row
        input_row = ctk.CTkFrame(self.container, fg_color='transparent')
        input_row.pack(fill='x')

        self.email_entry = ctk.CTkEntry(
            input_row,
            placeholder_text="Enter email and press Enter or click Add",
            fg_color=COLORS['bg_primary'],
            border_color=COLORS['border'],
            width=280
        )
        self.email_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        self.email_entry.bind('<Return>', self._on_enter_pressed)
        self.email_entry.bind('<KeyRelease>', self._on_key_release)

        self.add_btn = ctk.CTkButton(
            input_row,
            text="+ Add",
            width=60,
            height=28,
            fg_color=COLORS['accent'],
            hover_color=COLORS['accent_hover'],
            command=self._add_email_from_entry
        )
        self.add_btn.pack(side='left')

        # Load initial emails
        if initial_emails:
            self._load_emails(initial_emails)

    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email.strip()))

    def _load_emails(self, emails_str: str):
        """Load emails from comma-separated string"""
        if not emails_str:
            return
        for email in emails_str.split(','):
            email = email.strip()
            if email and self._validate_email(email):
                self._add_tag(email)

    def _on_enter_pressed(self, event=None):
        """Handle Enter key press"""
        self._add_email_from_entry()
        return "break"

    def _on_key_release(self, event=None):
        """Handle comma input to add email"""
        text = self.email_entry.get()
        if ',' in text:
            parts = text.split(',')
            for part in parts[:-1]:
                email = part.strip()
                if email and self._validate_email(email):
                    self._add_tag(email)
            # Keep any remaining text after last comma
            remaining = parts[-1].strip()
            self.email_entry.delete(0, 'end')
            if remaining:
                self.email_entry.insert(0, remaining)

    def _add_email_from_entry(self):
        """Add email from the entry field"""
        email = self.email_entry.get().strip().replace(',', '')

        if not email:
            return

        if not self._validate_email(email):
            messagebox.showwarning("Invalid Email", f"'{email}' is not a valid email address.")
            return

        if email.lower() in [e.lower() for e in self.emails]:
            messagebox.showinfo("Duplicate", f"'{email}' is already in the list.")
            self.email_entry.delete(0, 'end')
            return

        self._add_tag(email)
        self.email_entry.delete(0, 'end')

    def _add_tag(self, email: str):
        """Add an email tag widget"""
        if email.lower() in [e.lower() for e in self.emails]:
            return

        self.emails.append(email)

        # Create tag widget
        tag = ctk.CTkFrame(self.tags_frame, fg_color=COLORS['accent'], corner_radius=15)
        tag.pack(side='left', padx=2, pady=2)

        # Email label
        label = ctk.CTkLabel(
            tag,
            text=email,
            text_color=COLORS['bg_primary'],
            font=("Helvetica", 11),
            padx=8,
            pady=2
        )
        label.pack(side='left', padx=(8, 0))

        # Remove button
        remove_btn = ctk.CTkButton(
            tag,
            text="×",
            width=20,
            height=20,
            fg_color='transparent',
            hover_color=COLORS['accent_hover'],
            text_color=COLORS['bg_primary'],
            font=("Helvetica", 14, "bold"),
            command=lambda e=email: self._remove_tag(e)
        )
        remove_btn.pack(side='left', padx=(2, 4))

        self.tag_widgets[email] = tag
        self._notify_change()

    def _remove_tag(self, email: str):
        """Remove an email tag"""
        if email in self.emails:
            self.emails.remove(email)

        if email in self.tag_widgets:
            self.tag_widgets[email].destroy()
            del self.tag_widgets[email]

        self._notify_change()

    def _notify_change(self):
        """Notify callback about email list change"""
        if self.on_change:
            self.on_change(self.get_emails_string())

    def get_emails(self) -> List[str]:
        """Get list of emails"""
        return self.emails.copy()

    def get_emails_string(self) -> str:
        """Get emails as comma-separated string"""
        return ', '.join(self.emails)

    def set_emails(self, emails_str: str):
        """Set emails from comma-separated string"""
        # Clear existing
        for email in list(self.emails):
            self._remove_tag(email)
        # Load new
        self._load_emails(emails_str)

    def clear(self):
        """Clear all emails"""
        for email in list(self.emails):
            self._remove_tag(email)


def create_scheduling_view(gui, parent_frame):
    """Create the scheduling and automated reports view"""

    # Load config at the start for all settings
    from modules.ConfigManager import ConfigManager
    config = ConfigManager()

    frame = ctk.CTkScrollableFrame(parent_frame, fg_color=COLORS['bg_primary'])
    frame.pack(fill='both', expand=True)

    # Header
    header = ctk.CTkLabel(
        frame,
        text="SCHEDULED SCANS & AUTOMATED REPORTS",
        font=("Helvetica", 24, "bold"),
        text_color=COLORS['accent']
    )
    header.pack(pady=20)

    # Main content container
    content = ctk.CTkFrame(frame, fg_color=COLORS['bg_secondary'])
    content.pack(fill='both', expand=True, padx=20, pady=(0, 20))

    # ==================== Email Configuration Section ====================
    email_section = ctk.CTkFrame(content, fg_color=COLORS['bg_tertiary'])
    email_section.pack(fill='x', padx=20, pady=20)

    ctk.CTkLabel(
        email_section,
        text="Email Configuration",
        font=("Helvetica", 16, "bold"),
        text_color=COLORS['accent']
    ).pack(pady=(15, 10))

    # Active provider indicator (shows which provider will be used for sending)
    active_provider_frame = ctk.CTkFrame(email_section, fg_color=COLORS['bg_primary'])
    active_provider_frame.pack(fill='x', padx=20, pady=10)

    ctk.CTkLabel(
        active_provider_frame,
        text="Active Email Provider:",
        font=("Helvetica", 12, "bold"),
        text_color=COLORS['text_secondary']
    ).pack(side='left', padx=10)

    # Load saved active provider from config
    saved_active_provider = config.get('EmailNotifications', 'active_provider', 'None')
    gui.active_provider_var = ctk.StringVar(value=saved_active_provider)

    gui.active_provider_label = ctk.CTkLabel(
        active_provider_frame,
        text=f"[ {saved_active_provider} ]" if saved_active_provider != 'None' else "[ Not Set ]",
        font=("Helvetica", 14, "bold"),
        text_color=COLORS['success'] if saved_active_provider != 'None' else COLORS['warning']
    )
    gui.active_provider_label.pack(side='left', padx=10)

    # Email status indicator
    email_status_frame = ctk.CTkFrame(email_section, fg_color='transparent')
    email_status_frame.pack(fill='x', padx=20, pady=5)

    gui.email_status_label = ctk.CTkLabel(
        email_status_frame,
        text="Connection Status: Not Connected",
        text_color=COLORS['warning']
    )
    gui.email_status_label.pack(side='left')

    # Provider selector (for configuration only)
    provider_frame = ctk.CTkFrame(email_section, fg_color='transparent')
    provider_frame.pack(fill='x', padx=20, pady=10)

    ctk.CTkLabel(provider_frame, text="Configure Provider:", width=120, anchor='w').pack(side='left', padx=5)
    gui.email_provider_var = ctk.StringVar(value="O365")
    provider_selector = ctk.CTkSegmentedButton(
        provider_frame,
        values=["O365", "Gmail"],
        variable=gui.email_provider_var,
        command=lambda v: switch_email_provider(gui, v)
    )
    provider_selector.pack(side='left', padx=5)

    # Settings container (will hold provider-specific frames)
    gui.email_settings_container = ctk.CTkFrame(email_section, fg_color=COLORS['bg_primary'])
    gui.email_settings_container.pack(fill='x', padx=20, pady=10)

    # ===== O365 Settings Frame =====
    gui.o365_settings_frame = ctk.CTkFrame(gui.email_settings_container, fg_color='transparent')

    # O365 Client ID (load from config)
    o365_client_row = ctk.CTkFrame(gui.o365_settings_frame, fg_color='transparent')
    o365_client_row.pack(fill='x', pady=5)
    ctk.CTkLabel(o365_client_row, text="Client ID:", width=120, anchor='w').pack(side='left', padx=5)
    saved_o365_client_id = config.get('O365Email', 'client_id', 'ba562bf5-87ce-4f23-a50a-7f9fad1dabb4')
    gui.o365_client_id_var = ctk.StringVar(value=saved_o365_client_id)
    ctk.CTkEntry(o365_client_row, textvariable=gui.o365_client_id_var, width=350).pack(side='left', padx=5)

    # O365 Tenant ID (load from config)
    o365_tenant_row = ctk.CTkFrame(gui.o365_settings_frame, fg_color='transparent')
    o365_tenant_row.pack(fill='x', pady=5)
    ctk.CTkLabel(o365_tenant_row, text="Tenant ID:", width=120, anchor='w').pack(side='left', padx=5)
    saved_o365_tenant_id = config.get('O365Email', 'tenant_id', '7701d9e4-fc17-44a7-b421-77f3cac32795')
    gui.o365_tenant_id_var = ctk.StringVar(value=saved_o365_tenant_id)
    ctk.CTkEntry(o365_tenant_row, textvariable=gui.o365_tenant_id_var, width=350).pack(side='left', padx=5)

    # O365 Redirect URI (load from config)
    o365_redirect_row = ctk.CTkFrame(gui.o365_settings_frame, fg_color='transparent')
    o365_redirect_row.pack(fill='x', pady=5)
    ctk.CTkLabel(o365_redirect_row, text="Redirect URI:", width=120, anchor='w').pack(side='left', padx=5)
    saved_o365_redirect = config.get('O365Email', 'redirect_uri', 'http://localhost:8089/callback')
    gui.o365_redirect_uri_var = ctk.StringVar(value=saved_o365_redirect)
    ctk.CTkEntry(o365_redirect_row, textvariable=gui.o365_redirect_uri_var, width=350).pack(side='left', padx=5)

    # ===== Gmail Settings Frame (OAuth2) =====
    gui.gmail_settings_frame = ctk.CTkFrame(gui.email_settings_container, fg_color='transparent')

    # Gmail Client ID (load from config)
    gmail_client_row = ctk.CTkFrame(gui.gmail_settings_frame, fg_color='transparent')
    gmail_client_row.pack(fill='x', pady=5)
    ctk.CTkLabel(gmail_client_row, text="Client ID:", width=120, anchor='w').pack(side='left', padx=5)
    saved_gmail_client_id = config.get('GmailEmail', 'client_id', '')
    gui.gmail_client_id_var = ctk.StringVar(value=saved_gmail_client_id)
    ctk.CTkEntry(gmail_client_row, textvariable=gui.gmail_client_id_var, width=350,
                 placeholder_text="xxxxx.apps.googleusercontent.com").pack(side='left', padx=5)

    # Gmail Client Secret (load from config)
    gmail_secret_row = ctk.CTkFrame(gui.gmail_settings_frame, fg_color='transparent')
    gmail_secret_row.pack(fill='x', pady=5)
    ctk.CTkLabel(gmail_secret_row, text="Client Secret:", width=120, anchor='w').pack(side='left', padx=5)
    saved_gmail_secret = config.get('GmailEmail', 'client_secret', '')
    gui.gmail_client_secret_var = ctk.StringVar(value=saved_gmail_secret)
    ctk.CTkEntry(gmail_secret_row, textvariable=gui.gmail_client_secret_var, width=350, show='*',
                 placeholder_text="GOCSPX-xxxxx").pack(side='left', padx=5)

    # Gmail Redirect URI (load from config)
    gmail_redirect_row = ctk.CTkFrame(gui.gmail_settings_frame, fg_color='transparent')
    gmail_redirect_row.pack(fill='x', pady=5)
    ctk.CTkLabel(gmail_redirect_row, text="Redirect URI:", width=120, anchor='w').pack(side='left', padx=5)
    saved_gmail_redirect = config.get('GmailEmail', 'redirect_uri', 'http://localhost:8089/callback')
    gui.gmail_redirect_uri_var = ctk.StringVar(value=saved_gmail_redirect)
    ctk.CTkEntry(gmail_redirect_row, textvariable=gui.gmail_redirect_uri_var, width=350).pack(side='left', padx=5)

    # Show O365 settings by default
    gui.o365_settings_frame.pack(fill='x')

    # Email Recipients (shared between providers, load from O365 default)
    recipients_frame = ctk.CTkFrame(email_section, fg_color=COLORS['bg_primary'])
    recipients_frame.pack(fill='x', padx=20, pady=5)

    # Label for recipients
    ctk.CTkLabel(
        recipients_frame,
        text="📧 Email Recipients:",
        font=("Helvetica", 12, "bold"),
        text_color=COLORS['text_secondary']
    ).pack(anchor='w', padx=5, pady=(5, 5))

    # Load saved recipients
    saved_recipients = config.get('O365Email', 'default_recipients', '') or config.get('GmailEmail', 'default_recipients', '')

    # Store emails string for compatibility
    gui.email_recipients_var = ctk.StringVar(value=saved_recipients)

    # Callback to update StringVar when tags change
    def on_recipients_change(emails_str):
        gui.email_recipients_var.set(emails_str)
        # Auto-save recipients
        config.set('O365Email', 'default_recipients', emails_str)
        config.set('GmailEmail', 'default_recipients', emails_str)

    # Create tag-based email input
    gui.email_tag_input = EmailTagInput(
        recipients_frame,
        initial_emails=saved_recipients,
        on_change=on_recipients_change
    )
    gui.email_tag_input.pack(fill='x', padx=5, pady=5)

    # ===== Email Notification Options =====
    notification_frame = ctk.CTkFrame(email_section, fg_color=COLORS['bg_primary'])
    notification_frame.pack(fill='x', padx=20, pady=10)

    ctk.CTkLabel(
        notification_frame,
        text="Notification Options",
        font=("Helvetica", 12, "bold"),
        text_color=COLORS['text_secondary']
    ).pack(anchor='w', padx=5, pady=(5, 10))

    # Skip duplicate findings option
    gui.skip_duplicate_findings_var = ctk.BooleanVar(
        value=config.get('EmailNotifications', 'skip_duplicate_findings', 'True').lower() == 'true'
    )
    ctk.CTkCheckBox(
        notification_frame,
        text="Skip email if no new findings (scheduled scans only)",
        variable=gui.skip_duplicate_findings_var,
        text_color=COLORS['text_primary'],
        command=lambda: save_notification_settings(gui)
    ).pack(anchor='w', padx=20, pady=3)

    # Always send on critical threats
    gui.always_send_critical_var = ctk.BooleanVar(
        value=config.get('EmailNotifications', 'always_send_critical', 'True').lower() == 'true'
    )
    ctk.CTkCheckBox(
        notification_frame,
        text="Always send email on critical/major threats",
        variable=gui.always_send_critical_var,
        text_color=COLORS['text_primary'],
        command=lambda: save_notification_settings(gui)
    ).pack(anchor='w', padx=20, pady=3)

    # Always send on minor detections
    gui.always_send_minor_var = ctk.BooleanVar(
        value=config.get('EmailNotifications', 'always_send_minor', 'True').lower() == 'true'
    )
    ctk.CTkCheckBox(
        notification_frame,
        text="Always send email on any threat detection (minor/major)",
        variable=gui.always_send_minor_var,
        text_color=COLORS['text_primary'],
        command=lambda: save_notification_settings(gui)
    ).pack(anchor='w', padx=20, pady=3)

    # Attachment options label
    ctk.CTkLabel(
        notification_frame,
        text="Attachment Options:",
        font=("Helvetica", 11),
        text_color=COLORS['text_secondary']
    ).pack(anchor='w', padx=20, pady=(10, 5))

    # Attachment type checkboxes frame
    attach_frame = ctk.CTkFrame(notification_frame, fg_color='transparent')
    attach_frame.pack(fill='x', padx=20)

    # PDF attachment (default: False)
    gui.attach_pdf_var = ctk.BooleanVar(
        value=config.get('EmailNotifications', 'attach_pdf', 'False').lower() == 'true'
    )
    ctk.CTkCheckBox(
        attach_frame,
        text="PDF Reports",
        variable=gui.attach_pdf_var,
        text_color=COLORS['text_primary'],
        width=120,
        command=lambda: save_notification_settings(gui)
    ).pack(side='left', padx=5)

    # CSV attachment (default: False)
    gui.attach_csv_var = ctk.BooleanVar(
        value=config.get('EmailNotifications', 'attach_csv', 'False').lower() == 'true'
    )
    ctk.CTkCheckBox(
        attach_frame,
        text="CSV Data",
        variable=gui.attach_csv_var,
        text_color=COLORS['text_primary'],
        width=100,
        command=lambda: save_notification_settings(gui)
    ).pack(side='left', padx=5)

    # Excel attachment (default: True)
    gui.attach_excel_var = ctk.BooleanVar(
        value=config.get('EmailNotifications', 'attach_excel', 'True').lower() == 'true'
    )
    ctk.CTkCheckBox(
        attach_frame,
        text="Excel Reports",
        variable=gui.attach_excel_var,
        text_color=COLORS['text_primary'],
        width=120,
        command=lambda: save_notification_settings(gui)
    ).pack(side='left', padx=5)

    # HTML attachment (default: True)
    gui.attach_html_var = ctk.BooleanVar(
        value=config.get('EmailNotifications', 'attach_html', 'True').lower() == 'true'
    )
    ctk.CTkCheckBox(
        attach_frame,
        text="HTML Reports",
        variable=gui.attach_html_var,
        text_color=COLORS['text_primary'],
        width=120,
        command=lambda: save_notification_settings(gui)
    ).pack(side='left', padx=5)

    # IP Filtering Options
    ip_filter_label = ctk.CTkLabel(
        email_section,
        text="IP Address Filtering:",
        font=ctk.CTkFont(size=13, weight="bold"),
        text_color=COLORS['text_secondary']
    )
    ip_filter_label.pack(anchor='w', padx=20, pady=(15, 5))

    ip_filter_frame = ctk.CTkFrame(email_section, fg_color='transparent')
    ip_filter_frame.pack(fill='x', padx=20)

    # Include Public IPs (default: True)
    gui.include_public_ips_var = ctk.BooleanVar(
        value=config.get('EmailNotifications', 'include_public_ips', 'True').lower() == 'true'
    )
    ctk.CTkCheckBox(
        ip_filter_frame,
        text="Include Public IPs",
        variable=gui.include_public_ips_var,
        text_color=COLORS['text_primary'],
        width=150,
        command=lambda: save_notification_settings(gui)
    ).pack(side='left', padx=5)

    # Include Private IPs (default: True)
    gui.include_private_ips_var = ctk.BooleanVar(
        value=config.get('EmailNotifications', 'include_private_ips', 'True').lower() == 'true'
    )
    ctk.CTkCheckBox(
        ip_filter_frame,
        text="Include Private IPs",
        variable=gui.include_private_ips_var,
        text_color=COLORS['text_primary'],
        width=150,
        command=lambda: save_notification_settings(gui)
    ).pack(side='left', padx=5)

    # Connect button
    btn_frame = ctk.CTkFrame(email_section, fg_color='transparent')
    btn_frame.pack(pady=15)

    gui.connect_email_btn = ctk.CTkButton(
        btn_frame,
        text="Connect O365 Email",
        command=lambda: connect_email(gui),
        fg_color=COLORS['accent'],
        hover_color=COLORS['accent_hover'],
        width=180
    )
    gui.connect_email_btn.pack(side='left', padx=5)

    gui.disconnect_email_btn = ctk.CTkButton(
        btn_frame,
        text="Disconnect",
        command=lambda: disconnect_email(gui),
        fg_color=COLORS['danger'],
        hover_color='#cc3333',
        width=100,
        state='disabled'
    )
    gui.disconnect_email_btn.pack(side='left', padx=5)

    gui.test_email_btn = ctk.CTkButton(
        btn_frame,
        text="Send Test Email",
        command=lambda: send_test_email(gui),
        fg_color=COLORS['success'],
        hover_color='#00cc66',
        width=130,
        state='disabled'
    )
    gui.test_email_btn.pack(side='left', padx=5)

    gui.save_email_settings_btn = ctk.CTkButton(
        btn_frame,
        text="Save Settings",
        command=lambda: save_email_settings(gui),
        fg_color=COLORS['warning'],
        hover_color='#cc8800',
        width=100
    )
    gui.save_email_settings_btn.pack(side='left', padx=5)

    # ==================== Scheduler Status Section ====================
    scheduler_section = ctk.CTkFrame(content, fg_color=COLORS['bg_tertiary'])
    scheduler_section.pack(fill='x', padx=20, pady=10)

    scheduler_header = ctk.CTkFrame(scheduler_section, fg_color='transparent')
    scheduler_header.pack(fill='x', padx=20, pady=15)

    ctk.CTkLabel(
        scheduler_header,
        text="Scan Scheduler",
        font=("Helvetica", 16, "bold"),
        text_color=COLORS['accent']
    ).pack(side='left')

    gui.scheduler_status_label = ctk.CTkLabel(
        scheduler_header,
        text="Scheduler: Stopped",
        text_color=COLORS['danger']
    )
    gui.scheduler_status_label.pack(side='right')

    # Scheduler controls
    scheduler_controls = ctk.CTkFrame(scheduler_section, fg_color='transparent')
    scheduler_controls.pack(fill='x', padx=20, pady=10)

    gui.start_scheduler_btn = ctk.CTkButton(
        scheduler_controls,
        text="Start Scheduler",
        command=lambda: start_scheduler(gui),
        fg_color=COLORS['success'],
        hover_color='#00cc66',
        width=150
    )
    gui.start_scheduler_btn.pack(side='left', padx=5)

    gui.stop_scheduler_btn = ctk.CTkButton(
        scheduler_controls,
        text="Stop Scheduler",
        command=lambda: stop_scheduler(gui),
        fg_color=COLORS['danger'],
        hover_color='#cc3333',
        width=150,
        state='disabled'
    )
    gui.stop_scheduler_btn.pack(side='left', padx=5)

    # Next scheduled scans display
    gui.next_scans_label = ctk.CTkLabel(
        scheduler_section,
        text="No scheduled scans",
        text_color=COLORS['text_secondary']
    )
    gui.next_scans_label.pack(pady=(0, 15))

    # ==================== Schedule List Section ====================
    schedules_section = ctk.CTkFrame(content, fg_color=COLORS['bg_tertiary'])
    schedules_section.pack(fill='both', expand=True, padx=20, pady=10)

    schedules_header = ctk.CTkFrame(schedules_section, fg_color='transparent')
    schedules_header.pack(fill='x', padx=20, pady=15)

    ctk.CTkLabel(
        schedules_header,
        text="Scheduled Scans",
        font=("Helvetica", 16, "bold"),
        text_color=COLORS['accent']
    ).pack(side='left')

    ctk.CTkButton(
        schedules_header,
        text="+ Add Schedule",
        command=lambda: show_add_schedule_dialog(gui),
        fg_color=COLORS['accent'],
        hover_color=COLORS['accent_hover'],
        width=120
    ).pack(side='right')

    # Schedules list container
    gui.schedules_list_frame = ctk.CTkScrollableFrame(
        schedules_section,
        fg_color=COLORS['bg_primary'],
        height=300
    )
    gui.schedules_list_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))

    # Initialize the scheduler manager
    initialize_scheduler(gui)

    # Refresh schedules list
    refresh_schedules_list(gui)

    # Store refresh function
    gui.refresh_schedules = lambda: refresh_schedules_list(gui)


def initialize_scheduler(gui):
    """Initialize the scheduler manager"""
    try:
        from modules.ScheduledScanManager import ScheduledScanManager

        gui.scheduler_manager = ScheduledScanManager()
        gui.scheduler_manager.gui = gui

        # Set up callbacks
        gui.scheduler_manager.on_status_update = lambda msg: update_scheduler_status(gui, msg)
        gui.scheduler_manager.on_scan_start = lambda s: on_scheduled_scan_start(gui, s)
        gui.scheduler_manager.on_scan_complete = lambda s, r: on_scheduled_scan_complete(gui, s, r)
        gui.scheduler_manager.on_scan_error = lambda s, e: on_scheduled_scan_error(gui, s, e)

        gui.email_sender = None

        # Try to restore active email provider from cached tokens
        restore_email_provider(gui)

    except Exception as e:
        print(f"Error initializing scheduler: {e}")
        gui.scheduler_manager = None


def restore_email_provider(gui):
    """Try to restore email provider from cached tokens on startup"""
    try:
        from modules.ConfigManager import ConfigManager
        config = ConfigManager()

        saved_provider = config.get('EmailNotifications', 'active_provider', 'None')

        if saved_provider == 'O365':
            # Try to restore O365 from cache
            from modules.O365EmailSender import O365EmailSender
            client_id = config.get('O365Email', 'client_id', '')
            tenant_id = config.get('O365Email', 'tenant_id', '')

            if client_id and tenant_id:
                email_sender = O365EmailSender(client_id=client_id, tenant_id=tenant_id)
                if email_sender.is_authenticated():
                    gui.email_sender = email_sender
                    gui.email_status_label.configure(text="Connection Status: O365 Connected (Restored)", text_color=COLORS['success'])
                    gui.connect_email_btn.configure(text="Reconnect")
                    gui.disconnect_email_btn.configure(state='normal')
                    gui.test_email_btn.configure(state='normal')
                    print(f"O365 email restored from cache: {email_sender.user_email}")

        elif saved_provider == 'Gmail':
            # Try to restore Gmail from cache
            from modules.GmailEmailSender import GmailEmailSender
            client_id = config.get('GmailEmail', 'client_id', '')
            client_secret = config.get('GmailEmail', 'client_secret', '')

            if client_id and client_secret:
                email_sender = GmailEmailSender(client_id=client_id, client_secret=client_secret)
                if email_sender.is_authenticated():
                    gui.email_sender = email_sender
                    gui.email_status_label.configure(text="Connection Status: Gmail Connected (Restored)", text_color=COLORS['success'])
                    gui.connect_email_btn.configure(text="Reconnect")
                    gui.disconnect_email_btn.configure(state='normal')
                    gui.test_email_btn.configure(state='normal')
                    print(f"Gmail restored from cache: {email_sender.user_email}")

    except Exception as e:
        print(f"Could not restore email provider: {e}")


def save_notification_settings(gui):
    """Save notification checkbox settings to config file"""
    try:
        from modules.ConfigManager import ConfigManager
        config = ConfigManager()

        # Save all notification options
        config.set('EmailNotifications', 'skip_duplicate_findings', str(gui.skip_duplicate_findings_var.get()))
        config.set('EmailNotifications', 'always_send_critical', str(gui.always_send_critical_var.get()))
        config.set('EmailNotifications', 'always_send_minor', str(gui.always_send_minor_var.get()))
        config.set('EmailNotifications', 'attach_pdf', str(gui.attach_pdf_var.get()))
        config.set('EmailNotifications', 'attach_csv', str(gui.attach_csv_var.get()))
        config.set('EmailNotifications', 'attach_excel', str(gui.attach_excel_var.get()))
        config.set('EmailNotifications', 'attach_html', str(gui.attach_html_var.get()))

        # Save IP filtering options
        config.set('EmailNotifications', 'include_public_ips', str(gui.include_public_ips_var.get()))
        config.set('EmailNotifications', 'include_private_ips', str(gui.include_private_ips_var.get()))

    except Exception as e:
        print(f"Error saving notification settings: {e}")


def save_email_settings(gui):
    """Save all email provider settings to config file"""
    try:
        from modules.ConfigManager import ConfigManager
        config = ConfigManager()

        # Save O365 settings
        config.set('O365Email', 'client_id', gui.o365_client_id_var.get().strip())
        config.set('O365Email', 'tenant_id', gui.o365_tenant_id_var.get().strip())
        config.set('O365Email', 'redirect_uri', gui.o365_redirect_uri_var.get().strip())

        # Save Gmail settings
        config.set('GmailEmail', 'client_id', gui.gmail_client_id_var.get().strip())
        config.set('GmailEmail', 'client_secret', gui.gmail_client_secret_var.get().strip())
        config.set('GmailEmail', 'redirect_uri', gui.gmail_redirect_uri_var.get().strip())

        # Save recipients for both providers
        recipients = gui.email_recipients_var.get().strip()
        config.set('O365Email', 'default_recipients', recipients)
        config.set('GmailEmail', 'default_recipients', recipients)

        messagebox.showinfo("Settings Saved", "Email settings saved to config.ini\n\nYou can now connect with the updated credentials.")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to save settings: {e}")


def switch_email_provider(gui, provider):
    """Switch between O365 and Gmail settings display"""
    # Hide both frames
    gui.o365_settings_frame.pack_forget()
    gui.gmail_settings_frame.pack_forget()

    # Show the selected provider's frame
    if provider == "O365":
        gui.o365_settings_frame.pack(fill='x')
        gui.connect_email_btn.configure(text="Connect O365 Email")
    else:
        gui.gmail_settings_frame.pack(fill='x')
        gui.connect_email_btn.configure(text="Connect Gmail")


def connect_email(gui):
    """Route to appropriate email connection based on selected provider"""
    provider = gui.email_provider_var.get()
    if provider == "O365":
        connect_o365_email(gui)
    else:
        connect_gmail(gui)


def connect_o365_email(gui):
    """Connect to O365 email using OAuth2 with popup authentication dialog"""
    try:
        from modules.O365EmailSender import O365EmailSender
        import msal

        client_id = gui.o365_client_id_var.get()
        tenant_id = gui.o365_tenant_id_var.get()
        redirect_uri = gui.o365_redirect_uri_var.get()

        if not client_id or not tenant_id:
            messagebox.showerror("Error", "Please enter Client ID and Tenant ID")
            return

        gui.email_status_label.configure(text="Email Status: Connecting...", text_color=COLORS['warning'])
        gui.connect_email_btn.configure(state='disabled')

        def do_auth():
            try:
                gui.email_sender = O365EmailSender(
                    client_id=client_id,
                    tenant_id=tenant_id,
                    redirect_uri=redirect_uri
                )

                if gui.email_sender.is_authenticated():
                    gui.root.after(0, lambda: on_email_connected(gui))
                else:
                    # Show authentication popup dialog
                    gui.root.after(0, lambda: show_auth_popup(gui, gui.email_sender))

            except Exception as e:
                gui.root.after(0, lambda: on_email_error(gui, str(e)))

        threading.Thread(target=do_auth, daemon=True).start()

    except ImportError:
        messagebox.showerror("Error", "Please install msal package: pip install msal")
        gui.connect_email_btn.configure(state='normal')


def show_auth_popup(gui, email_sender):
    """Show authentication popup with browser-based OAuth2 PKCE flow"""
    import webbrowser
    import http.server
    import urllib.parse
    import secrets
    import base64
    import hashlib
    import json

    # Create popup dialog
    auth_dialog = ctk.CTkToplevel(gui.root)
    auth_dialog.title("Microsoft 365 Authentication")
    auth_dialog.geometry("450x280")
    auth_dialog.transient(gui.root)
    auth_dialog.grab_set()

    # Center on screen
    auth_dialog.update_idletasks()
    x = (auth_dialog.winfo_screenwidth() - 450) // 2
    y = (auth_dialog.winfo_screenheight() - 280) // 2
    auth_dialog.geometry(f"+{x}+{y}")

    auth_dialog.configure(fg_color=COLORS['bg_secondary'])

    # Header
    ctk.CTkLabel(
        auth_dialog,
        text="Microsoft 365 Sign-In",
        font=("Helvetica", 22, "bold"),
        text_color=COLORS['accent']
    ).pack(pady=(30, 10))

    # Status frame
    status_frame = ctk.CTkFrame(auth_dialog, fg_color=COLORS['bg_tertiary'])
    status_frame.pack(fill='x', padx=30, pady=20)

    status_label = ctk.CTkLabel(
        status_frame,
        text="Opening browser for sign-in...",
        font=("Helvetica", 12),
        text_color=COLORS['warning']
    )
    status_label.pack(pady=15)

    info_label = ctk.CTkLabel(
        status_frame,
        text="Please complete sign-in in your browser.\nThis window will close automatically.",
        font=("Helvetica", 10),
        text_color=COLORS['text_secondary']
    )
    info_label.pack(pady=(0, 15))

    # Cancel button
    cancel_btn = ctk.CTkButton(
        auth_dialog,
        text="Cancel",
        command=lambda: cancel_auth(),
        fg_color=COLORS['danger'],
        hover_color='#cc3333',
        width=120,
        height=35
    )
    cancel_btn.pack(pady=20)

    # State variables
    auth_state = {
        'cancelled': False,
        'server': None,
        'code_verifier': None,
        'state': None
    }

    def cancel_auth():
        auth_state['cancelled'] = True
        if auth_state['server']:
            try:
                auth_state['server'].shutdown()
            except (OSError, Exception):
                pass
        auth_dialog.destroy()
        gui.connect_email_btn.configure(state='normal')
        gui.email_status_label.configure(text="Email Status: Cancelled", text_color=COLORS['warning'])

    def start_oauth_flow():
        try:
            # OAuth2 configuration
            client_id = email_sender.client_id
            tenant_id = email_sender.tenant_id
            redirect_port = 8089
            redirect_uri = f'http://localhost:{redirect_port}/callback'

            auth_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize'
            token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
            # Use minimal scopes to avoid admin consent requirement
            scope = 'https://graph.microsoft.com/Mail.Send offline_access openid profile'

            # Generate PKCE code verifier and challenge
            code_verifier = secrets.token_urlsafe(64)
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip('=')

            state = secrets.token_urlsafe(32)

            # Store for callback
            auth_state['code_verifier'] = code_verifier
            auth_state['state'] = state
            auth_state['token_url'] = token_url
            auth_state['redirect_uri'] = redirect_uri
            auth_state['client_id'] = client_id
            auth_state['scope'] = scope

            # Build authorization URL
            params = {
                'client_id': client_id,
                'response_type': 'code',
                'redirect_uri': redirect_uri,
                'scope': scope,
                'state': state,
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256',
                'prompt': 'select_account'
            }

            auth_request_url = f"{auth_url}?{urllib.parse.urlencode(params)}"

            # Start local server in background thread
            threading.Thread(target=run_callback_server, args=(redirect_port,), daemon=True).start()

            # Open browser
            webbrowser.open(auth_request_url)

        except Exception as e:
            gui.root.after(0, lambda: show_error(str(e)))

    def run_callback_server(port):
        """Run local HTTP server to receive OAuth callback"""

        class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == '/callback':
                    query = urllib.parse.parse_qs(parsed.query)

                    if 'code' in query and 'state' in query:
                        code = query['code'][0]
                        state = query['state'][0]

                        # Verify state
                        if state == auth_state['state']:
                            # Send success response to browser
                            self.send_response(200)
                            self.send_header('Content-type', 'text/html')
                            self.end_headers()
                            success_html = """
                            <html><head><style>
                            body { font-family: 'Segoe UI', Arial; text-align: center; padding: 50px; background: #0a0a1a; color: #fff; }
                            .success { color: #00ff88; font-size: 28px; margin-bottom: 20px; }
                            p { color: #aaa; font-size: 16px; }
                            </style></head><body>
                            <h1 class="success">Authentication Successful!</h1>
                            <p>You can close this window and return to SOC Defense System.</p>
                            <script>setTimeout(function(){ window.close(); }, 2000);</script>
                            </body></html>
                            """
                            self.wfile.write(success_html.encode())

                            # Exchange code for token in main thread
                            gui.root.after(100, lambda: exchange_code_for_token(code))
                        else:
                            self.send_error(400, "Invalid state parameter")
                    elif 'error' in query:
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        error_desc = query.get('error_description', query.get('error', ['Unknown error']))[0]
                        error_html = f"""
                        <html><body style="font-family: 'Segoe UI', Arial; text-align: center; padding: 50px; background: #0a0a1a; color: #fff;">
                        <h1 style="color: #ff4444;">Authentication Failed</h1>
                        <p style="color: #aaa;">Error: {error_desc}</p>
                        <p style="color: #888;">Please close this window and try again.</p>
                        </body></html>
                        """
                        self.wfile.write(error_html.encode())
                        gui.root.after(100, lambda: show_error(error_desc))
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                pass  # Suppress logging

        server = None
        try:
            server = http.server.HTTPServer(('localhost', port), OAuthCallbackHandler)
            auth_state['server'] = server
            server.timeout = 120  # 2 minute timeout
            server.handle_request()  # Handle single request
        except Exception as e:
            if not auth_state['cancelled']:
                gui.root.after(100, lambda: show_error(f"Server error: {str(e)}"))
        finally:
            # Ensure server socket is properly closed
            if server:
                try:
                    server.server_close()
                except Exception:
                    pass

    def exchange_code_for_token(code):
        """Exchange authorization code for access token"""
        try:
            import urllib.request

            data = {
                'client_id': auth_state['client_id'],
                'code': code,
                'redirect_uri': auth_state['redirect_uri'],
                'grant_type': 'authorization_code',
                'code_verifier': auth_state['code_verifier'],
                'scope': auth_state['scope']
            }

            req = urllib.request.Request(
                auth_state['token_url'],
                data=urllib.parse.urlencode(data).encode(),
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                token_data = json.loads(response.read().decode())

            access_token = token_data.get('access_token')
            refresh_token = token_data.get('refresh_token', '')

            if not access_token:
                raise Exception("No access token received")

            # Get user email from ID token
            id_token = token_data.get('id_token', '')
            user_email = get_email_from_id_token(id_token)

            # Store tokens in email_sender
            email_sender.access_token = access_token
            email_sender.refresh_token = refresh_token
            email_sender.user_email = user_email
            email_sender._save_token_cache()

            # Success!
            auth_dialog.destroy()
            on_email_connected(gui, show_message=False)
            messagebox.showinfo("Success", f"Microsoft 365 Email connected successfully!\n\nAuthenticated as: {user_email}\n\nYou can now send automated security reports.")

        except Exception as e:
            show_error(str(e))

    def get_email_from_id_token(id_token):
        """Extract email from ID token"""
        try:
            if id_token:
                parts = id_token.split('.')
                if len(parts) >= 2:
                    payload = parts[1]
                    # Add padding if needed
                    payload += '=' * (4 - len(payload) % 4)
                    claims = json.loads(base64.urlsafe_b64decode(payload))
                    return claims.get('email') or claims.get('preferred_username') or claims.get('upn') or 'Unknown'
        except (ValueError, KeyError, json.JSONDecodeError, Exception):
            pass
        return 'Unknown'

    def show_error(error):
        status_label.configure(text=f"Error: {error}", text_color=COLORS['danger'])
        info_label.configure(text="Please try again or check your Azure AD configuration.")
        gui.connect_email_btn.configure(state='normal')

    # Start OAuth flow in background
    threading.Thread(target=start_oauth_flow, daemon=True).start()


def disconnect_email(gui):
    """Disconnect the current email provider"""
    try:
        from modules.ConfigManager import ConfigManager
        config = ConfigManager()

        # Clear email sender
        gui.email_sender = None

        # Clear active provider in config
        config.set('EmailNotifications', 'active_provider', 'None')

        # Update UI
        gui.active_provider_var.set('None')
        gui.active_provider_label.configure(
            text="[ Not Set ]",
            text_color=COLORS['warning']
        )
        gui.email_status_label.configure(
            text="Connection Status: Disconnected",
            text_color=COLORS['warning']
        )

        # Update buttons
        gui.connect_email_btn.configure(text=f"Connect {gui.email_provider_var.get()} Email")
        gui.disconnect_email_btn.configure(state='disabled')
        gui.test_email_btn.configure(state='disabled')

        messagebox.showinfo("Disconnected", "Email provider disconnected.\n\nYou can now connect to a different provider.")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to disconnect: {e}")


def set_active_provider(gui, provider_name, user_email=""):
    """Set the active email provider and update UI"""
    try:
        from modules.ConfigManager import ConfigManager
        config = ConfigManager()

        # Save to config
        config.set('EmailNotifications', 'active_provider', provider_name)

        # Update UI
        gui.active_provider_var.set(provider_name)
        display_text = f"[ {provider_name} ]"
        if user_email:
            display_text = f"[ {provider_name}: {user_email} ]"
        gui.active_provider_label.configure(
            text=display_text,
            text_color=COLORS['success']
        )

        # Enable disconnect button
        gui.disconnect_email_btn.configure(state='normal')

    except Exception as e:
        print(f"Error setting active provider: {e}")


def on_email_connected(gui, show_message=True):
    """Called when email is successfully connected"""
    gui.email_status_label.configure(text="Connection Status: O365 Connected", text_color=COLORS['success'])
    gui.connect_email_btn.configure(state='normal', text="Reconnect")
    gui.test_email_btn.configure(state='normal')

    # Set as active provider
    user_email = getattr(gui.email_sender, 'user_email', '') if gui.email_sender else ''
    set_active_provider(gui, "O365", user_email)

    # Save recipients to config for persistence
    try:
        from modules.ConfigManager import ConfigManager
        config = ConfigManager()
        recipients = gui.email_recipients_var.get().strip()
        if recipients:
            config.set('O365Email', 'default_recipients', recipients)
    except Exception as e:
        print(f"Could not save O365 recipients to config: {e}")

    if show_message:
        messagebox.showinfo("Success", "O365 Email connected and set as ACTIVE provider!")


def on_email_failed(gui):
    """Called when email connection fails"""
    gui.email_status_label.configure(text="Email Status: Failed", text_color=COLORS['danger'])
    gui.connect_email_btn.configure(state='normal')


def on_email_error(gui, error):
    """Called when email connection has an error"""
    gui.email_status_label.configure(text=f"Email Status: Error", text_color=COLORS['danger'])
    gui.connect_email_btn.configure(state='normal')
    messagebox.showerror("Email Error", f"Failed to connect: {error}")


def connect_gmail(gui):
    """Connect to Gmail using OAuth2 with popup authentication dialog"""
    try:
        from modules.GmailEmailSender import GmailEmailSender
        import webbrowser
        import http.server
        import urllib.parse
        import secrets
        import hashlib
        import base64
        import json

        client_id = gui.gmail_client_id_var.get().strip()
        client_secret = gui.gmail_client_secret_var.get().strip()
        redirect_uri = gui.gmail_redirect_uri_var.get().strip()

        if not client_id:
            messagebox.showerror("Error", "Please enter the Gmail Client ID")
            return

        if not client_secret:
            messagebox.showerror("Error", "Please enter the Gmail Client Secret")
            return

        # Create email sender instance
        email_sender = GmailEmailSender(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri)

        # Check for existing valid token
        if email_sender.is_authenticated():
            gui.email_sender = email_sender
            on_gmail_connected(gui, email_sender.user_email, show_message=True)
            return

        # Set up OAuth state
        gmail_auth_state = {
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
            'scope': 'https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/userinfo.email openid',
            'auth_url': 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_url': 'https://oauth2.googleapis.com/token',
            'state': secrets.token_urlsafe(32),
            'code_verifier': secrets.token_urlsafe(64),
            'cancelled': False,
            'server': None
        }

        # Generate code challenge for PKCE
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(gmail_auth_state['code_verifier'].encode()).digest()
        ).decode().rstrip('=')

        # Create auth dialog
        auth_dialog = ctk.CTkToplevel(gui.root)
        auth_dialog.title("Gmail Authentication")
        auth_dialog.geometry("500x300")
        auth_dialog.transient(gui.root)
        auth_dialog.grab_set()

        # Center dialog
        auth_dialog.update_idletasks()
        x = gui.root.winfo_x() + (gui.root.winfo_width() - 500) // 2
        y = gui.root.winfo_y() + (gui.root.winfo_height() - 300) // 2
        auth_dialog.geometry(f"+{x}+{y}")

        # Dialog content
        ctk.CTkLabel(auth_dialog, text="Gmail OAuth2 Authentication", font=("Helvetica", 18, "bold"),
                     text_color=COLORS['accent']).pack(pady=20)

        status_label = ctk.CTkLabel(auth_dialog, text="Opening browser for Google sign-in...",
                                     text_color=COLORS['text_primary'])
        status_label.pack(pady=10)

        info_label = ctk.CTkLabel(auth_dialog, text="Please sign in with your Google account in the browser window.",
                                   text_color=COLORS['text_secondary'], wraplength=400)
        info_label.pack(pady=10)

        def cancel_auth():
            gmail_auth_state['cancelled'] = True
            if gmail_auth_state['server']:
                try:
                    gmail_auth_state['server'].shutdown()
                except (OSError, Exception):
                    pass
            auth_dialog.destroy()
            gui.connect_email_btn.configure(state='normal')

        ctk.CTkButton(auth_dialog, text="Cancel", command=cancel_auth,
                      fg_color=COLORS['danger'], hover_color='#cc3333').pack(pady=20)

        def on_dialog_close():
            cancel_auth()

        auth_dialog.protocol("WM_DELETE_WINDOW", on_dialog_close)

        # Extract port from redirect URI
        redirect_port = int(urllib.parse.urlparse(redirect_uri).port or 8089)

        def start_gmail_oauth():
            try:
                params = {
                    'client_id': client_id,
                    'redirect_uri': redirect_uri,
                    'response_type': 'code',
                    'scope': gmail_auth_state['scope'],
                    'state': gmail_auth_state['state'],
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256',
                    'access_type': 'offline',
                    'prompt': 'consent'
                }

                auth_request_url = f"{gmail_auth_state['auth_url']}?{urllib.parse.urlencode(params)}"

                # Start local server
                threading.Thread(target=run_gmail_callback_server, args=(redirect_port,), daemon=True).start()

                # Open browser
                webbrowser.open(auth_request_url)

            except Exception as e:
                gui.root.after(0, lambda: show_gmail_error(str(e)))

        def run_gmail_callback_server(port):
            class GmailOAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    parsed = urllib.parse.urlparse(self.path)
                    if parsed.path == '/callback':
                        query = urllib.parse.parse_qs(parsed.query)

                        if 'code' in query and 'state' in query:
                            code = query['code'][0]
                            state = query['state'][0]

                            if state == gmail_auth_state['state']:
                                self.send_response(200)
                                self.send_header('Content-type', 'text/html')
                                self.end_headers()
                                success_html = """
                                <html><head><style>
                                body { font-family: 'Segoe UI', Arial; text-align: center; padding: 50px; background: #0a0a1a; color: #fff; }
                                .success { color: #00ff88; font-size: 28px; margin-bottom: 20px; }
                                </style></head><body>
                                <h1 class="success">Gmail Authentication Successful!</h1>
                                <p style="color: #aaa;">You can close this window and return to SOC Defense System.</p>
                                <script>setTimeout(function(){ window.close(); }, 2000);</script>
                                </body></html>
                                """
                                self.wfile.write(success_html.encode())
                                gui.root.after(100, lambda: exchange_gmail_token(code))
                            else:
                                self.send_error(400, "Invalid state parameter")
                        elif 'error' in query:
                            self.send_response(200)
                            self.send_header('Content-type', 'text/html')
                            self.end_headers()
                            error_desc = query.get('error_description', query.get('error', ['Unknown error']))[0]
                            error_html = f"""
                            <html><body style="font-family: 'Segoe UI', Arial; text-align: center; padding: 50px; background: #0a0a1a; color: #fff;">
                            <h1 style="color: #ff4444;">Authentication Failed</h1>
                            <p style="color: #aaa;">Error: {error_desc}</p>
                            </body></html>
                            """
                            self.wfile.write(error_html.encode())
                            gui.root.after(100, lambda: show_gmail_error(error_desc))
                    else:
                        self.send_error(404)

                def log_message(self, format, *args):
                    pass

            server = None
            try:
                server = http.server.HTTPServer(('localhost', port), GmailOAuthCallbackHandler)
                gmail_auth_state['server'] = server
                server.timeout = 120
                server.handle_request()
            except Exception as e:
                if not gmail_auth_state['cancelled']:
                    gui.root.after(100, lambda: show_gmail_error(f"Server error: {str(e)}"))
            finally:
                # Ensure server socket is properly closed
                if server:
                    try:
                        server.server_close()
                    except Exception:
                        pass

        def exchange_gmail_token(code):
            try:
                import urllib.request

                data = {
                    'client_id': gmail_auth_state['client_id'],
                    'client_secret': gmail_auth_state['client_secret'],
                    'code': code,
                    'redirect_uri': gmail_auth_state['redirect_uri'],
                    'grant_type': 'authorization_code',
                    'code_verifier': gmail_auth_state['code_verifier']
                }

                req = urllib.request.Request(
                    gmail_auth_state['token_url'],
                    data=urllib.parse.urlencode(data).encode(),
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )

                with urllib.request.urlopen(req, timeout=30) as response:
                    token_data = json.loads(response.read().decode())

                access_token = token_data.get('access_token')
                refresh_token = token_data.get('refresh_token', '')

                if not access_token:
                    raise Exception("No access token received")

                # Get user email from ID token or userinfo
                id_token = token_data.get('id_token', '')
                user_email = get_gmail_email_from_token(id_token, access_token)

                # Store tokens in email_sender
                email_sender.access_token = access_token
                email_sender.refresh_token = refresh_token
                email_sender.user_email = user_email
                email_sender._save_token_cache()

                gui.email_sender = email_sender
                auth_dialog.destroy()
                on_gmail_connected(gui, user_email, show_message=True)

            except Exception as e:
                show_gmail_error(str(e))

        def get_gmail_email_from_token(id_token, access_token):
            try:
                if id_token:
                    parts = id_token.split('.')
                    if len(parts) >= 2:
                        payload = parts[1]
                        payload += '=' * (4 - len(payload) % 4)
                        claims = json.loads(base64.urlsafe_b64decode(payload))
                        email = claims.get('email')
                        if email:
                            return email
                # Fallback: get from userinfo endpoint
                import urllib.request
                req = urllib.request.Request(
                    'https://www.googleapis.com/oauth2/v2/userinfo',
                    headers={'Authorization': f'Bearer {access_token}'}
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    userinfo = json.loads(response.read().decode())
                    return userinfo.get('email', 'Unknown')
            except (urllib.error.URLError, json.JSONDecodeError, Exception):
                return 'Unknown'

        def show_gmail_error(error):
            status_label.configure(text=f"Error: {error}", text_color=COLORS['danger'])
            info_label.configure(text="Please check your credentials and try again.")
            gui.connect_email_btn.configure(state='normal')

        # Start OAuth flow
        threading.Thread(target=start_gmail_oauth, daemon=True).start()

    except Exception as e:
        messagebox.showerror("Error", f"Connection error: {str(e)}")
        gui.connect_email_btn.configure(state='normal')


def on_gmail_connected(gui, email, show_message=True):
    """Called when Gmail is successfully connected"""
    gui.email_status_label.configure(text=f"Connection Status: Gmail Connected", text_color=COLORS['success'])
    gui.connect_email_btn.configure(state='normal', text="Reconnect")
    gui.test_email_btn.configure(state='normal')

    # Set as active provider
    set_active_provider(gui, "Gmail", email)

    # Save recipients to config for persistence
    try:
        from modules.ConfigManager import ConfigManager
        config = ConfigManager()
        recipients = gui.email_recipients_var.get().strip()
        if recipients:
            config.set('GmailEmail', 'default_recipients', recipients)
    except Exception as e:
        print(f"Could not save Gmail settings to config: {e}")

    if show_message:
        messagebox.showinfo("Success", f"Gmail connected and set as ACTIVE provider!\n\nAuthenticated as: {email}")


def on_gmail_failed(gui, error):
    """Called when Gmail connection fails"""
    gui.email_status_label.configure(text="Email Status: Failed", text_color=COLORS['danger'])
    gui.connect_email_btn.configure(state='normal')
    messagebox.showerror("Gmail Error", f"Failed to connect:\n{error}")


def send_test_email(gui):
    """Send a test email"""
    recipients = gui.email_recipients_var.get()
    if not recipients:
        messagebox.showwarning("Warning", "Please enter at least one email recipient")
        return

    recipient_list = [r.strip() for r in recipients.split(',') if r.strip()]

    # Cache email_sender reference to avoid thread safety issues
    email_sender = gui.email_sender
    if not email_sender:
        messagebox.showerror("Error", "Email not connected. Please connect first.")
        return

    # Determine provider name for message
    provider_name = gui.email_provider_var.get() if hasattr(gui, 'email_provider_var') else "Email"

    def do_send():
        def safe_gui_callback(callback):
            """Safely execute a GUI callback, checking if root still exists"""
            try:
                if gui.root and gui.root.winfo_exists():
                    gui.root.after(0, callback)
            except Exception:
                pass  # GUI was destroyed, ignore

        try:
            test_html = f"""
            <html>
            <body style="font-family: Arial; background: #1a1a2e; color: #fff; padding: 20px;">
                <h1 style="color: #00d4ff;">SOC Defense System - Test Email</h1>
                <p>This is a test email from your SOC Defense System.</p>
                <p>If you receive this email, your {provider_name} email integration is working correctly.</p>
                <hr style="border-color: #333;">
                <p style="color: #888; font-size: 12px;">Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </body>
            </html>
            """

            success = email_sender.send_email(
                to_recipients=recipient_list,
                subject="[SOC Defense] Test Email",
                body_html=test_html
            )

            if success:
                safe_gui_callback(lambda: messagebox.showinfo("Success", "Test email sent successfully!"))
            else:
                safe_gui_callback(lambda: messagebox.showerror("Error", "Failed to send test email"))

        except Exception as e:
            safe_gui_callback(lambda: messagebox.showerror("Error", f"Failed to send: {str(e)}"))

    threading.Thread(target=do_send, daemon=True).start()


def start_scheduler(gui):
    """Start the scheduled scan manager"""
    if gui.scheduler_manager:
        gui.scheduler_manager.start_scheduler()
        gui.start_scheduler_btn.configure(state='disabled')
        gui.stop_scheduler_btn.configure(state='normal')
        gui.scheduler_status_label.configure(text="Scheduler: Running", text_color=COLORS['success'])
        update_next_scans_display(gui)


def stop_scheduler(gui):
    """Stop the scheduled scan manager"""
    if gui.scheduler_manager:
        gui.scheduler_manager.stop_scheduler()
        gui.start_scheduler_btn.configure(state='normal')
        gui.stop_scheduler_btn.configure(state='disabled')
        gui.scheduler_status_label.configure(text="Scheduler: Stopped", text_color=COLORS['danger'])


def update_scheduler_status(gui, message):
    """Update scheduler status display"""
    gui.root.after(0, lambda: gui.update_status(f"Scheduler: {message}"))


def on_scheduled_scan_start(gui, schedule):
    """Called when a scheduled scan starts"""
    gui.root.after(0, lambda: gui.update_status(f"Starting scheduled scan: {schedule.name}"))


def on_scheduled_scan_complete(gui, schedule, result):
    """Called when a scheduled scan completes"""
    gui.root.after(0, lambda: gui.update_status(f"Completed scheduled scan: {schedule.name}"))
    gui.root.after(0, lambda: refresh_schedules_list(gui))


def on_scheduled_scan_error(gui, schedule, error):
    """Called when a scheduled scan has an error"""
    gui.root.after(0, lambda: gui.update_status(f"Error in {schedule.name}: {error}"))


def update_next_scans_display(gui):
    """Update the next scheduled scans display"""
    if gui.scheduler_manager:
        next_scans = gui.scheduler_manager.get_next_scheduled_scans(limit=3)
        if next_scans:
            text = "Next: " + " | ".join([f"{s['name']} in {s['time_until_human']}" for s in next_scans])
        else:
            text = "No upcoming scheduled scans"
        gui.next_scans_label.configure(text=text)


def refresh_schedules_list(gui):
    """Refresh the schedules list display"""
    # Clear existing items - collect first to avoid modifying during iteration
    widgets_to_destroy = list(gui.schedules_list_frame.winfo_children())
    for widget in widgets_to_destroy:
        try:
            widget.destroy()
        except Exception:
            pass  # Widget may already be destroyed

    if not gui.scheduler_manager:
        ctk.CTkLabel(
            gui.schedules_list_frame,
            text="Scheduler not initialized",
            text_color=COLORS['text_secondary']
        ).pack(pady=20)
        return

    schedules = gui.scheduler_manager.get_all_schedules()

    if not schedules:
        ctk.CTkLabel(
            gui.schedules_list_frame,
            text="No scheduled scans configured.\nClick '+ Add Schedule' to create one.",
            text_color=COLORS['text_secondary']
        ).pack(pady=20)
        return

    for schedule in schedules:
        create_schedule_card(gui, schedule)

    update_next_scans_display(gui)


def create_schedule_card(gui, schedule):
    """Create a card for a scheduled scan"""
    card = ctk.CTkFrame(gui.schedules_list_frame, fg_color=COLORS['bg_tertiary'], corner_radius=8)
    card.pack(fill='x', pady=5, padx=5)

    # Header row
    header = ctk.CTkFrame(card, fg_color='transparent')
    header.pack(fill='x', padx=15, pady=(15, 5))

    # Status indicator
    status_color = COLORS['success'] if schedule.enabled else COLORS['text_secondary']
    status_text = "Enabled" if schedule.enabled else "Disabled"

    ctk.CTkLabel(
        header,
        text=schedule.name,
        font=("Helvetica", 14, "bold"),
        text_color=COLORS['text_primary']
    ).pack(side='left')

    status_label = ctk.CTkLabel(
        header,
        text=status_text,
        text_color=status_color,
        font=("Helvetica", 10)
    )
    status_label.pack(side='right')

    # Details row
    details = ctk.CTkFrame(card, fg_color='transparent')
    details.pack(fill='x', padx=15, pady=5)

    freq_map = {
        '15min': 'Every 15 minutes',
        '30min': 'Every 30 minutes',
        'hourly': 'Hourly',
        '2hours': 'Every 2 hours',
        '4hours': 'Every 4 hours',
        '6hours': 'Every 6 hours',
        '12hours': 'Every 12 hours',
        'daily': 'Daily',
        'weekly': 'Weekly'
    }
    freq_text = freq_map.get(schedule.frequency, schedule.frequency)

    ctk.CTkLabel(
        details,
        text=f"Frequency: {freq_text} | Time Range: Last {schedule.time_range_hours}h | Min Severity: {schedule.min_severity}",
        text_color=COLORS['text_secondary'],
        font=("Helvetica", 11)
    ).pack(side='left')

    # Next run
    if schedule.next_run:
        next_run = datetime.fromisoformat(schedule.next_run)
        time_until = (next_run - datetime.now()).total_seconds()
        time_str = gui.scheduler_manager._format_time_delta(time_until) if gui.scheduler_manager else "?"
        next_text = f"Next: {time_str}"
    else:
        next_text = "Next: Not scheduled"

    ctk.CTkLabel(
        details,
        text=next_text,
        text_color=COLORS['accent'],
        font=("Helvetica", 11)
    ).pack(side='right')

    # Email info row
    if schedule.email_report:
        email_row = ctk.CTkFrame(card, fg_color='transparent')
        email_row.pack(fill='x', padx=15, pady=5)

        recipients_text = ', '.join(schedule.email_recipients[:2])
        if len(schedule.email_recipients) > 2:
            recipients_text += f" +{len(schedule.email_recipients) - 2} more"

        ctk.CTkLabel(
            email_row,
            text=f"Email: {recipients_text}" if recipients_text else "Email: No recipients",
            text_color=COLORS['text_secondary'],
            font=("Helvetica", 10)
        ).pack(side='left')

    # Stats row
    stats = ctk.CTkFrame(card, fg_color='transparent')
    stats.pack(fill='x', padx=15, pady=5)

    last_run_text = "Never" if not schedule.last_run else datetime.fromisoformat(schedule.last_run).strftime('%Y-%m-%d %H:%M')
    status_color = COLORS['success'] if schedule.last_status == 'completed' else COLORS['danger'] if schedule.last_status == 'failed' else COLORS['text_secondary']

    ctk.CTkLabel(
        stats,
        text=f"Last Run: {last_run_text} | Status: {schedule.last_status} | Runs: {schedule.run_count}",
        text_color=status_color,
        font=("Helvetica", 10)
    ).pack(side='left')

    # Action buttons
    actions = ctk.CTkFrame(card, fg_color='transparent')
    actions.pack(fill='x', padx=15, pady=(5, 15))

    ctk.CTkButton(
        actions,
        text="Run Now",
        command=lambda s=schedule: run_schedule_now(gui, s),
        fg_color=COLORS['accent'],
        hover_color=COLORS['accent_hover'],
        width=80,
        height=28
    ).pack(side='left', padx=2)

    toggle_text = "Disable" if schedule.enabled else "Enable"
    toggle_color = COLORS['warning'] if schedule.enabled else COLORS['success']
    ctk.CTkButton(
        actions,
        text=toggle_text,
        command=lambda s=schedule: toggle_schedule(gui, s),
        fg_color=toggle_color,
        width=80,
        height=28
    ).pack(side='left', padx=2)

    ctk.CTkButton(
        actions,
        text="Edit",
        command=lambda s=schedule: show_edit_schedule_dialog(gui, s),
        fg_color=COLORS['bg_secondary'],
        width=60,
        height=28
    ).pack(side='left', padx=2)

    ctk.CTkButton(
        actions,
        text="Delete",
        command=lambda s=schedule: delete_schedule(gui, s),
        fg_color=COLORS['danger'],
        hover_color='#cc3333',
        width=60,
        height=28
    ).pack(side='left', padx=2)


def run_schedule_now(gui, schedule):
    """Run a scheduled scan immediately"""
    if gui.scheduler_manager:
        gui.scheduler_manager.run_scan_now(schedule.id)
        gui.update_status(f"Running {schedule.name} now...")


def toggle_schedule(gui, schedule):
    """Toggle a schedule's enabled state"""
    if gui.scheduler_manager:
        if schedule.enabled:
            gui.scheduler_manager.disable_schedule(schedule.id)
        else:
            gui.scheduler_manager.enable_schedule(schedule.id)
        refresh_schedules_list(gui)


def delete_schedule(gui, schedule):
    """Delete a scheduled scan"""
    if messagebox.askyesno("Confirm Delete", f"Delete schedule '{schedule.name}'?"):
        if gui.scheduler_manager:
            gui.scheduler_manager.remove_schedule(schedule.id)
            refresh_schedules_list(gui)


def show_add_schedule_dialog(gui):
    """Show dialog to add a new scheduled scan"""
    dialog = ctk.CTkToplevel(gui.root)
    dialog.title("Add Scheduled Scan")
    dialog.geometry("550x950")
    dialog.transient(gui.root)
    dialog.grab_set()

    # Center on screen
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() - 550) // 2
    y = (dialog.winfo_screenheight() - 950) // 2
    dialog.geometry(f"+{x}+{y}")

    dialog.configure(fg_color=COLORS['bg_secondary'])

    # Title
    ctk.CTkLabel(
        dialog,
        text="Add Scheduled Scan",
        font=("Helvetica", 18, "bold"),
        text_color=COLORS['accent']
    ).pack(pady=20)

    # Form container (scrollable for many options)
    form = ctk.CTkScrollableFrame(dialog, fg_color=COLORS['bg_tertiary'])
    form.pack(fill='both', expand=True, padx=20, pady=(0, 10))

    # Name
    ctk.CTkLabel(form, text="Schedule Name:", anchor='w').pack(fill='x', padx=20, pady=(20, 5))
    name_var = ctk.StringVar(value="Hourly Security Scan")
    ctk.CTkEntry(form, textvariable=name_var, width=400).pack(padx=20)

    # Frequency
    ctk.CTkLabel(form, text="Frequency:", anchor='w').pack(fill='x', padx=20, pady=(15, 5))
    freq_var = ctk.StringVar(value="hourly")
    freq_menu = ctk.CTkOptionMenu(
        form,
        variable=freq_var,
        values=["15min", "30min", "hourly", "2hours", "4hours", "6hours", "12hours", "daily", "weekly"],
        width=400
    )
    freq_menu.pack(padx=20)

    # Time range
    ctk.CTkLabel(form, text="Time Range (hours to scan back):", anchor='w').pack(fill='x', padx=20, pady=(15, 5))
    range_var = ctk.StringVar(value="24")
    ctk.CTkEntry(form, textvariable=range_var, width=400).pack(padx=20)

    # Min severity
    ctk.CTkLabel(form, text="Minimum Severity Level:", anchor='w').pack(fill='x', padx=20, pady=(15, 5))
    severity_var = ctk.StringVar(value="10")
    ctk.CTkEntry(form, textvariable=severity_var, width=400).pack(padx=20)

    # Email options
    email_enabled_var = ctk.BooleanVar(value=True)
    ctk.CTkCheckBox(
        form,
        text="Send Email Report",
        variable=email_enabled_var
    ).pack(padx=20, pady=(15, 5), anchor='w')

    ctk.CTkLabel(form, text="Email Recipients (comma-separated):", anchor='w').pack(fill='x', padx=20, pady=(10, 5))
    recipients_var = ctk.StringVar(value=gui.email_recipients_var.get())
    ctk.CTkEntry(form, textvariable=recipients_var, width=400).pack(padx=20)

    # Email Trigger Options Section
    ctk.CTkLabel(
        form,
        text="Email Trigger Options:",
        anchor='w',
        font=ctk.CTkFont(size=13, weight="bold")
    ).pack(fill='x', padx=20, pady=(15, 5))

    trigger_frame = ctk.CTkFrame(form, fg_color='transparent')
    trigger_frame.pack(fill='x', padx=20, pady=5)

    send_on_complete_var = ctk.BooleanVar(value=True)
    ctk.CTkCheckBox(
        trigger_frame,
        text="Send alert when scan completes",
        variable=send_on_complete_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    send_on_exploit_var = ctk.BooleanVar(value=True)
    ctk.CTkCheckBox(
        trigger_frame,
        text="Send alert on successful exploit detected",
        variable=send_on_exploit_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    send_on_critical_cve_var = ctk.BooleanVar(value=True)
    ctk.CTkCheckBox(
        trigger_frame,
        text="Send alert when CRITICAL CVE found",
        variable=send_on_critical_cve_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    send_on_new_attacker_var = ctk.BooleanVar(value=True)
    ctk.CTkCheckBox(
        trigger_frame,
        text="Send alert when new attacker IP detected",
        variable=send_on_new_attacker_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    # Scheduled time for daily/weekly
    ctk.CTkLabel(form, text="Scheduled Time (for daily/weekly):", anchor='w').pack(fill='x', padx=20, pady=(15, 5))
    time_var = ctk.StringVar(value="08:00")
    ctk.CTkEntry(form, textvariable=time_var, width=400, placeholder_text="HH:MM (24h format)").pack(padx=20)

    # IP Filtering Section
    ctk.CTkLabel(
        form,
        text="IP Address Filtering:",
        anchor='w',
        font=ctk.CTkFont(size=13, weight="bold")
    ).pack(fill='x', padx=20, pady=(20, 5))

    # Filter frame for checkboxes
    filter_frame = ctk.CTkFrame(form, fg_color='transparent')
    filter_frame.pack(fill='x', padx=20, pady=5)

    include_public_var = ctk.BooleanVar(value=True)
    ctk.CTkCheckBox(
        filter_frame,
        text="Include Public IPs (External/Internet)",
        variable=include_public_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    include_private_var = ctk.BooleanVar(value=True)
    ctk.CTkCheckBox(
        filter_frame,
        text="Include Private IPs (Internal/RFC1918)",
        variable=include_private_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    # Note about invalid IPs
    ctk.CTkLabel(
        form,
        text="Note: Invalid IPs (0.0.0.0, 127.0.0.1, etc.) are always excluded",
        anchor='w',
        font=ctk.CTkFont(size=11),
        text_color=COLORS['text_secondary']
    ).pack(fill='x', padx=20, pady=(5, 10))

    # Buttons
    btn_frame = ctk.CTkFrame(dialog, fg_color='transparent')
    btn_frame.pack(pady=20)

    def save_schedule():
        try:
            from modules.ScheduledScanManager import ScheduledScan

            recipients = [r.strip() for r in recipients_var.get().split(',') if r.strip()]

            schedule = ScheduledScan(
                id=str(uuid.uuid4()),
                name=name_var.get(),
                enabled=True,
                frequency=freq_var.get(),
                time_range_hours=int(range_var.get()),
                min_severity=int(severity_var.get()),
                email_report=email_enabled_var.get(),
                email_recipients=recipients,
                scheduled_time=time_var.get(),
                include_public_ips=include_public_var.get(),
                include_private_ips=include_private_var.get(),
                send_on_complete=send_on_complete_var.get(),
                send_on_exploit=send_on_exploit_var.get(),
                send_on_critical_cve=send_on_critical_cve_var.get(),
                send_on_new_attacker=send_on_new_attacker_var.get()
            )

            if gui.scheduler_manager:
                gui.scheduler_manager.add_schedule(schedule)
                refresh_schedules_list(gui)
                dialog.destroy()
                messagebox.showinfo("Success", f"Schedule '{schedule.name}' created!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create schedule: {str(e)}")

    ctk.CTkButton(
        btn_frame,
        text="Save Schedule",
        command=save_schedule,
        fg_color=COLORS['success'],
        hover_color='#00cc66',
        width=150
    ).pack(side='left', padx=10)

    ctk.CTkButton(
        btn_frame,
        text="Cancel",
        command=dialog.destroy,
        fg_color=COLORS['danger'],
        hover_color='#cc3333',
        width=100
    ).pack(side='left', padx=10)


def show_edit_schedule_dialog(gui, schedule):
    """Show dialog to edit an existing scheduled scan"""
    dialog = ctk.CTkToplevel(gui.root)
    dialog.title("Edit Scheduled Scan")
    dialog.geometry("550x950")
    dialog.transient(gui.root)
    dialog.grab_set()

    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() - 550) // 2
    y = (dialog.winfo_screenheight() - 950) // 2
    dialog.geometry(f"+{x}+{y}")

    dialog.configure(fg_color=COLORS['bg_secondary'])

    ctk.CTkLabel(
        dialog,
        text="Edit Scheduled Scan",
        font=("Helvetica", 18, "bold"),
        text_color=COLORS['accent']
    ).pack(pady=20)

    # Use scrollable frame for form
    form = ctk.CTkScrollableFrame(dialog, fg_color=COLORS['bg_tertiary'])
    form.pack(fill='both', expand=True, padx=20, pady=(0, 10))

    # Pre-populate with existing values
    ctk.CTkLabel(form, text="Schedule Name:", anchor='w').pack(fill='x', padx=20, pady=(20, 5))
    name_var = ctk.StringVar(value=schedule.name)
    ctk.CTkEntry(form, textvariable=name_var, width=400).pack(padx=20)

    ctk.CTkLabel(form, text="Frequency:", anchor='w').pack(fill='x', padx=20, pady=(15, 5))
    freq_var = ctk.StringVar(value=schedule.frequency)
    ctk.CTkOptionMenu(
        form,
        variable=freq_var,
        values=["15min", "30min", "hourly", "2hours", "4hours", "6hours", "12hours", "daily", "weekly"],
        width=400
    ).pack(padx=20)

    ctk.CTkLabel(form, text="Time Range (hours):", anchor='w').pack(fill='x', padx=20, pady=(15, 5))
    range_var = ctk.StringVar(value=str(schedule.time_range_hours))
    ctk.CTkEntry(form, textvariable=range_var, width=400).pack(padx=20)

    ctk.CTkLabel(form, text="Minimum Severity:", anchor='w').pack(fill='x', padx=20, pady=(15, 5))
    severity_var = ctk.StringVar(value=str(schedule.min_severity))
    ctk.CTkEntry(form, textvariable=severity_var, width=400).pack(padx=20)

    email_enabled_var = ctk.BooleanVar(value=schedule.email_report)
    ctk.CTkCheckBox(form, text="Send Email Report", variable=email_enabled_var).pack(padx=20, pady=(15, 5), anchor='w')

    ctk.CTkLabel(form, text="Email Recipients:", anchor='w').pack(fill='x', padx=20, pady=(10, 5))
    recipients_var = ctk.StringVar(value=', '.join(schedule.email_recipients))
    ctk.CTkEntry(form, textvariable=recipients_var, width=400).pack(padx=20)

    # Email Trigger Options Section
    ctk.CTkLabel(
        form,
        text="Email Trigger Options:",
        anchor='w',
        font=ctk.CTkFont(size=13, weight="bold")
    ).pack(fill='x', padx=20, pady=(15, 5))

    trigger_frame = ctk.CTkFrame(form, fg_color='transparent')
    trigger_frame.pack(fill='x', padx=20, pady=5)

    send_on_complete_var = ctk.BooleanVar(value=getattr(schedule, 'send_on_complete', True))
    ctk.CTkCheckBox(
        trigger_frame,
        text="Send alert when scan completes",
        variable=send_on_complete_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    send_on_exploit_var = ctk.BooleanVar(value=getattr(schedule, 'send_on_exploit', True))
    ctk.CTkCheckBox(
        trigger_frame,
        text="Send alert on successful exploit detected",
        variable=send_on_exploit_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    send_on_critical_cve_var = ctk.BooleanVar(value=getattr(schedule, 'send_on_critical_cve', True))
    ctk.CTkCheckBox(
        trigger_frame,
        text="Send alert when CRITICAL CVE found",
        variable=send_on_critical_cve_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    send_on_new_attacker_var = ctk.BooleanVar(value=getattr(schedule, 'send_on_new_attacker', True))
    ctk.CTkCheckBox(
        trigger_frame,
        text="Send alert when new attacker IP detected",
        variable=send_on_new_attacker_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    ctk.CTkLabel(form, text="Scheduled Time:", anchor='w').pack(fill='x', padx=20, pady=(15, 5))
    time_var = ctk.StringVar(value=schedule.scheduled_time)
    ctk.CTkEntry(form, textvariable=time_var, width=400).pack(padx=20)

    # IP Filtering Section
    ctk.CTkLabel(
        form,
        text="IP Address Filtering:",
        anchor='w',
        font=ctk.CTkFont(size=13, weight="bold")
    ).pack(fill='x', padx=20, pady=(20, 5))

    filter_frame = ctk.CTkFrame(form, fg_color='transparent')
    filter_frame.pack(fill='x', padx=20, pady=5)

    include_public_var = ctk.BooleanVar(value=getattr(schedule, 'include_public_ips', True))
    ctk.CTkCheckBox(
        filter_frame,
        text="Include Public IPs (External/Internet)",
        variable=include_public_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    include_private_var = ctk.BooleanVar(value=getattr(schedule, 'include_private_ips', True))
    ctk.CTkCheckBox(
        filter_frame,
        text="Include Private IPs (Internal/RFC1918)",
        variable=include_private_var,
        text_color=COLORS['text_primary']
    ).pack(anchor='w', pady=2)

    ctk.CTkLabel(
        form,
        text="Note: Invalid IPs (0.0.0.0, 127.0.0.1, etc.) are always excluded",
        anchor='w',
        font=ctk.CTkFont(size=11),
        text_color=COLORS['text_secondary']
    ).pack(fill='x', padx=20, pady=(5, 10))

    btn_frame = ctk.CTkFrame(dialog, fg_color='transparent')
    btn_frame.pack(pady=20)

    def update_schedule():
        try:
            recipients = [r.strip() for r in recipients_var.get().split(',') if r.strip()]

            schedule.name = name_var.get()
            schedule.frequency = freq_var.get()
            schedule.time_range_hours = int(range_var.get())
            schedule.min_severity = int(severity_var.get())
            schedule.email_report = email_enabled_var.get()
            schedule.email_recipients = recipients
            schedule.scheduled_time = time_var.get()
            schedule.include_public_ips = include_public_var.get()
            schedule.include_private_ips = include_private_var.get()
            schedule.send_on_complete = send_on_complete_var.get()
            schedule.send_on_exploit = send_on_exploit_var.get()
            schedule.send_on_critical_cve = send_on_critical_cve_var.get()
            schedule.send_on_new_attacker = send_on_new_attacker_var.get()

            if gui.scheduler_manager:
                gui.scheduler_manager.update_schedule(schedule)
                refresh_schedules_list(gui)
                dialog.destroy()
                messagebox.showinfo("Success", "Schedule updated!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to update: {str(e)}")

    ctk.CTkButton(btn_frame, text="Save Changes", command=update_schedule, fg_color=COLORS['success'], width=150).pack(side='left', padx=10)
    ctk.CTkButton(btn_frame, text="Cancel", command=dialog.destroy, fg_color=COLORS['danger'], width=100).pack(side='left', padx=10)
