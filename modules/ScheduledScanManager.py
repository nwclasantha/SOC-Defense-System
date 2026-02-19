"""
Scheduled Scan Manager for SOC Defense System
Handles continuous monitoring with scheduled scans and automated reporting
"""

import os
import json
import logging
import threading
import asyncio
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
import time


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private (RFC 1918) or reserved"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except (ValueError, TypeError):
        return False


def is_valid_reportable_ip(ip_str: str) -> bool:
    """Check if an IP address is valid and should be included in reports.
    Excludes invalid IPs like 0.0.0.0, 255.255.255.255, empty strings, etc.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False

    # Exclude common invalid/placeholder IPs
    invalid_ips = {
        '0.0.0.0', '255.255.255.255', '127.0.0.1', '::1',
        'localhost', 'unknown', 'none', 'null', '-', ''
    }
    if ip_str.lower().strip() in invalid_ips:
        return False

    try:
        ip = ipaddress.ip_address(ip_str)
        # Exclude unspecified addresses (0.0.0.0, ::)
        if ip.is_unspecified:
            return False
        # Exclude loopback (127.x.x.x, ::1)
        if ip.is_loopback:
            return False
        # Exclude multicast addresses
        if ip.is_multicast:
            return False
        return True
    except (ValueError, TypeError):
        return False


def filter_attackers_by_ip_type(attackers: List, include_public: bool = True, include_private: bool = True) -> List:
    """Filter attackers based on IP type (public/private) and exclude invalid IPs"""
    filtered = []

    for attacker in attackers:
        ip = getattr(attacker, 'ip_address', '')

        # Always exclude invalid IPs
        if not is_valid_reportable_ip(ip):
            continue

        is_private = is_private_ip(ip)

        # Apply public/private filtering
        if include_public and include_private:
            filtered.append(attacker)
        elif include_private and is_private:
            filtered.append(attacker)
        elif include_public and not is_private:
            filtered.append(attacker)

    return filtered


class ScheduleFrequency(Enum):
    """Scan schedule frequency options"""
    EVERY_15_MINUTES = "15min"
    EVERY_30_MINUTES = "30min"
    HOURLY = "hourly"
    EVERY_2_HOURS = "2hours"
    EVERY_4_HOURS = "4hours"
    EVERY_6_HOURS = "6hours"
    EVERY_12_HOURS = "12hours"
    DAILY = "daily"
    WEEKLY = "weekly"
    CUSTOM = "custom"


@dataclass
class ScheduledScan:
    """Represents a scheduled scan configuration"""
    id: str
    name: str
    enabled: bool = True
    frequency: str = "hourly"
    custom_interval_minutes: int = 60
    time_range_hours: int = 24  # How far back to scan
    min_severity: int = 10
    email_report: bool = True
    email_recipients: List[str] = field(default_factory=list)
    email_on_critical_only: bool = False
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    run_count: int = 0
    last_status: str = "never_run"
    last_error: Optional[str] = None
    last_findings_hash: Optional[str] = None  # For duplicate detection
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    # Days of week for weekly schedule (0=Monday, 6=Sunday)
    weekly_days: List[int] = field(default_factory=lambda: [0, 1, 2, 3, 4])  # Mon-Fri by default
    # Time of day for daily/weekly schedules (24h format)
    scheduled_time: str = "08:00"

    # IP Filtering options
    include_public_ips: bool = True   # Include external/internet IPs
    include_private_ips: bool = True  # Include internal/RFC1918 IPs

    # Email Trigger options - control when emails are sent
    send_on_complete: bool = True       # Send alert when scan completes
    send_on_exploit: bool = True        # Send alert on successful exploit detected
    send_on_critical_cve: bool = True   # Send alert when CRITICAL CVE found
    send_on_new_attacker: bool = True   # Send alert when new attacker IP detected

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'ScheduledScan':
        """Create from dictionary with validation"""
        # Get valid field names from the dataclass
        import dataclasses
        valid_fields = {f.name for f in dataclasses.fields(cls)}

        # Filter out any extra fields that aren't part of the dataclass
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}

        # Ensure required fields exist
        if 'id' not in filtered_data or 'name' not in filtered_data:
            raise ValueError("ScheduledScan requires 'id' and 'name' fields")

        # Validate frequency if provided
        valid_frequencies = ['15min', '30min', 'hourly', '2hours', '4hours',
                            '6hours', '12hours', 'daily', 'weekly', 'custom']
        if 'frequency' in filtered_data and filtered_data['frequency'] not in valid_frequencies:
            filtered_data['frequency'] = 'hourly'  # Default to hourly if invalid

        return cls(**filtered_data)

    def get_interval_seconds(self) -> int:
        """Get the interval in seconds based on frequency"""
        intervals = {
            "15min": 15 * 60,
            "30min": 30 * 60,
            "hourly": 60 * 60,
            "2hours": 2 * 60 * 60,
            "4hours": 4 * 60 * 60,
            "6hours": 6 * 60 * 60,
            "12hours": 12 * 60 * 60,
            "daily": 24 * 60 * 60,
            "weekly": 7 * 24 * 60 * 60,
            "custom": self.custom_interval_minutes * 60
        }
        return intervals.get(self.frequency, 60 * 60)


class ScheduledScanManager:
    """Manages scheduled security scans and automated reporting"""

    def __init__(self, config_file: str = "config/scheduled_scans.json"):
        """
        Initialize the Scheduled Scan Manager

        Args:
            config_file: Path to save/load schedule configurations
        """
        self.config_file = Path(config_file)
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Scheduled scans
        self.schedules: Dict[str, ScheduledScan] = {}

        # Running state
        self.is_running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._schedule_lock = threading.Lock()  # Thread safety for schedule operations

        # Callbacks
        self.on_scan_start: Optional[Callable[[ScheduledScan], None]] = None
        self.on_scan_complete: Optional[Callable[[ScheduledScan, Dict], None]] = None
        self.on_scan_error: Optional[Callable[[ScheduledScan, str], None]] = None
        self.on_status_update: Optional[Callable[[str], None]] = None

        # Reference to GUI for running scans
        self.gui = None

        # Load saved schedules
        self._load_schedules()

    def _load_schedules(self):
        """Load schedules from config file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for schedule_data in data.get('schedules', []):
                        schedule = ScheduledScan.from_dict(schedule_data)
                        self.schedules[schedule.id] = schedule
                self.logger.info(f"Loaded {len(self.schedules)} scheduled scans")
            except Exception as e:
                self.logger.error(f"Error loading schedules: {e}")

    def _save_schedules(self):
        """Save schedules to config file"""
        try:
            data = {
                'schedules': [s.to_dict() for s in self.schedules.values()],
                'last_updated': datetime.now().isoformat()
            }
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving schedules: {e}")

    def add_schedule(self, schedule: ScheduledScan) -> bool:
        """
        Add a new scheduled scan

        Args:
            schedule: ScheduledScan configuration

        Returns:
            True if added successfully
        """
        try:
            # Calculate next run time
            schedule.next_run = self._calculate_next_run(schedule)
            self.schedules[schedule.id] = schedule
            self._save_schedules()
            self.logger.info(f"Added schedule: {schedule.name} (ID: {schedule.id})")
            return True
        except Exception as e:
            self.logger.error(f"Error adding schedule: {e}")
            return False

    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a scheduled scan"""
        if schedule_id in self.schedules:
            del self.schedules[schedule_id]
            self._save_schedules()
            self.logger.info(f"Removed schedule: {schedule_id}")
            return True
        return False

    def update_schedule(self, schedule: ScheduledScan) -> bool:
        """Update an existing schedule"""
        if schedule.id in self.schedules:
            schedule.next_run = self._calculate_next_run(schedule)
            self.schedules[schedule.id] = schedule
            self._save_schedules()
            return True
        return False

    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        """Get a schedule by ID"""
        return self.schedules.get(schedule_id)

    def get_all_schedules(self) -> List[ScheduledScan]:
        """Get all scheduled scans"""
        return list(self.schedules.values())

    def enable_schedule(self, schedule_id: str) -> bool:
        """Enable a scheduled scan"""
        if schedule_id in self.schedules:
            self.schedules[schedule_id].enabled = True
            self.schedules[schedule_id].next_run = self._calculate_next_run(self.schedules[schedule_id])
            self._save_schedules()
            return True
        return False

    def disable_schedule(self, schedule_id: str) -> bool:
        """Disable a scheduled scan"""
        if schedule_id in self.schedules:
            self.schedules[schedule_id].enabled = False
            self._save_schedules()
            return True
        return False

    def _calculate_next_run(self, schedule: ScheduledScan) -> str:
        """Calculate the next run time for a schedule"""
        now = datetime.now()

        # Helper function to safely parse time string
        def parse_scheduled_time(time_str: str) -> tuple:
            """Parse HH:MM time string with validation"""
            try:
                if not time_str or ':' not in time_str:
                    self.logger.warning(f"Invalid time format '{time_str}', using 08:00")
                    return 8, 0
                parts = time_str.split(':')
                hour = int(parts[0])
                minute = int(parts[1]) if len(parts) > 1 else 0
                # Validate ranges
                if not (0 <= hour <= 23) or not (0 <= minute <= 59):
                    self.logger.warning(f"Time out of range '{time_str}', using 08:00")
                    return 8, 0
                return hour, minute
            except (ValueError, IndexError):
                self.logger.warning(f"Failed to parse time '{time_str}', using 08:00")
                return 8, 0

        if schedule.frequency == "daily":
            # Parse scheduled time with validation
            hour, minute = parse_scheduled_time(schedule.scheduled_time)
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)

        elif schedule.frequency == "weekly":
            # Find next scheduled day
            hour, minute = parse_scheduled_time(schedule.scheduled_time)
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

            # Handle empty weekly_days - default to tomorrow
            if not schedule.weekly_days:
                self.logger.warning(f"Schedule '{schedule.name}' has no weekly days set, defaulting to tomorrow")
                next_run = (now + timedelta(days=1)).replace(hour=hour, minute=minute, second=0, microsecond=0)
            else:
                # Find next valid weekday
                days_checked = 0
                found_valid_day = False
                while days_checked < 8:
                    if next_run.weekday() in schedule.weekly_days and next_run > now:
                        found_valid_day = True
                        break
                    next_run += timedelta(days=1)
                    days_checked += 1

                # If no valid day found in next 8 days, default to next week same day
                if not found_valid_day:
                    self.logger.warning(f"Could not find valid weekly day for '{schedule.name}', using next occurrence")
                    next_run = (now + timedelta(days=7)).replace(hour=hour, minute=minute, second=0, microsecond=0)

        else:
            # Interval-based scheduling
            interval_seconds = schedule.get_interval_seconds()
            next_run = now + timedelta(seconds=interval_seconds)

        return next_run.isoformat()

    def start_scheduler(self):
        """Start the scheduler background thread"""
        if self.is_running:
            self.logger.warning("Scheduler already running")
            return

        self.is_running = True
        self._stop_event.clear()
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        self.logger.info("Scheduled scan manager started")

        if self.on_status_update:
            self.on_status_update("Scheduler started")

    def stop_scheduler(self):
        """Stop the scheduler background thread"""
        self.is_running = False
        self._stop_event.set()
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        self.logger.info("Scheduled scan manager stopped")

        if self.on_status_update:
            self.on_status_update("Scheduler stopped")

    def _scheduler_loop(self):
        """Main scheduler loop that checks and runs due scans"""
        self.logger.info("Scheduler loop started")

        while self.is_running and not self._stop_event.is_set():
            try:
                now = datetime.now()

                for schedule_id, schedule in list(self.schedules.items()):
                    if not schedule.enabled:
                        continue

                    if not schedule.next_run:
                        schedule.next_run = self._calculate_next_run(schedule)
                        continue

                    # Safely parse next_run datetime with exception handling
                    try:
                        next_run = datetime.fromisoformat(schedule.next_run)
                    except (ValueError, TypeError) as e:
                        self.logger.warning(f"Invalid next_run format for '{schedule.name}': {schedule.next_run}, recalculating")
                        schedule.next_run = self._calculate_next_run(schedule)
                        continue

                    if now >= next_run:
                        # Time to run this schedule
                        self._execute_scheduled_scan(schedule)

                # Check every 30 seconds
                self._stop_event.wait(30)

            except Exception as e:
                self.logger.error(f"Scheduler loop error: {e}")
                time.sleep(30)

        self.logger.info("Scheduler loop ended")

    def _execute_scheduled_scan(self, schedule: ScheduledScan):
        """Execute a scheduled scan"""
        # Thread-safe check-and-set to prevent concurrent execution of the same scan
        with self._schedule_lock:
            if getattr(schedule, '_is_running', False):
                self.logger.warning(f"Scan '{schedule.name}' is already running, skipping this execution")
                return
            schedule._is_running = True

        self.logger.info(f"Executing scheduled scan: {schedule.name}")

        if self.on_status_update:
            self.on_status_update(f"Running scheduled scan: {schedule.name}")

        try:
            # Update status
            schedule.last_run = datetime.now().isoformat()
            schedule.last_status = "running"
            schedule.run_count += 1

            # Notify scan start
            if self.on_scan_start:
                self.on_scan_start(schedule)

            # Run the actual scan via GUI
            if self.gui and hasattr(self.gui, 'run_scheduled_scan'):
                result = self.gui.run_scheduled_scan(schedule)

                # Validate result is not None
                if result is None:
                    schedule.last_status = "failed"
                    schedule.last_error = "Scan returned no result"
                    if self.on_scan_error:
                        self.on_scan_error(schedule, "Scan returned no result")
                    return

                # Update status based on result
                if result.get('success'):
                    schedule.last_status = "completed"
                    schedule.last_error = None

                    # Send email report if configured
                    if schedule.email_report and schedule.email_recipients:
                        self._send_scheduled_report(schedule, result)

                    if self.on_scan_complete:
                        self.on_scan_complete(schedule, result)
                else:
                    schedule.last_status = "failed"
                    schedule.last_error = result.get('error', 'Unknown error')

                    if self.on_scan_error:
                        self.on_scan_error(schedule, schedule.last_error)
            else:
                schedule.last_status = "failed"
                schedule.last_error = "GUI not available"

        except Exception as e:
            schedule.last_status = "failed"
            schedule.last_error = str(e)
            self.logger.error(f"Scheduled scan error: {e}")

            if self.on_scan_error:
                self.on_scan_error(schedule, str(e))

        finally:
            # Clear running flag
            schedule._is_running = False
            # Calculate next run
            schedule.next_run = self._calculate_next_run(schedule)
            self._save_schedules()

    def _send_scheduled_report(self, schedule: ScheduledScan, result: Dict):
        """Send email report for a scheduled scan with ALL enterprise reports attached"""
        try:
            # Get notification options from GUI (with defaults)
            skip_duplicates = True
            always_send_critical = True
            always_send_minor = True

            # Individual attachment type options (defaults: HTML + Excel only)
            attach_pdf = False
            attach_csv = False
            attach_excel = True
            attach_html = True

            if self.gui:
                skip_duplicates_var = getattr(self.gui, 'skip_duplicate_findings_var', None)
                skip_duplicates = skip_duplicates_var.get() if skip_duplicates_var else True

                always_send_critical_var = getattr(self.gui, 'always_send_critical_var', None)
                always_send_critical = always_send_critical_var.get() if always_send_critical_var else True

                always_send_minor_var = getattr(self.gui, 'always_send_minor_var', None)
                always_send_minor = always_send_minor_var.get() if always_send_minor_var else True

                # Individual attachment type options from GUI
                attach_pdf_var = getattr(self.gui, 'attach_pdf_var', None)
                attach_pdf = attach_pdf_var.get() if attach_pdf_var else False

                attach_csv_var = getattr(self.gui, 'attach_csv_var', None)
                attach_csv = attach_csv_var.get() if attach_csv_var else False

                attach_excel_var = getattr(self.gui, 'attach_excel_var', None)
                attach_excel = attach_excel_var.get() if attach_excel_var else True

                attach_html_var = getattr(self.gui, 'attach_html_var', None)
                attach_html = attach_html_var.get() if attach_html_var else True

                # IP filtering options
                include_public_ips_var = getattr(self.gui, 'include_public_ips_var', None)
                include_public_ips = include_public_ips_var.get() if include_public_ips_var else True

                include_private_ips_var = getattr(self.gui, 'include_private_ips_var', None)
                include_private_ips = include_private_ips_var.get() if include_private_ips_var else True

            # Apply IP filtering to attackers
            original_attackers = result.get('attackers', [])
            filtered_attackers = filter_attackers_by_ip_type(
                original_attackers,
                include_public=include_public_ips,
                include_private=include_private_ips
            )

            # Log filtering if applied
            if len(filtered_attackers) != len(original_attackers):
                self.logger.info(f"IP filtering: {len(original_attackers)} -> {len(filtered_attackers)} attackers "
                               f"(Public: {include_public_ips}, Private: {include_private_ips})")

            # Get threat counts from filtered attackers
            total_attackers = len(filtered_attackers)
            critical_count = sum(1 for a in filtered_attackers if getattr(a, 'risk_score', 0) >= 85)
            high_count = sum(1 for a in filtered_attackers if 70 <= getattr(a, 'risk_score', 0) < 85)

            # Get schedule-specific email trigger options (with defaults for backwards compatibility)
            send_on_complete = getattr(schedule, 'send_on_complete', True)
            send_on_exploit = getattr(schedule, 'send_on_exploit', True)
            send_on_critical_cve = getattr(schedule, 'send_on_critical_cve', True)
            send_on_new_attacker = getattr(schedule, 'send_on_new_attacker', True)

            # Determine if we should send email based on notification options
            should_send = False
            skip_reason = None
            send_reasons = []

            # Check if there are any threats detected
            has_critical = critical_count > 0
            has_high = high_count > 0
            has_any_threats = total_attackers > 0

            # Check for specific trigger conditions
            has_exploits = any(
                hasattr(a, 'attack_events') and any(
                    getattr(e, 'severity', 0) >= 12 or 'exploit' in str(getattr(e, 'rule_description', '')).lower()
                    for e in getattr(a, 'attack_events', [])
                )
                for a in filtered_attackers
            )

            has_critical_cve = any(
                hasattr(a, 'attack_events') and any(
                    'cve' in str(getattr(e, 'rule_description', '')).lower() and getattr(e, 'severity', 0) >= 12
                    for e in getattr(a, 'attack_events', [])
                )
                for a in filtered_attackers
            )

            # Check for new attackers (compare with last scan's attackers)
            last_attacker_ips = getattr(schedule, '_last_attacker_ips', set())
            current_attacker_ips = {getattr(a, 'ip_address', '') for a in filtered_attackers}
            new_attackers = current_attacker_ips - last_attacker_ips
            has_new_attackers = len(new_attackers) > 0

            # Update stored attacker IPs for next comparison
            schedule._last_attacker_ips = current_attacker_ips

            # Apply schedule-specific email trigger conditions
            if send_on_complete:
                should_send = True
                send_reasons.append("scan completed")

            if send_on_exploit and has_exploits:
                should_send = True
                send_reasons.append("exploit detected")

            if send_on_critical_cve and has_critical_cve:
                should_send = True
                send_reasons.append("critical CVE found")

            if send_on_new_attacker and has_new_attackers:
                should_send = True
                send_reasons.append(f"new attacker(s): {len(new_attackers)}")

            # Also check global GUI settings for critical/minor threats
            # Always send on critical threats if option enabled
            if always_send_critical and has_critical:
                should_send = True
                send_reasons.append(f"critical threats: {critical_count}")

            # Always send on any threat detection if option enabled
            if always_send_minor and has_any_threats:
                should_send = True
                if f"threats detected: {total_attackers}" not in send_reasons:
                    send_reasons.append(f"threats detected: {total_attackers}")

            if send_reasons:
                self.logger.info(f"Email trigger reasons: {', '.join(send_reasons)}")

            # Check for duplicate findings if skip_duplicates is enabled
            if skip_duplicates and not should_send:
                # Generate a hash of current findings
                current_findings_hash = self._generate_findings_hash(result)
                last_findings_hash = getattr(schedule, 'last_findings_hash', None)

                if current_findings_hash == last_findings_hash:
                    skip_reason = "no new findings (same as last scan)"
                    self.logger.info(f"Skipping email for {schedule.name} - {skip_reason}")
                    return
                else:
                    should_send = True
                    # Store the new hash
                    schedule.last_findings_hash = current_findings_hash

            # If no special conditions, just check if there are any results
            if not should_send and has_any_threats:
                should_send = True

            # Check if we should skip based on critical-only setting
            if schedule.email_on_critical_only:
                if critical_count == 0:
                    self.logger.info(f"Skipping email for {schedule.name} - no critical threats (critical-only mode)")
                    return

            if not should_send:
                self.logger.info(f"Skipping email for {schedule.name} - no threats detected")
                return

            # Get email sender from GUI
            if self.gui and hasattr(self.gui, 'email_sender') and self.gui.email_sender:
                from modules.O365EmailSender import SecurityReportEmailBuilder
                import os

                # Create filtered report data for email
                filtered_report_data = {
                    **result,
                    'total_attackers': total_attackers,
                    'critical_threats': critical_count,
                    'attackers': filtered_attackers
                }

                # Build email content with error handling
                try:
                    report_html = SecurityReportEmailBuilder.build_report_email(
                        report_data=filtered_report_data,
                        attackers=filtered_attackers,
                        validation_results=result.get('validation', {})
                    )
                except Exception as e:
                    self.logger.error(f"Failed to build email report HTML: {e}")
                    # Fallback to simple HTML
                    report_html = f"""
                    <html><body style="font-family: Arial; padding: 20px;">
                    <h1>Security Analysis Report</h1>
                    <p>Total Attackers: {total_attackers}</p>
                    <p>Critical Threats: {critical_count}</p>
                    <p>Analysis Time: {result.get('analysis_time', 'N/A')}</p>
                    <p><em>Note: Full report generation failed. Please check attachments.</em></p>
                    </body></html>
                    """

                # Collect attachments based on individual attachment type options
                all_attachments = []

                # Add main executive summary PDF if PDF attachments enabled
                if attach_pdf and result.get('pdf_bytes'):
                    all_attachments.append({
                        "name": f"Executive_Summary_{datetime.now().strftime('%Y%m%d')}.pdf",
                        "content_type": "application/pdf",
                        "content_bytes": result['pdf_bytes']
                    })

                # Add CSV attachment if CSV attachments enabled
                if attach_csv and result.get('csv_bytes'):
                    all_attachments.append({
                        "name": f"Attacker_Data_{datetime.now().strftime('%Y%m%d')}.csv",
                        "content_type": "text/csv",
                        "content_bytes": result['csv_bytes']
                    })

                # Add Excel attachment if Excel attachments enabled
                if attach_excel and result.get('excel_bytes'):
                    all_attachments.append({
                        "name": f"Security_Report_{datetime.now().strftime('%Y%m%d')}.xlsx",
                        "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "content_bytes": result['excel_bytes']
                    })

                # Add HTML attachment if HTML attachments enabled
                if attach_html and result.get('html_bytes'):
                    all_attachments.append({
                        "name": f"Security_Report_{datetime.now().strftime('%Y%m%d')}.html",
                        "content_type": "text/html",
                        "content_bytes": result['html_bytes']
                    })

                # Add all enterprise report files (ISO 27001, GDPR, NIST, OWASP, SOC2) based on attachment options
                all_report_files = result.get('all_report_files', {})

                def attach_report_file(file_path, file_type):
                    """Helper to attach a report file"""
                    if not file_path or not os.path.exists(file_path):
                        return
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read()
                        if file_type == 'pdf':
                            all_attachments.append({
                                "name": os.path.basename(file_path),
                                "content_type": "application/pdf",
                                "content_bytes": content
                            })
                        elif file_type == 'html':
                            all_attachments.append({
                                "name": os.path.basename(file_path),
                                "content_type": "text/html",
                                "content_bytes": content
                            })
                        elif file_type == 'excel':
                            all_attachments.append({
                                "name": os.path.basename(file_path),
                                "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                "content_bytes": content
                            })
                        self.logger.info(f"Attached: {os.path.basename(file_path)}")
                    except Exception as e:
                        self.logger.warning(f"Could not attach {file_path}: {e}")

                for report_type, files in all_report_files.items():
                    if isinstance(files, dict):
                        # Handle nested structure (e.g., Compliance reports)
                        for framework, framework_files in files.items():
                            if isinstance(framework_files, dict):
                                if attach_pdf and 'pdf' in framework_files:
                                    attach_report_file(framework_files['pdf'], 'pdf')
                                if attach_html and 'html' in framework_files:
                                    attach_report_file(framework_files['html'], 'html')
                                if attach_excel and 'excel' in framework_files:
                                    attach_report_file(framework_files['excel'], 'excel')
                        # Also check if files dict has direct keys
                        if attach_pdf and 'pdf' in files:
                            attach_report_file(files['pdf'], 'pdf')
                        if attach_html and 'html' in files:
                            attach_report_file(files['html'], 'html')
                        if attach_excel and 'excel' in files:
                            attach_report_file(files['excel'], 'excel')

                if all_attachments:
                    self.logger.info(f"Sending email with {len(all_attachments)} attachments (PDF: {attach_pdf}, CSV: {attach_csv}, Excel: {attach_excel}, HTML: {attach_html})")
                else:
                    self.logger.info("Sending email without attachments")

                # Validate email sender has send_email method before calling
                email_sender = self.gui.email_sender
                if not email_sender or not hasattr(email_sender, 'send_email'):
                    self.logger.error(f"Email sender not properly configured for {schedule.name}")
                    return

                # Send email with all attachments
                success = email_sender.send_email(
                    to_recipients=schedule.email_recipients,
                    subject=f"[SOC Report] Security Analysis - {result.get('critical_threats', 0)} Critical Threats - {result.get('analysis_time', '')}",
                    body_html=report_html,
                    attachments=all_attachments if all_attachments else None,
                    importance="high" if result.get('critical_threats', 0) > 0 else "normal"
                )

                if success:
                    self.logger.info(f"Email report sent for {schedule.name} with {len(all_attachments)} attachments")
                else:
                    self.logger.error(f"Failed to send email report for {schedule.name}")

        except Exception as e:
            import traceback
            self.logger.error(f"Error sending scheduled report email for '{schedule.name}': {e}")
            self.logger.error(f"Stack trace: {traceback.format_exc()}")

    def _generate_findings_hash(self, result: Dict) -> str:
        """Generate a hash of the findings to detect duplicates"""
        import hashlib

        # Create a string representation of key findings
        findings_data = []

        # Add attacker IPs and risk scores
        for attacker in result.get('attackers', []):
            ip = getattr(attacker, 'ip_address', str(attacker))
            risk = getattr(attacker, 'risk_score', 0)
            findings_data.append(f"{ip}:{risk}")

        # Add counts
        findings_data.append(f"total:{result.get('total_attackers', 0)}")
        findings_data.append(f"critical:{result.get('critical_threats', 0)}")

        # Sort for consistent hashing
        findings_data.sort()
        findings_str = '|'.join(findings_data)

        # Generate hash
        return hashlib.md5(findings_str.encode()).hexdigest()

    def run_scan_now(self, schedule_id: str) -> bool:
        """Manually trigger a scheduled scan to run immediately"""
        if schedule_id in self.schedules:
            schedule = self.schedules[schedule_id]
            threading.Thread(target=self._execute_scheduled_scan, args=(schedule,), daemon=True).start()
            return True
        return False

    def get_next_scheduled_scans(self, limit: int = 5) -> List[Dict]:
        """Get the next upcoming scheduled scans"""
        enabled_schedules = [s for s in self.schedules.values() if s.enabled and s.next_run]

        # Sort by next run time
        sorted_schedules = sorted(enabled_schedules, key=lambda s: s.next_run)

        result = []
        for schedule in sorted_schedules[:limit]:
            try:
                next_run = datetime.fromisoformat(schedule.next_run) if schedule.next_run else None
                time_until = (next_run - datetime.now()).total_seconds() if next_run else 0
            except (ValueError, TypeError):
                # Invalid datetime format, skip or use default
                next_run = None
                time_until = 0

            result.append({
                'id': schedule.id,
                'name': schedule.name,
                'next_run': schedule.next_run,
                'frequency': schedule.frequency,
                'time_until_seconds': time_until,
                'time_until_human': self._format_time_delta(time_until)
            })

        return result

    def _format_time_delta(self, seconds: float) -> str:
        """Format seconds into human-readable time"""
        if seconds < 0:
            return "overdue"
        elif seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds / 60)}m"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
        else:
            days = int(seconds / 86400)
            hours = int((seconds % 86400) / 3600)
            return f"{days}d {hours}h"

    def create_default_schedule(self) -> ScheduledScan:
        """Create a default schedule configuration"""
        import uuid
        return ScheduledScan(
            id=str(uuid.uuid4()),
            name="Default Security Scan",
            enabled=True,
            frequency="hourly",
            time_range_hours=24,
            min_severity=10,
            email_report=True,
            email_recipients=[],
            email_on_critical_only=False
        )


class ScheduleCalendarView:
    """Helper class for generating calendar views of scheduled scans"""

    @staticmethod
    def get_weekly_calendar(schedules: List[ScheduledScan]) -> Dict[str, List[Dict]]:
        """
        Generate a weekly calendar view of scheduled scans

        Returns:
            Dictionary with day names as keys and list of scheduled times as values
        """
        days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        calendar = {day: [] for day in days}

        now = datetime.now()
        week_start = now - timedelta(days=now.weekday())

        for schedule in schedules:
            if not schedule.enabled:
                continue

            if schedule.frequency == "weekly":
                for day_num in schedule.weekly_days:
                    day_name = days[day_num]
                    calendar[day_name].append({
                        'id': schedule.id,
                        'name': schedule.name,
                        'time': schedule.scheduled_time,
                        'type': 'weekly'
                    })

            elif schedule.frequency == "daily":
                for day_name in days:
                    calendar[day_name].append({
                        'id': schedule.id,
                        'name': schedule.name,
                        'time': schedule.scheduled_time,
                        'type': 'daily'
                    })

            else:
                # Interval-based - show next occurrence
                if schedule.next_run:
                    next_run = datetime.fromisoformat(schedule.next_run)
                    if week_start <= next_run < week_start + timedelta(days=7):
                        day_name = days[next_run.weekday()]
                        calendar[day_name].append({
                            'id': schedule.id,
                            'name': schedule.name,
                            'time': next_run.strftime('%H:%M'),
                            'type': schedule.frequency
                        })

        # Sort each day's schedules by time
        for day in calendar:
            calendar[day].sort(key=lambda x: x['time'])

        return calendar

    @staticmethod
    def get_monthly_calendar(schedules: List[ScheduledScan], year: int, month: int) -> List[List[Dict]]:
        """
        Generate a monthly calendar view

        Returns:
            List of weeks, each containing 7 days with scheduled scans
        """
        import calendar

        cal = calendar.Calendar(firstweekday=0)  # Monday start
        month_days = cal.monthdayscalendar(year, month)

        result = []
        for week in month_days:
            week_data = []
            for day in week:
                if day == 0:
                    week_data.append({'day': 0, 'scans': []})
                else:
                    day_date = datetime(year, month, day)
                    day_scans = []

                    for schedule in schedules:
                        if not schedule.enabled:
                            continue

                        # Check if this schedule runs on this day
                        if schedule.frequency == "daily":
                            day_scans.append({
                                'id': schedule.id,
                                'name': schedule.name,
                                'time': schedule.scheduled_time
                            })
                        elif schedule.frequency == "weekly" and day_date.weekday() in schedule.weekly_days:
                            day_scans.append({
                                'id': schedule.id,
                                'name': schedule.name,
                                'time': schedule.scheduled_time
                            })

                    week_data.append({
                        'day': day,
                        'date': day_date.isoformat(),
                        'scans': day_scans
                    })

            result.append(week_data)

        return result
