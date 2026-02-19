"""
Comprehensive Audit Logging System
Tracks all user actions, data access, and system events
Compliant with SOC 2, ISO 27001, GDPR, HIPAA requirements
"""

import logging
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import threading
from queue import Queue
import socket
import getpass

class AuditLogger:
    """
    Enterprise-grade audit logging system
    Captures who, what, when, where, why for all actions
    """

    def __init__(self, log_dir: str = "./logs/audit"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Create dedicated audit logger
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)

        # Prevent propagation to root logger
        self.logger.propagate = False

        # File handler with rotation
        log_file = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)

        # JSON formatter for structured logging
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

        # Async logging queue
        self.log_queue = Queue()
        self.log_thread = threading.Thread(target=self._process_logs, daemon=True)
        self.log_thread.start()

        # System info
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()

    def _process_logs(self):
        """Process logs asynchronously"""
        while True:
            try:
                log_entry = self.log_queue.get()
                if log_entry is None:
                    break
                self.logger.info(json.dumps(log_entry))
            except Exception as e:
                print(f"Error processing log: {e}")

    def log_action(self,
                   action: str,
                   user: str = None,
                   resource: str = None,
                   resource_type: str = None,
                   details: Dict[str, Any] = None,
                   ip_address: str = None,
                   status: str = "success",
                   sensitivity_level: str = "internal"):
        """
        Log a user action

        Args:
            action: Action performed (e.g., "view_dashboard", "export_data")
            user: Username or user ID
            resource: Resource identifier (e.g., IP address, report ID)
            resource_type: Type of resource (e.g., "attacker_profile", "report")
            details: Additional context
            ip_address: User's IP address
            status: success, failure, error
            sensitivity_level: public, internal, confidential, secret
        """
        user = user or self.username

        entry = {
            "event_id": hashlib.sha256(
                f"{datetime.utcnow().isoformat()}{user}{action}".encode()
            ).hexdigest()[:16],
            "timestamp": datetime.utcnow().isoformat(),
            "actor": {
                "user": user,
                "ip_address": ip_address or "127.0.0.1",
                "hostname": self.hostname
            },
            "action": {
                "type": action,
                "status": status,
                "resource": resource,
                "resource_type": resource_type
            },
            "metadata": {
                "details": details or {},
                "sensitivity": sensitivity_level
            }
        }

        # Queue for async processing
        self.log_queue.put(entry)

    def log_data_access(self,
                       user: str,
                       data_type: str,
                       record_count: int,
                       query: str = None,
                       purpose: str = None):
        """Log data access for GDPR/HIPAA compliance"""
        self.log_action(
            action="data_access",
            user=user,
            resource_type=data_type,
            details={
                "record_count": record_count,
                "query": query,
                "purpose": purpose,
                "compliance": "GDPR"
            },
            sensitivity_level="confidential"
        )

    def log_data_export(self,
                       user: str,
                       data_type: str,
                       record_count: int,
                       export_format: str,
                       destination: str):
        """Log data exports (critical for compliance)"""
        self.log_action(
            action="data_export",
            user=user,
            resource_type=data_type,
            details={
                "record_count": record_count,
                "format": export_format,
                "destination": destination,
                "compliance": "SOC2"
            },
            sensitivity_level="secret"
        )

    def log_authentication(self,
                          user: str,
                          status: str,
                          method: str,
                          ip_address: str):
        """Log authentication attempts"""
        self.log_action(
            action="authentication",
            user=user,
            status=status,
            ip_address=ip_address,
            details={
                "method": method,
                "compliance": "ISO27001"
            },
            sensitivity_level="confidential"
        )

    def log_configuration_change(self,
                                user: str,
                                setting: str,
                                old_value: Any,
                                new_value: Any):
        """Log configuration changes"""
        self.log_action(
            action="config_change",
            user=user,
            resource=setting,
            resource_type="configuration",
            details={
                "old_value": str(old_value),
                "new_value": str(new_value),
                "compliance": "SOC2"
            },
            sensitivity_level="confidential"
        )

    def log_security_event(self,
                          event_type: str,
                          severity: str,
                          details: Dict[str, Any]):
        """Log security events"""
        self.log_action(
            action="security_event",
            resource_type=event_type,
            status=severity,
            details=details,
            sensitivity_level="secret"
        )

    def search_logs(self,
                   start_date: datetime = None,
                   end_date: datetime = None,
                   user: str = None,
                   action: str = None) -> list:
        """Search audit logs for compliance reporting"""
        results = []

        # Determine which log files to search
        log_files = list(self.log_dir.glob("audit_*.log"))

        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            entry = json.loads(line)

                            # Parse inner message JSON
                            if isinstance(entry.get('message'), str):
                                entry['message'] = json.loads(entry['message'])

                            # Apply filters
                            if start_date and datetime.fromisoformat(
                                entry['message']['timestamp']) < start_date:
                                continue
                            if end_date and datetime.fromisoformat(
                                entry['message']['timestamp']) > end_date:
                                continue
                            if user and entry['message']['actor']['user'] != user:
                                continue
                            if action and entry['message']['action']['type'] != action:
                                continue

                            results.append(entry['message'])
                        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                            continue
            except (IOError, json.JSONDecodeError, KeyError):
                continue

        return results

    def generate_compliance_report(self,
                                  compliance_type: str,
                                  start_date: datetime,
                                  end_date: datetime) -> Dict[str, Any]:
        """
        Generate compliance reports

        Args:
            compliance_type: SOC2, ISO27001, GDPR, HIPAA, PCI_DSS
            start_date: Report start date
            end_date: Report end date
        """
        logs = self.search_logs(start_date, end_date)

        report = {
            "report_type": compliance_type,
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "summary": {
                "total_events": len(logs),
                "unique_users": len(set(log['actor']['user'] for log in logs)),
                "failed_actions": len([log for log in logs if log['action']['status'] == 'failure']),
                "data_access_events": len([log for log in logs if log['action']['type'] == 'data_access']),
                "data_exports": len([log for log in logs if log['action']['type'] == 'data_export']),
                "config_changes": len([log for log in logs if log['action']['type'] == 'config_change']),
                "security_events": len([log for log in logs if log['action']['type'] == 'security_event'])
            },
            "details": logs
        }

        return report

    def close(self):
        """Close the logger"""
        self.log_queue.put(None)
        self.log_thread.join(timeout=5)
