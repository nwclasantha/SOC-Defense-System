"""
O365 Email Sender Module for SOC Defense System
Sends validated security reports via Microsoft Graph API using OAuth2 PKCE flow
"""

import os
import json
import base64
import hashlib
import secrets
import webbrowser
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, parse_qs, urlparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
import msal


class O365EmailSender:
    """Microsoft 365 Email Sender using OAuth2 PKCE authentication"""

    # Microsoft Graph API endpoints
    GRAPH_API_ENDPOINT = "https://graph.microsoft.com/v1.0"

    def __init__(self, client_id: str, tenant_id: str, redirect_uri: str = "http://localhost:8089/callback"):
        """
        Initialize O365 Email Sender

        Args:
            client_id: Azure AD Application (client) ID
            tenant_id: Azure AD Directory (tenant) ID
            redirect_uri: OAuth redirect URI (must match Azure AD config)
        """
        self.client_id = client_id
        self.tenant_id = tenant_id
        self.redirect_uri = redirect_uri
        self.logger = logging.getLogger(__name__)

        # Token storage - direct JSON storage for browser-based OAuth
        self.token_cache_file = Path("config/o365_token_cache.json")
        self.token_cache_file.parent.mkdir(parents=True, exist_ok=True)

        # Initialize MSAL public client application
        self.authority = f"https://login.microsoftonline.com/{tenant_id}"
        self.scopes = ["Mail.Send", "Mail.ReadWrite", "User.Read"]

        # Token cache for MSAL (used by device code flow)
        self.cache = msal.SerializableTokenCache()

        # Create MSAL app
        self.app = msal.PublicClientApplication(
            client_id=self.client_id,
            authority=self.authority,
            token_cache=self.cache
        )

        # Current tokens
        self.access_token = None
        self.refresh_token = None
        self.user_email = None

        # Load any cached tokens
        self._load_token_cache()
        self._try_silent_auth()

    def _load_token_cache(self):
        """Load token cache from file"""
        if self.token_cache_file.exists():
            try:
                cache_data = json.loads(self.token_cache_file.read_text(encoding='utf-8'))
                # Load direct tokens (from browser-based OAuth)
                if 'access_token' in cache_data:
                    self.access_token = cache_data.get('access_token')
                if 'refresh_token' in cache_data:
                    self.refresh_token = cache_data.get('refresh_token')
                if 'user_email' in cache_data:
                    self.user_email = cache_data.get('user_email')
                # Also try to load MSAL cache
                if 'msal_cache' in cache_data:
                    self.cache.deserialize(cache_data['msal_cache'])
                self.logger.info("Token cache loaded successfully")
            except Exception as e:
                self.logger.warning(f"Could not load token cache: {e}")

    def _save_token_cache(self):
        """Save token cache to file"""
        try:
            cache_data = {
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'user_email': self.user_email,
                'client_id': self.client_id,
                'tenant_id': self.tenant_id,
                'timestamp': datetime.now().isoformat()
            }
            # Also save MSAL cache if it has data
            if self.cache.has_state_changed:
                cache_data['msal_cache'] = self.cache.serialize()
            self.token_cache_file.write_text(json.dumps(cache_data, indent=2), encoding='utf-8')
            self.logger.info("Token cache saved successfully")
        except Exception as e:
            self.logger.warning(f"Could not save token cache: {e}")

    def _try_silent_auth(self):
        """Try to authenticate silently using cached tokens"""
        # First check if we have a valid access token already loaded
        if self.access_token:
            self.logger.info("Using cached access token")
            return True

        # Try MSAL silent auth (for device code flow)
        accounts = self.app.get_accounts()
        if accounts:
            result = self.app.acquire_token_silent(self.scopes, account=accounts[0])
            if result and "access_token" in result:
                self.access_token = result["access_token"]
                self._save_token_cache()
                self.logger.info("MSAL silent authentication successful")
                return True

        # Try refreshing with refresh_token (for browser-based OAuth)
        if self.refresh_token:
            if self._refresh_access_token():
                return True

        return False

    def _refresh_access_token(self):
        """Refresh access token using refresh token"""
        if not self.refresh_token:
            return False

        try:
            import urllib.request
            import urllib.parse

            token_url = f'https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token'
            # Use minimal scopes to avoid admin consent requirement
            scope = 'https://graph.microsoft.com/Mail.Send offline_access openid profile'

            data = {
                'client_id': self.client_id,
                'refresh_token': self.refresh_token,
                'grant_type': 'refresh_token',
                'scope': scope
            }

            req = urllib.request.Request(
                token_url,
                data=urllib.parse.urlencode(data).encode(),
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                token_data = json.loads(response.read().decode())

            if 'access_token' in token_data:
                self.access_token = token_data['access_token']
                if 'refresh_token' in token_data:
                    self.refresh_token = token_data['refresh_token']
                self._save_token_cache()
                self.logger.info("Token refresh successful")
                return True

        except Exception as e:
            self.logger.warning(f"Token refresh failed: {e}")

        return False

    def authenticate_interactive(self, callback=None) -> bool:
        """
        Authenticate interactively using browser-based OAuth2 PKCE flow

        Args:
            callback: Optional callback function to call with status updates

        Returns:
            True if authentication successful
        """
        try:
            if callback:
                callback("Starting OAuth2 authentication...")

            # Use device code flow for better compatibility
            flow = self.app.initiate_device_flow(scopes=self.scopes)

            if "user_code" not in flow:
                self.logger.error(f"Device flow failed: {flow.get('error_description', 'Unknown error')}")
                if callback:
                    callback(f"Authentication failed: {flow.get('error_description', 'Unknown error')}")
                return False

            # Show user code to user
            message = flow["message"]
            self.logger.info(message)
            if callback:
                callback(message)

            # Open browser for user to authenticate
            webbrowser.open(flow["verification_uri"])

            # Wait for user to complete authentication
            result = self.app.acquire_token_by_device_flow(flow)

            if "access_token" in result:
                self.access_token = result["access_token"]
                self._save_token_cache()
                self.logger.info("Authentication successful")
                if callback:
                    callback("Authentication successful!")
                return True
            else:
                error = result.get("error_description", "Unknown error")
                self.logger.error(f"Authentication failed: {error}")
                if callback:
                    callback(f"Authentication failed: {error}")
                return False

        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            if callback:
                callback(f"Authentication error: {str(e)}")
            return False

    def is_authenticated(self) -> bool:
        """Check if we have a valid access token"""
        return self.access_token is not None

    def send_email(
        self,
        to_recipients: List[str],
        subject: str,
        body_html: str,
        attachments: Optional[List[Dict[str, Any]]] = None,
        cc_recipients: Optional[List[str]] = None,
        importance: str = "normal",
        _retry_count: int = 0
    ) -> bool:
        """
        Send an email via Microsoft Graph API

        Args:
            to_recipients: List of email addresses
            subject: Email subject
            body_html: HTML body content
            attachments: List of attachment dicts with 'name', 'content_type', 'content_bytes'
            cc_recipients: Optional CC recipients
            _retry_count: Internal parameter to prevent infinite recursion (max 1 retry)
            importance: Email importance (low, normal, high)

        Returns:
            True if email sent successfully
        """
        if not self.access_token:
            if not self._try_silent_auth():
                self.logger.error("Not authenticated. Call authenticate_interactive() first.")
                return False

        try:
            import requests

            # Build email message
            message = {
                "message": {
                    "subject": subject,
                    "body": {
                        "contentType": "HTML",
                        "content": body_html
                    },
                    "toRecipients": [
                        {"emailAddress": {"address": addr}} for addr in to_recipients
                    ],
                    "importance": importance
                },
                "saveToSentItems": True
            }

            # Add CC recipients if provided
            if cc_recipients:
                message["message"]["ccRecipients"] = [
                    {"emailAddress": {"address": addr}} for addr in cc_recipients
                ]

            # Add attachments if provided
            if attachments:
                message["message"]["attachments"] = []
                for attachment in attachments:
                    att_data = {
                        "@odata.type": "#microsoft.graph.fileAttachment",
                        "name": attachment["name"],
                        "contentType": attachment.get("content_type", "application/octet-stream"),
                        "contentBytes": base64.b64encode(attachment["content_bytes"]).decode("utf-8")
                    }
                    message["message"]["attachments"].append(att_data)

            # Send email via Graph API
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }

            response = requests.post(
                f"{self.GRAPH_API_ENDPOINT}/me/sendMail",
                headers=headers,
                json=message,
                timeout=30
            )

            if response.status_code == 202:
                self.logger.info(f"Email sent successfully to {', '.join(to_recipients)}")
                return True
            elif response.status_code == 401:
                # Token expired, invalidate and try to refresh
                if _retry_count >= 1:
                    self.logger.error("Max retry attempts exceeded for token refresh")
                    return False
                self.logger.info("Token expired, attempting refresh...")
                self.access_token = None  # Invalidate expired token
                if self._refresh_access_token() or self._try_silent_auth():
                    return self.send_email(to_recipients, subject, body_html, attachments, cc_recipients, importance, _retry_count + 1)
                else:
                    self.logger.error("Token refresh failed")
                    return False
            else:
                self.logger.error(f"Email send failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            self.logger.error(f"Error sending email: {e}")
            return False

    def send_security_report(
        self,
        to_recipients: List[str],
        report_data: Dict[str, Any],
        report_html: str,
        pdf_attachment: Optional[bytes] = None,
        csv_attachment: Optional[bytes] = None
    ) -> bool:
        """
        Send a security analysis report via email

        Args:
            to_recipients: List of recipient email addresses
            report_data: Dictionary containing report metadata
            report_html: HTML content of the report
            pdf_attachment: Optional PDF file bytes
            csv_attachment: Optional CSV file bytes

        Returns:
            True if email sent successfully
        """
        # Build subject with key metrics
        total_attackers = report_data.get('total_attackers', 0)
        critical_threats = report_data.get('critical_threats', 0)
        analysis_time = report_data.get('analysis_time', datetime.now().strftime('%Y-%m-%d %H:%M'))

        subject = f"[SOC Alert] Security Analysis Report - {critical_threats} Critical Threats Detected - {analysis_time}"

        if critical_threats == 0:
            subject = f"[SOC Report] Security Analysis Report - {total_attackers} Attackers Analyzed - {analysis_time}"

        # Prepare attachments
        attachments = []

        if pdf_attachment:
            attachments.append({
                "name": f"SOC_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                "content_type": "application/pdf",
                "content_bytes": pdf_attachment
            })

        if csv_attachment:
            attachments.append({
                "name": f"SOC_Attacker_Data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "content_type": "text/csv",
                "content_bytes": csv_attachment
            })

        # Determine importance based on threat level
        importance = "high" if critical_threats > 0 else "normal"

        return self.send_email(
            to_recipients=to_recipients,
            subject=subject,
            body_html=report_html,
            attachments=attachments if attachments else None,
            importance=importance
        )


class SecurityReportEmailBuilder:
    """Builds CISO-style executive briefing email with action items and mitigations"""

    @staticmethod
    def build_report_email(
        report_data: Dict[str, Any],
        attackers: List[Any],
        validation_results: Dict[str, Any]
    ) -> str:
        """
        Build CISO-style executive briefing email compatible with all email clients.
        Uses table-based layout with inline styles for maximum compatibility.

        Args:
            report_data: Report metadata
            attackers: List of attacker profiles
            validation_results: ML and threat intel validation results

        Returns:
            HTML string for email body
        """
        import ipaddress

        def is_valid_reportable_ip(ip_str):
            """Check if IP is valid and should be included in reports"""
            if not ip_str or not isinstance(ip_str, str):
                return False
            invalid_ips = {'0.0.0.0', '255.255.255.255', '127.0.0.1', '::1',
                          'localhost', 'unknown', 'none', 'null', '-', ''}
            if ip_str.lower().strip() in invalid_ips:
                return False
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
                    return False
                return True
            except (ValueError, TypeError):
                return False

        # Filter out invalid IPs from attackers list
        attackers = [a for a in attackers if is_valid_reportable_ip(getattr(a, 'ip_address', ''))]

        total_attackers = len(attackers)
        critical_count = sum(1 for a in attackers if getattr(a, 'risk_score', 0) >= 85)
        high_count = sum(1 for a in attackers if 70 <= getattr(a, 'risk_score', 0) < 85)
        medium_count = sum(1 for a in attackers if 40 <= getattr(a, 'risk_score', 0) < 70)
        low_count = sum(1 for a in attackers if getattr(a, 'risk_score', 0) < 40)
        total_events = sum(getattr(a, 'attack_count', 0) for a in attackers)

        # Get validation stats
        ml_validated = validation_results.get('ml_validated', 0)
        ti_validated = validation_results.get('ti_validated', 0)
        mitre_mapped = validation_results.get('mitre_mapped', 0)

        # ============ THREAT LEVEL DETERMINATION ============
        # Dynamic threat level based on actual threat counts
        if critical_count >= 10:
            threat_level = "CRITICAL"
            threat_color = "#b91c1c"
            threat_bg_color = "#fef2f2"
            threat_border = "#f87171"
            exec_summary = f"IMMEDIATE EXECUTIVE ATTENTION REQUIRED. Your organization is experiencing a significant security incident with {critical_count} critical-severity threat actors actively targeting your infrastructure. Coordinated response recommended."
        elif critical_count >= 5:
            threat_level = "HIGH"
            threat_color = "#c2410c"
            threat_bg_color = "#fff7ed"
            threat_border = "#fb923c"
            exec_summary = f"HIGH-PRIORITY SECURITY ALERT. {critical_count} critical-risk attackers have been identified requiring immediate investigation. SOC team engagement recommended within the hour."
        elif critical_count >= 1:
            threat_level = "ELEVATED"
            threat_color = "#b45309"
            threat_bg_color = "#fffbeb"
            threat_border = "#fbbf24"
            exec_summary = f"Elevated threat activity detected. {critical_count} critical attacker(s) flagged for priority response. Security team should assess within 4 hours."
        elif high_count >= 3:
            # 3+ high-risk attackers = ELEVATED (even without critical)
            threat_level = "ELEVATED"
            threat_color = "#b45309"
            threat_bg_color = "#fffbeb"
            threat_border = "#fbbf24"
            exec_summary = f"Elevated threat activity detected. {high_count} high-risk attackers identified requiring investigation. Security team should assess within 4 hours."
        elif high_count >= 1:
            # Any high-risk attackers = MODERATE (not LOW!)
            threat_level = "MODERATE"
            threat_color = "#0369a1"
            threat_bg_color = "#f0f9ff"
            threat_border = "#38bdf8"
            exec_summary = f"Moderate threat activity with {high_count} high-risk attacker(s) under monitoring. Standard incident response procedures apply."
        elif medium_count >= 10 or total_attackers >= 50:
            # Many medium threats or high volume = MODERATE
            threat_level = "MODERATE"
            threat_color = "#0369a1"
            threat_bg_color = "#f0f9ff"
            threat_border = "#38bdf8"
            exec_summary = f"Moderate threat activity with {total_attackers} threat actors detected. {medium_count} medium-risk attackers under monitoring."
        else:
            threat_level = "LOW"
            threat_color = "#15803d"
            threat_bg_color = "#f0fdf4"
            threat_border = "#4ade80"
            exec_summary = f"Security posture is stable. {total_attackers} low-risk threat actors detected. Continue routine monitoring and maintain defensive posture."

        # ============ ATTACK TYPE ANALYSIS ============
        attack_type_counts = {}
        for attacker in attackers:
            if attacker.attack_types:
                for attack_type in attacker.attack_types:
                    attack_type_name = attack_type.value if hasattr(attack_type, 'value') else str(attack_type)
                    attack_type_counts[attack_type_name] = attack_type_counts.get(attack_type_name, 0) + attacker.attack_count

        top_attack_types = sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # ============ GEOGRAPHIC ANALYSIS ============
        country_counts = {}
        for attacker in attackers:
            if attacker.geo_location:
                country = attacker.geo_location.get('country') or attacker.geo_location.get('country_code') or 'Unknown'
                country_counts[country] = country_counts.get(country, 0) + 1

        top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # ============ BUILD ACTION ITEMS with priorities ============
        action_items = []

        # Critical priority actions
        if critical_count > 0:
            critical_ips = [a.ip_address for a in sorted(attackers, key=lambda x: x.risk_score, reverse=True) if a.risk_score >= 85][:5]
            action_items.append({
                'priority': 'CRITICAL',
                'priority_color': '#b91c1c',
                'action': f'Block {critical_count} critical-risk IP addresses at perimeter firewall',
                'owner': 'Network Security Team',
                'details': f'Top IPs: {", ".join(critical_ips)}'
            })

        if high_count > 3:
            action_items.append({
                'priority': 'HIGH',
                'priority_color': '#c2410c',
                'action': f'Review and assess {high_count} high-risk attackers for potential blocking',
                'owner': 'SOC Analyst',
                'details': 'Analyze attack patterns and determine if blocking is warranted'
            })

        # Attack-type specific actions with mitigations
        if any('sql_injection' in str(at).lower() for at in attack_type_counts.keys()):
            action_items.append({
                'priority': 'HIGH',
                'priority_color': '#c2410c',
                'action': 'Enable WAF SQL injection protection rules',
                'owner': 'Application Security',
                'details': 'Review database access logs, enable parameterized queries, update WAF signatures'
            })

        if any('brute_force' in str(at).lower() for at in attack_type_counts.keys()):
            action_items.append({
                'priority': 'HIGH',
                'priority_color': '#c2410c',
                'action': 'Strengthen authentication controls',
                'owner': 'Identity & Access Management',
                'details': 'Implement account lockout after 5 failed attempts, enforce MFA for all privileged accounts'
            })

        if any('xss' in str(at).lower() for at in attack_type_counts.keys()):
            action_items.append({
                'priority': 'MEDIUM',
                'priority_color': '#b45309',
                'action': 'Review input sanitization in web applications',
                'owner': 'Development Team',
                'details': 'Enable Content Security Policy headers, sanitize all user inputs'
            })

        if any('reconnaissance' in str(at).lower() for at in attack_type_counts.keys()):
            action_items.append({
                'priority': 'MEDIUM',
                'priority_color': '#b45309',
                'action': 'Review network exposure and attack surface',
                'owner': 'Infrastructure Team',
                'details': 'Audit exposed services, disable unnecessary ports, implement rate limiting'
            })

        # Add standard recommendations if no specific actions
        if not action_items:
            action_items.append({
                'priority': 'LOW',
                'priority_color': '#15803d',
                'action': 'Continue routine security monitoring',
                'owner': 'SOC Team',
                'details': 'No immediate action required. Maintain current security posture.'
            })

        # ============ BUILD MITIGATION STRATEGIES ============
        mitigation_items = []

        if critical_count > 0 or high_count > 5:
            mitigation_items.append({
                'category': 'Immediate Response',
                'strategy': 'Implement emergency IP blocking via automated SOAR playbook or manual firewall rules',
                'impact': 'Prevents ongoing attack traffic'
            })

        if any('brute_force' in str(at).lower() for at in attack_type_counts.keys()):
            mitigation_items.append({
                'category': 'Authentication Hardening',
                'strategy': 'Deploy adaptive MFA, implement CAPTCHA after failed attempts, enable account lockout policies',
                'impact': 'Reduces credential stuffing success rate by 99%'
            })

        if any('sql_injection' in str(at).lower() for at in attack_type_counts.keys()):
            mitigation_items.append({
                'category': 'Database Protection',
                'strategy': 'Enable WAF virtual patching, implement prepared statements, restrict DB user privileges',
                'impact': 'Eliminates SQL injection attack vector'
            })

        if top_countries:
            top_origin = top_countries[0][0]
            mitigation_items.append({
                'category': 'Geo-blocking',
                'strategy': f'Consider geo-fencing or increased scrutiny for traffic from {top_origin} ({top_countries[0][1]} attackers)',
                'impact': 'Reduces attack surface from high-risk regions'
            })

        mitigation_items.append({
            'category': 'Long-term Hardening',
            'strategy': 'Review network segmentation, update IDS/IPS signatures, conduct penetration testing',
            'impact': 'Improves overall security posture'
        })

        # Build top attackers table rows
        top_attackers_html = ""
        for attacker in sorted(attackers, key=lambda x: getattr(x, 'risk_score', 0), reverse=True)[:10]:
            risk_score = round(getattr(attacker, 'risk_score', 0))
            risk_color = "#cc0000" if risk_score >= 85 else "#cc6600" if risk_score >= 70 else "#cc9900" if risk_score >= 40 else "#339933"
            geo = getattr(attacker, 'geo_location', None)
            country = (geo.get('country') or geo.get('country_code') or 'Unknown') if geo else 'Unknown'
            attack_types_str = ', '.join([t.value if hasattr(t, 'value') else str(t) for t in list(attacker.attack_types)[:3]]) if getattr(attacker, 'attack_types', None) else 'Unknown'

            attack_count = getattr(attacker, 'attack_count', 0)
            ip_address = getattr(attacker, 'ip_address', 'Unknown')
            top_attackers_html += f"""
                <tr style="background-color: #ffffff;">
                    <td style="padding: 10px 12px; border-bottom: 1px solid #dddddd; font-family: Arial, sans-serif; font-size: 13px; color: #333333;">{ip_address}</td>
                    <td style="padding: 10px 12px; border-bottom: 1px solid #dddddd; font-family: Arial, sans-serif; font-size: 16px; font-weight: bold; color: {risk_color}; text-align: center;">{risk_score}</td>
                    <td style="padding: 10px 12px; border-bottom: 1px solid #dddddd; font-family: Arial, sans-serif; font-size: 13px; color: #333333; text-align: center;">{attack_count:,}</td>
                    <td style="padding: 10px 12px; border-bottom: 1px solid #dddddd; font-family: Arial, sans-serif; font-size: 13px; color: #333333;">{country}</td>
                    <td style="padding: 10px 12px; border-bottom: 1px solid #dddddd; font-family: Arial, sans-serif; font-size: 11px; color: #666666;">{attack_types_str}</td>
                </tr>"""

        # Build attack types list
        attack_types_list = ""
        for attack_type, count in top_attack_types[:5]:
            percentage = (count / total_events * 100) if total_events > 0 else 0
            attack_types_list += f'<tr><td style="padding: 5px 0; font-family: Arial, sans-serif; font-size: 13px; color: #333333;">{attack_type.replace("_", " ").title()}: <strong>{count:,}</strong> ({percentage:.1f}%)</td></tr>'

        # Build geo list
        geo_list = ""
        for country, count in top_countries[:5]:
            percentage = (count / total_attackers * 100) if total_attackers > 0 else 0
            geo_list += f'<tr><td style="padding: 5px 0; font-family: Arial, sans-serif; font-size: 13px; color: #333333;">{country}: <strong>{count}</strong> attackers ({percentage:.1f}%)</td></tr>'

        # Build action items HTML
        action_items_html = ""
        for item in action_items:
            action_items_html += f"""
                <tr>
                    <td style="padding: 12px 15px; border-bottom: 1px solid #e2e8f0; vertical-align: top;">
                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                            <tr>
                                <td>
                                    <span style="display: inline-block; background-color: {item['priority_color']}; color: #ffffff; padding: 3px 8px; border-radius: 3px; font-family: Arial, sans-serif; font-size: 10px; font-weight: bold; letter-spacing: 0.5px;">{item['priority']}</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="font-family: Arial, sans-serif; font-size: 14px; font-weight: bold; color: #1f2937; padding: 8px 0 4px 0;">{item['action']}</td>
                            </tr>
                            <tr>
                                <td style="font-family: Arial, sans-serif; font-size: 12px; color: #6b7280;">Owner: <strong>{item['owner']}</strong></td>
                            </tr>
                            <tr>
                                <td style="font-family: Arial, sans-serif; font-size: 12px; color: #6b7280; padding-top: 4px;">{item['details']}</td>
                            </tr>
                        </table>
                    </td>
                </tr>"""

        # Build mitigation items HTML
        mitigation_items_html = ""
        for item in mitigation_items:
            mitigation_items_html += f"""
                <tr>
                    <td style="padding: 12px 15px; border-bottom: 1px solid #e2e8f0;">
                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                            <tr>
                                <td style="font-family: Arial, sans-serif; font-size: 12px; font-weight: bold; color: #059669; text-transform: uppercase; letter-spacing: 0.5px;">{item['category']}</td>
                            </tr>
                            <tr>
                                <td style="font-family: Arial, sans-serif; font-size: 13px; color: #1f2937; padding: 6px 0;">{item['strategy']}</td>
                            </tr>
                            <tr>
                                <td style="font-family: Arial, sans-serif; font-size: 11px; color: #059669; font-style: italic;">Impact: {item['impact']}</td>
                            </tr>
                        </table>
                    </td>
                </tr>"""

        # Build CISO-STYLE EXECUTIVE BRIEFING HTML
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Executive Briefing</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f3f4f6; font-family: Arial, Helvetica, sans-serif;">
    <!-- Wrapper Table -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 20px 10px;">
                <!-- Main Container -->
                <table role="presentation" width="700" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border: 1px solid #e5e7eb; max-width: 700px;">

                    <!-- EXECUTIVE HEADER -->
                    <tr>
                        <td style="background-color: #111827; padding: 25px 30px;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 11px; font-weight: bold; letter-spacing: 2px; color: #9ca3af; text-transform: uppercase;">
                                        Security Operations Center
                                    </td>
                                </tr>
                                <tr>
                                    <td style="font-family: Georgia, serif; font-size: 26px; font-weight: bold; color: #ffffff; padding: 8px 0;">
                                        Executive Security Briefing
                                    </td>
                                </tr>
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 13px; color: #9ca3af;">
                                        {datetime.now().strftime('%B %d, %Y at %H:%M')} | Analysis Period: {report_data.get('time_range_hours', 24)} Hours
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- THREAT STATUS BANNER -->
                    <tr>
                        <td style="background-color: {threat_bg_color}; padding: 20px 30px; border-left: 5px solid {threat_color};">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 11px; font-weight: bold; letter-spacing: 1px; color: {threat_color}; text-transform: uppercase;">
                                        Current Threat Level: {threat_level}
                                    </td>
                                </tr>
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 14px; color: #374151; padding-top: 10px; line-height: 1.5;">
                                        {exec_summary}
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- KEY METRICS SUMMARY -->
                    <tr>
                        <td style="padding: 25px 30px; border-bottom: 1px solid #e5e7eb;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 13px; font-weight: bold; color: #374151; text-transform: uppercase; letter-spacing: 1px; padding-bottom: 15px;">
                                        Threat Summary
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        <table role="presentation" width="100%" cellpadding="8" cellspacing="0">
                                            <tr>
                                                <td width="25%" style="background-color: #f9fafb; border: 1px solid #e5e7eb; text-align: center; padding: 15px;">
                                                    <div style="font-family: Arial, sans-serif; font-size: 28px; font-weight: bold; color: #111827;">{total_attackers:,}</div>
                                                    <div style="font-family: Arial, sans-serif; font-size: 10px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; padding-top: 4px;">Threat Actors</div>
                                                </td>
                                                <td width="25%" style="background-color: #fef2f2; border: 1px solid #fecaca; text-align: center; padding: 15px;">
                                                    <div style="font-family: Arial, sans-serif; font-size: 28px; font-weight: bold; color: #b91c1c;">{critical_count:,}</div>
                                                    <div style="font-family: Arial, sans-serif; font-size: 10px; color: #991b1b; text-transform: uppercase; letter-spacing: 0.5px; padding-top: 4px;">Critical</div>
                                                </td>
                                                <td width="25%" style="background-color: #fff7ed; border: 1px solid #fed7aa; text-align: center; padding: 15px;">
                                                    <div style="font-family: Arial, sans-serif; font-size: 28px; font-weight: bold; color: #c2410c;">{high_count:,}</div>
                                                    <div style="font-family: Arial, sans-serif; font-size: 10px; color: #9a3412; text-transform: uppercase; letter-spacing: 0.5px; padding-top: 4px;">High Risk</div>
                                                </td>
                                                <td width="25%" style="background-color: #f9fafb; border: 1px solid #e5e7eb; text-align: center; padding: 15px;">
                                                    <div style="font-family: Arial, sans-serif; font-size: 28px; font-weight: bold; color: #111827;">{total_events:,}</div>
                                                    <div style="font-family: Arial, sans-serif; font-size: 10px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; padding-top: 4px;">Total Events</div>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- ACTION ITEMS SECTION -->
                    <tr>
                        <td style="padding: 25px 30px; border-bottom: 1px solid #e5e7eb;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 13px; font-weight: bold; color: #b91c1c; text-transform: uppercase; letter-spacing: 1px; padding-bottom: 15px;">
                                        Required Actions
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border: 1px solid #e5e7eb;">
                                            {action_items_html}
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- MITIGATION STRATEGIES SECTION -->
                    <tr>
                        <td style="padding: 25px 30px; border-bottom: 1px solid #e5e7eb;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 13px; font-weight: bold; color: #059669; text-transform: uppercase; letter-spacing: 1px; padding-bottom: 15px;">
                                        Mitigation Strategies
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border: 1px solid #e5e7eb; background-color: #f0fdf4;">
                                            {mitigation_items_html}
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- TOP THREAT ACTORS -->
                    <tr>
                        <td style="padding: 25px 30px; border-bottom: 1px solid #e5e7eb;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 13px; font-weight: bold; color: #374151; text-transform: uppercase; letter-spacing: 1px; padding-bottom: 15px;">
                                        Priority Threat Actors (Top 10)
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border: 1px solid #e5e7eb;">
                                            <tr style="background-color: #374151;">
                                                <th style="padding: 10px 12px; text-align: left; font-family: Arial, sans-serif; font-size: 11px; font-weight: bold; color: #ffffff; text-transform: uppercase;">IP Address</th>
                                                <th style="padding: 10px 12px; text-align: center; font-family: Arial, sans-serif; font-size: 11px; font-weight: bold; color: #ffffff; text-transform: uppercase;">Risk</th>
                                                <th style="padding: 10px 12px; text-align: center; font-family: Arial, sans-serif; font-size: 11px; font-weight: bold; color: #ffffff; text-transform: uppercase;">Events</th>
                                                <th style="padding: 10px 12px; text-align: left; font-family: Arial, sans-serif; font-size: 11px; font-weight: bold; color: #ffffff; text-transform: uppercase;">Origin</th>
                                                <th style="padding: 10px 12px; text-align: left; font-family: Arial, sans-serif; font-size: 11px; font-weight: bold; color: #ffffff; text-transform: uppercase;">TTPs</th>
                                            </tr>
                                            {top_attackers_html}
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- ATTACK ANALYSIS -->
                    <tr>
                        <td style="padding: 25px 30px; border-bottom: 1px solid #e5e7eb;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="15">
                                <tr>
                                    <td width="50%" style="background-color: #f9fafb; border: 1px solid #e5e7eb; padding: 15px; vertical-align: top;">
                                        <div style="font-family: Arial, sans-serif; font-size: 12px; font-weight: bold; color: #374151; text-transform: uppercase; letter-spacing: 0.5px; padding-bottom: 10px;">Attack Vectors</div>
                                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                            {attack_types_list if attack_types_list else '<tr><td style="font-family: Arial, sans-serif; font-size: 13px; color: #6b7280;">No attack types identified</td></tr>'}
                                        </table>
                                    </td>
                                    <td width="50%" style="background-color: #f9fafb; border: 1px solid #e5e7eb; padding: 15px; vertical-align: top;">
                                        <div style="font-family: Arial, sans-serif; font-size: 12px; font-weight: bold; color: #374151; text-transform: uppercase; letter-spacing: 0.5px; padding-bottom: 10px;">Geographic Attribution</div>
                                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                            {geo_list if geo_list else '<tr><td style="font-family: Arial, sans-serif; font-size: 13px; color: #6b7280;">Geographic data unavailable</td></tr>'}
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- INTELLIGENCE VALIDATION -->
                    <tr>
                        <td style="padding: 25px 30px; border-bottom: 1px solid #e5e7eb;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 13px; font-weight: bold; color: #374151; text-transform: uppercase; letter-spacing: 1px; padding-bottom: 15px;">
                                        Intelligence Validation Summary
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        <table role="presentation" width="100%" cellpadding="8" cellspacing="0">
                                            <tr>
                                                <td width="33%" style="background-color: #eff6ff; border: 1px solid #bfdbfe; padding: 15px; text-align: center;">
                                                    <div style="font-family: Arial, sans-serif; font-size: 22px; font-weight: bold; color: #1d4ed8;">{ml_validated:,}</div>
                                                    <div style="font-family: Arial, sans-serif; font-size: 10px; color: #3b82f6; text-transform: uppercase; padding-top: 4px;">ML Validated</div>
                                                </td>
                                                <td width="33%" style="background-color: #f5f3ff; border: 1px solid #c4b5fd; padding: 15px; text-align: center;">
                                                    <div style="font-family: Arial, sans-serif; font-size: 22px; font-weight: bold; color: #6d28d9;">{ti_validated:,}</div>
                                                    <div style="font-family: Arial, sans-serif; font-size: 10px; color: #7c3aed; text-transform: uppercase; padding-top: 4px;">TI Corroborated</div>
                                                </td>
                                                <td width="33%" style="background-color: #ecfdf5; border: 1px solid #a7f3d0; padding: 15px; text-align: center;">
                                                    <div style="font-family: Arial, sans-serif; font-size: 22px; font-weight: bold; color: #047857;">{mitre_mapped:,}</div>
                                                    <div style="font-family: Arial, sans-serif; font-size: 10px; color: #059669; text-transform: uppercase; padding-top: 4px;">MITRE Mapped</div>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- FOOTER -->
                    <tr>
                        <td style="background-color: #111827; padding: 20px 30px;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 12px; color: #9ca3af; padding-bottom: 8px;">
                                        <strong style="color: #ffffff;">SOC Defense System</strong> | Automated Security Intelligence Platform
                                    </td>
                                </tr>
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 11px; color: #6b7280; padding-bottom: 8px;">
                                        Detailed compliance reports (ISO 27001, GDPR, NIST, OWASP, SOC 2, Threat Intelligence) are attached.
                                    </td>
                                </tr>
                                <tr>
                                    <td style="font-family: Arial, sans-serif; font-size: 10px; color: #4b5563; border-top: 1px solid #374151; padding-top: 10px;">
                                        CONFIDENTIAL - For authorized recipients only. Do not forward without approval.
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                </table>
                <!-- End Main Container -->
            </td>
        </tr>
    </table>
</body>
</html>
        """

        return html
