"""
Gmail Email Sender Module for SOC Defense System
Sends validated security reports via Gmail API using OAuth2 authentication
"""

import os
import json
import logging
import base64
import urllib.request
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders


class GmailEmailSender:
    """Gmail Email Sender using OAuth2 and Gmail API"""

    # Gmail API endpoint
    GMAIL_API_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
    TOKEN_URL = "https://oauth2.googleapis.com/token"

    def __init__(self, client_id: str = "", client_secret: str = "", redirect_uri: str = "http://localhost:8089/callback"):
        """
        Initialize Gmail Email Sender

        Args:
            client_id: Google OAuth2 Client ID
            client_secret: Google OAuth2 Client Secret
            redirect_uri: OAuth2 redirect URI
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.access_token = ""
        self.refresh_token = ""
        self.user_email = ""
        self.logger = logging.getLogger(__name__)

        # Token/credential storage
        self.token_cache_file = Path("config/gmail_token_cache.json")
        self.token_cache_file.parent.mkdir(parents=True, exist_ok=True)

        # Load any cached credentials
        self._load_token_cache()

    def _load_token_cache(self):
        """Load cached credentials from file"""
        if self.token_cache_file.exists():
            try:
                cache_data = json.loads(self.token_cache_file.read_text())
                self.access_token = cache_data.get('access_token', '')
                self.refresh_token = cache_data.get('refresh_token', '')
                self.user_email = cache_data.get('user_email', '')
                if not self.client_id:
                    self.client_id = cache_data.get('client_id', '')
                if not self.client_secret:
                    self.client_secret = cache_data.get('client_secret', '')
                self.logger.info("Gmail credentials loaded from cache")
            except Exception as e:
                self.logger.warning(f"Could not load Gmail token cache: {e}")

    def _save_token_cache(self):
        """Save credentials to cache file"""
        try:
            cache_data = {
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'user_email': self.user_email,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'redirect_uri': self.redirect_uri,
                'timestamp': datetime.now().isoformat()
            }
            self.token_cache_file.write_text(json.dumps(cache_data, indent=2))
            self.logger.info("Gmail credentials saved to cache")
        except Exception as e:
            self.logger.warning(f"Could not save Gmail token cache: {e}")

    def _refresh_access_token(self) -> bool:
        """Refresh the access token using refresh token"""
        if not self.refresh_token or not self.client_id or not self.client_secret:
            return False

        try:
            data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': self.refresh_token,
                'grant_type': 'refresh_token'
            }

            req = urllib.request.Request(
                self.TOKEN_URL,
                data=urllib.parse.urlencode(data).encode(),
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                token_data = json.loads(response.read().decode())

            self.access_token = token_data.get('access_token', '')
            if self.access_token:
                self._save_token_cache()
                self.logger.info("Gmail access token refreshed successfully")
                return True
            return False

        except Exception as e:
            self.logger.error(f"Failed to refresh Gmail token: {e}")
            return False

    def is_authenticated(self) -> bool:
        """Check if we have valid credentials by testing Gmail API"""
        if not self.access_token:
            return False

        try:
            # Try to get user profile to verify token
            req = urllib.request.Request(
                "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                headers={'Authorization': f'Bearer {self.access_token}'}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                profile = json.loads(response.read().decode())
                self.user_email = profile.get('emailAddress', self.user_email)
                self.logger.info(f"Gmail API authentication successful for {self.user_email}")
                return True
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Token expired, try to refresh (only once to avoid infinite recursion)
                self.logger.info("Gmail token expired, attempting refresh...")
                if self._refresh_access_token():
                    # Verify the new token works without recursion
                    try:
                        req2 = urllib.request.Request(
                            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                            headers={'Authorization': f'Bearer {self.access_token}'}
                        )
                        with urllib.request.urlopen(req2, timeout=10) as response:
                            profile = json.loads(response.read().decode())
                            self.user_email = profile.get('emailAddress', self.user_email)
                            return True
                    except Exception:
                        return False
            try:
                error_body = e.read().decode() if hasattr(e, 'fp') and e.fp else str(e)
            except Exception:
                error_body = str(e)
            self.logger.error(f"Gmail authentication failed: {e.code} - {error_body}")
            return False
        except Exception as e:
            self.logger.error(f"Gmail connection error: {e}")
            return False

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
        Send an email via Gmail API

        Args:
            to_recipients: List of email addresses
            subject: Email subject
            body_html: HTML body content
            attachments: List of attachment dicts with 'name', 'content_type', 'content_bytes'
            cc_recipients: Optional CC recipients
            importance: Email importance (low, normal, high)
            _retry_count: Internal retry counter to prevent infinite recursion

        Returns:
            True if email sent successfully
        """
        if not self.access_token:
            self.logger.error("Not authenticated. Please authenticate first.")
            return False

        # Prevent infinite recursion on token refresh failures
        if _retry_count >= 1:
            self.logger.error("Max retry attempts exceeded for token refresh")
            return False

        try:
            # Create MIME message
            if attachments:
                message = MIMEMultipart()
                message.attach(MIMEText(body_html, 'html'))

                for attachment in attachments:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment['content_bytes'])
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename="{attachment["name"]}"'
                    )
                    message.attach(part)
            else:
                message = MIMEText(body_html, 'html')

            # Set headers
            message['To'] = ', '.join(to_recipients)
            message['From'] = self.user_email
            message['Subject'] = subject

            if cc_recipients:
                message['Cc'] = ', '.join(cc_recipients)

            # Set priority header
            priority_map = {'high': '1', 'normal': '3', 'low': '5'}
            message['X-Priority'] = priority_map.get(importance, '3')

            # Encode message for Gmail API
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

            # Send via Gmail API
            send_data = json.dumps({'raw': raw_message}).encode()

            req = urllib.request.Request(
                self.GMAIL_API_URL,
                data=send_data,
                headers={
                    'Authorization': f'Bearer {self.access_token}',
                    'Content-Type': 'application/json'
                },
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=60) as response:
                result = json.loads(response.read().decode())
                self.logger.info(f"Gmail: Email sent successfully to {', '.join(to_recipients)}")
                return True

        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else str(e)
            self.logger.error(f"Gmail API error {e.code}: {error_body}")

            if e.code == 401:
                # Token expired, try to refresh and retry (with retry count to prevent infinite recursion)
                if self._refresh_access_token():
                    return self.send_email(to_recipients, subject, body_html, attachments, cc_recipients, importance, _retry_count + 1)
            return False
        except Exception as e:
            self.logger.error(f"Error sending Gmail: {e}")
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
