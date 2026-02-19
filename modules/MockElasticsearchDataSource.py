"""
Mock Elasticsearch Data Source - No Network Required
Returns data from local evidence vault instead of remote Elasticsearch

Use this when:
- Elasticsearch server is unavailable
- Testing/development without network
- Working offline
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import logging


class MockElasticsearchDataSource:
    """
    Mock Elasticsearch that reads from local evidence vault
    Drop-in replacement for ElasticsearchDataSource
    """

    def __init__(self, evidence_vault_path: str = "./evidence_vault/evidence_registry.json",
                 **kwargs):
        """
        Initialize mock Elasticsearch

        Args:
            evidence_vault_path: Path to evidence vault JSON file
            **kwargs: Ignored (for compatibility with real ElasticsearchDataSource)
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.evidence_vault_path = Path(evidence_vault_path)
        self.evidence_data = {}

        # Ignore real Elasticsearch parameters
        if kwargs:
            ignored_params = list(kwargs.keys())
            self.logger.info(f"[MOCK] Ignoring Elasticsearch params: {ignored_params}")

        # Load evidence vault
        self._load_evidence()

        self.logger.info(f"[MOCK MODE] Using local evidence vault")
        self.logger.info(f"[MOCK MODE] Loaded {len(self.evidence_data)} evidence items")

    def _load_evidence(self):
        """Load evidence from vault"""
        if self.evidence_vault_path.exists():
            try:
                with open(self.evidence_vault_path, 'r', encoding='utf-8') as f:
                    self.evidence_data = json.load(f)
                self.logger.info(f"[OK] Loaded evidence from {self.evidence_vault_path}")
            except Exception as e:
                self.logger.error(f"[ERROR] Failed to load evidence: {e}")
                self.evidence_data = {}
        else:
            self.logger.warning(f"[WARNING] Evidence vault not found: {self.evidence_vault_path}")
            self.logger.warning(f"[WARNING] Expected location: {self.evidence_vault_path.absolute()}")

    def query(self, query: Dict[str, Any], index: str = "*", size: int = 100) -> List[Dict[str, Any]]:
        """
        Mock query - returns evidence vault data

        Args:
            query: Elasticsearch query (ignored in mock)
            index: Index to query (ignored in mock)
            size: Maximum results to return

        Returns:
            List of documents in Elasticsearch format
        """
        self.logger.debug(f"[MOCK] Query received (returning evidence vault data)")

        # Convert evidence to Elasticsearch-like format
        results = []
        for evidence_id, evidence in list(self.evidence_data.items())[:size]:
            results.append({
                '_id': evidence_id,
                '_index': 'wazuh-alerts',
                '_type': '_doc',
                '_score': 1.0,
                '_source': {
                    'timestamp': evidence.get('collected_at', datetime.now().isoformat()),
                    'rule': {
                        'description': evidence.get('description', 'Mock alert'),
                        'level': 10,
                        'id': '100001'
                    },
                    'agent': {
                        'ip': evidence.get('source_system', '127.0.0.1'),
                        'name': 'mock-agent'
                    },
                    'full_log': evidence.get('description', ''),
                    'data': evidence,
                    # Original evidence data
                    'evidence_id': evidence_id,
                    'incident_id': evidence.get('incident_id', ''),
                    'tags': evidence.get('tags', []),
                }
            })

        self.logger.debug(f"[MOCK] Returning {len(results)} results")
        return results

    def is_available(self) -> bool:
        """
        Check if mock data source is available

        Returns:
            True if evidence vault loaded successfully
        """
        available = len(self.evidence_data) > 0
        if available:
            self.logger.debug("[MOCK] Data source available")
        else:
            self.logger.warning("[MOCK] Data source unavailable (no evidence loaded)")
        return available

    def get_recent_alerts(self, hours: int = 24, severity_min: int = 0) -> List[Dict[str, Any]]:
        """
        Get recent alerts from evidence vault

        Args:
            hours: Hours back to search
            severity_min: Minimum severity level

        Returns:
            List of recent alerts
        """
        self.logger.info(f"[MOCK] Getting recent alerts (last {hours}h, severity >= {severity_min})")

        cutoff_time = datetime.now() - timedelta(hours=hours)
        results = []

        for evidence_id, evidence in self.evidence_data.items():
            # Parse timestamp
            timestamp_str = evidence.get('collected_at', '')
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    if timestamp < cutoff_time:
                        continue  # Too old
                except (ValueError, TypeError):
                    pass

            # Check severity
            tags = evidence.get('tags', [])
            severity = 5  # Default

            for tag in tags:
                if 'severity_' in tag:
                    try:
                        sev = int(tag.split('_')[1])
                        severity = sev
                    except (ValueError, IndexError):
                        pass

            if severity < severity_min:
                continue

            results.append({
                '_id': evidence_id,
                '_source': evidence
            })

        self.logger.info(f"[MOCK] Found {len(results)} recent alerts")
        return results

    def search_by_ip(self, ip_address: str, hours: int = 168) -> List[Dict[str, Any]]:
        """
        Search for alerts related to specific IP

        Args:
            ip_address: IP address to search for
            hours: Hours back to search

        Returns:
            List of alerts for this IP
        """
        self.logger.info(f"[MOCK] Searching for IP: {ip_address}")

        results = []

        for evidence_id, evidence in self.evidence_data.items():
            incident_id = evidence.get('incident_id', '')

            # Check if IP is in incident ID
            if ip_address in incident_id or ip_address.replace('.', '-') in incident_id:
                results.append({
                    '_id': evidence_id,
                    '_source': evidence
                })

        self.logger.info(f"[MOCK] Found {len(results)} alerts for {ip_address}")
        return results

    def get_alert_count(self, hours: int = 24) -> int:
        """
        Get total alert count

        Args:
            hours: Hours back to count

        Returns:
            Number of alerts
        """
        alerts = self.get_recent_alerts(hours=hours)
        count = len(alerts)
        self.logger.debug(f"[MOCK] Alert count (last {hours}h): {count}")
        return count

    def get_unique_ips(self, hours: int = 24) -> List[str]:
        """
        Get list of unique source IPs

        Args:
            hours: Hours back to search

        Returns:
            List of unique IP addresses
        """
        ips = set()

        for evidence_id, evidence in self.evidence_data.items():
            incident_id = evidence.get('incident_id', '')

            if incident_id and '-' in incident_id:
                parts = incident_id.split('-')
                if len(parts) >= 3:
                    ip = '-'.join(parts[1:-1])
                    ips.add(ip)

        ip_list = sorted(list(ips))
        self.logger.info(f"[MOCK] Found {len(ip_list)} unique IPs")
        return ip_list

    def close(self):
        """Close connection (no-op for mock)"""
        self.logger.debug("[MOCK] Close called (no-op)")
        pass

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Compatibility alias
LocalDataSource = MockElasticsearchDataSource
