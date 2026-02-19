"""
Indicator of Compromise (IoC) Matching Engine
Matches observables against known IoCs from multiple threat feeds
Supports various IoC types and formats
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import re
import hashlib
import ipaddress
from collections import defaultdict

class IoCType(Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"
    USER_AGENT = "user_agent"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    CVE = "cve"
    YARA_RULE = "yara_rule"
    SSL_CERT_FINGERPRINT = "ssl_cert"
    CRYPTOCURRENCY_ADDRESS = "crypto_address"

class IoCSeverity(Enum):
    """IoC threat severity"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class IoC:
    """Indicator of Compromise"""
    ioc_id: str
    ioc_type: IoCType
    value: str
    severity: IoCSeverity

    # Threat context
    malware_family: Optional[str] = None
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None

    # Metadata
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    source: str = "manual"
    confidence: float = 0.5
    tags: Set[str] = field(default_factory=set)
    description: str = ""

    # MITRE ATT&CK
    mitre_techniques: List[str] = field(default_factory=list)

    # Tracking
    match_count: int = 0
    false_positive_count: int = 0
    active: bool = True
    expires_at: Optional[datetime] = None

@dataclass
class IoCMatch:
    """IoC match result"""
    match_id: str
    ioc_id: str
    ioc: IoC
    matched_value: str
    timestamp: datetime
    source_event: Dict[str, Any]
    confidence: float
    context: Dict[str, Any] = field(default_factory=dict)

class IoCMatcher:
    """
    High-performance IoC matching engine
    Matches observables against threat intelligence feeds
    """

    def __init__(self):
        # IoC database
        self.iocs: Dict[str, IoC] = {}

        # Indexed lookups for performance
        self.ioc_by_type: Dict[IoCType, Set[str]] = defaultdict(set)
        self.ioc_by_value: Dict[str, Set[str]] = defaultdict(set)

        # Match history
        self.matches: List[IoCMatch] = []

        # Whitelist (known good indicators)
        self.whitelist: Dict[IoCType, Set[str]] = defaultdict(set)

        # Statistics
        self.stats = {
            "total_matches": 0,
            "matches_by_type": defaultdict(int),
            "matches_by_severity": defaultdict(int)
        }

    def add_ioc(self,
                ioc_type: IoCType,
                value: str,
                severity: IoCSeverity,
                source: str = "manual",
                malware_family: str = None,
                threat_actor: str = None,
                campaign: str = None,
                tags: Set[str] = None,
                description: str = "",
                confidence: float = 0.5) -> IoC:
        """
        Add IoC to database

        Args:
            ioc_type: Type of IoC
            value: IoC value
            severity: Threat severity
            source: IoC source
            malware_family: Associated malware
            threat_actor: Associated threat actor
            campaign: Associated campaign
            tags: Tags
            description: Description
            confidence: Confidence score (0-1)

        Returns:
            Created IoC
        """
        # Normalize value
        normalized_value = self._normalize_value(ioc_type, value)

        # Generate ID
        ioc_id = hashlib.sha256(
            f"{ioc_type.value}:{normalized_value}".encode()
        ).hexdigest()[:16]

        # Check if exists
        if ioc_id in self.iocs:
            # Update existing
            existing = self.iocs[ioc_id]
            existing.last_seen = datetime.utcnow()
            existing.source = source
            if tags:
                existing.tags.update(tags)
            return existing

        # Create new IoC
        ioc = IoC(
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            value=normalized_value,
            severity=severity,
            malware_family=malware_family,
            threat_actor=threat_actor,
            campaign=campaign,
            source=source,
            confidence=confidence,
            tags=tags or set(),
            description=description
        )

        # Store
        self.iocs[ioc_id] = ioc
        self.ioc_by_type[ioc_type].add(ioc_id)
        self.ioc_by_value[normalized_value].add(ioc_id)

        return ioc

    def bulk_add_iocs(self, iocs: List[Dict[str, Any]]) -> int:
        """
        Bulk add IoCs from list

        Args:
            iocs: List of IoC dictionaries

        Returns:
            Number of IoCs added
        """
        count = 0
        for ioc_data in iocs:
            try:
                self.add_ioc(
                    ioc_type=IoCType[ioc_data["type"]],
                    value=ioc_data["value"],
                    severity=IoCSeverity[ioc_data.get("severity", "MEDIUM")],
                    source=ioc_data.get("source", "bulk_import"),
                    malware_family=ioc_data.get("malware_family"),
                    threat_actor=ioc_data.get("threat_actor"),
                    campaign=ioc_data.get("campaign"),
                    tags=set(ioc_data.get("tags", [])),
                    description=ioc_data.get("description", ""),
                    confidence=ioc_data.get("confidence", 0.5)
                )
                count += 1
            except Exception as e:
                print(f"Failed to add IoC {ioc_data.get('value')}: {e}")

        return count

    def match_event(self, event: Dict[str, Any]) -> List[IoCMatch]:
        """
        Match event against all IoCs

        Args:
            event: Event to check

        Returns:
            List of matches
        """
        matches = []

        # Extract observables from event
        observables = self._extract_observables(event)

        # Check each observable
        for obs_type, obs_value in observables:
            match = self._match_observable(obs_type, obs_value, event)
            if match:
                matches.extend(match)

        # Update statistics
        for match in matches:
            self.stats["total_matches"] += 1
            self.stats["matches_by_type"][match.ioc.ioc_type.value] += 1
            self.stats["matches_by_severity"][match.ioc.severity.value] += 1

            # Update IoC match count
            match.ioc.match_count += 1

        # Store matches
        self.matches.extend(matches)

        return matches

    def match_observable(self,
                        ioc_type: IoCType,
                        value: str,
                        confidence_threshold: float = 0.0) -> List[IoC]:
        """
        Match single observable against IoC database

        Args:
            ioc_type: Type of observable
            value: Observable value
            confidence_threshold: Minimum confidence

        Returns:
            List of matching IoCs
        """
        normalized = self._normalize_value(ioc_type, value)

        # Check whitelist
        if normalized in self.whitelist[ioc_type]:
            return []

        # Direct lookup
        matching_ioc_ids = self.ioc_by_value.get(normalized, set())

        # Get IoC objects
        matches = []
        for ioc_id in matching_ioc_ids:
            ioc = self.iocs.get(ioc_id)
            if ioc and ioc.active and ioc.confidence >= confidence_threshold:
                # Check expiration
                if ioc.expires_at and ioc.expires_at < datetime.utcnow():
                    ioc.active = False
                    continue
                matches.append(ioc)

        # Pattern matching for domains/URLs
        if ioc_type in [IoCType.DOMAIN, IoCType.URL] and not matches:
            matches.extend(self._pattern_match(ioc_type, normalized))

        return matches

    def search_iocs(self,
                   ioc_type: Optional[IoCType] = None,
                   severity: Optional[IoCSeverity] = None,
                   malware_family: Optional[str] = None,
                   threat_actor: Optional[str] = None,
                   campaign: Optional[str] = None,
                   tags: Optional[Set[str]] = None,
                   min_confidence: float = 0.0) -> List[IoC]:
        """
        Search IoC database with filters

        Args:
            ioc_type: Filter by type
            severity: Filter by severity
            malware_family: Filter by malware
            threat_actor: Filter by actor
            campaign: Filter by campaign
            tags: Filter by tags
            min_confidence: Minimum confidence

        Returns:
            Matching IoCs
        """
        results = []

        # Start with type filter if provided
        if ioc_type:
            candidate_ids = self.ioc_by_type.get(ioc_type, set())
        else:
            candidate_ids = set(self.iocs.keys())

        for ioc_id in candidate_ids:
            ioc = self.iocs[ioc_id]

            # Apply filters
            if severity and ioc.severity != severity:
                continue

            if malware_family and ioc.malware_family != malware_family:
                continue

            if threat_actor and ioc.threat_actor != threat_actor:
                continue

            if campaign and ioc.campaign != campaign:
                continue

            if tags and not tags.issubset(ioc.tags):
                continue

            if ioc.confidence < min_confidence:
                continue

            if not ioc.active:
                continue

            results.append(ioc)

        return results

    def add_to_whitelist(self, ioc_type: IoCType, value: str):
        """Add value to whitelist (known good)"""
        normalized = self._normalize_value(ioc_type, value)
        self.whitelist[ioc_type].add(normalized)

    def remove_from_whitelist(self, ioc_type: IoCType, value: str):
        """Remove value from whitelist"""
        normalized = self._normalize_value(ioc_type, value)
        self.whitelist[ioc_type].discard(normalized)

    def mark_false_positive(self, match_id: str):
        """Mark match as false positive"""
        for match in self.matches:
            if match.match_id == match_id:
                match.ioc.false_positive_count += 1

                # Auto-deactivate if too many false positives
                if match.ioc.false_positive_count > 5:
                    match.ioc.active = False
                break

    def get_recent_matches(self, hours: int = 24) -> List[IoCMatch]:
        """Get recent matches"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return [m for m in self.matches if m.timestamp > cutoff]

    def get_top_iocs(self, limit: int = 10) -> List[IoC]:
        """Get most frequently matched IoCs"""
        sorted_iocs = sorted(
            self.iocs.values(),
            key=lambda x: x.match_count,
            reverse=True
        )
        return sorted_iocs[:limit]

    def export_iocs(self,
                   format: str = "stix",
                   ioc_type: Optional[IoCType] = None) -> Dict[str, Any]:
        """
        Export IoCs in various formats

        Args:
            format: Export format (stix, csv, json)
            ioc_type: Filter by type

        Returns:
            Exported data
        """
        # Filter IoCs
        if ioc_type:
            iocs = [ioc for ioc in self.iocs.values() if ioc.ioc_type == ioc_type]
        else:
            iocs = list(self.iocs.values())

        if format == "stix":
            return self._export_stix(iocs)
        elif format == "json":
            return self._export_json(iocs)
        elif format == "csv":
            return self._export_csv(iocs)
        else:
            return {"error": "Unsupported format"}

    def _extract_observables(self, event: Dict[str, Any]) -> List[tuple]:
        """Extract observables from event"""
        observables = []

        # IP addresses
        if "source_ip" in event:
            observables.append((IoCType.IP_ADDRESS, event["source_ip"]))
        if "dest_ip" in event:
            observables.append((IoCType.IP_ADDRESS, event["dest_ip"]))

        # Domains
        if "domain" in event:
            observables.append((IoCType.DOMAIN, event["domain"]))

        # URLs
        if "url" in event:
            observables.append((IoCType.URL, event["url"]))

        # File hashes
        if "md5" in event:
            observables.append((IoCType.FILE_HASH_MD5, event["md5"]))
        if "sha1" in event:
            observables.append((IoCType.FILE_HASH_SHA1, event["sha1"]))
        if "sha256" in event:
            observables.append((IoCType.FILE_HASH_SHA256, event["sha256"]))

        # Email
        if "email" in event:
            observables.append((IoCType.EMAIL, event["email"]))

        # User Agent
        if "user_agent" in event:
            observables.append((IoCType.USER_AGENT, event["user_agent"]))

        return observables

    def _match_observable(self,
                         obs_type: IoCType,
                         obs_value: str,
                         event: Dict) -> List[IoCMatch]:
        """Match single observable"""
        matching_iocs = self.match_observable(obs_type, obs_value)

        matches = []
        for ioc in matching_iocs:
            match = IoCMatch(
                match_id=hashlib.sha256(
                    f"{ioc.ioc_id}:{obs_value}:{datetime.utcnow()}".encode()
                ).hexdigest()[:12],
                ioc_id=ioc.ioc_id,
                ioc=ioc,
                matched_value=obs_value,
                timestamp=datetime.utcnow(),
                source_event=event,
                confidence=ioc.confidence,
                context={
                    "event_type": event.get("event_type"),
                    "severity": ioc.severity.value,
                    "malware_family": ioc.malware_family,
                    "threat_actor": ioc.threat_actor
                }
            )
            matches.append(match)

        return matches

    def _normalize_value(self, ioc_type: IoCType, value: str) -> str:
        """Normalize IoC value"""
        value = value.strip().lower()

        if ioc_type == IoCType.IP_ADDRESS:
            # Validate IP
            try:
                ipaddress.ip_address(value)
                return value
            except (ValueError, TypeError):
                return value

        elif ioc_type == IoCType.DOMAIN:
            # Remove protocol
            value = re.sub(r'^https?://', '', value)
            # Remove trailing slash
            value = value.rstrip('/')
            return value

        elif ioc_type in [IoCType.FILE_HASH_MD5, IoCType.FILE_HASH_SHA1, IoCType.FILE_HASH_SHA256]:
            return value.lower()

        return value

    def _pattern_match(self, ioc_type: IoCType, value: str) -> List[IoC]:
        """Pattern-based matching for domains/URLs"""
        matches = []

        # Get all IoCs of this type
        for ioc_id in self.ioc_by_type.get(ioc_type, set()):
            ioc = self.iocs[ioc_id]

            # Check if value matches pattern
            if '*' in ioc.value or '?' in ioc.value:
                # Convert wildcard to regex
                pattern = ioc.value.replace('.', '\\.').replace('*', '.*').replace('?', '.')
                if re.match(f'^{pattern}$', value):
                    matches.append(ioc)

        return matches

    def _export_stix(self, iocs: List[IoC]) -> Dict[str, Any]:
        """Export as STIX 2.1 format"""
        stix_objects = []

        for ioc in iocs:
            stix_obj = {
                "type": "indicator",
                "id": f"indicator--{ioc.ioc_id}",
                "created": ioc.first_seen.isoformat(),
                "modified": ioc.last_seen.isoformat(),
                "name": f"{ioc.ioc_type.value}: {ioc.value}",
                "pattern": f"[{self._ioc_type_to_stix(ioc.ioc_type)}:value = '{ioc.value}']",
                "pattern_type": "stix",
                "valid_from": ioc.first_seen.isoformat(),
                "labels": list(ioc.tags)
            }
            stix_objects.append(stix_obj)

        return {
            "type": "bundle",
            "id": f"bundle--{hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest()[:16]}",
            "objects": stix_objects
        }

    def _export_json(self, iocs: List[IoC]) -> Dict[str, Any]:
        """Export as JSON"""
        return {
            "iocs": [
                {
                    "id": ioc.ioc_id,
                    "type": ioc.ioc_type.value,
                    "value": ioc.value,
                    "severity": ioc.severity.value,
                    "malware_family": ioc.malware_family,
                    "threat_actor": ioc.threat_actor,
                    "campaign": ioc.campaign,
                    "first_seen": ioc.first_seen.isoformat(),
                    "last_seen": ioc.last_seen.isoformat(),
                    "source": ioc.source,
                    "confidence": ioc.confidence,
                    "tags": list(ioc.tags),
                    "match_count": ioc.match_count
                }
                for ioc in iocs
            ]
        }

    def _export_csv(self, iocs: List[IoC]) -> str:
        """Export as CSV"""
        lines = ["type,value,severity,malware_family,threat_actor,confidence,tags"]

        for ioc in iocs:
            line = f"{ioc.ioc_type.value},{ioc.value},{ioc.severity.value},"
            line += f"{ioc.malware_family or ''},{ioc.threat_actor or ''},"
            line += f"{ioc.confidence},{';'.join(ioc.tags)}"
            lines.append(line)

        return "\n".join(lines)

    def _ioc_type_to_stix(self, ioc_type: IoCType) -> str:
        """Map IoC type to STIX observable type"""
        mapping = {
            IoCType.IP_ADDRESS: "ipv4-addr",
            IoCType.DOMAIN: "domain-name",
            IoCType.URL: "url",
            IoCType.FILE_HASH_MD5: "file:hashes.MD5",
            IoCType.FILE_HASH_SHA1: "file:hashes.SHA-1",
            IoCType.FILE_HASH_SHA256: "file:hashes.SHA-256",
            IoCType.EMAIL: "email-addr"
        }
        return mapping.get(ioc_type, "x-custom")

    def get_statistics(self) -> Dict[str, Any]:
        """Get IoC matching statistics"""
        return {
            "total_iocs": len(self.iocs),
            "active_iocs": len([i for i in self.iocs.values() if i.active]),
            "by_type": {k.value: len(v) for k, v in self.ioc_by_type.items()},
            "total_matches": self.stats["total_matches"],
            "matches_by_type": dict(self.stats["matches_by_type"]),
            "matches_by_severity": dict(self.stats["matches_by_severity"]),
            "whitelist_size": sum(len(v) for v in self.whitelist.values())
        }
