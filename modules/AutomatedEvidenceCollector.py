"""
Automated Evidence Collection System
Automatically collects, preserves, and catalogs digital evidence
Maintains chain of custody for forensic integrity
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter
import hashlib
import json
import gzip
import shutil
import os

class EvidenceType(Enum):
    """Types of digital evidence"""
    LOG_FILE = "log_file"
    NETWORK_CAPTURE = "network_capture"
    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image"
    SCREENSHOT = "screenshot"
    DATABASE_EXPORT = "database_export"
    EMAIL = "email"
    REGISTRY_EXPORT = "registry_export"
    PROCESS_LIST = "process_list"
    CONFIGURATION_FILE = "configuration_file"
    MALWARE_SAMPLE = "malware_sample"
    ARTIFACT = "artifact"

class EvidenceState(Enum):
    """Evidence collection state"""
    PENDING = "pending"
    COLLECTING = "collecting"
    COLLECTED = "collected"
    PRESERVED = "preserved"
    ANALYZED = "analyzed"
    ARCHIVED = "archived"
    DELETED = "deleted"

@dataclass
class ChainOfCustodyEntry:
    """Chain of custody record"""
    timestamp: datetime
    action: str
    actor: str
    location: str
    hash_before: Optional[str] = None
    hash_after: Optional[str] = None
    notes: str = ""

@dataclass
class Evidence:
    """Digital evidence record"""
    evidence_id: str
    incident_id: str
    evidence_type: EvidenceType
    state: EvidenceState

    # Source information
    source_system: str
    source_path: str
    collection_method: str

    # Collection metadata
    collected_at: datetime
    collected_by: str

    # Storage information
    storage_path: str
    file_size: int

    # Integrity verification
    md5_hash: str
    sha256_hash: str

    # Chain of custody
    chain_of_custody: List[ChainOfCustodyEntry] = field(default_factory=list)

    # Metadata
    tags: Set[str] = field(default_factory=set)
    description: str = ""
    classification: str = "confidential"
    retention_days: int = 2555  # 7 years default

    # Analysis
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    related_evidence: List[str] = field(default_factory=list)

    # Timestamps
    expires_at: Optional[datetime] = None
    last_accessed: datetime = field(default_factory=datetime.utcnow)

class AutomatedEvidenceCollector:
    """
    Automated digital evidence collection and preservation
    Ensures forensic integrity with chain of custody
    """

    def __init__(self, evidence_vault: str = "./evidence_vault"):
        self.vault_path = Path(evidence_vault)
        self.vault_path.mkdir(parents=True, exist_ok=True)

        # Evidence registry
        self.evidence_registry: Dict[str, Evidence] = {}

        # Collection rules
        self.collection_rules = self._init_collection_rules()

        # Load existing evidence
        self._load_registry()

    def trigger_collection(self,
                          incident_id: str,
                          trigger_type: str,
                          context: Dict[str, Any]) -> List[str]:
        """
        Trigger automated evidence collection based on incident

        Args:
            incident_id: Incident identifier
            trigger_type: Type of trigger (e.g., "ransomware_detected")
            context: Context information for collection

        Returns:
            List of evidence IDs collected
        """
        evidence_ids = []

        # Get collection rules for trigger
        rules = self.collection_rules.get(trigger_type, [])

        for rule in rules:
            try:
                evidence_id = self._execute_collection_rule(
                    incident_id,
                    rule,
                    context
                )
                if evidence_id:
                    evidence_ids.append(evidence_id)
            except Exception as e:
                print(f"Collection failed for rule {rule['name']}: {e}")

        return evidence_ids

    def collect_evidence(self,
                        incident_id: str,
                        evidence_type: EvidenceType,
                        source_system: str,
                        source_path: str,
                        collected_by: str,
                        description: str = "",
                        tags: Set[str] = None) -> Optional[Evidence]:
        """
        Manually collect evidence

        Args:
            incident_id: Incident ID
            evidence_type: Type of evidence
            source_system: Source system hostname/IP
            source_path: Path to evidence on source
            collected_by: Collector identifier
            description: Evidence description
            tags: Optional tags

        Returns:
            Evidence record
        """
        evidence_id = self._generate_evidence_id(incident_id, evidence_type)

        # Create evidence record
        evidence = Evidence(
            evidence_id=evidence_id,
            incident_id=incident_id,
            evidence_type=evidence_type,
            state=EvidenceState.COLLECTING,
            source_system=source_system,
            source_path=source_path,
            collection_method="manual",
            collected_at=datetime.utcnow(),
            collected_by=collected_by,
            storage_path="",
            file_size=0,
            md5_hash="",
            sha256_hash="",
            description=description,
            tags=tags or set()
        )

        # Collect and preserve
        try:
            self._collect_from_source(evidence, source_path)
            self._preserve_evidence(evidence)

            # Add to chain of custody
            evidence.chain_of_custody.append(ChainOfCustodyEntry(
                timestamp=datetime.utcnow(),
                action="collected",
                actor=collected_by,
                location=evidence.storage_path,
                hash_after=evidence.sha256_hash,
                notes=f"Collected from {source_system}:{source_path}"
            ))

            evidence.state = EvidenceState.COLLECTED

            # Register
            self.evidence_registry[evidence_id] = evidence
            self._save_registry()

            return evidence

        except Exception as e:
            evidence.state = EvidenceState.PENDING
            raise Exception(f"Evidence collection failed: {e}")

    def preserve_evidence(self, evidence_id: str) -> bool:
        """
        Preserve evidence with cryptographic hashing

        Args:
            evidence_id: Evidence identifier

        Returns:
            Success status
        """
        evidence = self.evidence_registry.get(evidence_id)
        if not evidence:
            return False

        try:
            self._preserve_evidence(evidence)
            evidence.state = EvidenceState.PRESERVED
            self._save_registry()
            return True
        except Exception as e:
            print(f"Preservation failed: {e}")
            return False

    def verify_integrity(self, evidence_id: str) -> Dict[str, Any]:
        """
        Verify evidence integrity

        Args:
            evidence_id: Evidence identifier

        Returns:
            Verification results
        """
        evidence = self.evidence_registry.get(evidence_id)
        if not evidence:
            return {"error": "Evidence not found"}

        if not os.path.exists(evidence.storage_path):
            return {
                "verified": False,
                "error": "Evidence file not found"
            }

        # Recalculate hashes
        current_md5 = self._calculate_md5(evidence.storage_path)
        current_sha256 = self._calculate_sha256(evidence.storage_path)

        md5_match = current_md5 == evidence.md5_hash
        sha256_match = current_sha256 == evidence.sha256_hash

        verified = md5_match and sha256_match

        # Add to chain of custody
        evidence.chain_of_custody.append(ChainOfCustodyEntry(
            timestamp=datetime.utcnow(),
            action="verified",
            actor="system",
            location=evidence.storage_path,
            hash_before=evidence.sha256_hash,
            hash_after=current_sha256,
            notes=f"Integrity verification: {'PASSED' if verified else 'FAILED'}"
        ))

        self._save_registry()

        return {
            "verified": verified,
            "evidence_id": evidence_id,
            "md5_match": md5_match,
            "sha256_match": sha256_match,
            "original_md5": evidence.md5_hash,
            "current_md5": current_md5,
            "original_sha256": evidence.sha256_hash,
            "current_sha256": current_sha256
        }

    def transfer_custody(self,
                        evidence_id: str,
                        from_actor: str,
                        to_actor: str,
                        reason: str) -> bool:
        """
        Transfer evidence custody

        Args:
            evidence_id: Evidence identifier
            from_actor: Current custodian
            to_actor: New custodian
            reason: Transfer reason

        Returns:
            Success status
        """
        evidence = self.evidence_registry.get(evidence_id)
        if not evidence:
            return False

        # Verify integrity before transfer
        verification = self.verify_integrity(evidence_id)
        if not verification.get("verified"):
            raise Exception("Cannot transfer - integrity check failed")

        # Record transfer
        evidence.chain_of_custody.append(ChainOfCustodyEntry(
            timestamp=datetime.utcnow(),
            action="custody_transfer",
            actor=f"{from_actor} → {to_actor}",
            location=evidence.storage_path,
            hash_before=evidence.sha256_hash,
            hash_after=evidence.sha256_hash,
            notes=f"Reason: {reason}"
        ))

        evidence.last_accessed = datetime.utcnow()
        self._save_registry()

        return True

    def search_evidence(self,
                       incident_id: Optional[str] = None,
                       evidence_type: Optional[EvidenceType] = None,
                       tags: Optional[Set[str]] = None,
                       start_date: Optional[datetime] = None,
                       end_date: Optional[datetime] = None) -> List[Evidence]:
        """
        Search evidence registry

        Args:
            incident_id: Filter by incident
            evidence_type: Filter by type
            tags: Filter by tags
            start_date: Collected after date
            end_date: Collected before date

        Returns:
            Matching evidence records
        """
        results = []

        for evidence in self.evidence_registry.values():
            # Apply filters
            if incident_id and evidence.incident_id != incident_id:
                continue

            if evidence_type and evidence.evidence_type != evidence_type:
                continue

            if tags and not tags.issubset(evidence.tags):
                continue

            if start_date and evidence.collected_at < start_date:
                continue

            if end_date and evidence.collected_at > end_date:
                continue

            results.append(evidence)

        return results

    def export_evidence_package(self,
                               incident_id: str,
                               output_path: str,
                               include_metadata: bool = True) -> Dict[str, Any]:
        """
        Export complete evidence package for incident

        Args:
            incident_id: Incident identifier
            output_path: Output directory path
            include_metadata: Include metadata files

        Returns:
            Export summary
        """
        evidence_list = self.search_evidence(incident_id=incident_id)

        if not evidence_list:
            return {"error": "No evidence found for incident"}

        export_dir = Path(output_path) / f"evidence_{incident_id}"
        export_dir.mkdir(parents=True, exist_ok=True)

        exported = []

        for evidence in evidence_list:
            # Copy evidence file
            if os.path.exists(evidence.storage_path):
                dest = export_dir / f"{evidence.evidence_id}_{Path(evidence.storage_path).name}"
                shutil.copy2(evidence.storage_path, dest)

                # Export metadata
                if include_metadata:
                    metadata = {
                        "evidence_id": evidence.evidence_id,
                        "type": evidence.evidence_type.value,
                        "source": evidence.source_system,
                        "collected_at": evidence.collected_at.isoformat(),
                        "collected_by": evidence.collected_by,
                        "md5": evidence.md5_hash,
                        "sha256": evidence.sha256_hash,
                        "chain_of_custody": [
                            {
                                "timestamp": entry.timestamp.isoformat(),
                                "action": entry.action,
                                "actor": entry.actor,
                                "notes": entry.notes
                            }
                            for entry in evidence.chain_of_custody
                        ]
                    }

                    metadata_file = export_dir / f"{evidence.evidence_id}_metadata.json"
                    with open(metadata_file, 'w', encoding='utf-8') as f:
                        json.dump(metadata, f, indent=2)

                exported.append(evidence.evidence_id)

        # Create manifest
        manifest = {
            "incident_id": incident_id,
            "export_date": datetime.utcnow().isoformat(),
            "evidence_count": len(exported),
            "evidence_items": exported
        }

        manifest_file = export_dir / "manifest.json"
        with open(manifest_file, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)

        return {
            "success": True,
            "export_path": str(export_dir),
            "evidence_count": len(exported),
            "manifest": manifest
        }

    def _execute_collection_rule(self,
                                 incident_id: str,
                                 rule: Dict,
                                 context: Dict) -> Optional[str]:
        """Execute automated collection rule"""
        evidence_type = EvidenceType[rule["evidence_type"]]
        source_system = context.get("source_system", "unknown")
        source_path = rule.get("source_path", "")

        # Execute collection
        evidence = self.collect_evidence(
            incident_id=incident_id,
            evidence_type=evidence_type,
            source_system=source_system,
            source_path=source_path,
            collected_by="automated_collector",
            description=rule.get("description", ""),
            tags=set(rule.get("tags", []))
        )

        return evidence.evidence_id if evidence else None

    def _collect_from_source(self, evidence: Evidence, source_path: str):
        """Collect evidence from source"""
        # Create storage path
        incident_dir = self.vault_path / evidence.incident_id
        incident_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{evidence.evidence_id}_{Path(source_path).name}"
        storage_path = incident_dir / filename

        # For this implementation, we'll simulate collection
        # In production, this would use SSH, WMI, or other remote collection methods

        if os.path.exists(source_path):
            # Copy local file
            shutil.copy2(source_path, storage_path)
        else:
            # Create placeholder for demonstration
            with open(storage_path, 'w', encoding='utf-8') as f:
                f.write(f"Evidence collected from {evidence.source_system}:{source_path}\n")
                f.write(f"Collection time: {datetime.utcnow().isoformat()}\n")

        evidence.storage_path = str(storage_path)
        evidence.file_size = os.path.getsize(storage_path)

    def _preserve_evidence(self, evidence: Evidence):
        """Preserve evidence with hashing and compression"""
        if not os.path.exists(evidence.storage_path):
            raise Exception("Evidence file not found")

        # Calculate hashes
        evidence.md5_hash = self._calculate_md5(evidence.storage_path)
        evidence.sha256_hash = self._calculate_sha256(evidence.storage_path)

        # Compress if large
        if evidence.file_size > 10 * 1024 * 1024:  # 10MB
            compressed_path = f"{evidence.storage_path}.gz"
            with open(evidence.storage_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Remove original, update path
            os.remove(evidence.storage_path)
            evidence.storage_path = compressed_path
            evidence.file_size = os.path.getsize(compressed_path)

    def _calculate_md5(self, file_path: str) -> str:
        """Calculate MD5 hash of file"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def _calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _generate_evidence_id(self, incident_id: str, evidence_type: EvidenceType) -> str:
        """Generate unique evidence identifier"""
        return hashlib.sha256(
            f"{incident_id}_{evidence_type.value}_{datetime.utcnow()}".encode()
        ).hexdigest()[:16]

    def _init_collection_rules(self) -> Dict[str, List[Dict]]:
        """Initialize automated collection rules"""
        return {
            "ransomware_detected": [
                {
                    "name": "collect_system_logs",
                    "evidence_type": "LOG_FILE",
                    "source_path": "/var/log/syslog",
                    "description": "System logs at time of ransomware detection",
                    "tags": ["ransomware", "logs", "system"]
                },
                {
                    "name": "collect_process_list",
                    "evidence_type": "PROCESS_LIST",
                    "source_path": "/proc",
                    "description": "Running processes during incident",
                    "tags": ["ransomware", "processes"]
                }
            ],
            "data_breach_detected": [
                {
                    "name": "collect_network_capture",
                    "evidence_type": "NETWORK_CAPTURE",
                    "source_path": "/var/log/network.pcap",
                    "description": "Network traffic during breach",
                    "tags": ["breach", "network"]
                },
                {
                    "name": "collect_database_logs",
                    "evidence_type": "LOG_FILE",
                    "source_path": "/var/log/database.log",
                    "description": "Database access logs",
                    "tags": ["breach", "database"]
                }
            ],
            "malware_detected": [
                {
                    "name": "collect_malware_sample",
                    "evidence_type": "MALWARE_SAMPLE",
                    "source_path": "/quarantine/sample",
                    "description": "Malware sample for analysis",
                    "tags": ["malware", "sample"]
                },
                {
                    "name": "collect_memory_dump",
                    "evidence_type": "MEMORY_DUMP",
                    "source_path": "/tmp/memory.dmp",
                    "description": "Memory dump for malware analysis",
                    "tags": ["malware", "memory"]
                }
            ]
        }

    def _save_registry(self):
        """Save evidence registry to disk"""
        registry_file = self.vault_path / "evidence_registry.json"

        registry_data = {}
        for evidence_id, evidence in self.evidence_registry.items():
            registry_data[evidence_id] = {
                "evidence_id": evidence.evidence_id,
                "incident_id": evidence.incident_id,
                "evidence_type": evidence.evidence_type.value,
                "state": evidence.state.value,
                "source_system": evidence.source_system,
                "source_path": evidence.source_path,
                "collected_at": evidence.collected_at.isoformat(),
                "collected_by": evidence.collected_by,
                "storage_path": evidence.storage_path,
                "md5_hash": evidence.md5_hash,
                "sha256_hash": evidence.sha256_hash,
                "file_size": evidence.file_size,
                "tags": list(evidence.tags),
                "description": evidence.description,
                "chain_of_custody": [
                    {
                        "timestamp": entry.timestamp.isoformat(),
                        "action": entry.action,
                        "actor": entry.actor,
                        "location": entry.location,
                        "notes": entry.notes
                    }
                    for entry in evidence.chain_of_custody
                ]
            }

        with open(registry_file, 'w', encoding='utf-8') as f:
            json.dump(registry_data, f, indent=2)

    def _load_registry(self):
        """Load evidence registry from disk"""
        registry_file = self.vault_path / "evidence_registry.json"

        if not registry_file.exists():
            return

        try:
            with open(registry_file, 'r', encoding='utf-8') as f:
                registry_data = json.load(f)

            # Reconstruct evidence objects
            for evidence_id, data in registry_data.items():
                try:
                    # Handle both uppercase and lowercase enum values
                    evidence_type_str = data["evidence_type"].upper()
                    state_str = data["state"].upper()

                    evidence = Evidence(
                        evidence_id=data["evidence_id"],
                        incident_id=data["incident_id"],
                        evidence_type=EvidenceType[evidence_type_str],
                        state=EvidenceState[state_str],
                        source_system=data["source_system"],
                        source_path=data["source_path"],
                        collection_method="automated",
                        collected_at=datetime.fromisoformat(data["collected_at"]),
                        collected_by=data["collected_by"],
                        storage_path=data["storage_path"],
                        file_size=data["file_size"],
                        md5_hash=data["md5_hash"],
                        sha256_hash=data["sha256_hash"],
                        tags=set(data.get("tags", [])),
                        description=data.get("description", "")
                    )

                    # Reconstruct chain of custody
                    for entry_data in data.get("chain_of_custody", []):
                        evidence.chain_of_custody.append(ChainOfCustodyEntry(
                            timestamp=datetime.fromisoformat(entry_data["timestamp"]),
                            action=entry_data["action"],
                            actor=entry_data["actor"],
                            location=entry_data["location"],
                            notes=entry_data.get("notes", "")
                        ))

                    self.evidence_registry[evidence_id] = evidence
                except Exception as e:
                    print(f"Warning: Failed to load evidence {evidence_id}: {e}")
                    continue
        except Exception as e:
            print(f"Warning: Failed to load evidence registry: {e}")
            # Start with empty registry if loading fails
            self.evidence_registry = {}

    def get_statistics(self) -> Dict[str, Any]:
        """Get evidence collection statistics"""
        total = len(self.evidence_registry)

        by_type = Counter(e.evidence_type for e in self.evidence_registry.values())
        by_state = Counter(e.state for e in self.evidence_registry.values())
        by_incident = Counter(e.incident_id for e in self.evidence_registry.values())

        total_size = sum(e.file_size for e in self.evidence_registry.values())

        return {
            "total_evidence_items": total,
            "by_type": {k.value: v for k, v in by_type.items()},
            "by_state": {k.value: v for k, v in by_state.items()},
            "incidents_with_evidence": len(by_incident),
            "total_storage_bytes": total_size,
            "total_storage_mb": total_size / (1024 * 1024)
        }
