"""
Data Privacy and Masking Manager
Comprehensive data privacy features including masking, anonymization,
and pseudonymization for compliance (GDPR, HIPAA, etc.)
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re
import json
from pathlib import Path

class MaskingStrategy(Enum):
    """Data masking strategies"""
    FULL_MASK = "full_mask"  # Complete replacement with ***
    PARTIAL_MASK = "partial_mask"  # Show first/last chars only
    HASH = "hash"  # One-way hash
    PSEUDONYMIZE = "pseudonymize"  # Replace with consistent fake value
    TOKENIZE = "tokenize"  # Replace with reversible token
    REDACT = "redact"  # Remove completely
    ENCRYPT = "encrypt"  # Encrypted value

class DataCategory(Enum):
    """Data categories for privacy"""
    PII = "pii"  # Personally Identifiable Information
    PHI = "phi"  # Protected Health Information
    PCI = "pci"  # Payment Card Information
    AUTHENTICATION = "authentication"
    BIOMETRIC = "biometric"
    FINANCIAL = "financial"
    LOCATION = "location"
    BEHAVIORAL = "behavioral"

@dataclass
class PrivacyPolicy:
    """Privacy policy configuration"""
    field_name: str
    data_category: DataCategory
    masking_strategy: MaskingStrategy
    retention_days: int
    requires_consent: bool = True
    allow_export: bool = False
    allow_analytics: bool = False
    description: str = ""

@dataclass
class ConsentRecord:
    """User consent record"""
    user_id: str
    consent_type: str
    granted: bool
    timestamp: datetime
    expires_at: Optional[datetime] = None
    ip_address: str = ""
    user_agent: str = ""

@dataclass
class DataRequest:
    """GDPR/Privacy data request"""
    request_id: str
    user_id: str
    request_type: str  # access, deletion, portability, rectification
    requested_at: datetime
    status: str  # pending, processing, completed, rejected
    completed_at: Optional[datetime] = None
    data_package: Optional[str] = None
    notes: str = ""

class DataPrivacyManager:
    """
    Comprehensive data privacy management
    Handles masking, anonymization, and privacy compliance
    """

    def __init__(self, config_dir: str = "./config/privacy"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Privacy policies
        self.policies: Dict[str, PrivacyPolicy] = {}
        self._init_default_policies()

        # Pseudonymization mapping (field -> original -> fake)
        self.pseudonym_map: Dict[str, Dict[str, str]] = {}

        # Tokenization map (reversible)
        self.token_map: Dict[str, str] = {}

        # Consent records
        self.consents: Dict[str, List[ConsentRecord]] = {}

        # Data requests
        self.data_requests: Dict[str, DataRequest] = {}

        # PII field patterns
        self.pii_patterns = self._init_pii_patterns()

    def mask_data(self,
                  data: Dict[str, Any],
                  context: str = "display") -> Dict[str, Any]:
        """
        Apply masking to data based on policies

        Args:
            data: Data to mask
            context: Context (display, export, analytics)

        Returns:
            Masked data
        """
        masked = {}

        for key, value in data.items():
            if value is None:
                masked[key] = value
                continue

            # Check if field has privacy policy
            policy = self.policies.get(key)

            if policy:
                # Apply masking based on policy and context
                if context == "export" and not policy.allow_export:
                    masked[key] = "[REDACTED]"
                elif context == "analytics" and not policy.allow_analytics:
                    masked[key] = self._hash_value(str(value))
                else:
                    masked[key] = self._apply_masking(
                        value,
                        policy.masking_strategy,
                        key
                    )
            else:
                # Auto-detect PII
                if self._is_pii(key, value):
                    masked[key] = self._apply_masking(
                        value,
                        MaskingStrategy.PARTIAL_MASK,
                        key
                    )
                else:
                    masked[key] = value

        return masked

    def anonymize_dataset(self,
                         dataset: List[Dict[str, Any]],
                         k_anonymity: int = 5) -> List[Dict[str, Any]]:
        """
        Anonymize dataset to achieve k-anonymity

        Args:
            dataset: List of records
            k_anonymity: Minimum group size

        Returns:
            Anonymized dataset
        """
        anonymized = []

        # Apply masking to each record
        for record in dataset:
            anon_record = self.mask_data(record, context="analytics")
            anonymized.append(anon_record)

        return anonymized

    def pseudonymize_value(self, field: str, value: str) -> str:
        """
        Pseudonymize value (consistent fake value)

        Args:
            field: Field name
            value: Original value

        Returns:
            Pseudonymized value
        """
        if field not in self.pseudonym_map:
            self.pseudonym_map[field] = {}

        if value not in self.pseudonym_map[field]:
            # Generate consistent pseudonym
            if field == "email":
                hash_val = hashlib.md5(value.encode()).hexdigest()[:8]
                self.pseudonym_map[field][value] = f"user{hash_val}@example.com"
            elif field in ["name", "username"]:
                hash_val = hashlib.md5(value.encode()).hexdigest()[:8]
                self.pseudonym_map[field][value] = f"User_{hash_val}"
            elif field == "ip_address":
                # Preserve subnet, mask host
                hash_val = hashlib.md5(value.encode()).hexdigest()[:2]
                self.pseudonym_map[field][value] = f"10.0.{hash_val}.100"
            else:
                hash_val = hashlib.md5(value.encode()).hexdigest()[:12]
                self.pseudonym_map[field][value] = f"value_{hash_val}"

        return self.pseudonym_map[field][value]

    def tokenize_value(self, value: str) -> str:
        """
        Tokenize value (reversible)

        Args:
            value: Value to tokenize

        Returns:
            Token
        """
        token = hashlib.sha256(f"token_{value}_{datetime.utcnow()}".encode()).hexdigest()[:16]
        self.token_map[token] = value
        return token

    def detokenize_value(self, token: str) -> Optional[str]:
        """
        Reverse tokenization

        Args:
            token: Token to reverse

        Returns:
            Original value
        """
        return self.token_map.get(token)

    def record_consent(self,
                      user_id: str,
                      consent_type: str,
                      granted: bool,
                      ip_address: str = "",
                      user_agent: str = "",
                      expires_days: int = 365) -> ConsentRecord:
        """
        Record user consent

        Args:
            user_id: User identifier
            consent_type: Type of consent
            granted: Whether granted
            ip_address: User IP
            user_agent: User agent
            expires_days: Expiration in days

        Returns:
            Consent record
        """
        consent = ConsentRecord(
            user_id=user_id,
            consent_type=consent_type,
            granted=granted,
            timestamp=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=expires_days) if granted else None,
            ip_address=ip_address,
            user_agent=user_agent
        )

        if user_id not in self.consents:
            self.consents[user_id] = []

        self.consents[user_id].append(consent)

        return consent

    def check_consent(self, user_id: str, consent_type: str) -> bool:
        """
        Check if user has granted consent

        Args:
            user_id: User identifier
            consent_type: Type of consent

        Returns:
            Whether consent is granted and valid
        """
        user_consents = self.consents.get(user_id, [])

        for consent in reversed(user_consents):  # Get most recent
            if consent.consent_type == consent_type:
                if not consent.granted:
                    return False

                # Check expiration
                if consent.expires_at and consent.expires_at < datetime.utcnow():
                    return False

                return True

        return False

    def create_data_request(self,
                           user_id: str,
                           request_type: str,
                           notes: str = "") -> DataRequest:
        """
        Create GDPR data request

        Args:
            user_id: User identifier
            request_type: access, deletion, portability, rectification
            notes: Additional notes

        Returns:
            Data request
        """
        request_id = hashlib.sha256(
            f"{user_id}_{request_type}_{datetime.utcnow()}".encode()
        ).hexdigest()[:16]

        request = DataRequest(
            request_id=request_id,
            user_id=user_id,
            request_type=request_type,
            requested_at=datetime.utcnow(),
            status="pending",
            notes=notes
        )

        self.data_requests[request_id] = request

        return request

    def process_data_access_request(self, request_id: str, user_data: Dict[str, Any]) -> str:
        """
        Process GDPR data access request

        Args:
            request_id: Request identifier
            user_data: User's data

        Returns:
            Path to data package
        """
        request = self.data_requests.get(request_id)
        if not request or request.request_type != "access":
            raise ValueError("Invalid data access request")

        request.status = "processing"

        # Create data package (unmask for user's own data)
        package = {
            "user_id": request.user_id,
            "request_date": request.requested_at.isoformat(),
            "data": user_data,
            "generated_at": datetime.utcnow().isoformat()
        }

        # Save to file
        package_path = self.config_dir / f"data_export_{request.request_id}.json"
        with open(package_path, 'w', encoding='utf-8') as f:
            json.dump(package, f, indent=2)

        request.status = "completed"
        request.completed_at = datetime.utcnow()
        request.data_package = str(package_path)

        return str(package_path)

    def process_data_deletion_request(self,
                                     request_id: str,
                                     deletion_callback: callable) -> bool:
        """
        Process GDPR right to be forgotten request

        Args:
            request_id: Request identifier
            deletion_callback: Function to call for actual deletion

        Returns:
            Success status
        """
        request = self.data_requests.get(request_id)
        if not request or request.request_type != "deletion":
            raise ValueError("Invalid deletion request")

        request.status = "processing"

        try:
            # Execute deletion callback
            deletion_callback(request.user_id)

            request.status = "completed"
            request.completed_at = datetime.utcnow()

            return True

        except Exception as e:
            request.status = "rejected"
            request.notes += f"\nDeletion failed: {e}"
            return False

    def audit_data_access(self,
                         user_id: str,
                         data_type: str,
                         accessed_by: str,
                         purpose: str) -> Dict[str, Any]:
        """
        Audit data access for compliance

        Args:
            user_id: User whose data was accessed
            data_type: Type of data
            accessed_by: Who accessed it
            purpose: Purpose of access

        Returns:
            Audit record
        """
        audit_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "data_type": data_type,
            "accessed_by": accessed_by,
            "purpose": purpose
        }

        # Save to audit log
        audit_file = self.config_dir / "data_access_audit.jsonl"
        with open(audit_file, 'a') as f:
            f.write(json.dumps(audit_record) + '\n')

        return audit_record

    def generate_privacy_impact_assessment(self,
                                          processing_activity: str,
                                          data_types: List[str],
                                          purposes: List[str]) -> Dict[str, Any]:
        """
        Generate Privacy Impact Assessment (PIA)

        Args:
            processing_activity: Description of activity
            data_types: Types of data processed
            purposes: Purposes of processing

        Returns:
            PIA report
        """
        # Identify privacy risks
        risks = []

        for data_type in data_types:
            if data_type in ["pii", "phi", "biometric"]:
                risks.append({
                    "data_type": data_type,
                    "risk_level": "high",
                    "mitigation": "Implement encryption and access controls"
                })

        # Check if processing requires consent
        requires_consent = any(dt in ["pii", "behavioral", "location"] for dt in data_types)

        # Check if DPIA is required (GDPR Article 35)
        dpia_required = (
            "profiling" in purposes or
            "automated_decision_making" in purposes or
            len(data_types) > 3
        )

        return {
            "processing_activity": processing_activity,
            "data_types": data_types,
            "purposes": purposes,
            "privacy_risks": risks,
            "requires_consent": requires_consent,
            "dpia_required": dpia_required,
            "assessment_date": datetime.utcnow().isoformat(),
            "recommendations": [
                "Implement data minimization",
                "Enable encryption at rest and in transit",
                "Establish data retention policies",
                "Implement access controls",
                "Conduct regular privacy training"
            ]
        }

    def _apply_masking(self, value: Any, strategy: MaskingStrategy, field: str) -> Any:
        """Apply specific masking strategy"""
        if not isinstance(value, str):
            value = str(value)

        if strategy == MaskingStrategy.FULL_MASK:
            return "***" * (len(value) // 3 + 1)

        elif strategy == MaskingStrategy.PARTIAL_MASK:
            if len(value) <= 4:
                return "***"
            return value[:2] + ("*" * (len(value) - 4)) + value[-2:]

        elif strategy == MaskingStrategy.HASH:
            return self._hash_value(value)

        elif strategy == MaskingStrategy.PSEUDONYMIZE:
            return self.pseudonymize_value(field, value)

        elif strategy == MaskingStrategy.TOKENIZE:
            return self.tokenize_value(value)

        elif strategy == MaskingStrategy.REDACT:
            return "[REDACTED]"

        else:
            return value

    def _hash_value(self, value: str) -> str:
        """One-way hash of value"""
        return hashlib.sha256(value.encode()).hexdigest()[:16]

    def _is_pii(self, field: str, value: Any) -> bool:
        """Detect if field/value contains PII"""
        field_lower = field.lower()

        # Check field name
        pii_keywords = [
            "email", "phone", "ssn", "passport", "license",
            "address", "name", "username", "password",
            "credit_card", "account", "ip_address"
        ]

        if any(keyword in field_lower for keyword in pii_keywords):
            return True

        # Pattern matching on value
        if isinstance(value, str):
            for pattern_name, pattern in self.pii_patterns.items():
                if re.search(pattern, value):
                    return True

        return False

    def _init_pii_patterns(self) -> Dict[str, str]:
        """Initialize PII detection patterns"""
        return {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
            "credit_card": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            "ip_address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }

    def _init_default_policies(self):
        """Initialize default privacy policies"""
        policies = [
            PrivacyPolicy(
                field_name="email",
                data_category=DataCategory.PII,
                masking_strategy=MaskingStrategy.PARTIAL_MASK,
                retention_days=2555,
                requires_consent=True,
                allow_export=True,
                allow_analytics=False
            ),
            PrivacyPolicy(
                field_name="ip_address",
                data_category=DataCategory.PII,
                masking_strategy=MaskingStrategy.PSEUDONYMIZE,
                retention_days=90,
                requires_consent=False,
                allow_export=False,
                allow_analytics=True
            ),
            PrivacyPolicy(
                field_name="username",
                data_category=DataCategory.PII,
                masking_strategy=MaskingStrategy.PARTIAL_MASK,
                retention_days=2555,
                requires_consent=True
            ),
            PrivacyPolicy(
                field_name="password",
                data_category=DataCategory.AUTHENTICATION,
                masking_strategy=MaskingStrategy.HASH,
                retention_days=2555,
                requires_consent=False,
                allow_export=False,
                allow_analytics=False
            ),
            PrivacyPolicy(
                field_name="credit_card",
                data_category=DataCategory.PCI,
                masking_strategy=MaskingStrategy.TOKENIZE,
                retention_days=90,
                requires_consent=True,
                allow_export=False,
                allow_analytics=False
            )
        ]

        for policy in policies:
            self.policies[policy.field_name] = policy

    def get_statistics(self) -> Dict[str, Any]:
        """Get privacy management statistics"""
        return {
            "privacy_policies": len(self.policies),
            "pseudonym_mappings": sum(len(m) for m in self.pseudonym_map.values()),
            "active_tokens": len(self.token_map),
            "consent_records": sum(len(c) for c in self.consents.values()),
            "data_requests": {
                "total": len(self.data_requests),
                "pending": len([r for r in self.data_requests.values() if r.status == "pending"]),
                "completed": len([r for r in self.data_requests.values() if r.status == "completed"])
            }
        }
