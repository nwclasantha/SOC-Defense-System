"""
MITRE ATT&CK Framework Mapper
Maps detected attacks to MITRE ATT&CK tactics and techniques
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
from modules.AttackType import AttackType

class MitreTactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"

@dataclass
class MitreTechnique:
    """MITRE ATT&CK Technique"""
    id: str
    name: str
    tactic: MitreTactic
    description: str
    sub_techniques: List[str] = None

    def __post_init__(self):
        if self.sub_techniques is None:
            self.sub_techniques = []

class MitreAttackMapper:
    """Maps attacks to MITRE ATT&CK framework"""

    # Singleton instance cache to avoid loading MITRE DB multiple times
    _instance = None
    _mitre_loader_cache = None

    @classmethod
    def get_instance(cls, use_local_db=True):
        """Get singleton instance of MitreAttackMapper (preferred for performance)"""
        if cls._instance is None:
            cls._instance = cls(use_local_db=use_local_db, _use_cache=True)
        return cls._instance

    def __init__(self, use_local_db=True, _use_cache=False):
        # Always use cached loader if available (for performance)
        if use_local_db and MitreAttackMapper._mitre_loader_cache is not None:
            self.mitre_loader = MitreAttackMapper._mitre_loader_cache
            self.techniques_db = {}
            self.attack_type_mappings = self._initialize_mappings()
            return

        # Try to load local MITRE database first
        self.mitre_loader = None
        if use_local_db:
            try:
                from modules.MitreDatabaseLoader import MitreDatabaseLoader
                self.mitre_loader = MitreDatabaseLoader()
                # Cache the loader for future instances
                MitreAttackMapper._mitre_loader_cache = self.mitre_loader
                print(f"[OK] Loaded local MITRE DB: {len(self.mitre_loader.techniques)} techniques, "
                      f"{len(self.mitre_loader.groups)} groups")
            except Exception as e:
                print(f"[WARN] Could not load local MITRE DB, using built-in: {e}")

        # Fallback to built-in techniques if no local DB
        if not self.mitre_loader:
            self.techniques_db = self._initialize_techniques()
        else:
            self.techniques_db = {}  # Will use mitre_loader instead

        self.attack_type_mappings = self._initialize_mappings()

    def _initialize_techniques(self) -> Dict[str, MitreTechnique]:
        """Initialize MITRE ATT&CK techniques database"""
        techniques = [
            # Initial Access
            MitreTechnique(
                id="T1190",
                name="Exploit Public-Facing Application",
                tactic=MitreTactic.INITIAL_ACCESS,
                description="Exploiting web servers, databases, or other internet-facing services",
                sub_techniques=["T1190.001", "T1190.002"]
            ),
            MitreTechnique(
                id="T1133",
                name="External Remote Services",
                tactic=MitreTactic.INITIAL_ACCESS,
                description="Using remote services like VPN, SSH, RDP for initial access"
            ),

            # Execution
            MitreTechnique(
                id="T1059",
                name="Command and Scripting Interpreter",
                tactic=MitreTactic.EXECUTION,
                description="Abusing command and script interpreters",
                sub_techniques=["T1059.001", "T1059.003", "T1059.004", "T1059.006"]
            ),
            MitreTechnique(
                id="T1203",
                name="Exploitation for Client Execution",
                tactic=MitreTactic.EXECUTION,
                description="Exploiting software vulnerabilities to execute code"
            ),
            MitreTechnique(
                id="T1059.001",
                name="PowerShell",
                tactic=MitreTactic.EXECUTION,
                description="Abuse PowerShell commands and scripts"
            ),
            MitreTechnique(
                id="T1059.003",
                name="Windows Command Shell",
                tactic=MitreTactic.EXECUTION,
                description="Abuse Windows command prompt or batch files"
            ),
            MitreTechnique(
                id="T1059.004",
                name="Unix Shell",
                tactic=MitreTactic.EXECUTION,
                description="Abuse Unix shell commands and scripts"
            ),

            # Persistence
            MitreTechnique(
                id="T1505",
                name="Server Software Component",
                tactic=MitreTactic.PERSISTENCE,
                description="Abuse server software components for persistence",
                sub_techniques=["T1505.001", "T1505.003"]
            ),
            MitreTechnique(
                id="T1505.003",
                name="Web Shell",
                tactic=MitreTactic.PERSISTENCE,
                description="Creating web shells for persistent access"
            ),
            MitreTechnique(
                id="T1053",
                name="Scheduled Task/Job",
                tactic=MitreTactic.PERSISTENCE,
                description="Abuse task scheduling for persistence"
            ),

            # Privilege Escalation
            MitreTechnique(
                id="T1068",
                name="Exploitation for Privilege Escalation",
                tactic=MitreTactic.PRIVILEGE_ESCALATION,
                description="Exploiting vulnerabilities to gain elevated privileges"
            ),
            MitreTechnique(
                id="T1078",
                name="Valid Accounts",
                tactic=MitreTactic.PRIVILEGE_ESCALATION,
                description="Using stolen credentials for privileged access"
            ),

            # Defense Evasion
            MitreTechnique(
                id="T1027",
                name="Obfuscated Files or Information",
                tactic=MitreTactic.DEFENSE_EVASION,
                description="Making files or information difficult to discover or analyze"
            ),
            MitreTechnique(
                id="T1036",
                name="Masquerading",
                tactic=MitreTactic.DEFENSE_EVASION,
                description="Manipulating features to make malicious code appear legitimate"
            ),
            MitreTechnique(
                id="T1140",
                name="Deobfuscate/Decode Files or Information",
                tactic=MitreTactic.DEFENSE_EVASION,
                description="Decoding or deobfuscating information"
            ),
            MitreTechnique(
                id="T1562",
                name="Impair Defenses",
                tactic=MitreTactic.DEFENSE_EVASION,
                description="Disabling or modifying tools or processes to evade detection"
            ),

            # Credential Access
            MitreTechnique(
                id="T1110",
                name="Brute Force",
                tactic=MitreTactic.CREDENTIAL_ACCESS,
                description="Trying multiple password combinations to gain access",
                sub_techniques=["T1110.001", "T1110.003"]
            ),
            MitreTechnique(
                id="T1555",
                name="Credentials from Password Stores",
                tactic=MitreTactic.CREDENTIAL_ACCESS,
                description="Stealing credentials from password stores"
            ),
            MitreTechnique(
                id="T1056",
                name="Input Capture",
                tactic=MitreTactic.CREDENTIAL_ACCESS,
                description="Capturing user input to obtain credentials"
            ),

            # Discovery
            MitreTechnique(
                id="T1083",
                name="File and Directory Discovery",
                tactic=MitreTactic.DISCOVERY,
                description="Enumerating files and directories"
            ),
            MitreTechnique(
                id="T1046",
                name="Network Service Discovery",
                tactic=MitreTactic.DISCOVERY,
                description="Discovering services on local or remote systems"
            ),
            MitreTechnique(
                id="T1018",
                name="Remote System Discovery",
                tactic=MitreTactic.DISCOVERY,
                description="Identifying remote systems"
            ),

            # Collection
            MitreTechnique(
                id="T1005",
                name="Data from Local System",
                tactic=MitreTactic.COLLECTION,
                description="Collecting data from local system sources"
            ),
            MitreTechnique(
                id="T1039",
                name="Data from Network Shared Drive",
                tactic=MitreTactic.COLLECTION,
                description="Accessing network shared drives to collect data"
            ),

            # Command and Control
            MitreTechnique(
                id="T1071",
                name="Application Layer Protocol",
                tactic=MitreTactic.COMMAND_AND_CONTROL,
                description="Using application layer protocols for C2",
                sub_techniques=["T1071.001", "T1071.004"]
            ),
            MitreTechnique(
                id="T1572",
                name="Protocol Tunneling",
                tactic=MitreTactic.COMMAND_AND_CONTROL,
                description="Tunneling network communications"
            ),

            # Exfiltration
            MitreTechnique(
                id="T1041",
                name="Exfiltration Over C2 Channel",
                tactic=MitreTactic.EXFILTRATION,
                description="Exfiltrating data over the C2 channel"
            ),
            MitreTechnique(
                id="T1048",
                name="Exfiltration Over Alternative Protocol",
                tactic=MitreTactic.EXFILTRATION,
                description="Exfiltrating data using alternative protocols"
            ),

            # Impact
            MitreTechnique(
                id="T1485",
                name="Data Destruction",
                tactic=MitreTactic.IMPACT,
                description="Destroying data and files"
            ),
            MitreTechnique(
                id="T1486",
                name="Data Encrypted for Impact",
                tactic=MitreTactic.IMPACT,
                description="Encrypting data to interrupt availability (ransomware)"
            ),
            MitreTechnique(
                id="T1490",
                name="Inhibit System Recovery",
                tactic=MitreTactic.IMPACT,
                description="Preventing recovery of system or data"
            ),
            MitreTechnique(
                id="T1498",
                name="Network Denial of Service",
                tactic=MitreTactic.IMPACT,
                description="Conducting DoS attacks"
            ),
        ]

        return {tech.id: tech for tech in techniques}

    def _initialize_mappings(self) -> Dict[AttackType, List[str]]:
        """Map attack types to MITRE techniques"""
        return {
            AttackType.SQL_INJECTION: ["T1190", "T1059"],
            AttackType.XSS: ["T1190", "T1059"],
            AttackType.COMMAND_INJECTION: ["T1190", "T1059", "T1059.004"],
            AttackType.PATH_TRAVERSAL: ["T1190", "T1083"],
            AttackType.SHELLSHOCK: ["T1190", "T1059.004", "T1068"],
            AttackType.BRUTE_FORCE: ["T1110", "T1110.001"],
            AttackType.DOS: ["T1498"],
            AttackType.EXPLOIT: ["T1190", "T1203", "T1068"],
            AttackType.MALWARE: ["T1203", "T1059", "T1505"],
            AttackType.PORT_SCAN: ["T1046", "T1018"],
            AttackType.LOG4J: ["T1190", "T1059", "T1068", "T1203"],
            AttackType.LDAP_INJECTION: ["T1190", "T1059"],
            AttackType.XXE: ["T1190", "T1005", "T1083"],
            AttackType.SSRF: ["T1190", "T1071"],
            AttackType.CREDENTIAL_ACCESS: ["T1110", "T1555", "T1056"],
            AttackType.RECONNAISSANCE: ["T1046", "T1083", "T1018"],
            AttackType.UNKNOWN: []
        }

    def map_attack_to_mitre(self, attack_type: AttackType,
                           description: str = "") -> List[MitreTechnique]:
        """Map an attack type to MITRE ATT&CK techniques"""
        technique_ids = self.attack_type_mappings.get(attack_type, [])

        # Enhanced mapping based on description
        if description:
            description_lower = description.lower()

            # Check for specific patterns in description
            if "powershell" in description_lower:
                technique_ids.append("T1059.001")
            if "cmd" in description_lower or "command" in description_lower:
                technique_ids.append("T1059.003")
            if "bash" in description_lower or "shell" in description_lower:
                technique_ids.append("T1059.004")
            if "brute" in description_lower or "password" in description_lower:
                technique_ids.append("T1110")
            if "scan" in description_lower or "probe" in description_lower:
                technique_ids.append("T1046")
            if "obfusc" in description_lower or "encod" in description_lower:
                technique_ids.append("T1027")

        # Remove duplicates and return technique objects
        unique_ids = list(set(technique_ids))
        techniques = []
        for tid in unique_ids:
            # Use get_technique_by_id to support both mitre_loader and techniques_db
            tech = self.get_technique_by_id(tid)
            if tech:
                techniques.append(tech)
        return techniques

    def get_tactics_for_attack(self, attack_type: AttackType) -> Set[MitreTactic]:
        """Get all MITRE tactics associated with an attack"""
        techniques = self.map_attack_to_mitre(attack_type)
        return {tech.tactic for tech in techniques}

    def get_technique_by_id(self, technique_id: str) -> Optional[MitreTechnique]:
        """Get technique details by ID"""
        if self.mitre_loader:
            return self.mitre_loader.get_technique(technique_id)
        return self.techniques_db.get(technique_id)

    def get_attack_summary(self, attack_type: AttackType,
                          description: str = "") -> Dict:
        """Get comprehensive MITRE mapping summary for an attack"""
        techniques = self.map_attack_to_mitre(attack_type, description)

        # Handle both MitreDatabaseLoader format (tactics list) and built-in format (tactic enum)
        all_tactics = set()
        mitre_techniques = []

        for tech in techniques:
            # Get technique ID - loader uses external_id, built-in uses id
            tech_id = getattr(tech, 'external_id', None) or getattr(tech, 'id', '')

            # Get tactics - loader has tactics list, built-in has single tactic enum
            if hasattr(tech, 'tactics') and isinstance(tech.tactics, list):
                # MitreDatabaseLoader format - tactics is list of tactic name strings
                tech_tactics = tech.tactics
                for tactic_name in tech_tactics:
                    all_tactics.add(tactic_name)
                tactic_str = tech_tactics[0] if tech_tactics else 'unknown'
            elif hasattr(tech, 'tactic'):
                # Built-in format - tactic is MitreTactic enum
                all_tactics.add(tech.tactic)
                tactic_str = tech.tactic.name if hasattr(tech.tactic, 'name') else str(tech.tactic)
            else:
                tactic_str = 'unknown'

            # Generate MITRE ATT&CK URL for the technique
            # Use URL from loader if available, otherwise generate standard URL
            tech_url = getattr(tech, 'url', None)
            if not tech_url and tech_id:
                # Generate URL: T1059.001 -> /techniques/T1059/001/
                if '.' in tech_id:
                    parent, sub = tech_id.split('.', 1)
                    tech_url = f"https://attack.mitre.org/techniques/{parent}/{sub}/"
                else:
                    tech_url = f"https://attack.mitre.org/techniques/{tech_id}/"

            mitre_techniques.append({
                'id': tech_id,
                'name': tech.name,
                'tactic': tactic_str,
                'description': getattr(tech, 'description', ''),
                'url': tech_url
            })

        # Build tactics list - handle both string and enum formats
        mitre_tactics = []
        for tactic in all_tactics:
            if isinstance(tactic, str):
                # String from loader - convert to standard format
                tactic_id = self._tactic_name_to_id(tactic)
                tactic_url = f"https://attack.mitre.org/tactics/{tactic_id}/"
                mitre_tactics.append({
                    'id': tactic_id,
                    'name': tactic.replace('-', ' ').title(),
                    'url': tactic_url
                })
            elif hasattr(tactic, 'value'):
                # MitreTactic enum
                tactic_url = f"https://attack.mitre.org/tactics/{tactic.value}/"
                mitre_tactics.append({
                    'id': tactic.value,
                    'name': tactic.name,
                    'url': tactic_url
                })

        return {
            'attack_type': attack_type.value if hasattr(attack_type, 'value') else str(attack_type),
            'mitre_tactics': mitre_tactics,
            'mitre_techniques': mitre_techniques,
            'kill_chain_phase': self._get_kill_chain_phase_from_names(all_tactics)
        }

    def _tactic_name_to_id(self, tactic_name: str) -> str:
        """Convert tactic name to MITRE ID"""
        tactic_map = {
            'reconnaissance': 'TA0043',
            'resource-development': 'TA0042',
            'initial-access': 'TA0001',
            'execution': 'TA0002',
            'persistence': 'TA0003',
            'privilege-escalation': 'TA0004',
            'defense-evasion': 'TA0005',
            'credential-access': 'TA0006',
            'discovery': 'TA0007',
            'lateral-movement': 'TA0008',
            'collection': 'TA0009',
            'command-and-control': 'TA0011',
            'exfiltration': 'TA0010',
            'impact': 'TA0040',
        }
        return tactic_map.get(tactic_name.lower(), tactic_name)

    def _get_kill_chain_phase_from_names(self, tactics) -> str:
        """Determine kill chain phase from tactics (handles both strings and enums)"""
        # Normalize to lowercase strings
        tactic_names = set()
        for t in tactics:
            if isinstance(t, str):
                tactic_names.add(t.lower().replace(' ', '-'))
            elif hasattr(t, 'name'):
                tactic_names.add(t.name.lower().replace('_', '-'))

        if 'reconnaissance' in tactic_names:
            return "Reconnaissance"
        elif 'initial-access' in tactic_names:
            return "Initial Access / Weaponization"
        elif 'execution' in tactic_names:
            return "Delivery / Exploitation"
        elif 'persistence' in tactic_names or 'privilege-escalation' in tactic_names:
            return "Installation"
        elif 'command-and-control' in tactic_names:
            return "Command & Control"
        elif 'exfiltration' in tactic_names or 'impact' in tactic_names:
            return "Actions on Objectives"
        else:
            return "Unknown"

    def _get_kill_chain_phase(self, tactics: Set[MitreTactic]) -> str:
        """Determine kill chain phase from tactics"""
        if MitreTactic.RECONNAISSANCE in tactics:
            return "Reconnaissance"
        elif MitreTactic.INITIAL_ACCESS in tactics:
            return "Initial Access / Weaponization"
        elif MitreTactic.EXECUTION in tactics:
            return "Delivery / Exploitation"
        elif MitreTactic.PERSISTENCE in tactics or MitreTactic.PRIVILEGE_ESCALATION in tactics:
            return "Installation"
        elif MitreTactic.COMMAND_AND_CONTROL in tactics:
            return "Command & Control"
        elif MitreTactic.EXFILTRATION in tactics or MitreTactic.IMPACT in tactics:
            return "Actions on Objectives"
        else:
            return "Unknown"

    def get_all_techniques(self) -> List[MitreTechnique]:
        """Get all available techniques"""
        if self.mitre_loader:
            return list(self.mitre_loader.techniques.values())
        return list(self.techniques_db.values())

    def get_techniques_by_tactic(self, tactic: MitreTactic) -> List[MitreTechnique]:
        """Get all techniques for a specific tactic"""
        # Use mitre_loader if available (has tactics as list of strings)
        if self.mitre_loader:
            tactic_name = tactic.name.lower().replace('_', '-')
            return [tech for tech in self.mitre_loader.techniques.values()
                    if tactic_name in [t.lower() for t in tech.tactics]]
        # Fall back to built-in techniques_db (has tactic as enum)
        return [tech for tech in self.techniques_db.values()
                if tech.tactic == tactic]
