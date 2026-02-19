"""
MITRE ATT&CK Database Loader
Loads and parses the official MITRE ATT&CK framework from mitre_cache.json
"""

import json
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class MitreTechnique:
    """MITRE ATT&CK Technique with all metadata"""
    id: str
    name: str
    description: str
    tactics: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    detection: str = ""
    is_subtechnique: bool = False
    parent_technique: Optional[str] = None
    external_id: str = ""
    url: str = ""
    version: str = ""
    deprecated: bool = False

@dataclass
class MitreTactic:
    """MITRE ATT&CK Tactic"""
    id: str
    name: str
    description: str
    shortname: str
    external_id: str = ""
    url: str = ""

@dataclass
class MitreGroup:
    """MITRE ATT&CK Group (Threat Actor)"""
    id: str
    name: str
    description: str
    aliases: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    software: List[str] = field(default_factory=list)
    external_id: str = ""
    url: str = ""

@dataclass
class MitreSoftware:
    """MITRE ATT&CK Software (Malware/Tool)"""
    id: str
    name: str
    description: str
    type: str  # malware or tool
    platforms: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    external_id: str = ""
    url: str = ""

class MitreDatabaseLoader:
    """Loads and parses MITRE ATT&CK database from JSON"""

    def __init__(self, cache_file: str = "mitre_cache.json"):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cache_file = Path(cache_file)

        # Storage
        self.techniques: Dict[str, MitreTechnique] = {}
        self.tactics: Dict[str, MitreTactic] = {}
        self.groups: Dict[str, MitreGroup] = {}
        self.software: Dict[str, MitreSoftware] = {}
        self.relationships: List[Dict] = []

        # Mappings
        self.technique_to_tactics: Dict[str, List[str]] = {}
        self.group_to_techniques: Dict[str, List[str]] = {}
        self.software_to_techniques: Dict[str, List[str]] = {}

        # Load if file exists
        if self.cache_file.exists():
            self.load()
        else:
            self.logger.warning(f"MITRE cache file not found: {cache_file}")

    def load(self):
        """Load MITRE ATT&CK data from JSON cache"""
        try:
            self.logger.info(f"Loading MITRE ATT&CK database from {self.cache_file}")

            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            objects = data.get('objects', [])
            self.logger.info(f"Found {len(objects)} objects in MITRE database")

            # First pass: Load base objects
            for obj in objects:
                obj_type = obj.get('type')

                if obj_type == 'attack-pattern':
                    self._load_technique(obj)
                elif obj_type == 'x-mitre-tactic':
                    self._load_tactic(obj)
                elif obj_type == 'intrusion-set':
                    self._load_group(obj)
                elif obj_type in ['malware', 'tool']:
                    self._load_software(obj)
                elif obj_type == 'relationship':
                    self.relationships.append(obj)

            # Second pass: Process relationships
            self._process_relationships()

            self.logger.info(f"Loaded {len(self.techniques)} techniques, "
                           f"{len(self.tactics)} tactics, "
                           f"{len(self.groups)} groups, "
                           f"{len(self.software)} software")

        except Exception as e:
            self.logger.error(f"Error loading MITRE database: {e}", exc_info=True)

    def _load_technique(self, obj: Dict):
        """Load attack pattern (technique)"""
        if obj.get('x_mitre_deprecated'):
            return  # Skip deprecated

        external_refs = obj.get('external_references', [])
        external_id = ""
        url = ""

        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                external_id = ref.get('external_id', '')
                url = ref.get('url', '')
                break

        # Check if it's a sub-technique (has a dot in ID like T1059.001)
        is_subtechnique = '.' in external_id
        parent_technique = external_id.split('.')[0] if is_subtechnique else None

        # Get tactics from kill_chain_phases
        tactics = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactics.append(phase.get('phase_name', ''))

        technique = MitreTechnique(
            id=obj['id'],
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            tactics=tactics,
            platforms=obj.get('x_mitre_platforms', []),
            data_sources=obj.get('x_mitre_data_sources', []),
            detection=obj.get('x_mitre_detection', ''),
            is_subtechnique=is_subtechnique,
            parent_technique=parent_technique,
            external_id=external_id,
            url=url,
            version=obj.get('x_mitre_version', ''),
            deprecated=obj.get('x_mitre_deprecated', False)
        )

        self.techniques[external_id] = technique
        self.technique_to_tactics[external_id] = tactics

    def _load_tactic(self, obj: Dict):
        """Load MITRE tactic"""
        external_refs = obj.get('external_references', [])
        external_id = ""
        url = ""

        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                external_id = ref.get('external_id', '')
                url = ref.get('url', '')
                break

        tactic = MitreTactic(
            id=obj['id'],
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            shortname=obj.get('x_mitre_shortname', ''),
            external_id=external_id,
            url=url
        )

        self.tactics[obj['id']] = tactic

    def _load_group(self, obj: Dict):
        """Load intrusion set (threat actor group)"""
        if obj.get('x_mitre_deprecated'):
            return

        external_refs = obj.get('external_references', [])
        external_id = ""
        url = ""

        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                external_id = ref.get('external_id', '')
                url = ref.get('url', '')
                break

        group = MitreGroup(
            id=obj['id'],
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            aliases=obj.get('aliases', []),
            external_id=external_id,
            url=url
        )

        self.groups[external_id] = group

    def _load_software(self, obj: Dict):
        """Load malware or tool"""
        if obj.get('x_mitre_deprecated') or obj.get('revoked'):
            return

        external_refs = obj.get('external_references', [])
        external_id = ""
        url = ""

        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                external_id = ref.get('external_id', '')
                url = ref.get('url', '')
                break

        software = MitreSoftware(
            id=obj['id'],
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            type=obj['type'],
            platforms=obj.get('x_mitre_platforms', []),
            external_id=external_id,
            url=url
        )

        self.software[external_id] = software

    def _process_relationships(self):
        """Process relationships between objects"""
        for rel in self.relationships:
            rel_type = rel.get('relationship_type')
            source = rel.get('source_ref')
            target = rel.get('target_ref')

            if not source or not target:
                continue

            # Group uses technique
            if rel_type == 'uses' and source.startswith('intrusion-set'):
                # Find group by ID
                group_id = None
                for gid, group in self.groups.items():
                    if group.id == source:
                        group_id = gid
                        break

                # Find technique by ID
                tech_id = None
                for tid, tech in self.techniques.items():
                    if tech.id == target:
                        tech_id = tid
                        break

                if group_id and tech_id:
                    if group_id not in self.group_to_techniques:
                        self.group_to_techniques[group_id] = []
                    self.group_to_techniques[group_id].append(tech_id)
                    self.groups[group_id].techniques.append(tech_id)

            # Software uses technique
            elif rel_type == 'uses' and (source.startswith('malware') or source.startswith('tool')):
                # Find software by ID
                soft_id = None
                for sid, soft in self.software.items():
                    if soft.id == source:
                        soft_id = sid
                        break

                # Find technique by ID
                tech_id = None
                for tid, tech in self.techniques.items():
                    if tech.id == target:
                        tech_id = tid
                        break

                if soft_id and tech_id:
                    if soft_id not in self.software_to_techniques:
                        self.software_to_techniques[soft_id] = []
                    self.software_to_techniques[soft_id].append(tech_id)
                    self.software[soft_id].techniques.append(tech_id)

    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        """Get technique by ID (e.g., T1059)"""
        return self.techniques.get(technique_id)

    def get_group(self, group_id: str) -> Optional[MitreGroup]:
        """Get group by ID (e.g., G0016)"""
        return self.groups.get(group_id)

    def get_software(self, software_id: str) -> Optional[MitreSoftware]:
        """Get software by ID (e.g., S0154)"""
        return self.software.get(software_id)

    def search_techniques(self, query: str) -> List[MitreTechnique]:
        """Search techniques by name or description"""
        query_lower = query.lower()
        results = []

        for tech in self.techniques.values():
            if (query_lower in tech.name.lower() or
                query_lower in tech.description.lower() or
                query_lower in tech.external_id.lower()):
                results.append(tech)

        return results

    def search_groups(self, query: str) -> List[MitreGroup]:
        """Search groups by name or alias"""
        query_lower = query.lower()
        results = []

        for group in self.groups.values():
            if (query_lower in group.name.lower() or
                any(query_lower in alias.lower() for alias in group.aliases)):
                results.append(group)

        return results

    def search_software(self, query: str) -> List[MitreSoftware]:
        """Search software by name"""
        query_lower = query.lower()
        results = []

        for soft in self.software.values():
            if query_lower in soft.name.lower():
                results.append(soft)

        return results

    def get_techniques_for_tactic(self, tactic_name: str) -> List[MitreTechnique]:
        """Get all techniques for a specific tactic"""
        results = []
        for tech in self.techniques.values():
            if tactic_name.lower() in [t.lower() for t in tech.tactics]:
                results.append(tech)
        return results

    def get_techniques_for_group(self, group_id: str) -> List[MitreTechnique]:
        """Get techniques used by a specific group"""
        tech_ids = self.group_to_techniques.get(group_id, [])
        return [self.techniques[tid] for tid in tech_ids if tid in self.techniques]

    def get_groups_using_technique(self, technique_id: str) -> List[MitreGroup]:
        """Get groups that use a specific technique"""
        results = []
        for group_id, tech_ids in self.group_to_techniques.items():
            if technique_id in tech_ids:
                results.append(self.groups[group_id])
        return results

    def get_stats(self) -> Dict:
        """Get database statistics"""
        return {
            'total_techniques': len(self.techniques),
            'total_tactics': len(self.tactics),
            'total_groups': len(self.groups),
            'total_software': len(self.software),
            'total_relationships': len(self.relationships),
            'subtechniques': sum(1 for t in self.techniques.values() if t.is_subtechnique),
            'active_techniques': sum(1 for t in self.techniques.values() if not t.deprecated),
        }
