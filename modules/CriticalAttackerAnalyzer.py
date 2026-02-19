import logging
import sys
import asyncio
import re
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np

# Module imports
from modules.RegexAttackDetector import RegexAttackDetector
from modules.CLIConfiguration import CLIConfiguration
from modules.CacheManager import CacheManager
from modules.SmartIPExtractor import SmartIPExtractor
from modules.GeoIPEnricher import GeoIPEnricher
from modules.ThreatIntelligenceEnricher import ThreatIntelligenceEnricher
from modules.AttackerProfile import AttackerProfile
from modules.AgentProfile import AgentProfile
from modules.DataSource import DataSource
from modules.ElasticsearchDataSource import ElasticsearchDataSource
from modules.AttackEvent import AttackEvent
from modules.AttackType import AttackType
from modules.MitreAttackMapper import MitreAttackMapper
from modules.MLAnomalyDetector import MLAnomalyDetector

# ML Validation Engine for ground truth building and accuracy measurement
try:
    from modules.MLValidationEngine import MLValidationEngine, get_validation_engine
    ML_VALIDATION_AVAILABLE = True
except ImportError:
    ML_VALIDATION_AVAILABLE = False

# Advanced Unsupervised Detection (VAE + Deep SVDD)
try:
    from modules.AdvancedUnsupervisedDetector import AdvancedUnsupervisedDetector
    ADVANCED_ML_AVAILABLE = True
except ImportError:
    ADVANCED_ML_AVAILABLE = False

# ============================================================================
# Main Analysis Engine from CLI Script
# ============================================================================

class CriticalAttackerAnalyzer:
    """Main analyzer for processing critical attacks and extracting attacker profiles."""

    def __init__(self, config: CLIConfiguration):
        self.config = config

        # Ensure output directory exists
        Path(config.output_directory).mkdir(parents=True, exist_ok=True)

        self.logger = self._setup_logging()
        self.cache = CacheManager(config.cache_directory) if config.enable_cache else None
        self.attack_detector = RegexAttackDetector()
        self.ip_extractor = SmartIPExtractor()
        self.geo_enricher = GeoIPEnricher(config.geoip_database_path)
        self.threat_enricher = ThreatIntelligenceEnricher(
            cache_manager=self.cache,
            virustotal_api_key=config.virustotal_api_key,
            abuseipdb_api_key=config.abuseipdb_api_key,
            enable_virustotal=getattr(config, 'enable_virustotal', True),
            enable_abuseipdb=getattr(config, 'enable_abuseipdb', True),
            enable_sans_isc=getattr(config, 'enable_sans_isc', True)
        )
        self.mitre_mapper = MitreAttackMapper.get_instance()

        # Initialize Hybrid ML Anomaly Detector for 100% validation
        try:
            self.ml_detector = MLAnomalyDetector(model_dir="./models")
            self.logger.info("Hybrid ML Anomaly Detector initialized for profile validation")
        except Exception as e:
            self.logger.warning(f"ML Detector initialization failed: {e}. ML validation disabled.")
            self.ml_detector = None

        # Initialize ML Validation Engine for ground truth and accuracy measurement
        self.validation_engine = None
        if ML_VALIDATION_AVAILABLE:
            try:
                self.validation_engine = get_validation_engine()
                self.logger.info("ML Validation Engine initialized for ground truth building")
            except Exception as e:
                self.logger.warning(f"ML Validation Engine init failed: {e}")

        # Initialize Advanced Unsupervised Detector (VAE + Deep SVDD)
        self.advanced_detector = None
        if ADVANCED_ML_AVAILABLE:
            try:
                self.advanced_detector = AdvancedUnsupervisedDetector(model_dir="./models/advanced_unsupervised")
                self.logger.info("Advanced Unsupervised Detector (VAE + Deep SVDD) initialized")
            except Exception as e:
                self.logger.warning(f"Advanced Unsupervised Detector init failed: {e}. Advanced detection disabled.")

    def _setup_logging(self) -> logging.Logger:
        """Configure logging with multiple handlers."""
        logger = logging.getLogger('CriticalAttackerAnalyzer')
        logger.setLevel(logging.DEBUG)

        # Prevent duplicate handlers - only add if not already present
        if logger.handlers:
            return logger

        # Prevent propagation to root logger (avoids duplicate output)
        logger.propagate = False

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)

        # File handler
        log_file = Path(self.config.output_directory) / f"analysis_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(str(log_file))
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

        return logger

    async def analyze(self, hours_back: Optional[int] = None, progress_callback=None) -> Tuple[List[AttackerProfile], Dict[str, AgentProfile]]:
        """Main analysis method to process alerts and extract attacker profiles."""
        hours = hours_back or self.config.default_hours_back
        self.logger.info(f"Starting critical attacker analysis for last {hours} hours")

        if progress_callback:
            progress_callback(0.1, "Building query...")
        self.logger.info("Building Elasticsearch query...")

        # Build time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        # Build Elasticsearch query
        query = self._build_critical_alerts_query(start_time, end_time)

        if progress_callback:
            progress_callback(0.15, "Resolving DNS...")
        self.logger.info("Resolving DNS...")

        # Fetch alerts from Elasticsearch
        async with ElasticsearchDataSource(self.config) as datasource:
            # Warmup DNS cache first to avoid timeout issues
            dns_result = await datasource.warmup_dns()
            self.logger.info(f"DNS warmup completed: {'success' if dns_result else 'failed (continuing anyway)'}")

            if progress_callback:
                progress_callback(0.2, "Connecting to Elasticsearch...")
            self.logger.info("Performing Elasticsearch health check...")

            # Health check
            if not await datasource.health_check():
                raise Exception("Elasticsearch is not accessible")
            self.logger.info("Elasticsearch connection verified")

            if progress_callback:
                progress_callback(0.3, "Querying critical alerts...")
            self.logger.info("Querying critical alerts (this may take a while for large datasets)...")

            alerts = await datasource.query_alerts(query)

        self.logger.info(f"=== ELASTICSEARCH RESULTS ===")
        self.logger.info(f"Retrieved {len(alerts)} critical alerts for analysis")

        # DEBUG: Show sample alert structure if any alerts returned
        if alerts:
            sample = alerts[0]
            self.logger.info(f"Sample alert keys: {list(sample.keys())}")
            if '_source' in sample:
                src = sample['_source']
                self.logger.info(f"Sample _source keys: {list(src.keys())[:20]}")
                if 'rule' in src:
                    self.logger.info(f"Sample rule: {src['rule']}")
                if 'agent' in src:
                    self.logger.info(f"Sample agent: {src['agent']}")
        else:
            self.logger.warning("NO ALERTS RETURNED FROM ELASTICSEARCH!")

        if progress_callback:
            progress_callback(0.5, f"Processing {len(alerts)} alerts...")

        # Process alerts in parallel
        attack_events = await self._process_alerts_parallel(alerts, progress_callback)

        self.logger.info(f"=== PROCESSING RESULTS ===")
        self.logger.info(f"Extracted {len(attack_events)} attack events from {len(alerts)} alerts")

        if progress_callback:
            progress_callback(0.7, "Building attacker profiles...")

        # Build attacker profiles
        attacker_profiles = self._build_attacker_profiles(attack_events)

        # Build agent profiles
        agent_profiles = self._build_agent_profiles(attack_events)

        if progress_callback:
            progress_callback(0.8, "Enriching with threat intelligence...")

        # Enrich profiles
        enriched_profiles = await self._enrich_profiles_parallel(attacker_profiles)

        if progress_callback:
            progress_callback(0.9, "Calculating risk scores...")

        # Calculate risk scores
        for profile in enriched_profiles:
            profile.calculate_risk_score()

        # Calculate agent risk levels
        for agent in agent_profiles.values():
            agent.calculate_risk_level()

        # Sort by risk score
        enriched_profiles.sort(key=lambda x: x.risk_score, reverse=True)

        self.logger.info(f"Identified {len(enriched_profiles)} unique attackers targeting {len(agent_profiles)} agents")

        if progress_callback:
            progress_callback(1.0, "Analysis complete!")

        return enriched_profiles, agent_profiles

    def _build_critical_alerts_query(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Build Elasticsearch query for alerts with full logs for ML/Hybrid analysis."""
        # CRITICAL: For scroll API, we need a valid batch size (not -1)
        batch_size = 1000 if self.config.max_results_per_query == -1 else min(self.config.max_results_per_query, 1000)

        # DEBUG: Log query parameters
        self.logger.info(f"=== QUERY PARAMETERS ===")
        self.logger.info(f"Time range: {start_time} to {end_time}")
        self.logger.info(f"Min severity level: {self.config.min_severity_level}")
        self.logger.info(f"Batch size: {batch_size}")
        self.logger.info(f"Max results: {self.config.max_results_per_query}")

        query = {
            "size": batch_size,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                                    "lte": end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                                }
                            }
                        },
                        {
                            "range": {
                                "rule.level": {
                                    "gte": self.config.min_severity_level
                                }
                            }
                        }
                    ]
                }
            },
            "_source": True,
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ]
        }

        self.logger.info(f"Query: {json.dumps(query, indent=2)}")
        return query

    async def _process_alerts_parallel(self, alerts: List[Dict[str, Any]], progress_callback=None) -> List[AttackEvent]:
        """Process alerts in parallel to extract attack events."""
        attack_events = []

        # Process in batches
        batch_size = self.config.batch_size
        total_batches = (len(alerts) + batch_size - 1) // batch_size

        for batch_idx, i in enumerate(range(0, len(alerts), batch_size)):
            batch = alerts[i:i + batch_size]

            if progress_callback:
                progress = 0.5 + (0.2 * (batch_idx / total_batches))
                progress_callback(progress, f"Processing batch {batch_idx + 1}/{total_batches}...")

            # Process batch with thread pool
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures = []

                for alert in batch:
                    future = executor.submit(self._process_single_alert, alert)
                    futures.append(future)

                # Collect results
                for future in as_completed(futures):
                    try:
                        event = future.result()
                        if event:
                            attack_events.append(event)
                    except Exception as e:
                        self.logger.error(f"Error processing alert: {e}")

        return attack_events

    def _process_single_alert(self, alert: Dict[str, Any]) -> Optional[AttackEvent]:
        """Process a single alert to extract ALL IPs (not just attacks) for comprehensive analysis."""
        source = alert.get('_source', {})

        # Extract source IP first (CRITICAL: get all IPs)
        attacker_ips = self.ip_extractor.extract(alert)
        if not attacker_ips:
            # DEBUG: Log why this alert has no IPs
            rule = source.get('rule', {})
            self.logger.debug(f"No IPs found in alert: rule_id={rule.get('id', 'unknown')}, desc={rule.get('description', 'unknown')[:50]}")
            return None

        # Use the first public IP found - validate it's a valid IP first
        attacker_ip = attacker_ips[0]

        # Validate IP address format
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(attacker_ip)
            # Skip invalid/special IPs
            if ip_obj.is_unspecified or ip_obj.is_loopback or ip_obj.is_multicast:
                self.logger.debug(f"Skipping special IP: {attacker_ip}")
                return None
        except ValueError:
            self.logger.debug(f"Invalid IP address format: {attacker_ip}")
            return None

        # Extract metadata
        rule = source.get('rule', {})
        agent = source.get('agent', {})

        # Get full log
        full_log = source.get('full_log', '')

        # Try to detect attack pattern
        is_attack, attack_type, payload = self.attack_detector.detect(full_log) if full_log else (False, AttackType.UNKNOWN, '')

        # CRITICAL FIX: Always ensure we have a meaningful payload and attack type
        # This ensures SSH Rule 5710 and other alerts always create valid events for reporting
        rule_id = rule.get('id', 'unknown')
        rule_description = rule.get('description', 'Network activity')

        if not is_attack or not payload:
            # Determine attack type from rule ID or description
            if rule_id == '5710' or 'ssh' in rule_description.lower():
                attack_type = AttackType.BRUTE_FORCE
            elif 'authentication' in rule_description.lower() or 'login' in rule_description.lower():
                attack_type = AttackType.BRUTE_FORCE
            elif 'sql' in rule_description.lower():
                attack_type = AttackType.SQL_INJECTION
            elif 'xss' in rule_description.lower() or 'script' in rule_description.lower():
                attack_type = AttackType.XSS
            elif 'command' in rule_description.lower():
                attack_type = AttackType.COMMAND_INJECTION
            elif 'scan' in rule_description.lower():
                attack_type = AttackType.PORT_SCAN
            else:
                attack_type = AttackType.UNKNOWN

            # Always use rule description as payload if no attack pattern detected
            # This ensures ALL alerts with IPs create meaningful events that appear in reports
            payload = rule_description
            if full_log:
                # Append first 150 chars of log for context
                payload += f" | Log: {full_log[:150]}"

            is_attack = True  # Treat all alerts as potential attacks for comprehensive reporting

        # Extract CVEs
        cve_list = []
        if 'cve' in source.get('data', {}):
            cve_list.append(source['data']['cve'])
        if 'info' in rule and 'CVE' in rule['info']:
            cve_match = re.findall(r'CVE-\d{4}-\d+', rule['info'])
            cve_list.extend(cve_match)

        # Parse timestamp safely
        timestamp_str = source.get('timestamp', '')
        try:
            if timestamp_str:
                parsed_timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                parsed_timestamp = datetime.utcnow()
        except (ValueError, AttributeError):
            parsed_timestamp = datetime.utcnow()

        # Get MITRE ATT&CK mapping for this attack
        mitre_data = None
        try:
            mitre_summary = self.mitre_mapper.get_attack_summary(attack_type, rule_description)
            if mitre_summary:
                tactics = mitre_summary.get('mitre_tactics', [])
                techniques = mitre_summary.get('mitre_techniques', [])
                if tactics or techniques:
                    mitre_data = {
                        'tactics': [t.get('name', t.get('id', '')) for t in tactics],
                        'techniques': [{'id': t.get('id', ''), 'name': t.get('name', '')} for t in techniques]
                    }
                    self.logger.debug(f"MITRE mapped for {attack_type}: {len(tactics)} tactics, {len(techniques)} techniques")
        except Exception as e:
            self.logger.debug(f"MITRE mapping failed for {attack_type}: {e}")

        # Create event for this IP - now ALL alerts with IPs create events
        return AttackEvent(
            timestamp=parsed_timestamp,
            ip_address=attacker_ip,
            rule_level=rule.get('level', 0),
            rule_id=rule_id,
            description=rule_description,
            attack_type=attack_type,
            payload=payload,  # Now always has meaningful content
            agent_name=agent.get('name', 'unknown'),
            agent_ip=agent.get('ip', 'unknown'),
            agent_id=agent.get('id', 'unknown'),
            cve_list=list(set(cve_list)),
            confidence_score=85.0 if is_attack else 70.0,  # Higher confidence for rule-based detection
            mitre_attack=mitre_data
        )

    def _build_attacker_profiles(self, attack_events: List[AttackEvent]) -> List[AttackerProfile]:
        """Build attacker profiles from attack events with enhanced agent tracking."""
        # Group events by attacker IP
        attacker_groups = defaultdict(list)
        for event in attack_events:
            attacker_groups[event.ip_address].append(event)

        # Create profiles
        profiles = []
        for ip_address, events in attacker_groups.items():
            # Sort events by timestamp
            events.sort(key=lambda x: x.timestamp)

            # Extract unique values with agent details
            attack_types = set(event.attack_type for event in events)
            targeted_agents = set()
            targeted_agents_details = {}
            cve_exploits = set()

            for event in events:
                # Create agent key with full details
                agent_key = f"{event.agent_id}|{event.agent_name}|{event.agent_ip}"
                targeted_agents.add(agent_key)

                # Store detailed agent information
                if agent_key not in targeted_agents_details:
                    targeted_agents_details[agent_key] = {
                        'agent_id': event.agent_id,
                        'agent_name': event.agent_name,
                        'agent_ip': event.agent_ip,
                        'attack_count': 0,
                        'attack_types': set()
                    }

                targeted_agents_details[agent_key]['attack_count'] += 1
                attack_type_name = event.attack_type.value if hasattr(event.attack_type, 'value') else str(event.attack_type)
                targeted_agents_details[agent_key]['attack_types'].add(attack_type_name)

                cve_exploits.update(event.cve_list)

            # Calculate confidence score
            confidence_scores = [event.confidence_score for event in events]
            avg_confidence = np.mean(confidence_scores)

            profile = AttackerProfile(
                ip_address=ip_address,
                first_seen=events[0].timestamp,
                last_seen=events[-1].timestamp,
                attack_count=len(events),
                attack_events=events,
                attack_types=attack_types,
                targeted_agents=targeted_agents,
                cve_exploits=cve_exploits,
                confidence_score=avg_confidence,
                targeted_agents_details=targeted_agents_details
            )

            profiles.append(profile)

        return profiles

    def _build_agent_profiles(self, attack_events: List[AttackEvent]) -> Dict[str, AgentProfile]:
        """Build profiles for each targeted agent."""
        agent_profiles = {}

        for event in attack_events:
            agent_key = f"{event.agent_id}|{event.agent_name}|{event.agent_ip}"

            if agent_key not in agent_profiles:
                agent_profiles[agent_key] = AgentProfile(
                    agent_id=event.agent_id,
                    agent_name=event.agent_name,
                    agent_ip=event.agent_ip,
                    total_attacks=0,
                    unique_attackers=set(),
                    attack_types=set(),
                    cve_exploits=set(),
                    first_attack=event.timestamp,
                    last_attack=event.timestamp,
                    attack_events=[]
                )

            profile = agent_profiles[agent_key]
            profile.total_attacks += 1
            profile.unique_attackers.add(event.ip_address)
            if event.attack_type:  # Only add if not None
                profile.attack_types.add(event.attack_type)
            if event.cve_list:  # Only update if not None/empty
                profile.cve_exploits.update(event.cve_list)
            profile.attack_events.append(event)

            if event.timestamp < profile.first_attack:
                profile.first_attack = event.timestamp
            if event.timestamp > profile.last_attack:
                profile.last_attack = event.timestamp

        return agent_profiles

    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if an IP address is private/internal (RFC 1918, loopback, link-local)"""
        import ipaddress
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            return False

    async def _enrich_profiles_parallel(self, profiles: List[AttackerProfile]) -> List[AttackerProfile]:
        """
        ML-First Enrichment Pipeline with Private/Public IP separation.

        Workflow:
        1. Separate Private IPs (ML-only) from Public IPs (ML + API)
        2. GeoIP enrichment (fast, local)
        3. ML prediction for ALL IPs
        4. Threat Intelligence APIs ONLY for PUBLIC IPs (Private IPs have no external TI data)
        5. FINAL ML prediction with enriched data

        Private IPs: Use ONLY Hybrid ML engine (no external API calls)
        Public IPs: Use enabled APIs (VirusTotal, AbuseIPDB, SANS ISC based on settings)
        """
        self.logger.info(f"Starting ML-First enrichment pipeline for {len(profiles)} profiles...")
        self.logger.info("=" * 60)
        self.logger.info("WORKFLOW: Private IPs -> ML Only | Public IPs -> ML + Enabled APIs")
        self.logger.info("=" * 60)

        # Step 0: Separate Private and Public IPs
        private_profiles = []
        public_profiles = []
        for profile in profiles:
            if self._is_private_ip(profile.ip_address):
                private_profiles.append(profile)
            else:
                public_profiles.append(profile)

        self.logger.info(f"Step 0/7: IP Classification - {len(private_profiles)} Private, {len(public_profiles)} Public")

        # Step 1: Enrich with GeoIP data (synchronous, local - no API calls)
        self.logger.info("Step 1/7: GeoIP enrichment (local database)...")
        for profile in profiles:
            if self.geo_enricher:
                profile.geo_location = self.geo_enricher.enrich(profile.ip_address)

        # Step 2: ML prediction for ALL IPs (both private and public)
        self.logger.info("Step 2/7: ML prediction for ALL IPs...")
        suspicious_public_profiles = []
        low_risk_public_profiles = []

        if self.ml_detector:
            # Process ALL profiles with ML (private + public)
            for profile in profiles:
                try:
                    ml_result = self.ml_detector.detect_anomaly(profile)
                    profile.ml_prediction_initial = ml_result
                except Exception as e:
                    self.logger.debug(f"Initial ML failed for {profile.ip_address}: {e}")
                    profile.ml_prediction_initial = {'is_anomaly': False, 'score': 0}

            # For PRIVATE IPs: ML-only, no API enrichment needed
            for profile in private_profiles:
                profile.threat_reputation = {'sources': ['ML_Only'], 'is_private_ip': True}
                profile.threat_intel = profile.threat_reputation

            # For PUBLIC IPs: Determine if API enrichment is needed based on ML
            for profile in public_profiles:
                ml_result = getattr(profile, 'ml_prediction_initial', {})
                is_suspicious = self._is_suspicious_for_api(profile, ml_result)

                if is_suspicious:
                    suspicious_public_profiles.append(profile)
                else:
                    low_risk_public_profiles.append(profile)
                    profile.threat_reputation = {'sources': ['ML_Only'], 'ml_low_risk': True}
                    profile.threat_intel = profile.threat_reputation

            self.logger.info(f"  -> Private IPs: {len(private_profiles)} (ML-only, no API calls)")
            self.logger.info(f"  -> Public IPs requiring API: {len(suspicious_public_profiles)}/{len(public_profiles)}")
            self.logger.info(f"  -> Public IPs skipped (ML low-risk): {len(low_risk_public_profiles)}")
        else:
            self.logger.warning("ML detector not available - calling APIs for ALL public profiles")
            suspicious_public_profiles = public_profiles
            for profile in private_profiles:
                profile.threat_reputation = {'sources': ['ML_Only'], 'is_private_ip': True}
                profile.threat_intel = profile.threat_reputation

        # Step 3: Threat Intelligence enrichment ONLY for PUBLIC suspicious IPs
        # Process in batches with progress reporting
        total_public = len(suspicious_public_profiles)
        self.logger.info(f"Step 3/7: Threat Intelligence APIs for {total_public} PUBLIC suspicious IPs...")
        self.logger.info(f"  -> Rate limits: VT=4/min, AbuseIPDB=30/min, SANS=60/min (APIs run in parallel)")

        async def enrich_threat_intel(profile: AttackerProfile, idx: int):
            # Only call APIs for public IPs
            profile.threat_reputation = await self.threat_enricher.enrich(profile.ip_address)
            profile.threat_intel = profile.threat_reputation
            if (idx + 1) % 10 == 0 or idx + 1 == total_public:
                self.logger.info(f"  -> Progress: {idx + 1}/{total_public} IPs enriched ({(idx+1)*100//total_public}%)")
            return profile

        if suspicious_public_profiles:
            # Process in batches of 10 for better progress visibility
            batch_size = 10
            for batch_start in range(0, total_public, batch_size):
                batch_end = min(batch_start + batch_size, total_public)
                batch = suspicious_public_profiles[batch_start:batch_end]
                tasks = [enrich_threat_intel(profile, batch_start + i) for i, profile in enumerate(batch)]
                await asyncio.gather(*tasks)

            self.logger.info(f"  -> Enriched {total_public} PUBLIC profiles with enabled APIs")

            # Show cache statistics
            try:
                cache_stats = self.threat_enricher.get_cache_stats()
                persistent_stats = cache_stats.get('persistent_cache', {})
                hit_rate = persistent_stats.get('hit_rate_percent', 0)
                vt_cached = persistent_stats.get('virustotal_cached_ips', 0)
                abuse_cached = persistent_stats.get('abuseipdb_cached_ips', 0)
                self.logger.info(f"  -> Cache: {hit_rate}% hit rate, {vt_cached} VT cached, {abuse_cached} AbuseIPDB cached")
            except Exception as e:
                self.logger.debug(f"Cache stats unavailable: {e}")

        # Combine all profiles back (Private IPs + Public IPs with API + Public IPs ML-only)
        enriched_profiles = private_profiles + suspicious_public_profiles + low_risk_public_profiles

        # Step 3.5: Fill missing GeoIP from AbuseIPDB or SANS ISC
        self.logger.info("Step 3.5/7: Filling missing GeoIP from TI sources...")
        geo_fallback_count = 0
        for profile in enriched_profiles:
            if not profile.geo_location or not profile.geo_location.get('country'):
                # Try to get location from threat intel sources
                ti_data = profile.threat_reputation or {}

                # Try AbuseIPDB first (has country_code)
                abuse_data = ti_data.get('abuseipdb_data', {})
                if abuse_data and abuse_data.get('country_code'):
                    profile.geo_location = profile.geo_location or {}
                    profile.geo_location['country_code'] = abuse_data.get('country_code')
                    profile.geo_location['country'] = abuse_data.get('country_code')  # Will be resolved
                    profile.geo_location['isp'] = abuse_data.get('isp', 'Unknown')
                    profile.geo_location['usage_type'] = abuse_data.get('usage_type', 'Unknown')
                    profile.geo_location['source'] = 'AbuseIPDB'
                    geo_fallback_count += 1
                    continue

                # Try SANS ISC (may have location data)
                sans_data = ti_data.get('sans_isc_data', {})
                if sans_data and sans_data.get('country'):
                    profile.geo_location = profile.geo_location or {}
                    profile.geo_location['country'] = sans_data.get('country')
                    profile.geo_location['country_code'] = sans_data.get('country_code', '')
                    profile.geo_location['source'] = 'SANS_ISC'
                    geo_fallback_count += 1

        if geo_fallback_count > 0:
            self.logger.info(f"  -> Filled {geo_fallback_count} missing GeoIP from TI sources")

        # Step 4: MITRE ATT&CK is already mapped in attack events (done during event creation)
        self.logger.info("Step 4/7: MITRE ATT&CK mapping (already in events)...")
        mitre_count = sum(1 for p in enriched_profiles
                         for e in p.attack_events
                         if hasattr(e, 'mitre_attack') and e.mitre_attack)
        self.logger.info(f"  -> {mitre_count} events have MITRE ATT&CK mappings")

        # Step 5: FINAL validation - Different logic for Private vs Public IPs
        # Private IPs: Use Hybrid ML only (no TI available)
        # Public IPs: Use TI-based validation to AVOID FALSE POSITIVES from ML
        self.logger.info("Step 5/7: FINAL validation (Private=ML, Public=TI-based)...")

        ml_validated = 0
        ml_anomalies = 0
        ti_validated = 0
        ti_confirmed_malicious = 0

        for profile in enriched_profiles:
            is_private = self._is_private_ip(profile.ip_address)

            if is_private:
                # PRIVATE IPs: Use ML-only validation (no TI data available)
                if self.ml_detector:
                    try:
                        ml_result = self.ml_detector.detect_anomaly(profile)
                        profile.ml_prediction = ml_result
                        ml_validated += 1
                        if ml_result.get('is_anomaly', False):
                            ml_anomalies += 1
                    except Exception as e:
                        self.logger.debug(f"ML detection failed for private IP {profile.ip_address}: {e}")
                        profile.ml_prediction = {
                            'is_anomaly': False,
                            'score': 0,
                            'anomaly_score': 0,
                            'severity': 'unknown',
                            'explanation': f'ML validation error: {str(e)}',
                            'confidence': 0,
                            'detection_method': 'Error'
                        }
                else:
                    profile.ml_prediction = None
            else:
                # PUBLIC IPs: Use TI-based validation to avoid ML false positives
                # Logic: AbuseIPDB (not whitelisted + confidence > 0 + reports > 0) = BAD
                #    OR: Whitelisted by AbuseIPDB BUT SANS confirms (count > 0 + attacks > 0) = BAD
                ti_validated += 1
                is_confirmed_bad = profile.is_confirmed_malicious_public_ip()
                ti_reason = profile.get_ti_validation_reason()

                if is_confirmed_bad:
                    ti_confirmed_malicious += 1
                    profile.ml_prediction = {
                        'is_anomaly': True,
                        'score': 0.95,
                        'anomaly_score': 0.95,
                        'severity': 'high',
                        'explanation': f'TI-confirmed malicious: {ti_reason}',
                        'confidence': 95,
                        'detection_method': 'TI_Validation',
                        'ti_confirmed': True,
                        'ti_reason': ti_reason
                    }
                else:
                    # Not confirmed malicious by TI - likely benign or insufficient data
                    profile.ml_prediction = {
                        'is_anomaly': False,
                        'score': 0.2,
                        'anomaly_score': 0.2,
                        'severity': 'low',
                        'explanation': f'TI validation: {ti_reason}',
                        'confidence': 70,
                        'detection_method': 'TI_Validation',
                        'ti_confirmed': False,
                        'ti_reason': ti_reason
                    }

        self.logger.info(f"  -> Private IPs: {ml_validated} validated by ML, {ml_anomalies} anomalies")
        self.logger.info(f"  -> Public IPs: {ti_validated} validated by TI, {ti_confirmed_malicious} confirmed malicious")
        self.logger.info(f"  -> TI Validation avoids ML false positives for public IPs")

        # Step 5.5: Advanced Unsupervised Detection (VAE + Deep SVDD)
        if self.advanced_detector:
            self.logger.info("Step 5.5/8: Advanced Unsupervised Detection (VAE + Deep SVDD)...")
            advanced_detected = 0
            advanced_anomalies = 0

            # Train if enough data and models not trained yet
            if len(enriched_profiles) >= 20:
                model_info = self.advanced_detector.get_model_info()
                if not model_info.get('vae_trained') or not model_info.get('svdd_trained'):
                    self.logger.info("  -> Training VAE + Deep SVDD models...")
                    try:
                        train_result = self.advanced_detector.train(enriched_profiles, epochs=50)
                        if train_result.get('status') == 'success':
                            self.logger.info(f"  -> VAE + Deep SVDD trained on {train_result.get('samples', 0)} samples")
                    except Exception as e:
                        self.logger.warning(f"  -> Advanced model training failed: {e}")

            # Run detection for all profiles
            for profile in enriched_profiles:
                try:
                    advanced_result = self.advanced_detector.detect(profile)
                    profile.advanced_ml_prediction = advanced_result
                    advanced_detected += 1
                    if advanced_result.get('is_anomaly', False):
                        advanced_anomalies += 1
                except Exception as e:
                    self.logger.debug(f"Advanced detection failed for {profile.ip_address}: {e}")
                    profile.advanced_ml_prediction = {
                        'is_anomaly': False,
                        'error': str(e),
                        'detection_method': 'Advanced Unsupervised (Error)'
                    }

            self.logger.info(f"  -> VAE + Deep SVDD validated {advanced_detected}/{len(enriched_profiles)} profiles")
            self.logger.info(f"  -> {advanced_anomalies} anomalies detected by Advanced ML")
        else:
            self.logger.info("Step 5.5/8: Advanced Unsupervised Detection - SKIPPED (not available)")
            for profile in enriched_profiles:
                profile.advanced_ml_prediction = None

        # Log validation summary
        self._log_validation_summary(enriched_profiles)

        # Step 6: Build ground truth dataset for ML validation (async task)
        if self.validation_engine:
            try:
                # Build threat intel map for ground truth builder
                ti_map = {}
                for profile in enriched_profiles:
                    if profile.threat_reputation:
                        ti_map[profile.ip_address] = profile.threat_reputation

                result = self.validation_engine.ground_truth.build_from_profiles(
                    enriched_profiles, ti_map
                )
                self.logger.info(f"Step 6/7: Ground Truth Dataset - Added {result['added']} samples "
                               f"(Total: {result['total']} - {result['malicious']} malicious, {result['benign']} benign)")
            except Exception as e:
                self.logger.debug(f"Ground truth building failed: {e}")

        # Step 7: AUTO-RETRAIN ML models with new data (incremental learning)
        if self.ml_detector and len(enriched_profiles) >= 5:
            try:
                self.logger.info("Step 7/7: Auto-retraining ML models with new data...")
                retrain_result = self._auto_retrain_models(enriched_profiles)
                if retrain_result.get('status') == 'success':
                    self.logger.info(f"  -> ML models retrained: {retrain_result.get('samples_trained', 0)} samples, "
                                   f"accuracy: {retrain_result.get('accuracy', 0):.1%}")
                else:
                    self.logger.debug(f"  -> Skipped retraining: {retrain_result.get('message', 'insufficient data')}")
            except Exception as e:
                self.logger.debug(f"Auto-retrain skipped: {e}")

        return enriched_profiles

    def _auto_retrain_models(self, profiles: List[AttackerProfile]) -> Dict[str, Any]:
        """
        Automatically retrain ML models with new profile data.

        This implements incremental learning - models improve with each scan.
        """
        if not self.ml_detector:
            return {'status': 'skipped', 'message': 'ML detector not available'}

        # Need at least 10 profiles for meaningful training
        if len(profiles) < 10:
            return {'status': 'skipped', 'message': f'Need at least 10 profiles (got {len(profiles)})'}

        try:
            # Train anomaly detector (Isolation Forest + ensemble)
            anomaly_result = self.ml_detector.train_anomaly_detector(profiles)

            # Train risk scorer (Random Forest classifier)
            risk_result = self.ml_detector.train_risk_scorer(profiles)

            return {
                'status': 'success',
                'samples_trained': anomaly_result.get('samples_trained', 0),
                'features_count': anomaly_result.get('features_count', 0),
                'accuracy': risk_result.get('accuracy', 0),
                'autoencoder_trained': anomaly_result.get('autoencoder_trained', False),
                'ensemble_trained': anomaly_result.get('ensemble_trained', False)
            }
        except Exception as e:
            self.logger.warning(f"Auto-retrain failed: {e}")
            return {'status': 'error', 'message': str(e)}

    def _is_suspicious_for_api(self, profile: AttackerProfile, ml_result: dict) -> bool:
        """
        Determine if a profile needs external API enrichment based on ML + behavioral signals.

        Returns True if the IP should be enriched with external threat intelligence.
        This is the core logic for reducing API calls while maintaining accuracy.

        AGGRESSIVE THRESHOLDS: Only call APIs for truly suspicious IPs.
        Most IPs are benign scanners - save API quota for real threats.
        """
        suspicion_score = 0

        # ML flags as anomaly - strong indicator (+2)
        if ml_result and ml_result.get('is_anomaly', False):
            suspicion_score += 2

        # Check ML anomaly score threshold - only very anomalous
        anomaly_score = ml_result.get('anomaly_score', 0) if ml_result else 0
        if anomaly_score < -0.7:  # Very anomalous only
            suspicion_score += 2
        elif anomaly_score < -0.5:
            suspicion_score += 1

        # High attack count - only very high counts matter
        if profile.attack_count > 100:
            suspicion_score += 2
        elif profile.attack_count > 50:
            suspicion_score += 1
        # Skip moderate counts - too common

        # High risk score - only critical
        if profile.risk_score > 85:
            suspicion_score += 2
        elif profile.risk_score > 75:
            suspicion_score += 1

        # CVE exploitation detected - always investigate (+3)
        if len(profile.cve_exploits) > 0:
            suspicion_score += 3

        # Targeting many systems - lateral movement indicator
        if len(profile.targeted_agents) > 10:
            suspicion_score += 2
        elif len(profile.targeted_agents) > 5:
            suspicion_score += 1

        # Multiple attack types - sophisticated attacker
        if len(profile.attack_types) > 5:
            suspicion_score += 2
        elif len(profile.attack_types) > 3:
            suspicion_score += 1

        # Very high severity events - critical alerts only
        critical_events = sum(1 for e in profile.attack_events if e.rule_level >= 12)
        if critical_events > 3:
            suspicion_score += 2
        elif critical_events > 0:
            suspicion_score += 1

        # Need at least 2 points to warrant API call (lowered from 4)
        # This allows more IPs to get TI enrichment for accurate risk scoring
        return suspicion_score >= 2

    def _log_validation_summary(self, profiles: List[AttackerProfile]):
        """Log comprehensive validation summary for all profiles"""
        total = len(profiles) if profiles else 1  # Avoid division by zero
        geo_enriched = sum(1 for p in profiles if p.geo_location)
        ti_enriched = sum(1 for p in profiles if p.threat_reputation)
        ti_malicious = sum(1 for p in profiles if p.threat_reputation and p.threat_reputation.get('is_malicious'))
        ml_validated = sum(1 for p in profiles if p.ml_prediction)
        ml_anomalies = sum(1 for p in profiles if p.ml_prediction and p.ml_prediction.get('is_anomaly'))

        # Count by TI source
        sans_data = sum(1 for p in profiles if p.threat_reputation and 'SANS_ISC' in p.threat_reputation.get('sources', []))
        abuse_data = sum(1 for p in profiles if p.threat_reputation and 'AbuseIPDB' in p.threat_reputation.get('sources', []))
        vt_data = sum(1 for p in profiles if p.threat_reputation and 'VirusTotal' in p.threat_reputation.get('sources', []))

        # Count geo data sources
        geo_from_geoip = sum(1 for p in profiles if p.geo_location and p.geo_location.get('source', 'GeoIP') == 'GeoIP')
        geo_from_abuse = sum(1 for p in profiles if p.geo_location and p.geo_location.get('source') == 'AbuseIPDB')
        geo_from_sans = sum(1 for p in profiles if p.geo_location and p.geo_location.get('source') == 'SANS_ISC')

        # ML-First workflow metrics
        api_calls_saved = total - ti_enriched
        api_reduction_pct = (api_calls_saved / total * 100) if total > 0 else 0

        self.logger.info("=" * 60)
        self.logger.info("VALIDATION SUMMARY - ML-First Workflow")
        self.logger.info("=" * 60)
        self.logger.info(f"Total Profiles: {total}")
        self.logger.info("--- ML-First API Optimization ---")
        self.logger.info(f"  API Calls Made: {ti_enriched}/{total}")
        self.logger.info(f"  API Calls Saved: {api_calls_saved}/{total} ({api_reduction_pct:.1f}% reduction)")
        self.logger.info("--- Location Data Sources ---")
        self.logger.info(f"  GeoIP Database: {geo_from_geoip}/{total}")
        self.logger.info(f"  AbuseIPDB Fallback: {geo_from_abuse}/{total}")
        self.logger.info(f"  SANS ISC Fallback: {geo_from_sans}/{total}")
        self.logger.info(f"  Total with Location: {geo_enriched}/{total} ({100*geo_enriched/total:.1f}%)")
        self.logger.info("--- Threat Intelligence Sources ---")
        self.logger.info(f"  SANS ISC: {sans_data}/{total}")
        self.logger.info(f"  AbuseIPDB: {abuse_data}/{total}")
        self.logger.info(f"  VirusTotal: {vt_data}/{total}")
        self.logger.info(f"  Combined TI: {ti_enriched}/{total} ({100*ti_enriched/total:.1f}%)")
        self.logger.info(f"  Flagged Malicious: {ti_malicious}/{total}")
        self.logger.info("--- Final ML Validation ---")
        self.logger.info(f"  ML Validated: {ml_validated}/{total} ({100*ml_validated/total:.1f}%)")
        self.logger.info(f"  ML Anomalies: {ml_anomalies}/{total}")

        # Advanced Unsupervised Detection metrics
        advanced_validated = sum(1 for p in profiles if p.advanced_ml_prediction)
        advanced_anomalies = sum(1 for p in profiles if p.advanced_ml_prediction and p.advanced_ml_prediction.get('is_anomaly'))
        vae_anomalies = sum(1 for p in profiles if p.advanced_ml_prediction and p.advanced_ml_prediction.get('vae_anomaly'))
        svdd_anomalies = sum(1 for p in profiles if p.advanced_ml_prediction and p.advanced_ml_prediction.get('svdd_anomaly'))

        self.logger.info("--- Advanced Unsupervised Detection (VAE + Deep SVDD) ---")
        self.logger.info(f"  Advanced ML Validated: {advanced_validated}/{total} ({100*advanced_validated/total:.1f}%)")
        self.logger.info(f"  VAE Anomalies: {vae_anomalies}/{total}")
        self.logger.info(f"  Deep SVDD Anomalies: {svdd_anomalies}/{total}")
        self.logger.info(f"  Combined Anomalies: {advanced_anomalies}/{total}")
        self.logger.info("=" * 60)
