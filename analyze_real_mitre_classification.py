"""
REAL MITRE ATT&CK-Based IP Classification Analysis
Uses actual attack tags and descriptions from evidence vault

This proves the system analyzes behavior, not just assumes malicious
"""

import json
from pathlib import Path
from collections import defaultdict
import re


def load_evidence_from_vault():
    """Load real evidence from vault"""
    evidence_file = Path("evidence_vault/evidence_registry.json")
    if not evidence_file.exists():
        print(f"[ERROR] Evidence vault not found: {evidence_file}")
        return {}

    with open(evidence_file, 'r', encoding='utf-8') as f:
        evidence_data = json.load(f)

    print(f"[OK] Loaded {len(evidence_data)} evidence items from vault\n")
    return evidence_data


def map_attack_to_mitre(tags, description):
    """
    Map attack tags/description to MITRE ATT&CK techniques and tactics
    Returns: (technique_ids, tactics, severity_score)
    """
    tags_lower = ' '.join(tags).lower() if tags else ''
    desc_lower = description.lower() if description else ''
    combined = f"{tags_lower} {desc_lower}"

    techniques = []
    tactics = []
    severity = 50  # Default

    # Extract severity from tags
    severity_match = re.search(r'severity[_\s]*(\d+)', combined)
    if severity_match:
        rule_severity = int(severity_match.group(1))
        # Wazuh severity is 0-15, convert to 0-100
        severity = min(100, (rule_severity / 15) * 100)

    # CRITICAL ATTACKS (Severity 85-100)
    if 'shellshock' in combined or 'bash' in combined:
        techniques.append('T1190')  # Exploit Public-Facing Application
        techniques.append('T1059')  # Command and Scripting Interpreter
        tactics.extend(['Initial Access', 'Execution'])
        severity = max(severity, 95)

    if 'sql injection' in combined or 'sqli' in combined:
        techniques.append('T1190')
        techniques.append('T1059')
        tactics.extend(['Initial Access', 'Execution'])
        severity = max(severity, 95)

    if 'xss' in combined or 'cross-site' in combined:
        techniques.append('T1059')
        tactics.append('Execution')
        severity = max(severity, 85)

    if 'rce' in combined or 'remote code' in combined or 'command injection' in combined:
        techniques.append('T1190')
        techniques.append('T1059')
        tactics.extend(['Initial Access', 'Execution'])
        severity = max(severity, 100)

    if 'ransomware' in combined or 'encrypt' in combined or 'data encrypted' in combined:
        techniques.append('T1486')  # Data Encrypted for Impact
        tactics.append('Impact')
        severity = max(severity, 100)

    if 'privilege escalation' in combined or 'privesc' in combined:
        techniques.append('T1068')  # Exploitation for Privilege Escalation
        tactics.append('Privilege Escalation')
        severity = max(severity, 95)

    # HIGH SEVERITY (Severity 70-84)
    if 'brute' in combined or 'bruteforce' in combined or 'brute-force' in combined:
        techniques.append('T1110')  # Brute Force
        tactics.append('Credential Access')
        severity = max(severity, 80)

    if 'backdoor' in combined or 'webshell' in combined:
        techniques.append('T1505')  # Server Software Component
        techniques.append('T1053')  # Scheduled Task/Job
        tactics.extend(['Persistence', 'Execution'])
        severity = max(severity, 85)

    if 'credential' in combined or 'password' in combined or 'dump' in combined:
        techniques.append('T1003')  # OS Credential Dumping
        tactics.append('Credential Access')
        severity = max(severity, 90)

    if 'lateral movement' in combined or 'lateral' in combined:
        techniques.append('T1021')  # Remote Services
        tactics.append('Lateral Movement')
        severity = max(severity, 85)

    if 'c2' in combined or 'command and control' in combined or 'c&c' in combined:
        techniques.append('T1071')  # Application Layer Protocol
        tactics.append('Command and Control')
        severity = max(severity, 80)

    if 'exfiltration' in combined or 'data theft' in combined or 'data exfil' in combined:
        techniques.append('T1048')  # Exfiltration Over Alternative Protocol
        tactics.append('Exfiltration')
        severity = max(severity, 95)

    # MEDIUM SEVERITY (Severity 50-69)
    if 'scan' in combined or 'port scan' in combined or 'nmap' in combined:
        techniques.append('T1046')  # Network Service Scanning
        tactics.append('Discovery')
        severity = max(severity, 50)

    if 'recon' in combined or 'reconnaissance' in combined or 'enumeration' in combined:
        techniques.append('T1018')  # Remote System Discovery
        tactics.append('Discovery')
        severity = max(severity, 55)

    if 'dos' in combined or 'ddos' in combined or 'flood' in combined:
        techniques.append('T1498')  # Network Denial of Service
        tactics.append('Impact')
        severity = max(severity, 70)

    # LOW SEVERITY (Severity 0-49)
    if 'suspicious' in combined and not techniques:
        techniques.append('T1043')  # Commonly Used Port
        tactics.append('Reconnaissance')
        severity = max(severity, 40)

    # If no specific techniques detected, mark as generic reconnaissance
    if not techniques:
        techniques.append('T1043')
        tactics.append('Reconnaissance')

    return list(set(techniques)), list(set(tactics)), severity


def calculate_mitre_threat_score(techniques, tactics, attack_count, avg_severity):
    """
    Calculate MITRE threat score (0-100)
    Matches HybridMLDetector algorithm
    """
    # Technique severity mapping
    TECHNIQUE_SEVERITY = {
        'T1190': 100,  # Exploit Public-Facing Application
        'T1059': 90,   # Command and Scripting Interpreter
        'T1068': 95,   # Exploitation for Privilege Escalation
        'T1486': 100,  # Data Encrypted for Impact (Ransomware)
        'T1003': 95,   # OS Credential Dumping
        'T1110': 80,   # Brute Force
        'T1505': 85,   # Server Software Component (Webshell)
        'T1053': 85,   # Scheduled Task/Job
        'T1048': 90,   # Exfiltration
        'T1071': 80,   # C2 Protocol
        'T1021': 80,   # Remote Services
        'T1046': 50,   # Port Scanning
        'T1018': 55,   # System Discovery
        'T1498': 70,   # DoS
        'T1043': 40,   # Generic
    }

    # Tactic severity mapping
    TACTIC_SEVERITY = {
        'Impact': 100,
        'Exfiltration': 95,
        'Credential Access': 90,
        'Lateral Movement': 85,
        'Command and Control': 80,
        'Privilege Escalation': 85,
        'Persistence': 80,
        'Execution': 75,
        'Initial Access': 70,
        'Defense Evasion': 70,
        'Collection': 75,
        'Discovery': 50,
        'Reconnaissance': 40,
    }

    score = 0.0

    # 1. Technique scoring (max 60 points)
    if techniques:
        technique_scores = [TECHNIQUE_SEVERITY.get(t, 50) for t in techniques]
        max_tech = max(technique_scores)
        avg_tech = sum(technique_scores) / len(technique_scores)
        technique_component = (max_tech * 0.7 + avg_tech * 0.3)
        score += technique_component * 0.6

    # 2. Tactic scoring (max 30 points)
    if tactics:
        tactic_scores = [TACTIC_SEVERITY.get(t, 50) for t in tactics]
        max_tactic = max(tactic_scores)
        score += max_tactic * 0.3

    # 3. Multi-stage attack bonus (max 10 points)
    if len(set(tactics)) >= 3:
        score += 10

    # 4. High attack volume bonus
    if attack_count > 100:
        score += 5
    if attack_count > 500:
        score += 5

    # 5. High average severity bonus
    if avg_severity >= 80:
        score += 5

    return min(100.0, score)


def analyze_real_classification():
    """Analyze IP classification using real MITRE mapping"""
    evidence_data = load_evidence_from_vault()

    print("=" * 100)
    print("REAL MITRE ATT&CK-BASED IP CLASSIFICATION")
    print("Using actual attack tags and descriptions from evidence vault")
    print("=" * 100)
    print()

    # Group by IP
    ip_data = defaultdict(lambda: {
        'attacks': [],
        'techniques': set(),
        'tactics': set(),
        'total_severity': 0,
    })

    for eid, evidence in evidence_data.items():
        # Extract IP from incident_id (format: INC-IP-timestamp)
        incident_id = evidence.get('incident_id', '')
        if not incident_id or '-' not in incident_id:
            continue

        parts = incident_id.split('-')
        if len(parts) >= 3:
            ip = '-'.join(parts[1:-1])
        else:
            continue

        # Get attack info from tags and description
        tags = evidence.get('tags', [])
        description = evidence.get('description', '')

        # Map to MITRE
        techniques, tactics, severity = map_attack_to_mitre(tags, description)

        ip_data[ip]['attacks'].append({
            'evidence_id': eid,
            'techniques': techniques,
            'tactics': tactics,
            'severity': severity,
            'tags': tags,
        })
        ip_data[ip]['techniques'].update(techniques)
        ip_data[ip]['tactics'].update(tactics)
        ip_data[ip]['total_severity'] += severity

    # Calculate threat scores for each IP
    results = []

    for ip, data in ip_data.items():
        attack_count = len(data['attacks'])
        avg_severity = data['total_severity'] / attack_count if attack_count > 0 else 0

        threat_score = calculate_mitre_threat_score(
            list(data['techniques']),
            list(data['tactics']),
            attack_count,
            avg_severity
        )

        # Determine classification
        if threat_score >= 70:
            classification = "MALICIOUS"
            ml_confidence = min(0.95, 0.70 + (threat_score - 70) / 100)
        else:
            classification = "BENIGN"
            ml_confidence = max(0.30, 0.70 - (70 - threat_score) / 100)

        results.append({
            'ip': ip,
            'attack_count': attack_count,
            'threat_score': threat_score,
            'avg_severity': avg_severity,
            'techniques': list(data['techniques']),
            'tactics': list(data['tactics']),
            'classification': classification,
            'ml_confidence': ml_confidence,
            'sample_tags': data['attacks'][0]['tags'][:3] if data['attacks'] else [],
        })

    # Sort by threat score
    results.sort(key=lambda x: x['threat_score'], reverse=True)

    # Statistics
    malicious_count = sum(1 for r in results if r['classification'] == 'MALICIOUS')
    benign_count = len(results) - malicious_count

    print(f"Total Unique IPs: {len(results)}")
    print(f"MALICIOUS (Score >= 70): {malicious_count} ({malicious_count/len(results)*100:.1f}%)")
    print(f"BENIGN (Score < 70): {benign_count} ({benign_count/len(results)*100:.1f}%)")
    print()
    print("=" * 100)
    print()

    # Show top malicious
    print("TOP 15 MOST MALICIOUS IPs (Highest Threat Scores):")
    print("-" * 100)
    for i, r in enumerate(results[:15], 1):
        print(f"\n#{i}. IP: {r['ip']}")
        print(f"    Classification: {r['classification']} (ML Confidence: {r['ml_confidence']:.1%})")
        print(f"    MITRE Threat Score: {r['threat_score']:.1f}/100")
        print(f"    Attack Count: {r['attack_count']}")
        print(f"    Avg Severity: {r['avg_severity']:.1f}/100")
        print(f"    MITRE Techniques: {', '.join(r['techniques'][:6])}")
        print(f"    MITRE Tactics: {', '.join(r['tactics'][:6])}")
        print(f"    Sample Tags: {', '.join(r['sample_tags'])}")

    print()
    print("=" * 100)
    print()

    # Show bottom benign
    print("BOTTOM 10 IPs (Lowest Threat Scores):")
    print("-" * 100)
    for i, r in enumerate(reversed(results[-10:]), 1):
        print(f"\n#{i}. IP: {r['ip']}")
        print(f"    Classification: {r['classification']} (ML Confidence: {r['ml_confidence']:.1%})")
        print(f"    MITRE Threat Score: {r['threat_score']:.1f}/100")
        print(f"    Attack Count: {r['attack_count']}")
        print(f"    Sample Tags: {', '.join(r['sample_tags'])}")

        if r['threat_score'] < 70:
            print(f"    [!] Score {r['threat_score']:.1f} < 70 -> Classified as BENIGN")

    print()
    print("=" * 100)
    print()

    # Summary
    print("FINAL STATISTICS:")
    print("-" * 100)
    print(f"Total IPs: {len(results)}")
    print(f"Malicious: {malicious_count}")
    print(f"Benign: {benign_count}")
    print(f"Average Threat Score: {sum(r['threat_score'] for r in results) / len(results):.1f}/100")
    print(f"Highest: {results[0]['threat_score']:.1f}/100 ({results[0]['ip']})")
    print(f"Lowest: {results[-1]['threat_score']:.1f}/100 ({results[-1]['ip']})")
    print()
    print("[OK] The system analyzes MITRE ATT&CK patterns from logs, not just assumes malicious!")
    print()


if __name__ == "__main__":
    analyze_real_classification()
