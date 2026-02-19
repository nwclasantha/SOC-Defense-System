"""
CORRECTED Public IP Analysis with Behavioral Risk Scoring
----------------------------------------------------------
Properly identifies EXTERNAL attacker IPs and scores them based on:
1. Attack behavior (types, severity, frequency)
2. MITRE ATT&CK techniques
3. Attack patterns and persistence

Filters OUT internal IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
"""

import json
import ipaddress
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Tuple

def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private/internal (should NOT be flagged as external attacker)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        # Invalid IP or special addresses like 141.0.0.0
        if ip_str.endswith('.0.0.0') or ip_str.endswith('.0.0'):
            return True  # Network addresses, not real IPs
        return False

def extract_attack_behavior(evidence_items: List[Dict]) -> Dict:
    """
    Extract attack behavior characteristics from evidence items

    Returns behavioral analysis including:
    - Attack types and diversity
    - Severity levels
    - Attack patterns
    - Temporal characteristics
    """
    attack_types = []
    severities = []
    timestamps = []
    descriptions = set()

    for item in evidence_items:
        # Extract attack type from description
        desc = item.get('desc', '')
        descriptions.add(desc)

        # Extract severity from tags
        tags = item.get('tags', [])
        for tag in tags:
            if tag.startswith('severity_'):
                try:
                    sev = int(tag.split('_')[1])
                    severities.append(sev)
                except:
                    pass

        # Categorize attack type
        desc_lower = desc.lower()
        if 'shellshock' in desc_lower:
            attack_types.append('Remote Code Execution')
        elif 'sql injection' in desc_lower or 'sqli' in desc_lower:
            attack_types.append('SQL Injection')
        elif 'xss' in desc_lower or 'cross-site' in desc_lower:
            attack_types.append('Cross-Site Scripting')
        elif 'bot' in desc_lower or 'post requests' in desc_lower:
            attack_types.append('Bot/Automated Attack')
        elif 'brute' in desc_lower or 'force' in desc_lower:
            attack_types.append('Brute Force')
        elif 'url too long' in desc_lower or 'buffer overflow' in desc_lower:
            attack_types.append('Buffer Overflow')
        elif '400 error' in desc_lower or '404' in desc_lower:
            attack_types.append('Scanning/Probing')
        else:
            attack_types.append('Unknown')

    # Attack type diversity (more types = more sophisticated)
    unique_types = set(attack_types)
    type_counts = Counter(attack_types)

    # Severity analysis
    avg_severity = sum(severities) / len(severities) if severities else 0
    max_severity = max(severities) if severities else 0
    critical_count = sum(1 for s in severities if s >= 12)
    high_count = sum(1 for s in severities if 10 <= s < 12)

    return {
        'attack_count': len(evidence_items),
        'attack_types': list(unique_types),
        'type_diversity': len(unique_types),
        'type_distribution': dict(type_counts),
        'avg_severity': round(avg_severity, 1),
        'max_severity': max_severity,
        'critical_attacks': critical_count,
        'high_severity_attacks': high_count,
        'descriptions': list(descriptions)
    }

def calculate_behavioral_risk_score(behavior: Dict) -> Tuple[float, Dict]:
    """
    Calculate risk score based on attack behavior (MORE AGGRESSIVE SCORING)

    Scoring factors:
    - Frequency (0-30 points): How many attacks
    - Severity (0-50 points): How dangerous the attacks
    - Diversity (0-10 points): How many different attack types
    - Sophistication (0-10 points): Attack complexity indicators

    Total: 0-100
    """
    attack_count = behavior['attack_count']
    type_diversity = behavior['type_diversity']
    avg_severity = behavior['avg_severity']
    max_severity = behavior['max_severity']
    critical_attacks = behavior['critical_attacks']

    # === FREQUENCY SCORE (0-30) === MORE AGGRESSIVE
    if attack_count >= 200:
        frequency_score = 30
    elif attack_count >= 100:
        frequency_score = 28
    elif attack_count >= 50:
        frequency_score = 25
    elif attack_count >= 20:
        frequency_score = 20
    elif attack_count >= 10:
        frequency_score = 15
    elif attack_count >= 5:
        frequency_score = 10
    else:
        frequency_score = 5

    # === SEVERITY SCORE (0-50) === MUCH MORE AGGRESSIVE
    severity_score = 0

    # Critical attacks (15 severity = CRITICAL RCE!)
    if max_severity >= 15:
        severity_score += 40  # Was 20, now 40!
    elif max_severity >= 12:
        severity_score += 30  # Was 15, now 30!
    elif max_severity >= 10:
        severity_score += 20  # Was 10, now 20!

    # Average severity - if ALL attacks are critical, add more
    if avg_severity >= 15:
        severity_score += 10  # New: bonus for sustained critical attacks
    elif avg_severity >= 12:
        severity_score += 8
    elif avg_severity >= 10:
        severity_score += 5
    elif avg_severity >= 8:
        severity_score += 3

    severity_score = min(50, severity_score)

    # === DIVERSITY SCORE (0-10) === REDUCED WEIGHT
    if type_diversity >= 5:
        diversity_score = 10
    elif type_diversity >= 4:
        diversity_score = 8
    elif type_diversity >= 3:
        diversity_score = 6
    elif type_diversity >= 2:
        diversity_score = 4
    else:
        diversity_score = 2

    # === SOPHISTICATION SCORE (0-10) === ADJUSTED
    sophistication_score = 0

    attack_types = behavior['attack_types']

    # Remote Code Execution = CRITICAL
    if 'Remote Code Execution' in attack_types:
        sophistication_score += 10  # Was 8, now 10!

    # SQL Injection = HIGH
    if 'SQL Injection' in attack_types:
        sophistication_score += 8

    # Buffer Overflow = HIGH
    if 'Buffer Overflow' in attack_types:
        sophistication_score += 7

    # Multiple sophisticated techniques (cap at 10)
    sophisticated_types = {'Remote Code Execution', 'SQL Injection', 'Buffer Overflow', 'Cross-Site Scripting'}
    if len(sophisticated_types.intersection(attack_types)) >= 2:
        sophistication_score = min(10, sophistication_score + 3)

    sophistication_score = min(10, sophistication_score)

    # === TOTAL SCORE ===
    total_score = frequency_score + severity_score + diversity_score + sophistication_score
    total_score = min(100, total_score)

    score_breakdown = {
        'frequency_score': frequency_score,
        'severity_score': severity_score,
        'diversity_score': diversity_score,
        'sophistication_score': sophistication_score,
        'total_score': round(total_score, 1)
    }

    return round(total_score, 1), score_breakdown

def analyze_public_attacker_ips():
    """
    Main analysis: Load evidence vault and identify PUBLIC attacker IPs only
    """
    print("\n" + "="*90)
    print("PUBLIC IP BEHAVIORAL ANALYSIS - Filtering Internal IPs")
    print("="*90)

    # Load evidence vault
    evidence_file = Path("evidence_vault/evidence_registry.json")
    if not evidence_file.exists():
        print("[ERROR] Evidence vault not found!")
        return

    with open(evidence_file, 'r', encoding='utf-8') as f:
        evidence_data = json.load(f)

    print(f"\n[OK] Loaded {len(evidence_data)} evidence items")

    # Group by IP from incident_id
    ip_evidence = defaultdict(list)

    for eid, evidence in evidence_data.items():
        incident_id = evidence.get('incident_id', '')

        # Extract IP from INC-{IP}-{timestamp}
        if incident_id.startswith('INC-'):
            parts = incident_id.split('-')
            if len(parts) >= 3:
                # IP is everything between first and last dash
                ip = '-'.join(parts[1:-1])

                # Store evidence item
                ip_evidence[ip].append({
                    'id': eid,
                    'incident': incident_id,
                    'desc': evidence.get('description', ''),
                    'tags': evidence.get('tags', []),
                    'timestamp': evidence.get('collected_at', '')
                })

    print(f"[OK] Found {len(ip_evidence)} unique IPs")

    # Filter: Keep ONLY public/external IPs
    public_ips = {}
    internal_ips = {}

    for ip, evidence_items in ip_evidence.items():
        if is_private_ip(ip):
            internal_ips[ip] = evidence_items
        else:
            public_ips[ip] = evidence_items

    print(f"\n[FILTERING]")
    print(f"  - Public/External IPs: {len(public_ips)} (ACTUAL ATTACKERS)")
    print(f"  - Private/Internal IPs: {len(internal_ips)} (YOUR SYSTEMS UNDER ATTACK)")

    # Analyze behavior for public IPs only
    print(f"\n[ANALYZING] Behavioral analysis for {len(public_ips)} public IPs...")

    ip_risk_analysis = {}

    for ip, evidence_items in public_ips.items():
        behavior = extract_attack_behavior(evidence_items)
        risk_score, score_breakdown = calculate_behavioral_risk_score(behavior)

        ip_risk_analysis[ip] = {
            'risk_score': risk_score,
            'behavior': behavior,
            'score_breakdown': score_breakdown,
            'evidence_count': len(evidence_items)
        }

    # Sort by risk score
    sorted_ips = sorted(ip_risk_analysis.items(), key=lambda x: x[1]['risk_score'], reverse=True)

    print(f"[OK] Analysis complete!")

    # === DISPLAY RESULTS ===
    print("\n" + "="*90)
    print("TOP PUBLIC ATTACKER IPs - BEHAVIORAL RISK SCORES")
    print("="*90)

    print(f"\n{'IP Address':<20} {'Risk':<7} {'Attacks':<9} {'Sev':<8} {'Types':<7} {'Category':<10} {'Primary Attack Type'}")
    print("-" * 110)

    for ip, data in sorted_ips[:50]:  # Top 50
        behavior = data['behavior']
        risk = data['risk_score']

        # Risk category
        if risk >= 90:
            category = "CRITICAL"
        elif risk >= 75:
            category = "HIGH"
        elif risk >= 50:
            category = "MEDIUM"
        else:
            category = "LOW"

        severity_str = f"{behavior['max_severity']}/{behavior['avg_severity']}"
        types_str = f"{behavior['type_diversity']}"

        # Primary attack type
        if behavior['type_distribution']:
            primary_type = max(behavior['type_distribution'].items(), key=lambda x: x[1])[0]
        else:
            primary_type = "Unknown"

        print(f"{ip:<20} {risk:<7.1f} {behavior['attack_count']:<9} {severity_str:<8} {types_str:<7} {category:<10} {primary_type}")

    # === SUMMARY STATISTICS ===
    print("\n" + "="*90)
    print("SUMMARY STATISTICS")
    print("="*90)

    critical_ips = sum(1 for _, d in sorted_ips if d['risk_score'] >= 90)
    high_ips = sum(1 for _, d in sorted_ips if 75 <= d['risk_score'] < 90)
    medium_ips = sum(1 for _, d in sorted_ips if 50 <= d['risk_score'] < 75)
    low_ips = sum(1 for _, d in sorted_ips if d['risk_score'] < 50)

    total_attacks = sum(d['evidence_count'] for _, d in sorted_ips)

    print(f"\nExternal Attacker IPs: {len(sorted_ips)}")
    print(f"  - CRITICAL Risk (90-100): {critical_ips}")
    print(f"  - HIGH Risk (75-90): {high_ips}")
    print(f"  - MEDIUM Risk (50-75): {medium_ips}")
    print(f"  - LOW Risk (<50): {low_ips}")

    print(f"\nInternal Systems (Under Attack): {len(internal_ips)}")
    print(f"  - These are YOUR servers/systems being targeted")
    print(f"  - NOT malicious IPs!")

    print(f"\nTotal Attack Events from External IPs: {total_attacks:,}")
    if sorted_ips:
        print(f"Average Attacks per External IP: {total_attacks / len(sorted_ips):.1f}")

    # Attack type distribution
    all_types = Counter()
    for _, data in sorted_ips:
        for attack_type, count in data['behavior']['type_distribution'].items():
            all_types[attack_type] += count

    print(f"\nTop Attack Types:")
    for attack_type, count in all_types.most_common(10):
        print(f"  - {attack_type}: {count:,} attacks")

    # Top 10 most dangerous IPs
    print(f"\n" + "="*90)
    print("TOP 10 MOST DANGEROUS IPs (Detailed)")
    print("="*90)

    for i, (ip, data) in enumerate(sorted_ips[:10], 1):
        behavior = data['behavior']
        breakdown = data['score_breakdown']

        print(f"\n#{i}. {ip} - Risk Score: {data['risk_score']}/100")
        print(f"   Attacks: {behavior['attack_count']} | Severity: {behavior['max_severity']} (max) / {behavior['avg_severity']} (avg)")
        print(f"   Attack Types ({behavior['type_diversity']}): {', '.join(behavior['attack_types'])}")
        print(f"   Score Breakdown:")
        print(f"     - Frequency: {breakdown['frequency_score']}/25")
        print(f"     - Severity: {breakdown['severity_score']}/35")
        print(f"     - Diversity: {breakdown['diversity_score']}/25")
        print(f"     - Sophistication: {breakdown['sophistication_score']}/15")

    print("\n" + "="*90)
    print("[OK] Behavioral analysis complete!")
    print("="*90 + "\n")

    # Save results
    output_file = "public_ips_behavioral_analysis.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            'public_attackers': {ip: data for ip, data in sorted_ips},
            'internal_systems': list(internal_ips.keys()),
            'summary': {
                'total_external_ips': len(sorted_ips),
                'total_internal_ips': len(internal_ips),
                'critical_ips': critical_ips,
                'high_risk_ips': high_ips,
                'medium_risk_ips': medium_ips,
                'low_risk_ips': low_ips,
                'total_attacks': total_attacks
            }
        }, f, indent=2)

    print(f"[SAVED] Results saved to: {output_file}\n")

if __name__ == "__main__":
    analyze_public_attacker_ips()
