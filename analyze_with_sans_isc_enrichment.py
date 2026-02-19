"""
COMPLETE THREAT ANALYSIS - Public IPs with SANS ISC Enrichment
---------------------------------------------------------------
Combines:
1. Behavioral analysis (attack types, severity, patterns)
2. SANS ISC reputation data (global attack reports)
3. Comprehensive risk scoring (0-100)

This is the COMPLETE implementation of your hybrid approach!
"""

import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List

# Add modules to path
sys.path.insert(0, str(Path.cwd()))

from modules.SANSISCValidator import SANSISCValidator
from analyze_public_ips_with_behavior import (
    is_private_ip,
    extract_attack_behavior,
    calculate_behavioral_risk_score
)

def enhance_risk_with_sans_isc(behavioral_risk: float, sans_data: Dict) -> tuple:
    """
    Enhance behavioral risk score with SANS ISC reputation data

    Final Risk Score = Behavioral (70%) + SANS ISC (30%)

    Args:
        behavioral_risk: Risk score from behavioral analysis (0-100)
        sans_data: SANS ISC validation result

    Returns:
        (enhanced_risk_score, sans_contribution, explanation)
    """
    # SANS ISC contribution (0-30 points max, 30% weight)
    sans_score = 0
    sans_details = []

    if sans_data.get('error'):
        # No SANS data available - use behavioral only
        sans_details.append("SANS ISC: No data (using behavioral only)")
        return behavioral_risk, 0, sans_details

    attack_count = sans_data.get('attack_count', 0)
    threat_score = sans_data.get('threat_score', 0)
    confidence = sans_data.get('confidence', 0)

    # Global attack reports (0-15 points)
    if attack_count >= 10000:
        sans_score += 15
        sans_details.append(f"CRITICAL: {attack_count:,} attacks reported globally")
    elif attack_count >= 1000:
        sans_score += 13
        sans_details.append(f"HIGH: {attack_count:,} attacks reported globally")
    elif attack_count >= 100:
        sans_score += 10
        sans_details.append(f"MEDIUM: {attack_count:,} attacks reported globally")
    elif attack_count >= 10:
        sans_score += 7
        sans_details.append(f"LOW: {attack_count} attacks reported globally")
    elif attack_count > 0:
        sans_score += 3
        sans_details.append(f"Known: {attack_count} attacks reported")
    else:
        sans_details.append("Unknown to SANS ISC (not seen attacking)")

    # SANS threat score (0-10 points)
    sans_score += min(10, threat_score / 10)

    # Confidence multiplier
    sans_score = sans_score * confidence

    sans_score = min(30, sans_score)  # Cap at 30

    # Calculate final enhanced score
    # Behavioral: 70% weight, SANS: 30% weight
    enhanced_score = (behavioral_risk * 0.7) + (sans_score / 30 * 100 * 0.3)
    enhanced_score = min(100, enhanced_score)

    # Add first/last seen
    if sans_data.get('first_seen'):
        sans_details.append(f"First seen: {sans_data['first_seen']}")
    if sans_data.get('last_seen'):
        sans_details.append(f"Last seen: {sans_data['last_seen']}")

    return round(enhanced_score, 1), round(sans_score, 1), sans_details

def main():
    print("\n" + "="*100)
    print("COMPLETE THREAT ANALYSIS - Behavioral + SANS ISC Reputation")
    print("="*100)

    # Load evidence vault
    evidence_file = Path("evidence_vault/evidence_registry.json")
    if not evidence_file.exists():
        print("[ERROR] Evidence vault not found!")
        return

    with open(evidence_file, 'r', encoding='utf-8') as f:
        evidence_data = json.load(f)

    print(f"\n[STEP 1] Loaded {len(evidence_data)} evidence items")

    # Group by IP
    ip_evidence = defaultdict(list)
    for eid, evidence in evidence_data.items():
        incident_id = evidence.get('incident_id', '')
        if incident_id.startswith('INC-'):
            parts = incident_id.split('-')
            if len(parts) >= 3:
                ip = '-'.join(parts[1:-1])
                ip_evidence[ip].append({
                    'id': eid,
                    'desc': evidence.get('description', ''),
                    'tags': evidence.get('tags', []),
                    'timestamp': evidence.get('collected_at', '')
                })

    # Filter public IPs only
    public_ips = {ip: items for ip, items in ip_evidence.items() if not is_private_ip(ip)}

    print(f"[STEP 2] Filtered to {len(public_ips)} public/external attacker IPs")

    # Behavioral analysis
    print(f"[STEP 3] Performing behavioral analysis...")
    behavioral_analysis = {}

    for ip, evidence_items in public_ips.items():
        behavior = extract_attack_behavior(evidence_items)
        risk_score, score_breakdown = calculate_behavioral_risk_score(behavior)

        behavioral_analysis[ip] = {
            'risk_score': risk_score,
            'behavior': behavior,
            'score_breakdown': score_breakdown,
            'evidence_count': len(evidence_items)
        }

    print(f"[OK] Behavioral analysis complete")

    # SANS ISC enrichment
    print(f"\n[STEP 4] Querying SANS ISC for reputation data...")
    print(f"   This may take a few minutes for {len(public_ips)} IPs...")
    print(f"   (API calls with 1 second delay per IP)")

    sans_validator = SANSISCValidator(cache_dir="./cache/sans_isc")

    # Query top 50 IPs by behavioral risk (to save time)
    top_ips = sorted(behavioral_analysis.keys(), key=lambda ip: behavioral_analysis[ip]['risk_score'], reverse=True)[:50]

    print(f"   Querying top 50 IPs by behavioral risk...")
    sans_results = sans_validator.validate_batch(top_ips, delay_seconds=1.0)

    print(f"[OK] SANS ISC data retrieved")

    # Enhanced risk scoring
    print(f"\n[STEP 5] Calculating enhanced risk scores (Behavioral 70% + SANS 30%)...")

    enhanced_analysis = {}

    for ip, data in behavioral_analysis.items():
        if ip in sans_results:
            enhanced_risk, sans_contribution, sans_details = enhance_risk_with_sans_isc(
                data['risk_score'],
                sans_results[ip]
            )
        else:
            # No SANS data - use behavioral only
            enhanced_risk = data['risk_score']
            sans_contribution = 0
            sans_details = ["SANS ISC: Not queried (lower priority IP)"]

        enhanced_analysis[ip] = {
            'enhanced_risk': enhanced_risk,
            'behavioral_risk': data['risk_score'],
            'sans_contribution': sans_contribution,
            'sans_details': sans_details,
            'sans_data': sans_results.get(ip, {}),
            'behavior': data['behavior'],
            'score_breakdown': data['score_breakdown']
        }

    # Sort by enhanced risk
    sorted_ips = sorted(enhanced_analysis.items(), key=lambda x: x[1]['enhanced_risk'], reverse=True)

    print(f"[OK] Enhanced analysis complete!")

    # === DISPLAY RESULTS ===
    print("\n" + "="*100)
    print("TOP MALICIOUS IPs - ENHANCED RISK SCORES (Behavioral + SANS ISC)")
    print("="*100)

    print(f"\n{'IP Address':<20} {'Enhanced':<10} {'Behavioral':<12} {'SANS':<8} {'Attacks':<9} {'Global':<12} {'Category'}")
    print("-" * 100)

    for ip, data in sorted_ips[:30]:  # Top 30
        enhanced = data['enhanced_risk']
        behavioral = data['behavioral_risk']
        sans_contrib = data['sans_contribution']
        behavior = data['behavior']

        # Risk category (TI-VALIDATED THRESHOLDS)
        if enhanced >= 85:
            category = "CRITICAL"
        elif enhanced >= 70:
            category = "HIGH"
        elif enhanced >= 40:
            category = "MEDIUM"
        else:
            category = "LOW"

        # Global attack count from SANS
        sans_data = data['sans_data']
        global_attacks = sans_data.get('attack_count', 0) if sans_data else 0
        global_str = f"{global_attacks:,}" if global_attacks > 0 else "Unknown"

        print(f"{ip:<20} {enhanced:<10.1f} {behavioral:<12.1f} {sans_contrib:<8.1f} {behavior['attack_count']:<9} {global_str:<12} {category}")

    # Detailed top 10
    print("\n" + "="*100)
    print("TOP 10 MOST DANGEROUS IPs - DETAILED ANALYSIS")
    print("="*100)

    for i, (ip, data) in enumerate(sorted_ips[:10], 1):
        behavior = data['behavior']
        breakdown = data['score_breakdown']
        sans_details = data['sans_details']

        print(f"\n#{i}. {ip}")
        print(f"   ENHANCED RISK: {data['enhanced_risk']}/100")
        print(f"   + Behavioral Risk: {data['behavioral_risk']}/100 (70% weight)")
        print(f"     - Frequency: {breakdown['frequency_score']}/30")
        print(f"     - Severity: {breakdown['severity_score']}/50")
        print(f"     - Diversity: {breakdown['diversity_score']}/10")
        print(f"     - Sophistication: {breakdown['sophistication_score']}/10")
        print(f"   + SANS ISC: {data['sans_contribution']}/30 (30% weight)")
        for detail in sans_details:
            print(f"      * {detail}")

        print(f"\n   Local Attacks: {behavior['attack_count']}")
        print(f"   Attack Types: {', '.join(behavior['attack_types'])}")
        print(f"   Max Severity: {behavior['max_severity']}/15")
        print(f"   Avg Severity: {behavior['avg_severity']}")

    # Summary statistics
    print("\n" + "="*100)
    print("SUMMARY STATISTICS")
    print("="*100)

    critical_count = sum(1 for _, d in sorted_ips if d['enhanced_risk'] >= 85)
    high_count = sum(1 for _, d in sorted_ips if 70 <= d['enhanced_risk'] < 85)
    medium_count = sum(1 for _, d in sorted_ips if 40 <= d['enhanced_risk'] < 70)
    low_count = sum(1 for _, d in sorted_ips if d['enhanced_risk'] < 40)

    print(f"\nRisk Distribution (Enhanced Scores - TI-VALIDATED THRESHOLDS):")
    print(f"  CRITICAL (85-100): {critical_count} IPs")
    print(f"  HIGH (70-84):      {high_count} IPs")
    print(f"  MEDIUM (40-69):    {medium_count} IPs")
    print(f"  LOW (<40):         {low_count} IPs")

    # SANS ISC statistics
    sans_known = sum(1 for ip in top_ips if sans_results.get(ip, {}).get('attack_count', 0) > 0)
    sans_malicious = sum(1 for ip in top_ips if sans_results.get(ip, {}).get('is_malicious', False))

    print(f"\nSANS ISC Intelligence:")
    print(f"  IPs Queried: {len(top_ips)}")
    print(f"  Known to SANS: {sans_known} ({sans_known/len(top_ips)*100:.1f}%)")
    print(f"  Confirmed Malicious: {sans_malicious} ({sans_malicious/len(top_ips)*100:.1f}%)")

    # Attack type distribution
    all_types = Counter()
    for _, data in sorted_ips:
        for attack_type, count in data['behavior']['type_distribution'].items():
            all_types[attack_type] += count

    print(f"\nAttack Type Distribution:")
    for attack_type, count in all_types.most_common(5):
        print(f"  {attack_type}: {count:,} attacks")

    print("\n" + "="*100)
    print("[SUCCESS] Complete threat analysis finished!")
    print("="*100)

    # Save results
    output_file = "complete_threat_analysis_with_sans.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            'enhanced_analysis': {ip: data for ip, data in sorted_ips},
            'summary': {
                'total_ips': len(sorted_ips),
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count,
                'sans_queried': len(top_ips),
                'sans_known': sans_known,
                'sans_malicious': sans_malicious
            },
            'attack_types': dict(all_types)
        }, f, indent=2)

    print(f"\n[SAVED] Complete analysis saved to: {output_file}\n")

if __name__ == "__main__":
    main()
