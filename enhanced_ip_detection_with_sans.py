"""
Enhanced IP Detection with SANS ISC Validation
Combines MITRE ATT&CK behavioral analysis + SANS ISC threat intelligence

This provides the most accurate malicious IP detection by:
1. Analyzing behavior patterns (MITRE ATT&CK)
2. Validating against global threat intelligence (SANS ISC)
3. Adjusting confidence based on external reputation
"""

import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import sys

# Import SANS validator
sys.path.insert(0, str(Path(__file__).parent))
from modules.SANSIPReputationValidator import SANSIPReputationValidator
from analyze_real_mitre_classification import (
    load_evidence_from_vault,
    map_attack_to_mitre,
    calculate_mitre_threat_score,
    extract_ip_from_incident_id
)


def enhance_detection_with_sans(results: list, validator: SANSIPReputationValidator,
                                sans_threshold: int = 50) -> list:
    """
    Enhance MITRE-based detection with SANS ISC validation

    Args:
        results: List of IP analysis results from MITRE analysis
        validator: SANS ISC validator instance
        sans_threshold: SANS reputation score threshold (default 50)

    Returns:
        Enhanced results with SANS validation
    """
    print("\n" + "=" * 100)
    print("ENHANCING DETECTION WITH SANS ISC THREAT INTELLIGENCE")
    print("=" * 100)
    print()

    enhanced_results = []

    for i, ip_data in enumerate(results, 1):
        ip = ip_data['ip']
        mitre_score = ip_data['threat_score']
        mitre_classification = ip_data['classification']
        mitre_confidence = ip_data['ml_confidence']

        print(f"[{i}/{len(results)}] Validating {ip} with SANS ISC...")

        # Query SANS ISC
        is_malicious_sans, sans_details = validator.is_malicious(ip, threshold=sans_threshold)

        # Enhanced decision logic
        final_classification = mitre_classification
        final_confidence = mitre_confidence
        confidence_adjustment = 0
        verdict_changed = False

        sans_score = sans_details.get('reputation_score', 0) if sans_details else 0

        # Decision Matrix:
        # 1. Both agree MALICIOUS -> High confidence
        # 2. Both agree BENIGN -> High confidence
        # 3. MITRE says MALICIOUS, SANS unknown -> Keep MITRE verdict
        # 4. MITRE says MALICIOUS, SANS says BENIGN -> Reduce confidence
        # 5. MITRE says BENIGN, SANS says MALICIOUS -> Upgrade to SUSPICIOUS
        # 6. SANS unknown -> Use MITRE only

        if is_malicious_sans is None:
            # SANS has no data - use MITRE only
            reasoning = "SANS ISC: No data available. Using MITRE analysis only."

        elif is_malicious_sans and mitre_classification == "MALICIOUS":
            # Both agree MALICIOUS -> Boost confidence
            confidence_adjustment = +0.10
            final_confidence = min(0.99, mitre_confidence + confidence_adjustment)
            reasoning = f"MITRE + SANS AGREE: Both detect malicious behavior. SANS reports {sans_details['attacks']} attacks, {sans_details['count']} reports."

        elif not is_malicious_sans and mitre_classification == "BENIGN":
            # Both agree BENIGN -> Boost confidence
            confidence_adjustment = +0.10
            final_confidence = min(0.99, abs(mitre_confidence - 1.0) + confidence_adjustment)
            reasoning = f"MITRE + SANS AGREE: Both indicate benign/low-threat. SANS score: {sans_score}/100."

        elif mitre_classification == "MALICIOUS" and not is_malicious_sans:
            # MITRE says bad, SANS says good -> Reduce confidence
            confidence_adjustment = -0.20
            final_confidence = max(0.50, mitre_confidence + confidence_adjustment)

            # If confidence drops below 70%, downgrade to SUSPICIOUS
            if final_confidence < 0.70:
                final_classification = "SUSPICIOUS"
                verdict_changed = True

            reasoning = f"MITRE: MALICIOUS ({mitre_score:.1f}/100), but SANS ISC shows benign ({sans_score}/100). Confidence reduced."

        elif mitre_classification == "BENIGN" and is_malicious_sans:
            # MITRE says good, SANS says bad -> Upgrade to SUSPICIOUS
            final_classification = "SUSPICIOUS"
            confidence_adjustment = +0.15
            final_confidence = 0.65  # Moderate confidence
            verdict_changed = True
            reasoning = f"MITRE: BENIGN ({mitre_score:.1f}/100), but SANS ISC reports malicious activity ({sans_details['attacks']} attacks). Upgraded to SUSPICIOUS."

        else:
            reasoning = "Standard MITRE-based classification."

        # Build enhanced result
        enhanced_data = {
            **ip_data,  # Keep original MITRE data
            'final_classification': final_classification,
            'final_confidence': final_confidence,
            'mitre_original_classification': mitre_classification,
            'mitre_original_confidence': mitre_confidence,
            'sans_is_malicious': is_malicious_sans,
            'sans_reputation_score': sans_score,
            'sans_details': sans_details,
            'confidence_adjustment': confidence_adjustment,
            'verdict_changed': verdict_changed,
            'reasoning': reasoning,
        }

        enhanced_results.append(enhanced_data)

        # Print summary
        if verdict_changed:
            print(f"  [!] VERDICT CHANGED: {mitre_classification} -> {final_classification}")
        print(f"  Final: {final_classification} (Confidence: {final_confidence:.1%})")
        print(f"  {reasoning}")
        print()

    return enhanced_results


def analyze_with_sans_validation():
    """
    Complete analysis workflow with SANS ISC validation
    """
    print("=" * 100)
    print("ENHANCED IP DETECTION: MITRE ATT&CK + SANS ISC THREAT INTELLIGENCE")
    print("=" * 100)
    print()

    # Step 1: Load evidence
    evidence_data = load_evidence_from_vault()
    if not evidence_data:
        print("[ERROR] No evidence data available")
        return

    # Step 2: MITRE behavioral analysis
    print("Step 1: Performing MITRE ATT&CK behavioral analysis...")
    print("-" * 100)

    ip_data = defaultdict(lambda: {
        'attacks': [],
        'techniques': set(),
        'tactics': set(),
        'total_severity': 0,
    })

    for eid, evidence in evidence_data.items():
        incident_id = evidence.get('incident_id', '')
        if not incident_id or '-' not in incident_id:
            continue

        parts = incident_id.split('-')
        if len(parts) >= 3:
            ip = '-'.join(parts[1:-1])
        else:
            continue

        tags = evidence.get('tags', [])
        description = evidence.get('description', '')
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

    # Calculate MITRE threat scores
    mitre_results = []

    for ip, data in ip_data.items():
        attack_count = len(data['attacks'])
        avg_severity = data['total_severity'] / attack_count if attack_count > 0 else 0

        threat_score = calculate_mitre_threat_score(
            list(data['techniques']),
            list(data['tactics']),
            attack_count,
            avg_severity
        )

        if threat_score >= 70:
            classification = "MALICIOUS"
            ml_confidence = min(0.95, 0.70 + (threat_score - 70) / 100)
        else:
            classification = "BENIGN"
            ml_confidence = max(0.30, 0.70 - (70 - threat_score) / 100)

        mitre_results.append({
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

    mitre_results.sort(key=lambda x: x['threat_score'], reverse=True)

    mitre_malicious = sum(1 for r in mitre_results if r['classification'] == 'MALICIOUS')
    print(f"[OK] MITRE Analysis Complete: {len(mitre_results)} IPs analyzed")
    print(f"     MALICIOUS: {mitre_malicious}, BENIGN: {len(mitre_results) - mitre_malicious}")
    print()

    # Step 3: SANS ISC validation (only for top IPs to save API calls)
    print("Step 2: Validating with SANS ISC Threat Intelligence...")
    print("-" * 100)
    print("[NOTE] Validating top 50 IPs (highest threat scores) to conserve API quota")
    print()

    validator = SANSIPReputationValidator(cache_ttl_hours=24)

    # Validate top 50 IPs by threat score
    top_ips = mitre_results[:50]

    enhanced_results = enhance_detection_with_sans(top_ips, validator, sans_threshold=40)

    # Keep remaining IPs with MITRE-only classification
    remaining_ips = mitre_results[50:]
    for ip_data in remaining_ips:
        enhanced_results.append({
            **ip_data,
            'final_classification': ip_data['classification'],
            'final_confidence': ip_data['ml_confidence'],
            'mitre_original_classification': ip_data['classification'],
            'mitre_original_confidence': ip_data['ml_confidence'],
            'sans_is_malicious': None,
            'sans_reputation_score': 0,
            'sans_details': None,
            'confidence_adjustment': 0,
            'verdict_changed': False,
            'reasoning': 'MITRE analysis only (not validated with SANS)',
        })

    # Step 4: Final statistics
    print("=" * 100)
    print("FINAL RESULTS")
    print("=" * 100)
    print()

    final_malicious = sum(1 for r in enhanced_results if r['final_classification'] == 'MALICIOUS')
    final_benign = sum(1 for r in enhanced_results if r['final_classification'] == 'BENIGN')
    final_suspicious = sum(1 for r in enhanced_results if r['final_classification'] == 'SUSPICIOUS')
    verdict_changes = sum(1 for r in enhanced_results if r.get('verdict_changed', False))

    print(f"Total IPs: {len(enhanced_results)}")
    print(f"  MALICIOUS: {final_malicious} ({final_malicious/len(enhanced_results)*100:.1f}%)")
    print(f"  BENIGN: {final_benign} ({final_benign/len(enhanced_results)*100:.1f}%)")
    print(f"  SUSPICIOUS: {final_suspicious} ({final_suspicious/len(enhanced_results)*100:.1f}%)")
    print(f"\nVerdicts Changed by SANS Validation: {verdict_changes}")
    print()

    # Show top 10 final malicious
    print("=" * 100)
    print("TOP 10 CONFIRMED MALICIOUS IPs (After SANS Validation)")
    print("=" * 100)
    print()

    final_malicious_sorted = [r for r in enhanced_results if r['final_classification'] == 'MALICIOUS']
    final_malicious_sorted.sort(key=lambda x: x['final_confidence'], reverse=True)

    for i, r in enumerate(final_malicious_sorted[:10], 1):
        print(f"#{i}. {r['ip']}")
        print(f"    Final Verdict: {r['final_classification']} (Confidence: {r['final_confidence']:.1%})")
        print(f"    MITRE Score: {r['threat_score']:.1f}/100")
        print(f"    SANS Score: {r['sans_reputation_score']}/100")
        if r['sans_details']:
            print(f"    SANS Attacks: {r['sans_details'].get('attacks', 0)}, Reports: {r['sans_details'].get('count', 0)}")
        print(f"    {r['reasoning']}")
        print()

    # Show suspicious cases
    if final_suspicious > 0:
        print("=" * 100)
        print("SUSPICIOUS IPs (Conflicting Intelligence)")
        print("=" * 100)
        print()

        suspicious_sorted = [r for r in enhanced_results if r['final_classification'] == 'SUSPICIOUS']

        for i, r in enumerate(suspicious_sorted, 1):
            print(f"#{i}. {r['ip']}")
            print(f"    Final Verdict: {r['final_classification']} (Confidence: {r['final_confidence']:.1%})")
            print(f"    MITRE Score: {r['threat_score']:.1f}/100")
            print(f"    SANS Score: {r['sans_reputation_score']}/100")
            print(f"    {r['reasoning']}")
            print()

    # Save results
    output_file = Path("enhanced_detection_results_with_sans.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(enhanced_results, f, indent=2, default=str)

    print("=" * 100)
    print(f"[OK] Results saved to: {output_file}")
    print()

    # Cache stats
    cache_stats = validator.get_cache_stats()
    print("SANS ISC Cache Statistics:")
    print(f"  Total Cached: {cache_stats['total_cached']}")
    print(f"  Valid: {cache_stats['valid']}")
    print(f"  Expired: {cache_stats['expired']}")
    print()


if __name__ == "__main__":
    analyze_with_sans_validation()
