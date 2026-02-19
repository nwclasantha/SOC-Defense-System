"""
ML Validation Engine - Ground Truth Dataset & Accuracy Measurement
==================================================================

This module provides:
1. Ground truth dataset creation from Wazuh alerts + Threat Intelligence
2. Proper ML training with K-fold cross-validation
3. Real accuracy metrics (Precision, Recall, F1, ROC-AUC)
4. Model performance tracking over time

Author: SOC Defense System
Version: 1.0.0
"""

import numpy as np
import json
import pickle
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field, asdict

try:
    from sklearn.model_selection import (
        cross_val_score, StratifiedKFold, train_test_split,
        cross_val_predict, learning_curve
    )
    from sklearn.metrics import (
        precision_score, recall_score, f1_score, roc_auc_score,
        confusion_matrix, classification_report, precision_recall_curve,
        average_precision_score, roc_curve
    )
    from sklearn.ensemble import (
        RandomForestClassifier, GradientBoostingClassifier,
        IsolationForest, VotingClassifier
    )
    from sklearn.svm import OneClassSVM
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False


@dataclass
class GroundTruthSample:
    """A single ground truth sample for ML training"""
    ip_address: str
    is_malicious: bool  # True = malicious, False = benign
    confidence: float   # 0.0 to 1.0 - how confident are we in this label
    label_sources: List[str] = field(default_factory=list)  # What confirmed this label
    features: Dict[str, float] = field(default_factory=dict)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()


@dataclass
class MLMetrics:
    """ML model performance metrics"""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    roc_auc: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    true_positive_count: int = 0
    true_negative_count: int = 0
    false_positive_count: int = 0
    false_negative_count: int = 0
    total_samples: int = 0
    cross_val_scores: List[float] = field(default_factory=list)
    cross_val_mean: float = 0.0
    cross_val_std: float = 0.0
    training_date: str = ""
    model_version: str = "1.0.0"

    def __post_init__(self):
        if not self.training_date:
            self.training_date = datetime.now().isoformat()


class GroundTruthBuilder:
    """
    Builds ground truth dataset from multiple authoritative sources.

    MALICIOUS indicators (label = 1):
    - AbuseIPDB confidence >= 80%
    - SANS ISC attack count >= 5
    - VirusTotal malicious >= 3
    - Wazuh alert level >= 12
    - Known malware C2 servers

    BENIGN indicators (label = 0):
    - Private/internal IPs
    - Known CDN providers (Cloudflare, Akamai, Fastly)
    - Known cloud providers (AWS, Azure, GCP)
    - Wazuh alert level < 3 with no threat intel hits
    - Whitelisted IPs
    """

    def __init__(self, dataset_path: str = "./data/ground_truth"):
        self.dataset_path = Path(dataset_path)
        self.dataset_path.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(self.__class__.__name__)

        # Ground truth dataset
        self.samples: List[GroundTruthSample] = []

        # Known benign patterns
        self.known_cdns = [
            'cloudflare', 'akamai', 'fastly', 'cloudfront',
            'incapsula', 'imperva', 'stackpath'
        ]
        self.known_clouds = [
            'amazon', 'aws', 'microsoft', 'azure', 'google', 'gcp',
            'digitalocean', 'linode', 'vultr', 'oracle'
        ]

        # Load existing dataset
        self._load_dataset()

    def _load_dataset(self):
        """Load existing ground truth dataset"""
        dataset_file = self.dataset_path / "ground_truth_dataset.json"
        if dataset_file.exists():
            try:
                with open(dataset_file, 'r') as f:
                    data = json.load(f)
                    self.samples = [GroundTruthSample(**s) for s in data.get('samples', [])]
                    self.logger.info(f"Loaded {len(self.samples)} ground truth samples")
            except Exception as e:
                self.logger.warning(f"Could not load ground truth dataset: {e}")
                self.samples = []

    def _save_dataset(self):
        """Save ground truth dataset"""
        dataset_file = self.dataset_path / "ground_truth_dataset.json"
        try:
            data = {
                'version': '1.0.0',
                'updated_at': datetime.now().isoformat(),
                'total_samples': len(self.samples),
                'malicious_count': sum(1 for s in self.samples if s.is_malicious),
                'benign_count': sum(1 for s in self.samples if not s.is_malicious),
                'samples': [asdict(s) for s in self.samples]
            }
            with open(dataset_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info(f"Saved {len(self.samples)} ground truth samples")
        except Exception as e:
            self.logger.error(f"Could not save ground truth dataset: {e}")

    def add_sample_from_profile(self, profile, threat_intel: Dict = None) -> Optional[GroundTruthSample]:
        """
        Create ground truth sample from attacker profile + threat intel.

        Returns sample only if we have HIGH CONFIDENCE in the label.
        """
        ip = profile.ip_address

        # Skip if we already have this IP
        if any(s.ip_address == ip for s in self.samples):
            return None

        label_sources = []
        malicious_score = 0
        benign_score = 0

        # === MALICIOUS INDICATORS ===

        # Check Wazuh alert severity
        max_severity = 0
        for event in profile.attack_events:
            if hasattr(event, 'rule_level'):
                max_severity = max(max_severity, event.rule_level)

        if max_severity >= 12:
            malicious_score += 3
            label_sources.append(f"Wazuh_Level_{max_severity}")
        elif max_severity >= 10:
            malicious_score += 2
            label_sources.append(f"Wazuh_Level_{max_severity}")
        elif max_severity >= 7:
            malicious_score += 1
            label_sources.append(f"Wazuh_Level_{max_severity}")

        # Check Threat Intelligence using TI VALIDATION RULES:
        # Rule 1: is_whitelisted=0 AND abuse_confidence_score>0 AND total_reports>0 → BAD IP
        # Rule 2: is_whitelisted=1 AND SANS count>0 AND attacks>0 → BAD IP
        if threat_intel:
            # AbuseIPDB - use 'or {}' to handle None values
            abuse_data = threat_intel.get('abuseipdb_data') or {}
            is_whitelisted = abuse_data.get('is_whitelisted', False)
            abuse_confidence = abuse_data.get('abuse_confidence_score', 0) or 0
            total_reports = abuse_data.get('total_reports', 0) or 0

            # SANS ISC - use 'or {}' to handle None values
            sans_data = threat_intel.get('sans_isc_data') or {}
            sans_count = sans_data.get('count', 0) or sans_data.get('attack_count', 0) or 0
            sans_attacks = sans_data.get('attacks', 0) or 0

            # TI VALIDATION RULE 1: AbuseIPDB confirms BAD
            # is_whitelisted=0 AND abuse_confidence_score>0 AND total_reports>0
            if not is_whitelisted and abuse_confidence > 0 and total_reports > 0:
                malicious_score += 4  # Strong TI confirmation
                label_sources.append(f"AbuseIPDB_Conf{abuse_confidence}%_Reports{total_reports}_NotWhitelisted")

            # TI VALIDATION RULE 2: Whitelisted by AbuseIPDB BUT SANS confirms malicious
            # is_whitelisted=1 AND SANS count>0 AND SANS attacks>0
            elif is_whitelisted and sans_count > 0 and sans_attacks > 0:
                malicious_score += 4  # SANS overrides whitelist
                label_sources.append(f"SANS_Count{sans_count}_Attacks{sans_attacks}_OverridesWhitelist")

            # VirusTotal - use 'or {}' to handle None values
            vt_data = threat_intel.get('virustotal_data') or {}
            if vt_data:
                vt_malicious = vt_data.get('malicious', 0) or 0
                if vt_malicious >= 5:
                    malicious_score += 3
                    label_sources.append(f"VT_{vt_malicious}_malicious")
                elif vt_malicious >= 3:
                    malicious_score += 2
                    label_sources.append(f"VT_{vt_malicious}_malicious")
                elif vt_malicious >= 1:
                    malicious_score += 1
                    label_sources.append(f"VT_{vt_malicious}_malicious")

            # Check if TI flagged as malicious
            if threat_intel.get('is_malicious', False):
                malicious_score += 2
                label_sources.append("TI_Malicious_Flag")

        # Attack patterns
        if profile.attack_count >= 100:
            malicious_score += 2
            label_sources.append(f"High_Attack_Count_{profile.attack_count}")
        elif profile.attack_count >= 20:
            malicious_score += 1
            label_sources.append(f"Attack_Count_{profile.attack_count}")

        # CVE exploits
        if len(profile.cve_exploits) >= 3:
            malicious_score += 2
            label_sources.append(f"CVE_Exploits_{len(profile.cve_exploits)}")
        elif len(profile.cve_exploits) >= 1:
            malicious_score += 1
            label_sources.append(f"CVE_Exploits_{len(profile.cve_exploits)}")

        # === BENIGN INDICATORS ===

        # Private IP
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                benign_score += 5
                label_sources.append("Private_IP")
        except ValueError:
            pass

        # Known CDN/Cloud provider
        if threat_intel:
            abuse_isp_data = threat_intel.get('abuseipdb_data') or {}
            isp = (abuse_isp_data.get('isp', '') or '').lower()
            for cdn in self.known_cdns:
                if cdn in isp:
                    benign_score += 2
                    label_sources.append(f"Known_CDN_{cdn}")
                    break
            for cloud in self.known_clouds:
                if cloud in isp:
                    benign_score += 1
                    label_sources.append(f"Known_Cloud_{cloud}")
                    break

        # Low activity + no threat intel
        if max_severity < 3 and profile.attack_count < 3:
            if not threat_intel or not threat_intel.get('is_malicious', False):
                benign_score += 2
                label_sources.append("Low_Activity_Clean")

        # === DETERMINE LABEL ===

        # Need clear signal to assign label
        if malicious_score >= 4 and malicious_score > benign_score * 2:
            is_malicious = True
            confidence = min(0.95, 0.5 + malicious_score * 0.1)
        elif benign_score >= 4 and benign_score > malicious_score * 2:
            is_malicious = False
            confidence = min(0.95, 0.5 + benign_score * 0.1)
        else:
            # Ambiguous - don't add to ground truth
            return None

        # Extract features
        features = self._extract_features(profile, threat_intel)

        sample = GroundTruthSample(
            ip_address=ip,
            is_malicious=is_malicious,
            confidence=confidence,
            label_sources=label_sources,
            features=features
        )

        self.samples.append(sample)
        return sample

    def _extract_features(self, profile, threat_intel: Dict = None) -> Dict[str, float]:
        """Extract numeric features for ML training"""
        features = {}

        # Basic profile features
        features['attack_count'] = float(profile.attack_count)
        features['unique_attack_types'] = float(len(profile.attack_types))
        features['targeted_agents'] = float(len(profile.targeted_agents))
        features['cve_count'] = float(len(profile.cve_exploits))
        features['risk_score'] = float(profile.risk_score)

        # Time-based features
        if profile.first_seen and profile.last_seen:
            duration = (profile.last_seen - profile.first_seen).total_seconds()
            features['attack_duration_hours'] = duration / 3600
            features['attacks_per_hour'] = profile.attack_count / max(duration / 3600, 1)
        else:
            features['attack_duration_hours'] = 0.0
            features['attacks_per_hour'] = 0.0

        # Severity features
        severities = [e.rule_level for e in profile.attack_events if hasattr(e, 'rule_level')]
        features['max_severity'] = float(max(severities)) if severities else 0.0
        features['avg_severity'] = float(np.mean(severities)) if severities else 0.0
        features['high_severity_count'] = float(sum(1 for s in severities if s >= 10))

        # Threat intel features
        if threat_intel:
            abuse_data = threat_intel.get('abuseipdb_data') or {}
            features['abuseipdb_confidence'] = float(abuse_data.get('abuse_confidence_score', 0) or 0)
            features['abuseipdb_reports'] = float(abuse_data.get('total_reports', 0) or 0)

            sans_data = threat_intel.get('sans_isc_data') or {}
            features['sans_attacks'] = float(sans_data.get('attacks', 0) or 0)
            features['sans_count'] = float(sans_data.get('count', 0) or 0)

            vt_data = threat_intel.get('virustotal_data') or {}
            features['vt_malicious'] = float(vt_data.get('malicious', 0) or 0)
            features['vt_suspicious'] = float(vt_data.get('suspicious', 0) or 0)

            features['ti_is_malicious'] = 1.0 if threat_intel.get('is_malicious', False) else 0.0
        else:
            features['abuseipdb_confidence'] = 0.0
            features['abuseipdb_reports'] = 0.0
            features['sans_attacks'] = 0.0
            features['sans_count'] = 0.0
            features['vt_malicious'] = 0.0
            features['vt_suspicious'] = 0.0
            features['ti_is_malicious'] = 0.0

        return features

    def build_from_profiles(self, profiles: List, threat_intel_map: Dict[str, Dict] = None):
        """
        Build ground truth dataset from list of attacker profiles.

        Args:
            profiles: List of AttackerProfile objects
            threat_intel_map: Dict mapping IP -> threat intel data
        """
        added = 0
        skipped = 0

        for profile in profiles:
            ti_data = threat_intel_map.get(profile.ip_address, {}) if threat_intel_map else None
            sample = self.add_sample_from_profile(profile, ti_data)
            if sample:
                added += 1
            else:
                skipped += 1

        self._save_dataset()

        malicious = sum(1 for s in self.samples if s.is_malicious)
        benign = len(self.samples) - malicious

        self.logger.info(f"Ground Truth Update: Added {added}, Skipped {skipped}")
        self.logger.info(f"Total Dataset: {len(self.samples)} samples ({malicious} malicious, {benign} benign)")

        return {
            'added': added,
            'skipped': skipped,
            'total': len(self.samples),
            'malicious': malicious,
            'benign': benign
        }

    def get_training_data(self) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Get training data as numpy arrays.

        Returns:
            X: Feature matrix (n_samples, n_features)
            y: Labels (n_samples,) - 1=malicious, 0=benign
            feature_names: List of feature names
        """
        if not self.samples:
            return np.array([]), np.array([]), []

        # Get feature names from first sample
        feature_names = list(self.samples[0].features.keys())

        # Build arrays
        X = []
        y = []

        for sample in self.samples:
            # Ensure all features are present
            row = [sample.features.get(f, 0.0) for f in feature_names]
            X.append(row)
            y.append(1 if sample.is_malicious else 0)

        return np.array(X), np.array(y), feature_names

    def get_statistics(self) -> Dict[str, Any]:
        """Get dataset statistics"""
        if not self.samples:
            return {'total': 0, 'malicious': 0, 'benign': 0}

        malicious = [s for s in self.samples if s.is_malicious]
        benign = [s for s in self.samples if not s.is_malicious]

        total = len(self.samples)
        return {
            'total': total,
            'malicious': len(malicious),
            'benign': len(benign),
            'malicious_pct': (len(malicious) / total * 100) if total > 0 else 0,
            'benign_pct': (len(benign) / total * 100) if total > 0 else 0,
            'avg_malicious_confidence': np.mean([s.confidence for s in malicious]) if malicious else 0,
            'avg_benign_confidence': np.mean([s.confidence for s in benign]) if benign else 0,
            'label_sources': self._get_label_source_stats()
        }

    def _get_label_source_stats(self) -> Dict[str, int]:
        """Get counts of label sources"""
        source_counts = defaultdict(int)
        for sample in self.samples:
            for source in sample.label_sources:
                # Extract source type (e.g., "Wazuh_Level_12" -> "Wazuh")
                source_type = source.split('_')[0]
                source_counts[source_type] += 1
        return dict(source_counts)


class MLValidationEngine:
    """
    Validates ML models with proper metrics and cross-validation.

    Provides:
    - K-fold cross-validation
    - Precision, Recall, F1-score
    - ROC-AUC
    - Confusion matrix
    - Learning curves
    - Model comparison
    """

    def __init__(self, model_dir: str = "./models/validated_ml"):
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for MLValidationEngine")

        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(self.__class__.__name__)

        # Ground truth builder
        self.ground_truth = GroundTruthBuilder()

        # Models
        self.models = {}
        self.best_model = None
        self.best_model_name = None

        # Metrics history
        self.metrics_history: List[MLMetrics] = []

        # Preprocessing
        self.scaler = StandardScaler()
        self.feature_names = []

        # Load existing metrics
        self._load_metrics_history()

    def _load_metrics_history(self):
        """Load metrics history"""
        metrics_file = self.model_dir / "metrics_history.json"
        if metrics_file.exists():
            try:
                with open(metrics_file, 'r') as f:
                    data = json.load(f)
                    self.metrics_history = [MLMetrics(**m) for m in data]
            except Exception as e:
                self.logger.warning(f"Could not load metrics history: {e}")

    def _save_metrics_history(self):
        """Save metrics history"""
        metrics_file = self.model_dir / "metrics_history.json"
        try:
            data = [asdict(m) for m in self.metrics_history]
            with open(metrics_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Could not save metrics history: {e}")

    def train_and_validate(self, n_folds: int = 5) -> MLMetrics:
        """
        Train models with K-fold cross-validation and return metrics.

        Args:
            n_folds: Number of cross-validation folds

        Returns:
            MLMetrics object with all performance metrics
        """
        # Get training data
        X, y, self.feature_names = self.ground_truth.get_training_data()

        if len(X) < 20:
            self.logger.warning(f"Not enough samples for training: {len(X)}. Need at least 20.")
            return MLMetrics(total_samples=len(X))

        # Check class balance
        n_malicious = sum(y)
        n_benign = len(y) - n_malicious

        if n_malicious < 5 or n_benign < 5:
            self.logger.warning(f"Class imbalance too severe: {n_malicious} malicious, {n_benign} benign")
            return MLMetrics(total_samples=len(X))

        self.logger.info(f"Training on {len(X)} samples ({n_malicious} malicious, {n_benign} benign)")

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Initialize models
        self.models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                class_weight='balanced',
                random_state=42
            ),
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                random_state=42
            )
        }

        if XGBOOST_AVAILABLE:
            self.models['XGBoost'] = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                scale_pos_weight=n_benign / max(n_malicious, 1),
                random_state=42,
                eval_metric='logloss'
            )

        # Cross-validation for each model
        best_score = 0
        best_model_name = None
        cv_results = {}

        cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

        for name, model in self.models.items():
            try:
                # Cross-validation scores
                scores = cross_val_score(model, X_scaled, y, cv=cv, scoring='f1')
                cv_results[name] = {
                    'mean': scores.mean(),
                    'std': scores.std(),
                    'scores': scores.tolist()
                }

                self.logger.info(f"{name}: F1={scores.mean():.4f} (+/- {scores.std():.4f})")

                if scores.mean() > best_score:
                    best_score = scores.mean()
                    best_model_name = name

            except Exception as e:
                self.logger.error(f"Error training {name}: {e}")

        if not best_model_name:
            self.logger.error("No models trained successfully")
            return MLMetrics(total_samples=len(X))

        # Train best model on full data and get detailed metrics
        self.best_model_name = best_model_name
        self.best_model = self.models[best_model_name]

        # Split for final evaluation
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, stratify=y, random_state=42
        )

        self.best_model.fit(X_train, y_train)
        y_pred = self.best_model.predict(X_test)
        y_proba = self.best_model.predict_proba(X_test)[:, 1]

        # Calculate metrics
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        metrics = MLMetrics(
            accuracy=(tp + tn) / len(y_test),
            precision=precision_score(y_test, y_pred, zero_division=0),
            recall=recall_score(y_test, y_pred, zero_division=0),
            f1_score=f1_score(y_test, y_pred, zero_division=0),
            roc_auc=roc_auc_score(y_test, y_proba) if len(np.unique(y_test)) > 1 else 0,
            false_positive_rate=fp / max(fp + tn, 1),
            false_negative_rate=fn / max(fn + tp, 1),
            true_positive_count=int(tp),
            true_negative_count=int(tn),
            false_positive_count=int(fp),
            false_negative_count=int(fn),
            total_samples=len(X),
            cross_val_scores=cv_results[best_model_name]['scores'],
            cross_val_mean=cv_results[best_model_name]['mean'],
            cross_val_std=cv_results[best_model_name]['std'],
            model_version=f"{best_model_name}_v1"
        )

        # Log detailed results
        self.logger.info("=" * 60)
        self.logger.info(f"BEST MODEL: {best_model_name}")
        self.logger.info("=" * 60)
        self.logger.info(f"Accuracy:  {metrics.accuracy:.4f} ({metrics.accuracy*100:.2f}%)")
        self.logger.info(f"Precision: {metrics.precision:.4f} ({metrics.precision*100:.2f}%)")
        self.logger.info(f"Recall:    {metrics.recall:.4f} ({metrics.recall*100:.2f}%)")
        self.logger.info(f"F1-Score:  {metrics.f1_score:.4f} ({metrics.f1_score*100:.2f}%)")
        self.logger.info(f"ROC-AUC:   {metrics.roc_auc:.4f} ({metrics.roc_auc*100:.2f}%)")
        self.logger.info(f"FP Rate:   {metrics.false_positive_rate:.4f} ({metrics.false_positive_rate*100:.2f}%)")
        self.logger.info(f"FN Rate:   {metrics.false_negative_rate:.4f} ({metrics.false_negative_rate*100:.2f}%)")
        self.logger.info("=" * 60)
        self.logger.info("Confusion Matrix:")
        self.logger.info(f"  True Positives:  {tp}")
        self.logger.info(f"  True Negatives:  {tn}")
        self.logger.info(f"  False Positives: {fp}")
        self.logger.info(f"  False Negatives: {fn}")
        self.logger.info("=" * 60)

        # Save metrics and model
        self.metrics_history.append(metrics)
        self._save_metrics_history()
        self._save_model()

        # Retrain on full dataset for deployment
        self.best_model.fit(X_scaled, y)
        self._save_model()

        return metrics

    def _save_model(self):
        """Save trained model and scaler"""
        try:
            model_file = self.model_dir / "best_model.pkl"
            with open(model_file, 'wb') as f:
                pickle.dump({
                    'model': self.best_model,
                    'model_name': self.best_model_name,
                    'scaler': self.scaler,
                    'feature_names': self.feature_names
                }, f)
            self.logger.info(f"Saved model to {model_file}")
        except Exception as e:
            self.logger.error(f"Could not save model: {e}")

    def load_model(self) -> bool:
        """Load trained model"""
        model_file = self.model_dir / "best_model.pkl"
        if not model_file.exists():
            return False

        try:
            with open(model_file, 'rb') as f:
                data = pickle.load(f)
                self.best_model = data['model']
                self.best_model_name = data['model_name']
                self.scaler = data['scaler']
                self.feature_names = data['feature_names']
            self.logger.info(f"Loaded model: {self.best_model_name}")
            return True
        except Exception as e:
            self.logger.error(f"Could not load model: {e}")
            return False

    def predict(self, profile, threat_intel: Dict = None) -> Dict[str, Any]:
        """
        Predict if profile is malicious using validated model.

        Returns prediction with confidence and explanation.
        """
        if self.best_model is None:
            if not self.load_model():
                return {
                    'is_malicious': False,
                    'confidence': 0.0,
                    'error': 'No trained model available'
                }

        # Extract features
        features = self.ground_truth._extract_features(profile, threat_intel)

        # Ensure feature order matches training
        X = np.array([[features.get(f, 0.0) for f in self.feature_names]])
        X_scaled = self.scaler.transform(X)

        # Predict
        prediction = self.best_model.predict(X_scaled)[0]
        proba = self.best_model.predict_proba(X_scaled)[0]

        return {
            'is_malicious': bool(prediction == 1),
            'confidence': float(max(proba)),
            'malicious_probability': float(proba[1]) if len(proba) > 1 else 0.0,
            'benign_probability': float(proba[0]),
            'model': self.best_model_name,
            'features_used': len(self.feature_names)
        }

    def get_latest_metrics(self) -> Optional[MLMetrics]:
        """Get most recent metrics"""
        return self.metrics_history[-1] if self.metrics_history else None

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all metrics history"""
        if not self.metrics_history:
            return {'total_training_runs': 0}

        latest = self.metrics_history[-1]

        # Track improvement over time
        if len(self.metrics_history) > 1:
            first = self.metrics_history[0]
            improvement = {
                'accuracy': latest.accuracy - first.accuracy,
                'precision': latest.precision - first.precision,
                'recall': latest.recall - first.recall,
                'f1_score': latest.f1_score - first.f1_score
            }
        else:
            improvement = None

        return {
            'total_training_runs': len(self.metrics_history),
            'latest': asdict(latest),
            'improvement': improvement,
            'best_f1': max(m.f1_score for m in self.metrics_history),
            'best_precision': max(m.precision for m in self.metrics_history),
            'best_roc_auc': max(m.roc_auc for m in self.metrics_history)
        }


# Singleton instance for global access
_validation_engine: Optional[MLValidationEngine] = None

def get_validation_engine() -> MLValidationEngine:
    """Get or create the global validation engine instance"""
    global _validation_engine
    if _validation_engine is None:
        _validation_engine = MLValidationEngine()
    return _validation_engine
