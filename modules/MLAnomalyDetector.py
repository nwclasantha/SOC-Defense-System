"""
Machine Learning-based Anomaly Detection System
Uses Isolation Forest, Autoencoders, and ensemble methods
"""

import numpy as np
import pickle
import json
from datetime import datetime
from typing import List, Dict, Any, Tuple
from pathlib import Path
from collections import defaultdict

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
    from sklearn.preprocessing import StandardScaler, RobustScaler
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.decomposition import PCA
    from sklearn.svm import OneClassSVM
    from sklearn.neighbors import LocalOutlierFactor
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Suppress TensorFlow verbose messages BEFORE import
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # 0=all, 1=info, 2=warning, 3=error
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'  # Disable oneDNN messages

# Try to import deep learning for autoencoders
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

class MLAnomalyDetector:
    """
    Advanced anomaly detection using multiple ML algorithms
    """

    def __init__(self, model_dir: str = "./models"):
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for ML features")

        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        # Primary Models
        self.isolation_forest = None
        self.risk_scorer = None

        # Advanced Models for Higher Precision
        self.one_class_svm = None  # For low FP rate
        self.autoencoder = None  # Deep learning anomaly detection
        self.ensemble_classifier = None  # Voting ensemble
        self.lof = None  # Local Outlier Factor

        # Preprocessing
        self.scaler = RobustScaler()  # More robust to outliers than StandardScaler
        self.pca = None  # Will be initialized dynamically based on data

        # Fine-tuning parameters for 98.6% PRECISION
        self.contamination = 0.02  # Very low contamination = minimal false positives
        self.precision_threshold = 0.986  # Target: 98.6% precision

        # Load existing models if available
        self._load_models()

    def extract_features(self, attacker_profile) -> np.ndarray:
        """
        Extract numerical features from attacker profile with Threat Intelligence & MITRE ATT&CK

        Features:
        - Attack count & Risk score
        - Threat Intelligence scores
        - MITRE ATT&CK techniques count
        - CVE exploits
        - Attack type diversity
        - Severity levels
        - Time-based features
        - Payload characteristics
        """
        features = []

        # Basic metrics
        features.append(attacker_profile.attack_count)
        features.append(attacker_profile.risk_score)
        features.append(len(attacker_profile.targeted_agents))
        features.append(len(attacker_profile.attack_types))
        features.append(len(attacker_profile.cve_exploits))

        # CRITICAL: Threat Intelligence Scores
        # Handle case where threat_intel exists but is None
        threat_intel = getattr(attacker_profile, 'threat_intel', None) or {}
        features.append(threat_intel.get('risk_score', 0))  # External threat score
        features.append(1 if threat_intel.get('is_malicious', False) else 0)  # Known malicious IP
        features.append(1 if threat_intel.get('is_tor', False) else 0)  # TOR exit node
        features.append(1 if threat_intel.get('is_proxy', False) else 0)  # Proxy/VPN
        features.append(len(threat_intel.get('threat_types', [])))  # Number of threat categories

        # CRITICAL: MITRE ATT&CK Techniques
        mitre_techniques = set()
        for event in attacker_profile.attack_events:
            # Use mitre_attack dict (correct attribute from AttackEvent)
            if hasattr(event, 'mitre_attack') and event.mitre_attack:
                mitre_data = event.mitre_attack
                if isinstance(mitre_data, dict):
                    # Extract techniques - handle both key formats
                    for tech_key in ['techniques', 'mitre_techniques']:
                        for tech in mitre_data.get(tech_key, []):
                            if isinstance(tech, dict):
                                mitre_techniques.add(tech.get('id', '') or tech.get('name', ''))
                            elif isinstance(tech, str):
                                mitre_techniques.add(tech)
                    # Also count tactics - handle both key formats
                    for tactic_key in ['tactics', 'mitre_tactics']:
                        for tactic in mitre_data.get(tactic_key, []):
                            if isinstance(tactic, dict):
                                mitre_techniques.add(tactic.get('name', '') or tactic.get('id', ''))
                            elif isinstance(tactic, str):
                                mitre_techniques.add(tactic)
        features.append(len(mitre_techniques))  # Number of unique MITRE techniques/tactics

        # CRITICAL: Rule severity levels (HIGH severity = more dangerous)
        max_severity = 0
        avg_severity = 0
        for event in attacker_profile.attack_events:
            if hasattr(event, 'rule_level'):
                max_severity = max(max_severity, event.rule_level)
                avg_severity += event.rule_level
        features.append(max_severity)
        features.append(avg_severity / max(attacker_profile.attack_count, 1))

        # Time features
        time_span = (attacker_profile.last_seen - attacker_profile.first_seen).total_seconds()
        features.append(time_span)
        features.append(attacker_profile.attack_count / max(time_span / 3600, 1))  # attacks per hour

        # Attack type distribution
        attack_type_counts = defaultdict(int)
        for event in attacker_profile.attack_events:
            attack_type_name = event.attack_type.value if hasattr(event.attack_type, 'value') else str(event.attack_type)
            attack_type_counts[attack_type_name] += 1

        # One-hot encoding for top 5 attack types
        top_attack_types = ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'BRUTE_FORCE']
        for attack_type in top_attack_types:
            features.append(attack_type_counts.get(attack_type, 0))

        # Payload features
        total_payload_length = sum(len(event.payload) for event in attacker_profile.attack_events if event.payload)
        features.append(total_payload_length)
        features.append(total_payload_length / max(attacker_profile.attack_count, 1))  # avg payload length

        # Geographic features (high-risk countries)
        if attacker_profile.geo_location:
            features.append(1)  # has geo data
            country = attacker_profile.geo_location.get('country', '')
            # High-risk indicators
            high_risk_countries = ['CN', 'RU', 'KP', 'IR']  # Example high-risk countries
            features.append(1 if country in high_risk_countries else 0)
        else:
            features.append(0)
            features.append(0)

        # Temporal patterns
        hour_distribution = [0] * 24
        for event in attacker_profile.attack_events:
            hour_distribution[event.timestamp.hour] += 1

        # Statistical features of hour distribution
        features.append(np.std(hour_distribution))  # Temporal variance
        features.append(np.max(hour_distribution))  # Peak activity

        return np.array(features)

    def train_anomaly_detector(self, attacker_profiles: List) -> Dict[str, Any]:
        """
        Train Isolation Forest for anomaly detection

        Returns:
            Training metrics and model info
        """
        if not attacker_profiles:
            return {"status": "error", "message": "No data to train on"}

        # Extract features
        X = np.array([self.extract_features(profile) for profile in attacker_profiles])

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Apply PCA for dimensionality reduction (dynamically set components)
        n_samples, n_features = X_scaled.shape
        n_components = min(10, n_samples, n_features)  # Use max 10 components or less if limited data
        self.pca = PCA(n_components=n_components)
        X_pca = self.pca.fit_transform(X_scaled)

        # Train Isolation Forest with LOWER contamination for higher precision
        self.isolation_forest = IsolationForest(
            contamination=self.contamination,  # 5% expected anomalies (lower = fewer FP)
            random_state=42,
            n_estimators=200,  # More trees = better accuracy
            max_samples='auto',
            bootstrap=True,  # Enable bootstrapping
            n_jobs=-1  # Use all cores
        )
        self.isolation_forest.fit(X_pca)

        # Train One-Class SVM for additional precision (very low FP rate)
        try:
            self.one_class_svm = OneClassSVM(
                kernel='rbf',
                gamma='auto',
                nu=self.contamination  # Same as contamination for consistency
            )
            self.one_class_svm.fit(X_scaled)
        except Exception as e:
            print(f"One-Class SVM training skipped: {e}")

        # Train Local Outlier Factor
        try:
            self.lof = LocalOutlierFactor(
                n_neighbors=min(20, len(X)),
                contamination=self.contamination,
                novelty=True  # Enable prediction on new data
            )
            self.lof.fit(X_scaled)
        except Exception as e:
            print(f"LOF training skipped: {e}")

        # Train Autoencoder for deep learning anomaly detection
        if TENSORFLOW_AVAILABLE and len(X) >= 50:  # Need enough data for deep learning
            try:
                self.autoencoder = self._build_autoencoder(X_scaled.shape[1])
                self.autoencoder.fit(
                    X_scaled, X_scaled,
                    epochs=50,
                    batch_size=32,
                    validation_split=0.2,
                    verbose=0
                )
                print("Autoencoder trained successfully")
            except Exception as e:
                print(f"Autoencoder training skipped: {e}")

        # Train Ensemble Classifier (voting ensemble)
        try:
            # Create base classifiers
            rf_clf = RandomForestClassifier(n_estimators=100, random_state=42)
            gb_clf = GradientBoostingClassifier(n_estimators=100, random_state=42)

            # Create labels: normal (0) vs anomalous (1) based on isolation forest predictions
            predictions = self.isolation_forest.predict(X_pca)
            y_labels = np.where(predictions == -1, 1, 0)  # -1 is anomaly, convert to 1

            # Only train if we have both classes
            if len(np.unique(y_labels)) > 1:
                self.ensemble_classifier = VotingClassifier(
                    estimators=[('rf', rf_clf), ('gb', gb_clf)],
                    voting='soft'
                )
                self.ensemble_classifier.fit(X_scaled, y_labels)
                print("Ensemble Classifier trained successfully")
            else:
                print("Ensemble Classifier training skipped: need both normal and anomalous samples")
        except Exception as e:
            print(f"Ensemble Classifier training skipped: {e}")

        # Get anomaly scores
        anomaly_scores = self.isolation_forest.decision_function(X_pca)

        # Save models
        self._save_models()

        return {
            "status": "success",
            "samples_trained": len(X),
            "features_count": X.shape[1],
            "pca_components": X_pca.shape[1],
            "anomaly_threshold": np.percentile(anomaly_scores, 10),
            "autoencoder_trained": self.autoencoder is not None,
            "ensemble_trained": self.ensemble_classifier is not None,
            "model_saved": str(self.model_dir / "isolation_forest.pkl")
        }

    def detect_anomaly(self, attacker_profile) -> Dict[str, Any]:
        """
        Detect if an attacker profile is anomalous using ENSEMBLE voting + Rule-based detection

        Returns:
            Dict with anomaly score, is_anomaly flag, and explanation
        """
        # RULE-BASED OVERRIDE: Flag high-severity attackers immediately
        # Any IP that triggered Wazuh critical alerts (level >= 10) is malicious
        max_severity = 0
        for event in attacker_profile.attack_events:
            if hasattr(event, 'rule_level'):
                max_severity = max(max_severity, event.rule_level)

        # Rule 1: High severity attacks = ANOMALY
        if max_severity >= 10:
            return {
                "is_anomaly": True,
                "score": min(max_severity / 15.0, 1.0),  # Normalize to 0-1
                "anomaly_score": min(max_severity / 15.0, 1.0),
                "severity": "critical" if max_severity >= 15 else "high",
                "explanation": f"CRITICAL: Triggered Wazuh alert level {max_severity}. Known attack pattern detected.",
                "confidence": 0.95,
                "ensemble_votes": "Rule-based detection",
                "detection_method": "Rule-based (High Severity)"
            }

        # Rule 2: Check threat intelligence (handle None case)
        threat_intel = getattr(attacker_profile, 'threat_intel', None) or {}
        if threat_intel.get('is_malicious', False):
            return {
                "is_anomaly": True,
                "score": threat_intel.get('risk_score', 100) / 100.0,
                "anomaly_score": threat_intel.get('risk_score', 100) / 100.0,
                "severity": "critical",
                "explanation": f"THREAT INTEL: Known malicious IP. Threat types: {', '.join(threat_intel.get('threat_types', ['Unknown']))}",
                "confidence": 0.98,
                "ensemble_votes": "Rule-based detection",
                "detection_method": "Threat Intelligence"
            }

        # Rule 3: Risk score threshold (HIGH RISK)
        if attacker_profile.risk_score >= 85:
            return {
                "is_anomaly": True,
                "score": attacker_profile.risk_score / 100.0,
                "anomaly_score": attacker_profile.risk_score / 100.0,
                "severity": "high",
                "explanation": f"HIGH RISK: Risk score {round(attacker_profile.risk_score)}/100. Multiple attack indicators detected.",
                "confidence": 0.90,
                "ensemble_votes": "Rule-based detection",
                "detection_method": "Risk Score Threshold"
            }

        # Rule 4: Medium severity alerts (5-9) = SUSPICIOUS (ignoring LOW 0-4)
        if max_severity >= 5:
            return {
                "is_anomaly": True,
                "score": max_severity / 15.0,  # Normalize to 0-1
                "anomaly_score": max_severity / 15.0,
                "severity": "medium",
                "explanation": f"SUSPICIOUS: Triggered Wazuh alert level {max_severity}. Potential attack pattern.",
                "confidence": 0.75,
                "ensemble_votes": "Rule-based detection",
                "detection_method": "Rule-based (Medium Severity)"
            }

        # Rule 5: Attack count threshold (repeated activity from same IP)
        if attacker_profile.attack_count >= 5:
            return {
                "is_anomaly": True,
                "score": min(attacker_profile.attack_count / 20.0, 1.0),
                "anomaly_score": min(attacker_profile.attack_count / 20.0, 1.0),
                "severity": "medium",
                "explanation": f"REPEATED ACTIVITY: {attacker_profile.attack_count} events from this IP. Possible scanning or reconnaissance.",
                "confidence": 0.70,
                "ensemble_votes": "Rule-based detection",
                "detection_method": "Repeated Activity"
            }

        # Rule 6: No alerts = LEGITIMATE TRAFFIC
        if max_severity == 0 and attacker_profile.attack_count < 3:
            return {
                "is_anomaly": False,
                "score": 0.1,
                "anomaly_score": 0.1,
                "severity": "low",
                "explanation": "LEGITIMATE: No security alerts triggered. Normal network activity.",
                "confidence": 0.85,
                "ensemble_votes": "Rule-based detection",
                "detection_method": "Legitimate Traffic"
            }

        # If models not trained, use rule-based only (default to suspicious for any activity)
        if self.isolation_forest is None:
            return {
                "is_anomaly": True,
                "score": 0.50,
                "anomaly_score": 0.50,
                "severity": "low",
                "explanation": "LOW RISK: Minimal suspicious indicators. ML models not yet trained for precise classification.",
                "confidence": 0.60,
                "ensemble_votes": "Rule-based detection",
                "detection_method": "Default suspicious"
            }

        # Extract and transform features for ML-based detection
        features = self.extract_features(attacker_profile).reshape(1, -1)
        features_scaled = self.scaler.transform(features)
        features_pca = self.pca.transform(features_scaled)

        # Ensemble voting: collect predictions from multiple models
        votes = []
        scores = []

        # Model 1: Isolation Forest
        if_score = self.isolation_forest.decision_function(features_pca)[0]
        if_prediction = self.isolation_forest.predict(features_pca)[0]
        votes.append(1 if if_prediction == -1 else 0)
        scores.append(abs(if_score))

        # Model 2: One-Class SVM (low FP rate)
        if self.one_class_svm is not None:
            try:
                svm_prediction = self.one_class_svm.predict(features_scaled)[0]
                svm_score = self.one_class_svm.score_samples(features_scaled)[0]
                votes.append(1 if svm_prediction == -1 else 0)
                scores.append(abs(svm_score))
            except (ValueError, IndexError, AttributeError):
                pass

        # Model 3: Local Outlier Factor
        if self.lof is not None:
            try:
                lof_prediction = self.lof.predict(features_scaled)[0]
                lof_score = self.lof.score_samples(features_scaled)[0]
                votes.append(1 if lof_prediction == -1 else 0)
                scores.append(abs(lof_score))
            except (ValueError, IndexError, AttributeError):
                pass

        # ENSEMBLE VOTING: Require MAJORITY vote for anomaly (reduces FP)
        # If we have 3 models, need at least 2 to agree
        # This significantly reduces false positives!
        majority_threshold = len(votes) / 2
        anomaly_votes = sum(votes)
        is_anomaly = anomaly_votes > majority_threshold

        # Average anomaly score
        avg_score = np.mean(scores) if scores else if_score

        # Confidence based on vote consensus
        # Higher consensus = higher confidence
        vote_confidence = anomaly_votes / len(votes) if votes else 0.5
        confidence = vote_confidence * abs(avg_score)

        return {
            "is_anomaly": is_anomaly,
            "score": float(avg_score),
            "anomaly_score": float(avg_score),
            "severity": "critical" if is_anomaly and avg_score > 0.7 else "high" if is_anomaly else "normal",
            "explanation": self._explain_anomaly(attacker_profile, features[0]) if is_anomaly else "Normal behavior",
            "confidence": confidence,
            "ensemble_votes": f"{anomaly_votes}/{len(votes)}",  # Show voting detail
            "detection_method": "ML Ensemble Voting"
        }

    def _explain_anomaly(self, profile, features) -> str:
        """Generate human-readable explanation of why profile is anomalous"""
        explanations = []

        if profile.attack_count > 1000:
            explanations.append(f"Extremely high attack count: {profile.attack_count}")

        if len(profile.targeted_agents) > 50:
            explanations.append(f"Targeting unusually many systems: {len(profile.targeted_agents)}")

        if len(profile.attack_types) > 5:
            explanations.append(f"Using diverse attack methods: {len(profile.attack_types)}")

        if len(profile.cve_exploits) > 10:
            explanations.append(f"Exploiting many CVEs: {len(profile.cve_exploits)}")

        return " | ".join(explanations) if explanations else "Unusual attack pattern detected"

    def train_risk_scorer(self, attacker_profiles: List, labels: List[int] = None) -> Dict[str, Any]:
        """
        Train Random Forest for risk scoring

        Args:
            attacker_profiles: List of attacker profiles
            labels: Optional labels (0-100 risk scores)
        """
        if not attacker_profiles:
            return {"status": "error", "message": "No data to train on"}

        X = np.array([self.extract_features(profile) for profile in attacker_profiles])

        # If no labels provided, use current risk scores
        if labels is None:
            labels = [int(profile.risk_score) for profile in attacker_profiles]

        # Convert to classification problem (low, medium, high, critical)
        y = np.array([
            0 if score < 50 else 1 if score < 70 else 2 if score < 85 else 3
            for score in labels
        ])

        # Train Random Forest with COST-SENSITIVE learning for higher precision
        # Penalize FP more heavily than FN
        class_weights = {
            0: 1.0,  # Low risk - normal weight
            1: 1.5,  # Medium risk - slightly higher
            2: 2.0,  # High risk - higher weight (reduce FP)
            3: 3.0   # Critical - highest weight (minimize FP)
        }

        self.risk_scorer = RandomForestClassifier(
            n_estimators=200,  # More trees = better accuracy
            max_depth=15,  # Deeper trees for complex patterns
            min_samples_split=5,  # Prevent overfitting
            min_samples_leaf=2,
            random_state=42,
            class_weight=class_weights,  # Cost-sensitive
            n_jobs=-1,  # Use all cores
            bootstrap=True,
            oob_score=True  # Out-of-bag scoring
        )

        self.risk_scorer.fit(X, y)

        # Save model
        self._save_models()

        # Use OOB score (out-of-bag) for realistic accuracy estimate
        # This is a proper holdout estimate, not training accuracy which would be ~100%
        # OOB uses samples not included in each tree's bootstrap sample for validation
        oob_accuracy = self.risk_scorer.oob_score_ if hasattr(self.risk_scorer, 'oob_score_') else 0.0

        return {
            "status": "success",
            "samples_trained": len(X),
            "accuracy": float(oob_accuracy),
            "feature_importance": self._get_feature_importance().tolist()
        }

    def predict_risk(self, attacker_profile) -> Dict[str, Any]:
        """
        Predict risk score using ML model

        Returns:
            Dict with predicted risk class and probability
        """
        if self.risk_scorer is None:
            return {
                "risk_class": "unknown",
                "confidence": 0.0,
                "ml_risk_score": attacker_profile.risk_score
            }

        features = self.extract_features(attacker_profile).reshape(1, -1)
        prediction = self.risk_scorer.predict(features)[0]
        probabilities = self.risk_scorer.predict_proba(features)[0]

        # Get actual number of classes from probabilities
        n_classes = len(probabilities)
        risk_classes = ["low", "medium", "high", "critical"][:n_classes]
        risk_scores = [25, 60, 77.5, 92.5][:n_classes]

        # Ensure prediction index is valid
        if prediction >= n_classes:
            prediction = n_classes - 1

        return {
            "risk_class": risk_classes[prediction],
            "ml_risk_score": risk_scores[prediction],
            "confidence": float(probabilities[prediction]),
            "probabilities": {
                risk_classes[i]: float(probabilities[i])
                for i in range(n_classes)
            }
        }

    def cluster_attackers(self, attacker_profiles: List, n_clusters: int = 5) -> Dict[str, Any]:
        """
        Cluster attackers using K-Means for behavioral analysis

        Returns:
            Cluster assignments and characteristics
        """
        if len(attacker_profiles) < n_clusters:
            return {"status": "error", "message": "Not enough data for clustering"}

        X = np.array([self.extract_features(profile) for profile in attacker_profiles])
        X_scaled = self.scaler.fit_transform(X)

        # K-Means clustering
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        clusters = kmeans.fit_predict(X_scaled)

        # Analyze clusters
        cluster_info = {}
        for i in range(n_clusters):
            cluster_profiles = [p for p, c in zip(attacker_profiles, clusters) if c == i]
            cluster_info[f"cluster_{i}"] = {
                "size": len(cluster_profiles),
                "avg_risk_score": np.mean([p.risk_score for p in cluster_profiles]),
                "avg_attack_count": np.mean([p.attack_count for p in cluster_profiles]),
                "common_attack_types": self._get_common_attack_types(cluster_profiles),
                "sample_ips": [p.ip_address for p in cluster_profiles[:5]]
            }

        return {
            "status": "success",
            "n_clusters": n_clusters,
            "clusters": cluster_info
        }

    def _get_common_attack_types(self, profiles: List) -> List[str]:
        """Get most common attack types in a cluster"""
        attack_types = defaultdict(int)
        for profile in profiles:
            for attack_type in profile.attack_types:
                attack_type_name = attack_type.value if hasattr(attack_type, 'value') else str(attack_type)
                attack_types[attack_type_name] += 1

        sorted_types = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)
        return [t[0] for t in sorted_types[:3]]

    def _get_feature_importance(self) -> np.ndarray:
        """Get feature importance from Random Forest"""
        if self.risk_scorer is None:
            return np.array([])
        return self.risk_scorer.feature_importances_

    def _build_autoencoder(self, input_dim: int):
        """Build autoencoder model for anomaly detection"""
        if not TENSORFLOW_AVAILABLE:
            return None

        encoder = models.Sequential([
            layers.Dense(32, activation='relu', input_shape=(input_dim,)),
            layers.Dense(16, activation='relu'),
            layers.Dense(8, activation='relu')
        ])

        decoder = models.Sequential([
            layers.Dense(16, activation='relu', input_shape=(8,)),
            layers.Dense(32, activation='relu'),
            layers.Dense(input_dim, activation='sigmoid')
        ])

        autoencoder = models.Sequential([encoder, decoder])
        autoencoder.compile(optimizer='adam', loss='mse')

        return autoencoder

    def _save_models(self):
        """Save models to disk"""
        if self.isolation_forest:
            with open(self.model_dir / "isolation_forest.pkl", 'wb') as f:
                pickle.dump(self.isolation_forest, f)

        if self.risk_scorer:
            with open(self.model_dir / "risk_scorer.pkl", 'wb') as f:
                pickle.dump(self.risk_scorer, f)

        if self.one_class_svm:
            with open(self.model_dir / "one_class_svm.pkl", 'wb') as f:
                pickle.dump(self.one_class_svm, f)

        if self.lof:
            with open(self.model_dir / "lof.pkl", 'wb') as f:
                pickle.dump(self.lof, f)

        if self.ensemble_classifier:
            with open(self.model_dir / "ensemble_classifier.pkl", 'wb') as f:
                pickle.dump(self.ensemble_classifier, f)

        if self.autoencoder and TENSORFLOW_AVAILABLE:
            self.autoencoder.save(str(self.model_dir / "autoencoder.keras"))

        with open(self.model_dir / "scaler.pkl", 'wb') as f:
            pickle.dump(self.scaler, f)

        if hasattr(self, 'pca') and self.pca:
            with open(self.model_dir / "pca.pkl", 'wb') as f:
                pickle.dump(self.pca, f)

    def _load_models(self):
        """Load models from disk"""
        try:
            if (self.model_dir / "isolation_forest.pkl").exists():
                with open(self.model_dir / "isolation_forest.pkl", 'rb') as f:
                    self.isolation_forest = pickle.load(f)

            if (self.model_dir / "risk_scorer.pkl").exists():
                with open(self.model_dir / "risk_scorer.pkl", 'rb') as f:
                    self.risk_scorer = pickle.load(f)

            if (self.model_dir / "one_class_svm.pkl").exists():
                with open(self.model_dir / "one_class_svm.pkl", 'rb') as f:
                    self.one_class_svm = pickle.load(f)

            if (self.model_dir / "lof.pkl").exists():
                with open(self.model_dir / "lof.pkl", 'rb') as f:
                    self.lof = pickle.load(f)

            if (self.model_dir / "ensemble_classifier.pkl").exists():
                with open(self.model_dir / "ensemble_classifier.pkl", 'rb') as f:
                    self.ensemble_classifier = pickle.load(f)

            if TENSORFLOW_AVAILABLE and (self.model_dir / "autoencoder.keras").exists():
                custom_objects = {
                    'mse': keras.losses.MeanSquaredError(),
                    'mean_squared_error': keras.losses.MeanSquaredError()
                }
                self.autoencoder = keras.models.load_model(
                    str(self.model_dir / "autoencoder.keras"),
                    custom_objects=custom_objects
                )

            if (self.model_dir / "scaler.pkl").exists():
                with open(self.model_dir / "scaler.pkl", 'rb') as f:
                    self.scaler = pickle.load(f)

            if (self.model_dir / "pca.pkl").exists():
                with open(self.model_dir / "pca.pkl", 'rb') as f:
                    self.pca = pickle.load(f)
        except Exception as e:
            print(f"Warning: Could not load models: {e}")
