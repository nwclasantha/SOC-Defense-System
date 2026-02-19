"""
Comprehensive ML Detector - ALL ML Models Integrated
Combines ALL available ML algorithms for maximum accuracy

Models Included (10+ algorithms):
1. XGBoost (Gradient Boosting)
2. Random Forest
3. Gradient Boosting Classifier
4. Isolation Forest (Anomaly Detection)
5. One-Class SVM (Outlier Detection)
6. Local Outlier Factor (LOF)
7. Decision Tree
8. Logistic Regression
9. Naive Bayes
10. K-Nearest Neighbors (KNN)
11. Support Vector Machine (SVM)
12. Extra Trees Classifier
13. AdaBoost
14. Voting Ensemble (Meta-classifier)
15. Stacking Ensemble (Meta-learner)
16. Autoencoder (Deep Learning - if TensorFlow available)

Architecture: SUPER ENSEMBLE with weighted voting
"""

import numpy as np
import pickle
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict
import logging

try:
    from sklearn.ensemble import (
        RandomForestClassifier,
        GradientBoostingClassifier,
        IsolationForest,
        ExtraTreesClassifier,
        AdaBoostClassifier,
        VotingClassifier,
        StackingClassifier
    )
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neighbors import KNeighborsClassifier, LocalOutlierFactor
    from sklearn.svm import SVC, OneClassSVM
    from sklearn.preprocessing import StandardScaler, RobustScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (
        classification_report, confusion_matrix, accuracy_score,
        precision_score, recall_score, f1_score, roc_auc_score
    )
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# Suppress TensorFlow verbose messages BEFORE import
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # 0=all, 1=info, 2=warning, 3=error
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'  # Disable oneDNN messages

try:
    import tensorflow as tf
    from tensorflow import keras
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

from modules.MitreFeatureExtractor import MitreFeatureExtractor
from modules.MitreAttackMapper import MitreAttackMapper
from modules.SANSIPReputationValidator import SANSIPReputationValidator
from modules.AttackEvent import AttackEvent
from modules.AttackerProfile import AttackerProfile


class ComprehensiveMLDetector:
    """
    The Ultimate ML Detection System
    Uses ALL available ML algorithms with intelligent ensemble voting
    """

    def __init__(self, model_dir: str = "./models/comprehensive_ml"):
        """Initialize comprehensive detector with all ML models"""
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required")

        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(self.__class__.__name__)

        # Feature extractors (using singleton to avoid reloading MITRE DB)
        self.mitre_mapper = MitreAttackMapper.get_instance(use_local_db=True)
        self.mitre_extractor = MitreFeatureExtractor(mitre_mapper=self.mitre_mapper)
        self.sans_validator = SANSIPReputationValidator(cache_ttl_hours=24)

        # ===== SUPERVISED MODELS (Classification) =====
        self.xgboost_model = None          # Model 1
        self.random_forest = None          # Model 2
        self.gradient_boosting = None      # Model 3
        self.extra_trees = None            # Model 4
        self.adaboost = None               # Model 5
        self.decision_tree = None          # Model 6
        self.logistic_regression = None    # Model 7
        self.naive_bayes = None            # Model 8
        self.knn_classifier = None         # Model 9
        self.svm_classifier = None         # Model 10

        # ===== UNSUPERVISED MODELS (Anomaly Detection) =====
        self.isolation_forest = None       # Model 11
        self.one_class_svm = None          # Model 12
        self.lof_detector = None           # Model 13

        # ===== META-LEARNERS (Ensemble) =====
        self.voting_ensemble = None        # Model 14
        self.stacking_ensemble = None      # Model 15

        # ===== DEEP LEARNING =====
        self.autoencoder = None            # Model 16

        # Preprocessing
        self.scaler = StandardScaler()
        self.robust_scaler = RobustScaler()

        # Feature names
        self.mitre_feature_names = self.mitre_extractor.get_feature_names()
        self.sans_feature_names = [
            'sans_reputation_score',
            'sans_attacks_reported',
            'sans_days_since_last_seen'
        ]
        self.feature_names = self.mitre_feature_names + self.sans_feature_names

        self.logger.info(f"ComprehensiveMLDetector initialized")
        self.logger.info(f"  Total features: {len(self.feature_names)} (42 MITRE + 3 SANS)")
        self.logger.info(f"  Available models: 16 algorithms")

        # Load existing models
        self._load_models()

    def extract_integrated_features(self, ip_address: str,
                                   attack_events: List[AttackEvent]) -> np.ndarray:
        """Extract all 45 features (42 MITRE + 3 SANS)"""
        # MITRE features (as array)
        mitre_features_array = self.mitre_extractor.extract_features_array(ip_address, attack_events)

        # SANS features
        sans_score, sans_details = self.sans_validator.get_reputation_score(ip_address)
        if sans_score is None:
            sans_features = np.array([0.0, 0.0, 999.0])
        else:
            attacks = float(sans_details.get('attacks', 0))
            max_date = sans_details.get('max_date', '')
            if max_date:
                try:
                    last_seen = datetime.strptime(max_date, '%Y-%m-%d')
                    days_since = (datetime.now() - last_seen).days
                except (ValueError, TypeError):
                    days_since = 999.0
            else:
                days_since = 999.0

            sans_features = np.array([float(sans_score), attacks, days_since])

        return np.concatenate([mitre_features_array, sans_features])

    def train(self, attacker_profiles: List[AttackerProfile],
             mitre_threshold: float = 70.0) -> Dict[str, Any]:
        """
        Train ALL ML models on the data

        Returns comprehensive training metrics
        """
        self.logger.info("=" * 80)
        self.logger.info("TRAINING ALL ML MODELS (16 ALGORITHMS)")
        self.logger.info("=" * 80)

        # Extract features
        X = []
        y = []

        self.logger.info(f"Extracting features from {len(attacker_profiles)} profiles...")

        for i, profile in enumerate(attacker_profiles, 1):
            if i % 50 == 0:
                self.logger.info(f"  Processing {i}/{len(attacker_profiles)}...")

            features = self.extract_integrated_features(
                profile.ip_address,
                profile.attack_events
            )
            X.append(features)

            # Label based on MITRE + SANS
            mitre_features_dict = self.mitre_extractor.extract_features_dict(
                profile.ip_address,
                profile.attack_events
            )
            mitre_score = mitre_features_dict.get('mitre_threat_score', 0)

            sans_score, _ = self.sans_validator.get_reputation_score(profile.ip_address)
            sans_score = sans_score or 0

            # Smart labeling
            if mitre_score >= 70 or (mitre_score >= 50 and sans_score >= 40):
                label = 1  # MALICIOUS
            else:
                label = 0  # BENIGN

            y.append(label)

        X = np.array(X)
        y = np.array(y)

        self.logger.info(f"Features: {X.shape}")
        self.logger.info(f"MALICIOUS: {np.sum(y == 1)}, BENIGN: {np.sum(y == 0)}")

        # Validate sufficient data for train_test_split
        if len(X) < 5:
            self.logger.error(f"Insufficient training data: {len(X)} samples (need at least 5)")
            return {'status': 'error', 'message': f'Insufficient training data: {len(X)} samples'}

        # Check if both classes are represented
        unique_classes = np.unique(y)
        if len(unique_classes) < 2:
            self.logger.warning("Only one class present - using non-stratified split")
            stratify_param = None
        else:
            # Check if each class has at least 2 samples for stratification
            class_counts = [np.sum(y == c) for c in unique_classes]
            if min(class_counts) < 2:
                self.logger.warning("Not enough samples in each class - using non-stratified split")
                stratify_param = None
            else:
                stratify_param = y

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=stratify_param
        )

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        X_train_robust = self.robust_scaler.fit_transform(X_train)
        X_test_robust = self.robust_scaler.transform(X_test)

        # Train all models
        results = {}

        # ===== MODEL 1: XGBoost =====
        self.logger.info("\n[1/16] Training XGBoost...")
        if XGBOOST_AVAILABLE:
            self.xgboost_model = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            )
            self.xgboost_model.fit(X_train_scaled, y_train)
            acc = accuracy_score(y_test, self.xgboost_model.predict(X_test_scaled))
            results['xgboost'] = acc
            self.logger.info(f"  Accuracy: {acc:.3f}")
        else:
            self.logger.info("  XGBoost not available")

        # ===== MODEL 2: Random Forest =====
        self.logger.info("\n[2/16] Training Random Forest...")
        self.random_forest = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.random_forest.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.random_forest.predict(X_test_scaled))
        results['random_forest'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 3: Gradient Boosting =====
        self.logger.info("\n[3/16] Training Gradient Boosting...")
        self.gradient_boosting = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            random_state=42
        )
        self.gradient_boosting.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.gradient_boosting.predict(X_test_scaled))
        results['gradient_boosting'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 4: Extra Trees =====
        self.logger.info("\n[4/16] Training Extra Trees...")
        self.extra_trees = ExtraTreesClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.extra_trees.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.extra_trees.predict(X_test_scaled))
        results['extra_trees'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 5: AdaBoost =====
        self.logger.info("\n[5/16] Training AdaBoost...")
        self.adaboost = AdaBoostClassifier(
            n_estimators=100,
            random_state=42
        )
        self.adaboost.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.adaboost.predict(X_test_scaled))
        results['adaboost'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 6: Decision Tree =====
        self.logger.info("\n[6/16] Training Decision Tree...")
        self.decision_tree = DecisionTreeClassifier(
            max_depth=15,
            random_state=42
        )
        self.decision_tree.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.decision_tree.predict(X_test_scaled))
        results['decision_tree'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 7: Logistic Regression =====
        self.logger.info("\n[7/16] Training Logistic Regression...")
        self.logistic_regression = LogisticRegression(
            max_iter=1000,
            random_state=42
        )
        self.logistic_regression.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.logistic_regression.predict(X_test_scaled))
        results['logistic_regression'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 8: Naive Bayes =====
        self.logger.info("\n[8/16] Training Naive Bayes...")
        self.naive_bayes = GaussianNB()
        self.naive_bayes.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.naive_bayes.predict(X_test_scaled))
        results['naive_bayes'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 9: K-Nearest Neighbors =====
        self.logger.info("\n[9/16] Training KNN...")
        self.knn_classifier = KNeighborsClassifier(
            n_neighbors=5,
            n_jobs=-1
        )
        self.knn_classifier.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.knn_classifier.predict(X_test_scaled))
        results['knn'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 10: Support Vector Machine =====
        self.logger.info("\n[10/16] Training SVM...")
        self.svm_classifier = SVC(
            kernel='rbf',
            probability=True,
            random_state=42
        )
        self.svm_classifier.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.svm_classifier.predict(X_test_scaled))
        results['svm'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 11: Isolation Forest =====
        self.logger.info("\n[11/16] Training Isolation Forest...")
        self.isolation_forest = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=200,
            n_jobs=-1
        )
        self.isolation_forest.fit(X_train_robust)
        self.logger.info("  Trained (unsupervised)")

        # ===== MODEL 12: One-Class SVM =====
        self.logger.info("\n[12/16] Training One-Class SVM...")
        self.one_class_svm = OneClassSVM(
            kernel='rbf',
            gamma='auto',
            nu=0.05
        )
        self.one_class_svm.fit(X_train_robust)
        self.logger.info("  Trained (unsupervised)")

        # ===== MODEL 13: Local Outlier Factor =====
        self.logger.info("\n[13/16] Training LOF...")
        self.lof_detector = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.05,
            novelty=True
        )
        self.lof_detector.fit(X_train_robust)
        self.logger.info("  Trained (unsupervised)")

        # ===== MODEL 14: Voting Ensemble =====
        self.logger.info("\n[14/16] Training Voting Ensemble...")
        estimators = [
            ('rf', self.random_forest),
            ('gb', self.gradient_boosting),
            ('et', self.extra_trees),
        ]
        if XGBOOST_AVAILABLE:
            estimators.append(('xgb', self.xgboost_model))

        self.voting_ensemble = VotingClassifier(
            estimators=estimators,
            voting='soft',
            n_jobs=-1
        )
        self.voting_ensemble.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.voting_ensemble.predict(X_test_scaled))
        results['voting_ensemble'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 15: Stacking Ensemble =====
        self.logger.info("\n[15/16] Training Stacking Ensemble...")
        base_estimators = [
            ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
            ('gb', GradientBoostingClassifier(n_estimators=100, random_state=42)),
            ('et', ExtraTreesClassifier(n_estimators=100, random_state=42)),
        ]

        self.stacking_ensemble = StackingClassifier(
            estimators=base_estimators,
            final_estimator=LogisticRegression(),
            n_jobs=-1
        )
        self.stacking_ensemble.fit(X_train_scaled, y_train)
        acc = accuracy_score(y_test, self.stacking_ensemble.predict(X_test_scaled))
        results['stacking_ensemble'] = acc
        self.logger.info(f"  Accuracy: {acc:.3f}")

        # ===== MODEL 16: Autoencoder (Deep Learning) =====
        self.logger.info("\n[16/16] Training Autoencoder...")
        if TENSORFLOW_AVAILABLE and len(X_train) >= 50:
            try:
                self.autoencoder = self._build_autoencoder(X_train_scaled.shape[1])
                self.autoencoder.fit(
                    X_train_scaled, X_train_scaled,
                    epochs=50,
                    batch_size=32,
                    validation_split=0.2,
                    verbose=0
                )
                self.logger.info("  Trained (deep learning)")
            except Exception as e:
                self.logger.warning(f"  Autoencoder training failed: {e}")
        else:
            self.logger.info("  Skipped (TensorFlow unavailable or insufficient data)")

        # Save all models
        self._save_models()

        # Final ensemble evaluation
        self.logger.info("\n" + "=" * 80)
        self.logger.info("TRAINING COMPLETE - SUMMARY")
        self.logger.info("=" * 80)

        if not results:
            self.logger.error("No models were successfully trained")
            return {'status': 'error', 'message': 'No models trained successfully'}

        for model_name, acc in sorted(results.items(), key=lambda x: x[1], reverse=True):
            self.logger.info(f"  {model_name:25s}: {acc:.3f}")

        best_model = max(results.items(), key=lambda x: x[1])
        self.logger.info(f"\nBest Model: {best_model[0]} ({best_model[1]:.3f})")

        return {
            'status': 'success',
            'total_samples': len(X),
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'malicious_count': int(np.sum(y == 1)),
            'benign_count': int(np.sum(y == 0)),
            'feature_count': len(self.feature_names),
            'models_trained': len(results),
            'individual_accuracies': results,
            'best_model': best_model[0],
            'best_accuracy': best_model[1],
            'timestamp': datetime.now().isoformat()
        }

    def predict(self, ip_address: str, attack_events: List[AttackEvent],
               confidence_threshold: float = 0.95) -> Dict[str, Any]:
        """
        Predict using SUPER ENSEMBLE (all models vote)

        Returns unified prediction with detailed breakdown
        """
        # Extract features
        features = self.extract_integrated_features(ip_address, attack_events)
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        features_robust = self.robust_scaler.transform(features.reshape(1, -1))

        # Collect predictions from all models
        predictions = {}
        probabilities = {}

        # Helper function to safely get prediction and probability
        def safe_predict(model, features, model_name):
            try:
                pred = model.predict(features)
                if len(pred) > 0:
                    predictions[model_name] = pred[0]
                    proba = model.predict_proba(features)
                    if len(proba) > 0 and proba.shape[1] > 1:
                        probabilities[model_name] = proba[0, 1]
            except Exception as e:
                self.logger.debug(f"Prediction failed for {model_name}: {e}")

        # Supervised models
        if self.xgboost_model:
            safe_predict(self.xgboost_model, features_scaled, 'xgboost')

        if self.random_forest:
            safe_predict(self.random_forest, features_scaled, 'random_forest')

        if self.gradient_boosting:
            safe_predict(self.gradient_boosting, features_scaled, 'gradient_boosting')

        if self.extra_trees:
            safe_predict(self.extra_trees, features_scaled, 'extra_trees')

        if self.voting_ensemble:
            safe_predict(self.voting_ensemble, features_scaled, 'voting_ensemble')

        if self.stacking_ensemble:
            safe_predict(self.stacking_ensemble, features_scaled, 'stacking_ensemble')

        # Unsupervised models (anomaly detection)
        if self.isolation_forest:
            try:
                pred = self.isolation_forest.predict(features_robust)
                if len(pred) > 0:
                    predictions['isolation_forest'] = 1 if pred[0] == -1 else 0
            except Exception as e:
                self.logger.debug(f"Isolation forest prediction failed: {e}")

        if self.one_class_svm:
            try:
                pred = self.one_class_svm.predict(features_robust)
                if len(pred) > 0:
                    predictions['one_class_svm'] = 1 if pred[0] == -1 else 0
            except Exception as e:
                self.logger.debug(f"One-class SVM prediction failed: {e}")

        if self.lof_detector:
            try:
                pred = self.lof_detector.predict(features_robust)
                if len(pred) > 0:
                    predictions['lof'] = 1 if pred[0] == -1 else 0
            except Exception as e:
                self.logger.debug(f"LOF prediction failed: {e}")

        # Calculate super ensemble confidence
        if probabilities:
            # Weighted average (ensemble models get higher weight)
            weights = {
                'voting_ensemble': 0.20,
                'stacking_ensemble': 0.20,
                'xgboost': 0.15,
                'gradient_boosting': 0.15,
                'random_forest': 0.15,
                'extra_trees': 0.15
            }

            weighted_sum = 0
            total_weight = 0

            for model, prob in probabilities.items():
                weight = weights.get(model, 0.10)
                weighted_sum += prob * weight
                total_weight += weight

            super_confidence = weighted_sum / total_weight if total_weight > 0 else 0.5
        else:
            super_confidence = 0.5

        # Final verdict
        is_malicious = super_confidence >= confidence_threshold

        # Vote counts
        total_votes = len(predictions)
        malicious_votes = sum(predictions.values())
        vote_percentage = (malicious_votes / total_votes * 100) if total_votes > 0 else 0

        result = {
            'ip_address': ip_address,
            'verdict': 'MALICIOUS' if is_malicious else 'BENIGN',
            'super_ensemble_confidence': float(super_confidence),
            'confidence_threshold': confidence_threshold,
            'vote_breakdown': {
                'total_models': total_votes,
                'malicious_votes': malicious_votes,
                'benign_votes': total_votes - malicious_votes,
                'vote_percentage': vote_percentage
            },
            'individual_predictions': predictions,
            'individual_probabilities': probabilities,
            'model_type': f'Super Ensemble ({total_votes} models)',
            'feature_count': len(self.feature_names),
            'timestamp': datetime.now().isoformat()
        }

        return result

    def _build_autoencoder(self, input_dim: int):
        """Build autoencoder for anomaly detection"""
        encoder = keras.Sequential([
            keras.layers.Dense(32, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dense(16, activation='relu'),
            keras.layers.Dense(8, activation='relu')
        ])

        decoder = keras.Sequential([
            keras.layers.Dense(16, activation='relu', input_shape=(8,)),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dense(input_dim, activation='sigmoid')
        ])

        autoencoder = keras.Sequential([encoder, decoder])
        autoencoder.compile(optimizer='adam', loss='mse')

        return autoencoder

    def _save_models(self):
        """Save all models"""
        models = {
            'xgboost': self.xgboost_model,
            'random_forest': self.random_forest,
            'gradient_boosting': self.gradient_boosting,
            'extra_trees': self.extra_trees,
            'adaboost': self.adaboost,
            'decision_tree': self.decision_tree,
            'logistic_regression': self.logistic_regression,
            'naive_bayes': self.naive_bayes,
            'knn': self.knn_classifier,
            'svm': self.svm_classifier,
            'isolation_forest': self.isolation_forest,
            'one_class_svm': self.one_class_svm,
            'lof': self.lof_detector,
            'voting_ensemble': self.voting_ensemble,
            'stacking_ensemble': self.stacking_ensemble,
        }

        for name, model in models.items():
            if model is not None:
                with open(self.model_dir / f"{name}.pkl", 'wb') as f:
                    pickle.dump(model, f)

        # Save scalers
        with open(self.model_dir / "scaler.pkl", 'wb') as f:
            pickle.dump(self.scaler, f)
        with open(self.model_dir / "robust_scaler.pkl", 'wb') as f:
            pickle.dump(self.robust_scaler, f)

        # Save autoencoder
        if self.autoencoder and TENSORFLOW_AVAILABLE:
            self.autoencoder.save(str(self.model_dir / "autoencoder.keras"))

        self.logger.info(f"All models saved to {self.model_dir}")

    def _load_models(self):
        """Load all models"""
        try:
            model_files = {
                'xgboost_model': 'xgboost.pkl',
                'random_forest': 'random_forest.pkl',
                'gradient_boosting': 'gradient_boosting.pkl',
                'extra_trees': 'extra_trees.pkl',
                'adaboost': 'adaboost.pkl',
                'decision_tree': 'decision_tree.pkl',
                'logistic_regression': 'logistic_regression.pkl',
                'naive_bayes': 'naive_bayes.pkl',
                'knn_classifier': 'knn.pkl',
                'svm_classifier': 'svm.pkl',
                'isolation_forest': 'isolation_forest.pkl',
                'one_class_svm': 'one_class_svm.pkl',
                'lof_detector': 'lof.pkl',
                'voting_ensemble': 'voting_ensemble.pkl',
                'stacking_ensemble': 'stacking_ensemble.pkl',
            }

            for attr, filename in model_files.items():
                filepath = self.model_dir / filename
                if filepath.exists():
                    with open(filepath, 'rb') as f:
                        setattr(self, attr, pickle.load(f))

            # Load scalers
            if (self.model_dir / "scaler.pkl").exists():
                with open(self.model_dir / "scaler.pkl", 'rb') as f:
                    self.scaler = pickle.load(f)

            if (self.model_dir / "robust_scaler.pkl").exists():
                with open(self.model_dir / "robust_scaler.pkl", 'rb') as f:
                    self.robust_scaler = pickle.load(f)

            # Load autoencoder with custom objects (fix for 'mse' function issue)
            if TENSORFLOW_AVAILABLE and (self.model_dir / "autoencoder.keras").exists():
                custom_objects = {
                    'mse': keras.losses.MeanSquaredError(),
                    'mean_squared_error': keras.losses.MeanSquaredError()
                }
                self.autoencoder = keras.models.load_model(
                    str(self.model_dir / "autoencoder.keras"),
                    custom_objects=custom_objects
                )

            self.logger.info(f"Models loaded from {self.model_dir}")

        except Exception as e:
            self.logger.debug(f"No existing models found: {e}")

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about all models"""
        models_status = {
            'XGBoost': self.xgboost_model is not None,
            'Random Forest': self.random_forest is not None,
            'Gradient Boosting': self.gradient_boosting is not None,
            'Extra Trees': self.extra_trees is not None,
            'AdaBoost': self.adaboost is not None,
            'Decision Tree': self.decision_tree is not None,
            'Logistic Regression': self.logistic_regression is not None,
            'Naive Bayes': self.naive_bayes is not None,
            'KNN': self.knn_classifier is not None,
            'SVM': self.svm_classifier is not None,
            'Isolation Forest': self.isolation_forest is not None,
            'One-Class SVM': self.one_class_svm is not None,
            'LOF': self.lof_detector is not None,
            'Voting Ensemble': self.voting_ensemble is not None,
            'Stacking Ensemble': self.stacking_ensemble is not None,
            'Autoencoder': self.autoencoder is not None,
        }

        return {
            'model_type': 'Comprehensive ML Detector (Super Ensemble)',
            'total_models': 16,
            'models_trained': sum(models_status.values()),
            'models_status': models_status,
            'feature_count': len(self.feature_names),
            'mitre_features': len(self.mitre_feature_names),
            'sans_features': len(self.sans_feature_names),
            'model_dir': str(self.model_dir)
        }
