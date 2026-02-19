"""
Advanced Machine Learning Engine
Implements LSTM, GRU, Autoencoders, XGBoost for attack prediction and pattern analysis
"""

import numpy as np
import pickle
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from collections import defaultdict, deque

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
    from tensorflow.keras import layers, models, callbacks
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

try:
    from sklearn.preprocessing import StandardScaler, MinMaxScaler
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

class AdvancedMLEngine:
    """
    Advanced ML Engine with Deep Learning capabilities
    - LSTM/GRU for attack pattern prediction
    - Autoencoders for anomaly detection
    - XGBoost for high-performance classification
    - Time-series forecasting
    """

    def __init__(self, model_dir: str = "./models/advanced"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        # Models
        self.lstm_model = None
        self.autoencoder = None
        self.xgboost_model = None

        # Scalers
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.time_scaler = MinMaxScaler() if SKLEARN_AVAILABLE else None

        # Autoencoder threshold (set during training)
        self.reconstruction_threshold = None

        # Sequence length for LSTM/GRU
        self.sequence_length = 24  # 24-hour sequences

        # Load existing models
        self._load_models()

    def build_lstm_model(self, input_shape: Tuple, output_dim: int = 10):
        """
        Build LSTM model for attack pattern prediction

        Args:
            input_shape: (sequence_length, n_features)
            output_dim: Number of output classes (attack types)

        Returns:
            Compiled LSTM model
        """
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow is required for LSTM models")

        model = models.Sequential([
            layers.LSTM(128, return_sequences=True, input_shape=input_shape),
            layers.Dropout(0.3),
            layers.LSTM(64, return_sequences=False),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dense(output_dim, activation='softmax')
        ])

        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )

        return model

    def build_gru_model(self, input_shape: Tuple, output_dim: int = 10):
        """
        Build GRU model for attack pattern prediction
        (Faster than LSTM with similar performance)

        Args:
            input_shape: (sequence_length, n_features)
            output_dim: Number of output classes

        Returns:
            Compiled GRU model
        """
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow is required for GRU models")

        model = models.Sequential([
            layers.GRU(128, return_sequences=True, input_shape=input_shape),
            layers.Dropout(0.3),
            layers.GRU(64, return_sequences=False),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dense(output_dim, activation='softmax')
        ])

        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )

        return model

    def build_autoencoder(self, input_dim: int):
        """
        Build Autoencoder for anomaly detection

        Args:
            input_dim: Number of input features

        Returns:
            Compiled autoencoder model
        """
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow is required for Autoencoders")

        # Encoder
        encoder_input = layers.Input(shape=(input_dim,))
        encoded = layers.Dense(64, activation='relu')(encoder_input)
        encoded = layers.Dense(32, activation='relu')(encoded)
        encoded = layers.Dense(16, activation='relu')(encoded)

        # Decoder
        decoded = layers.Dense(32, activation='relu')(encoded)
        decoded = layers.Dense(64, activation='relu')(decoded)
        decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)

        # Autoencoder
        autoencoder = models.Model(encoder_input, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')

        return autoencoder

    def train_lstm_pattern_predictor(self,
                                     attack_sequences: List[List[Dict]],
                                     epochs: int = 50,
                                     batch_size: int = 32) -> Dict[str, Any]:
        """
        Train LSTM model to predict next attack type

        Args:
            attack_sequences: List of attack event sequences
            epochs: Training epochs
            batch_size: Batch size

        Returns:
            Training history
        """
        if not TENSORFLOW_AVAILABLE:
            return {"error": "TensorFlow not available"}

        # Prepare sequences
        X, y = self._prepare_sequences(attack_sequences)

        if len(X) < 10:
            return {"error": "Not enough data for training"}

        # Build model
        self.lstm_model = self.build_lstm_model(
            input_shape=(X.shape[1], X.shape[2]),
            output_dim=10  # 10 attack types
        )

        # Callbacks
        early_stop = callbacks.EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True
        )

        checkpoint = callbacks.ModelCheckpoint(
            str(self.model_dir / 'lstm_best.keras'),
            save_best_only=True,
            monitor='val_loss'
        )

        # Train
        history = self.lstm_model.fit(
            X, y,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.2,
            callbacks=[early_stop, checkpoint],
            verbose=0
        )

        # Save model
        self.lstm_model.save(str(self.model_dir / 'lstm_model.keras'))

        # Safely extract metrics (handle empty history)
        accuracy_history = history.history.get('accuracy', [])
        val_accuracy_history = history.history.get('val_accuracy', [])
        loss_history = history.history.get('loss', [])

        return {
            "status": "success",
            "samples": len(X),
            "final_accuracy": float(accuracy_history[-1]) if accuracy_history else 0.0,
            "val_accuracy": float(val_accuracy_history[-1]) if val_accuracy_history else 0.0,
            "epochs_trained": len(loss_history)
        }

    def predict_next_attack(self, recent_attacks: List[Dict]) -> Dict[str, Any]:
        """
        Predict next likely attack type using LSTM

        Args:
            recent_attacks: Recent attack events (last 24 hours)

        Returns:
            Prediction with probabilities
        """
        if not self.lstm_model:
            return {"error": "Model not trained"}

        # Prepare sequence
        sequence = self._prepare_single_sequence(recent_attacks)

        if sequence is None:
            return {"error": "Invalid sequence"}

        # Predict
        prediction = self.lstm_model.predict(sequence, verbose=0)

        attack_types = [
            "SQL_INJECTION", "XSS", "COMMAND_INJECTION",
            "PATH_TRAVERSAL", "BRUTE_FORCE", "XXE",
            "SSRF", "FILE_INCLUSION", "DESERIALIZATION",
            "AUTHENTICATION_BYPASS"
        ]

        # Safely handle empty or malformed predictions
        if prediction is None or len(prediction) == 0 or len(prediction[0]) == 0:
            return {"error": "Model returned empty prediction"}

        predicted_idx = int(np.argmax(prediction[0]))
        # Ensure predicted_idx is within bounds
        if predicted_idx >= len(attack_types):
            predicted_idx = 0  # Default to first attack type
        confidence = float(prediction[0][min(predicted_idx, len(prediction[0]) - 1)])

        return {
            "predicted_attack_type": attack_types[predicted_idx],
            "confidence": confidence,
            "probabilities": {
                attack_types[i]: float(prediction[0][i]) if i < len(prediction[0]) else 0.0
                for i in range(len(attack_types))
            },
            "high_risk": confidence > 0.7
        }

    def train_autoencoder_detector(self,
                                   normal_profiles: List,
                                   epochs: int = 100,
                                   batch_size: int = 32) -> Dict[str, Any]:
        """
        Train Autoencoder for anomaly detection

        Args:
            normal_profiles: List of normal (non-anomalous) attacker profiles
            epochs: Training epochs
            batch_size: Batch size

        Returns:
            Training history
        """
        if not TENSORFLOW_AVAILABLE:
            return {"error": "TensorFlow not available"}

        # Extract features
        X = np.array([self._extract_features(p) for p in normal_profiles])

        if len(X) < 10:
            return {"error": "Not enough data"}

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Build model
        self.autoencoder = self.build_autoencoder(X_scaled.shape[1])

        # Train
        history = self.autoencoder.fit(
            X_scaled, X_scaled,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.2,
            callbacks=[
                callbacks.EarlyStopping(patience=10, restore_best_weights=True)
            ],
            verbose=0
        )

        # Calculate reconstruction threshold (95th percentile)
        reconstructions = self.autoencoder.predict(X_scaled, verbose=0)
        mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
        self.reconstruction_threshold = np.percentile(mse, 95)

        # Save
        self.autoencoder.save(str(self.model_dir / 'autoencoder.keras'))

        # Safely get final loss
        loss_history = history.history.get('loss', [])
        final_loss = float(loss_history[-1]) if loss_history else 0.0

        return {
            "status": "success",
            "samples": len(X),
            "final_loss": final_loss,
            "threshold": float(self.reconstruction_threshold)
        }

    def detect_anomaly_autoencoder(self, profile) -> Dict[str, Any]:
        """
        Detect anomalies using Autoencoder

        Args:
            profile: Attacker profile to check

        Returns:
            Anomaly detection result
        """
        if not self.autoencoder:
            return {"error": "Model not trained"}

        if self.reconstruction_threshold is None:
            return {"error": "Autoencoder threshold not set - model needs training"}

        # Check if scaler is fitted
        if not hasattr(self.scaler, 'mean_') or self.scaler.mean_ is None:
            return {"error": "Scaler not fitted - model needs training"}

        # Extract and scale features
        features = self._extract_features(profile).reshape(1, -1)
        features_scaled = self.scaler.transform(features)

        # Reconstruct
        reconstruction = self.autoencoder.predict(features_scaled, verbose=0)

        # Calculate reconstruction error
        mse = np.mean(np.power(features_scaled - reconstruction, 2))

        is_anomaly = mse > self.reconstruction_threshold

        return {
            "is_anomaly": bool(is_anomaly),
            "reconstruction_error": float(mse),
            "threshold": float(self.reconstruction_threshold),
            "severity": "critical" if mse > self.reconstruction_threshold * 2 else "high" if is_anomaly else "normal"
        }

    def train_xgboost_classifier(self,
                                 attacker_profiles: List,
                                 labels: List[int]) -> Dict[str, Any]:
        """
        Train XGBoost for high-performance risk classification

        Args:
            attacker_profiles: List of profiles
            labels: Risk labels (0-3: low, medium, high, critical)

        Returns:
            Training metrics
        """
        if not XGBOOST_AVAILABLE:
            return {"error": "XGBoost not available"}

        # Extract features
        X = np.array([self._extract_features(p) for p in attacker_profiles])
        y = np.array(labels)

        # Split into train and test sets for proper accuracy evaluation
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Train XGBoost
        self.xgboost_model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            objective='multi:softmax',
            num_class=4,
            use_label_encoder=False,
            eval_metric='mlogloss'
        )

        self.xgboost_model.fit(X_train, y_train)

        # Calculate accuracy on test data (proper holdout evaluation)
        predictions = self.xgboost_model.predict(X_test)
        accuracy = np.mean(predictions == y_test)

        # Save model
        self.xgboost_model.save_model(str(self.model_dir / 'xgboost_model.json'))

        return {
            "status": "success",
            "samples": len(X),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "accuracy": float(accuracy),
            "feature_importance": self.xgboost_model.feature_importances_.tolist()
        }

    def predict_risk_xgboost(self, profile) -> Dict[str, Any]:
        """
        Predict risk using XGBoost

        Args:
            profile: Attacker profile

        Returns:
            Risk prediction
        """
        if not self.xgboost_model:
            return {"error": "Model not trained"}

        features = self._extract_features(profile).reshape(1, -1)
        prediction = self.xgboost_model.predict(features)[0]
        probabilities = self.xgboost_model.predict_proba(features)[0]

        risk_levels = ["low", "medium", "high", "critical"]
        risk_scores = [25, 60, 77.5, 92.5]

        return {
            "risk_level": risk_levels[prediction],
            "risk_score": risk_scores[prediction],
            "confidence": float(probabilities[prediction]),
            "probabilities": {
                risk_levels[i]: float(probabilities[i])
                for i in range(len(risk_levels))
            }
        }

    def _extract_features(self, profile) -> np.ndarray:
        """Extract features from attacker profile"""
        features = [
            profile.attack_count,
            profile.risk_score,
            len(profile.targeted_agents),
            len(profile.attack_types),
            len(profile.cve_exploits),
            (profile.last_seen - profile.first_seen).total_seconds(),
            profile.attack_count / max((profile.last_seen - profile.first_seen).total_seconds() / 3600, 1)
        ]

        # Add attack type counts (top 10)
        attack_types = ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION',
                       'PATH_TRAVERSAL', 'BRUTE_FORCE', 'XXE', 'SSRF',
                       'FILE_INCLUSION', 'DESERIALIZATION', 'AUTHENTICATION_BYPASS']

        attack_counts = defaultdict(int)
        for event in profile.attack_events:
            attack_type_name = event.attack_type.value if hasattr(event.attack_type, 'value') else str(event.attack_type)
            attack_counts[attack_type_name] += 1

        for at in attack_types:
            features.append(attack_counts.get(at, 0))

        return np.array(features, dtype=np.float32)

    def _prepare_sequences(self, attack_sequences: List[List[Dict]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare sequences for LSTM training"""
        X, y = [], []

        for sequence in attack_sequences:
            if len(sequence) < self.sequence_length + 1:
                continue

            for i in range(len(sequence) - self.sequence_length):
                seq = sequence[i:i + self.sequence_length]
                target = sequence[i + self.sequence_length]

                # Extract features from each event
                features = [self._extract_event_features(event) for event in seq]
                X.append(features)

                # Target is attack type
                y.append(self._attack_type_to_int(target.get('attack_type', 'UNKNOWN')))

        return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)

    def _prepare_single_sequence(self, attacks: List[Dict]) -> Optional[np.ndarray]:
        """Prepare single sequence for prediction"""
        if len(attacks) < self.sequence_length:
            return None

        sequence = attacks[-self.sequence_length:]
        features = [self._extract_event_features(event) for event in sequence]

        return np.array([features], dtype=np.float32)

    def _extract_event_features(self, event: Dict) -> List[float]:
        """Extract features from single attack event"""
        return [
            event.get('severity', 0),
            len(event.get('payload', '')),
            event.get('timestamp', datetime.now()).hour,
            self._attack_type_to_int(event.get('attack_type', 'UNKNOWN'))
        ]

    def _attack_type_to_int(self, attack_type: str) -> int:
        """Convert attack type to integer"""
        types = {
            "SQL_INJECTION": 0, "XSS": 1, "COMMAND_INJECTION": 2,
            "PATH_TRAVERSAL": 3, "BRUTE_FORCE": 4, "XXE": 5,
            "SSRF": 6, "FILE_INCLUSION": 7, "DESERIALIZATION": 8,
            "AUTHENTICATION_BYPASS": 9
        }
        return types.get(attack_type, 0)

    def _load_models(self):
        """Load existing models"""
        try:
            # Custom objects for model loading (fix for 'mse' function issue)
            custom_objects = {
                'mse': keras.losses.MeanSquaredError(),
                'mean_squared_error': keras.losses.MeanSquaredError()
            }

            if TENSORFLOW_AVAILABLE and (self.model_dir / 'lstm_model.keras').exists():
                self.lstm_model = keras.models.load_model(
                    str(self.model_dir / 'lstm_model.keras'),
                    custom_objects=custom_objects
                )

            if TENSORFLOW_AVAILABLE and (self.model_dir / 'autoencoder.keras').exists():
                self.autoencoder = keras.models.load_model(
                    str(self.model_dir / 'autoencoder.keras'),
                    custom_objects=custom_objects
                )

            if XGBOOST_AVAILABLE and (self.model_dir / 'xgboost_model.json').exists():
                self.xgboost_model = xgb.XGBClassifier()
                self.xgboost_model.load_model(str(self.model_dir / 'xgboost_model.json'))
        except Exception as e:
            print(f"Warning: Could not load models: {e}")
