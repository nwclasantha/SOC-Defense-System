"""
Advanced Unsupervised ML Detector
=================================
State-of-the-art unsupervised anomaly detection using:
1. Variational Autoencoder (VAE) - Probabilistic anomaly detection
2. Deep SVDD - Hypersphere-based one-class classification

These models excel at detecting:
- Zero-day attacks (never seen before)
- Obfuscated/encoded attack payloads
- Novel attack patterns
- APT-style sophisticated attacks

Author: SOC Defense System
Version: 2.0.0
"""

import numpy as np
import pickle
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict

# Check for PyTorch
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

# Check for sklearn
try:
    from sklearn.preprocessing import StandardScaler, RobustScaler
    from sklearn.decomposition import PCA
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# =============================================================================
# VARIATIONAL AUTOENCODER (VAE)
# =============================================================================

class VAEEncoder(nn.Module):
    """VAE Encoder - Maps input to latent distribution parameters"""

    def __init__(self, input_dim: int, hidden_dims: List[int], latent_dim: int):
        super().__init__()

        # Build encoder layers
        layers = []
        prev_dim = input_dim
        for h_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.LeakyReLU(0.2),
                nn.Dropout(0.2)
            ])
            prev_dim = h_dim

        self.encoder = nn.Sequential(*layers)

        # Latent space parameters (mean and log-variance)
        self.fc_mu = nn.Linear(hidden_dims[-1], latent_dim)
        self.fc_logvar = nn.Linear(hidden_dims[-1], latent_dim)

    def forward(self, x):
        h = self.encoder(x)
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        return mu, logvar


class VAEDecoder(nn.Module):
    """VAE Decoder - Reconstructs input from latent space"""

    def __init__(self, latent_dim: int, hidden_dims: List[int], output_dim: int):
        super().__init__()

        # Build decoder layers (reverse of encoder)
        layers = []
        prev_dim = latent_dim
        for h_dim in reversed(hidden_dims):
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.LeakyReLU(0.2),
                nn.Dropout(0.2)
            ])
            prev_dim = h_dim

        # Output layer
        layers.append(nn.Linear(hidden_dims[0], output_dim))

        self.decoder = nn.Sequential(*layers)

    def forward(self, z):
        return self.decoder(z)


class VariationalAutoencoder(nn.Module):
    """
    Variational Autoencoder for Anomaly Detection

    VAE learns the probability distribution of normal traffic.
    Anomalies have HIGH reconstruction error + LOW likelihood.

    Key advantages:
    - Uncertainty quantification (knows when it's unsure)
    - Smooth latent space (better generalization)
    - Probabilistic anomaly scoring
    """

    def __init__(self, input_dim: int, hidden_dims: List[int] = None,
                 latent_dim: int = 16):
        super().__init__()

        if hidden_dims is None:
            hidden_dims = [128, 64, 32]

        self.input_dim = input_dim
        self.latent_dim = latent_dim

        self.encoder = VAEEncoder(input_dim, hidden_dims, latent_dim)
        self.decoder = VAEDecoder(latent_dim, hidden_dims, input_dim)

    def reparameterize(self, mu, logvar):
        """Reparameterization trick for backpropagation through sampling"""
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def forward(self, x):
        mu, logvar = self.encoder(x)
        z = self.reparameterize(mu, logvar)
        reconstruction = self.decoder(z)
        return reconstruction, mu, logvar

    def loss_function(self, x, reconstruction, mu, logvar, beta: float = 1.0):
        """
        VAE Loss = Reconstruction Loss + KL Divergence

        Args:
            x: Original input
            reconstruction: Reconstructed output
            mu: Latent mean
            logvar: Latent log-variance
            beta: Weight for KL divergence (beta-VAE)
        """
        # Reconstruction loss (MSE)
        recon_loss = nn.functional.mse_loss(reconstruction, x, reduction='sum')

        # KL Divergence: D_KL(q(z|x) || p(z))
        # Closed-form for Gaussian: -0.5 * sum(1 + log(sigma^2) - mu^2 - sigma^2)
        kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())

        return recon_loss + beta * kl_loss, recon_loss, kl_loss

    def get_anomaly_score(self, x):
        """
        Calculate anomaly score for input

        Higher score = more anomalous

        Score combines:
        1. Reconstruction error (how well can we reconstruct?)
        2. KL divergence (how far from normal distribution?)
        """
        self.eval()
        with torch.no_grad():
            reconstruction, mu, logvar = self.forward(x)

            # Reconstruction error per sample
            recon_error = torch.mean((x - reconstruction) ** 2, dim=1)

            # KL divergence per sample
            kl_div = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp(), dim=1)

            # Combined anomaly score (normalized)
            anomaly_score = recon_error + 0.1 * kl_div

        return anomaly_score.numpy()


# =============================================================================
# DEEP SVDD (Support Vector Data Description)
# =============================================================================

class DeepSVDDNetwork(nn.Module):
    """
    Deep SVDD Network - Maps inputs to hypersphere space

    The network learns to map normal data close to a center point.
    Anomalies are mapped far from the center.
    """

    def __init__(self, input_dim: int, hidden_dims: List[int] = None,
                 output_dim: int = 32):
        super().__init__()

        if hidden_dims is None:
            hidden_dims = [128, 64]

        # Build network layers
        layers = []
        prev_dim = input_dim

        for h_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
                nn.Dropout(0.1)
            ])
            prev_dim = h_dim

        # Output layer (no activation - we want unbounded output)
        layers.append(nn.Linear(hidden_dims[-1], output_dim))

        self.network = nn.Sequential(*layers)
        self.output_dim = output_dim

    def forward(self, x):
        return self.network(x)


class DeepSVDD:
    """
    Deep Support Vector Data Description

    State-of-the-art one-class classification using deep learning.

    Key idea:
    - Learn a neural network that maps normal data to a hypersphere
    - The center of the hypersphere represents "normal"
    - Distance from center = anomaly score

    Advantages over traditional SVDD:
    - Learns complex, non-linear mappings
    - Scales to high-dimensional data
    - Better generalization
    """

    def __init__(self, input_dim: int, hidden_dims: List[int] = None,
                 output_dim: int = 32, nu: float = 0.1):
        """
        Args:
            input_dim: Number of input features
            hidden_dims: Hidden layer dimensions
            output_dim: Output embedding dimension
            nu: Anomaly fraction (expected proportion of anomalies)
        """
        self.input_dim = input_dim
        self.output_dim = output_dim
        self.nu = nu

        self.network = DeepSVDDNetwork(input_dim, hidden_dims, output_dim)
        self.center = None  # Will be initialized during training
        self.radius = None  # Decision boundary radius

    def init_center(self, dataloader, eps: float = 0.1):
        """
        Initialize hypersphere center as mean of initial network outputs

        This is crucial for good performance - center should be in
        a "reasonable" location in the output space.
        """
        self.network.eval()
        n_samples = 0
        center = torch.zeros(self.output_dim)

        with torch.no_grad():
            for data in dataloader:
                if isinstance(data, (list, tuple)):
                    x = data[0]
                else:
                    x = data
                outputs = self.network(x)
                center += torch.sum(outputs, dim=0)
                n_samples += outputs.shape[0]

        center /= n_samples

        # Avoid center being too close to origin (can cause collapse)
        center[(abs(center) < eps) & (center < 0)] = -eps
        center[(abs(center) < eps) & (center >= 0)] = eps

        self.center = center
        return center

    def compute_loss(self, outputs):
        """
        Deep SVDD Loss: Mean squared distance to center

        We want to minimize the distance of normal points to the center.
        """
        dist = torch.sum((outputs - self.center) ** 2, dim=1)
        return torch.mean(dist)

    def get_anomaly_score(self, x):
        """
        Calculate anomaly score (distance to center)

        Higher score = further from center = more anomalous
        """
        self.network.eval()
        with torch.no_grad():
            outputs = self.network(x)
            # Squared distance to center
            scores = torch.sum((outputs - self.center) ** 2, dim=1)
        return scores.numpy()

    def compute_radius(self, dataloader, quantile: float = None):
        """
        Compute decision boundary radius

        Points beyond this radius are classified as anomalies.
        """
        if quantile is None:
            quantile = 1 - self.nu  # e.g., 0.95 if nu=0.05

        self.network.eval()
        all_scores = []

        with torch.no_grad():
            for data in dataloader:
                if isinstance(data, (list, tuple)):
                    x = data[0]
                else:
                    x = data
                scores = self.get_anomaly_score(x)
                all_scores.extend(scores)

        self.radius = np.quantile(all_scores, quantile)
        return self.radius


# =============================================================================
# ADVANCED UNSUPERVISED DETECTOR (Main Class)
# =============================================================================

class AdvancedUnsupervisedDetector:
    """
    Advanced Unsupervised Anomaly Detector

    Combines VAE + Deep SVDD for state-of-the-art detection of:
    - Zero-day attacks
    - Novel attack patterns
    - Obfuscated payloads
    - APT-style attacks

    Features:
    - Ensemble voting between VAE and Deep SVDD
    - Automatic threshold calibration
    - Uncertainty quantification
    - Self-improving with new data
    """

    def __init__(self, model_dir: str = "./models/advanced_unsupervised"):
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch is required for AdvancedUnsupervisedDetector. "
                            "Install with: pip install torch")

        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for AdvancedUnsupervisedDetector")

        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(self.__class__.__name__)

        # Models
        self.vae = None
        self.deep_svdd = None

        # Preprocessing
        self.scaler = RobustScaler()
        self.feature_names = []

        # Thresholds (calibrated during training)
        self.vae_threshold = None
        self.svdd_threshold = None

        # Training history
        self.training_history = []

        # Device (GPU if available)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.logger.info(f"Using device: {self.device}")

        # Load existing models
        self._load_models()

    def extract_features(self, attacker_profile) -> np.ndarray:
        """
        Extract comprehensive features for unsupervised learning

        Features designed to capture:
        - Attack behavior patterns
        - Temporal characteristics
        - Target diversity
        - Severity indicators
        - MITRE ATT&CK coverage
        """
        features = []

        # === BASIC METRICS ===
        features.append(float(attacker_profile.attack_count))
        features.append(float(attacker_profile.risk_score))
        features.append(float(len(attacker_profile.targeted_agents)))
        features.append(float(len(attacker_profile.attack_types)))
        features.append(float(len(attacker_profile.cve_exploits)))

        # === TEMPORAL FEATURES ===
        time_span = (attacker_profile.last_seen - attacker_profile.first_seen).total_seconds()
        features.append(time_span / 3600)  # Duration in hours
        features.append(attacker_profile.attack_count / max(time_span / 3600, 0.01))  # Velocity

        # === SEVERITY FEATURES ===
        severities = [e.rule_level for e in attacker_profile.attack_events
                     if hasattr(e, 'rule_level')]
        features.append(float(max(severities)) if severities else 0)
        features.append(float(np.mean(severities)) if severities else 0)
        features.append(float(np.std(severities)) if len(severities) > 1 else 0)
        features.append(float(sum(1 for s in severities if s >= 10)))  # Critical count
        features.append(float(sum(1 for s in severities if s >= 12)))  # Very critical

        # === MITRE ATT&CK FEATURES ===
        mitre_tactics = set()
        mitre_techniques = set()
        for event in attacker_profile.attack_events:
            if hasattr(event, 'mitre_attack') and event.mitre_attack:
                mitre_data = event.mitre_attack
                if isinstance(mitre_data, dict):
                    for tactic in mitre_data.get('tactics', []) + mitre_data.get('mitre_tactics', []):
                        if isinstance(tactic, dict):
                            mitre_tactics.add(tactic.get('name', '') or tactic.get('id', ''))
                        elif isinstance(tactic, str):
                            mitre_tactics.add(tactic)
                    for tech in mitre_data.get('techniques', []) + mitre_data.get('mitre_techniques', []):
                        if isinstance(tech, dict):
                            mitre_techniques.add(tech.get('id', '') or tech.get('name', ''))
                        elif isinstance(tech, str):
                            mitre_techniques.add(tech)

        features.append(float(len(mitre_tactics)))
        features.append(float(len(mitre_techniques)))

        # === ATTACK TYPE DIVERSITY ===
        attack_type_counts = defaultdict(int)
        for event in attacker_profile.attack_events:
            attack_type_name = event.attack_type.value if hasattr(event.attack_type, 'value') else str(event.attack_type)
            attack_type_counts[attack_type_name] += 1

        # Distribution entropy (higher = more diverse attacks)
        total = sum(attack_type_counts.values()) or 1
        probs = [c / total for c in attack_type_counts.values()]
        entropy = -sum(p * np.log(p + 1e-10) for p in probs if p > 0)
        features.append(entropy)

        # Specific attack type flags
        attack_types = ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION',
                       'PATH_TRAVERSAL', 'BRUTE_FORCE', 'LOG4J', 'SHELLSHOCK']
        for at in attack_types:
            features.append(float(attack_type_counts.get(at, 0)))

        # === PAYLOAD FEATURES ===
        payloads = [e.payload for e in attacker_profile.attack_events if e.payload]
        total_payload_len = sum(len(p) for p in payloads)
        features.append(float(total_payload_len))
        features.append(float(total_payload_len / max(len(payloads), 1)))  # Avg length

        # Special character density (indicates encoded/obfuscated attacks)
        special_chars = sum(1 for p in payloads for c in p
                          if c in ';<>|&$`\\{}[]()%')
        features.append(float(special_chars / max(total_payload_len, 1)))

        # === TEMPORAL PATTERNS ===
        hours = [e.timestamp.hour for e in attacker_profile.attack_events]
        if hours:
            hour_counts = [hours.count(h) for h in range(24)]
            features.append(float(np.std(hour_counts)))  # Temporal variance
            features.append(float(max(hour_counts)))  # Peak hour activity
            # Night activity (suspicious hours 0-6)
            night_attacks = sum(1 for h in hours if 0 <= h <= 6)
            features.append(float(night_attacks / len(hours)))
        else:
            features.extend([0.0, 0.0, 0.0])

        # === THREAT INTEL FEATURES (if available) ===
        ti = getattr(attacker_profile, 'threat_reputation', None) or {}
        features.append(float(ti.get('is_malicious', False)))

        abuse_data = ti.get('abuseipdb_data', {}) or {}
        features.append(float(abuse_data.get('abuse_confidence_score', 0) or 0))
        features.append(float(abuse_data.get('total_reports', 0) or 0))

        sans_data = ti.get('sans_isc_data', {}) or {}
        features.append(float(sans_data.get('attacks', 0) or 0))
        features.append(float(sans_data.get('threat_score', 0) or 0))

        # === GEO FEATURES ===
        geo = getattr(attacker_profile, 'geo_location', None) or {}
        # High-risk country indicator
        high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'SY']
        country_code = geo.get('country_code', '')
        features.append(float(country_code in high_risk_countries))

        return np.array(features, dtype=np.float32)

    def get_feature_names(self) -> List[str]:
        """Return list of feature names"""
        return [
            'attack_count', 'risk_score', 'targeted_agents', 'attack_types', 'cve_exploits',
            'duration_hours', 'attack_velocity',
            'max_severity', 'avg_severity', 'std_severity', 'critical_count', 'very_critical_count',
            'mitre_tactics', 'mitre_techniques',
            'attack_entropy',
            'sql_injection', 'xss', 'command_injection', 'path_traversal',
            'brute_force', 'log4j', 'shellshock',
            'total_payload_len', 'avg_payload_len', 'special_char_density',
            'temporal_variance', 'peak_hour_activity', 'night_attack_ratio',
            'ti_is_malicious', 'abuseipdb_score', 'abuseipdb_reports',
            'sans_attacks', 'sans_threat_score',
            'high_risk_country'
        ]

    def train(self, attacker_profiles: List, epochs: int = 100,
              batch_size: int = 32, learning_rate: float = 1e-3) -> Dict[str, Any]:
        """
        Train VAE and Deep SVDD on attacker profiles

        Args:
            attacker_profiles: List of AttackerProfile objects
            epochs: Training epochs
            batch_size: Batch size
            learning_rate: Learning rate

        Returns:
            Training metrics
        """
        if len(attacker_profiles) < 20:
            self.logger.warning(f"Need at least 20 profiles for training, got {len(attacker_profiles)}")
            return {'status': 'error', 'message': 'Insufficient training data'}

        self.logger.info(f"Training Advanced Unsupervised Detector on {len(attacker_profiles)} profiles")
        self.logger.info("=" * 60)

        # Extract features
        self.feature_names = self.get_feature_names()
        X = np.array([self.extract_features(p) for p in attacker_profiles])

        # Handle NaN/Inf values
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Convert to tensor
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)
        dataset = TensorDataset(X_tensor)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        input_dim = X_scaled.shape[1]

        # Initialize VAE
        self.logger.info("Training Variational Autoencoder (VAE)...")
        self.vae = VariationalAutoencoder(
            input_dim=input_dim,
            hidden_dims=[128, 64, 32],
            latent_dim=16
        ).to(self.device)

        vae_metrics = self._train_vae(dataloader, epochs, learning_rate)

        # Initialize Deep SVDD
        self.logger.info("Training Deep SVDD...")
        self.deep_svdd = DeepSVDD(
            input_dim=input_dim,
            hidden_dims=[128, 64],
            output_dim=32,
            nu=0.05  # Expect 5% anomalies
        )
        self.deep_svdd.network.to(self.device)

        svdd_metrics = self._train_deep_svdd(dataloader, epochs, learning_rate)

        # Calibrate thresholds
        self.logger.info("Calibrating anomaly thresholds...")
        self._calibrate_thresholds(X_tensor)

        # Save models
        self._save_models()

        # Training summary
        metrics = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'samples': len(attacker_profiles),
            'features': input_dim,
            'vae_final_loss': vae_metrics['final_loss'],
            'svdd_final_loss': svdd_metrics['final_loss'],
            'vae_threshold': float(self.vae_threshold),
            'svdd_threshold': float(self.svdd_threshold),
            'device': str(self.device)
        }

        self.training_history.append(metrics)
        self._save_training_history()

        self.logger.info("=" * 60)
        self.logger.info(f"Training complete!")
        self.logger.info(f"  VAE Loss: {vae_metrics['final_loss']:.4f}")
        self.logger.info(f"  SVDD Loss: {svdd_metrics['final_loss']:.4f}")
        self.logger.info(f"  VAE Threshold: {self.vae_threshold:.4f}")
        self.logger.info(f"  SVDD Threshold: {self.svdd_threshold:.4f}")
        self.logger.info("=" * 60)

        return metrics

    def _train_vae(self, dataloader, epochs: int, lr: float) -> Dict:
        """Train VAE model"""
        optimizer = optim.Adam(self.vae.parameters(), lr=lr)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10, factor=0.5)

        self.vae.train()
        losses = []

        for epoch in range(epochs):
            epoch_loss = 0
            for batch in dataloader:
                x = batch[0].to(self.device)

                optimizer.zero_grad()
                reconstruction, mu, logvar = self.vae(x)
                loss, recon_loss, kl_loss = self.vae.loss_function(
                    x, reconstruction, mu, logvar, beta=0.5
                )
                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()

            avg_loss = epoch_loss / len(dataloader)
            losses.append(avg_loss)
            scheduler.step(avg_loss)

            if (epoch + 1) % 20 == 0:
                self.logger.info(f"  VAE Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")

        return {'final_loss': losses[-1], 'loss_history': losses}

    def _train_deep_svdd(self, dataloader, epochs: int, lr: float) -> Dict:
        """Train Deep SVDD model"""
        # Initialize center
        self.deep_svdd.init_center(dataloader)
        self.deep_svdd.center = self.deep_svdd.center.to(self.device)

        optimizer = optim.Adam(self.deep_svdd.network.parameters(), lr=lr, weight_decay=1e-6)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10, factor=0.5)

        self.deep_svdd.network.train()
        losses = []

        for epoch in range(epochs):
            epoch_loss = 0
            for batch in dataloader:
                x = batch[0].to(self.device)

                optimizer.zero_grad()
                outputs = self.deep_svdd.network(x)
                loss = self.deep_svdd.compute_loss(outputs)
                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()

            avg_loss = epoch_loss / len(dataloader)
            losses.append(avg_loss)
            scheduler.step(avg_loss)

            if (epoch + 1) % 20 == 0:
                self.logger.info(f"  SVDD Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")

        # Compute decision boundary radius
        self.deep_svdd.compute_radius(dataloader, quantile=0.95)

        return {'final_loss': losses[-1], 'loss_history': losses}

    def _calibrate_thresholds(self, X_tensor):
        """Calibrate anomaly thresholds based on training data"""
        # Get scores for training data
        vae_scores = self.vae.get_anomaly_score(X_tensor.cpu())

        self.deep_svdd.network.eval()
        with torch.no_grad():
            svdd_scores = self.deep_svdd.get_anomaly_score(X_tensor.cpu())

        # Set thresholds at 95th percentile (top 5% are anomalies)
        self.vae_threshold = np.percentile(vae_scores, 95)
        self.svdd_threshold = np.percentile(svdd_scores, 95)

    def detect(self, attacker_profile) -> Dict[str, Any]:
        """
        Detect if attacker profile is anomalous

        Uses ensemble of VAE + Deep SVDD for robust detection.

        Returns:
            Dict with anomaly verdict, scores, and explanation
        """
        if self.vae is None or self.deep_svdd is None:
            return {
                'is_anomaly': False,
                'error': 'Models not trained',
                'confidence': 0.0
            }

        # Extract and preprocess features
        features = self.extract_features(attacker_profile)
        features = np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=-1e6)
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        X_tensor = torch.FloatTensor(features_scaled).to(self.device)

        # Get VAE anomaly score
        self.vae.eval()
        vae_score = float(self.vae.get_anomaly_score(X_tensor.cpu())[0])
        vae_anomaly = vae_score > self.vae_threshold
        vae_confidence = min(vae_score / (self.vae_threshold * 2), 1.0)

        # Get Deep SVDD anomaly score
        self.deep_svdd.network.eval()
        svdd_score = float(self.deep_svdd.get_anomaly_score(X_tensor.cpu())[0])
        svdd_anomaly = svdd_score > self.svdd_threshold
        svdd_confidence = min(svdd_score / (self.svdd_threshold * 2), 1.0)

        # Ensemble decision (require BOTH to agree for high precision)
        # Or very high score on one model
        strong_vae = vae_score > self.vae_threshold * 1.5
        strong_svdd = svdd_score > self.svdd_threshold * 1.5

        is_anomaly = (vae_anomaly and svdd_anomaly) or strong_vae or strong_svdd

        # Combined confidence
        ensemble_confidence = (vae_confidence + svdd_confidence) / 2

        # Determine severity
        if vae_score > self.vae_threshold * 2 or svdd_score > self.svdd_threshold * 2:
            severity = 'critical'
        elif vae_score > self.vae_threshold * 1.5 or svdd_score > self.svdd_threshold * 1.5:
            severity = 'high'
        elif is_anomaly:
            severity = 'medium'
        else:
            severity = 'low'

        # Generate explanation
        explanation = self._generate_explanation(
            attacker_profile, features, vae_score, svdd_score, is_anomaly
        )

        return {
            'is_anomaly': is_anomaly,
            'severity': severity,
            'confidence': float(ensemble_confidence),
            'vae_score': vae_score,
            'vae_threshold': float(self.vae_threshold),
            'vae_anomaly': vae_anomaly,
            'svdd_score': svdd_score,
            'svdd_threshold': float(self.svdd_threshold),
            'svdd_anomaly': svdd_anomaly,
            'ensemble_vote': f"VAE={'ANOMALY' if vae_anomaly else 'NORMAL'}, SVDD={'ANOMALY' if svdd_anomaly else 'NORMAL'}",
            'explanation': explanation,
            'detection_method': 'Advanced Unsupervised (VAE + Deep SVDD)'
        }

    def detect_batch(self, attacker_profiles: List) -> List[Dict[str, Any]]:
        """Detect anomalies for multiple profiles"""
        return [self.detect(p) for p in attacker_profiles]

    def _generate_explanation(self, profile, features, vae_score, svdd_score,
                             is_anomaly) -> str:
        """Generate human-readable explanation"""
        parts = []

        if is_anomaly:
            parts.append("**ANOMALY DETECTED** - Advanced unsupervised models flagged this IP")

            # Explain why
            reasons = []
            if profile.attack_count > 50:
                reasons.append(f"High attack count ({profile.attack_count})")
            if len(profile.attack_types) > 3:
                reasons.append(f"Diverse attack types ({len(profile.attack_types)})")
            if profile.risk_score > 70:
                reasons.append(f"High risk score ({profile.risk_score:.1f})")
            if len(profile.cve_exploits) > 0:
                reasons.append(f"CVE exploitation ({len(profile.cve_exploits)} CVEs)")

            severities = [e.rule_level for e in profile.attack_events if hasattr(e, 'rule_level')]
            if severities and max(severities) >= 12:
                reasons.append(f"Critical severity alerts (max: {max(severities)})")

            if reasons:
                parts.append("\n**Key indicators:**")
                for r in reasons[:5]:
                    parts.append(f"  - {r}")

            parts.append(f"\n**Model scores:**")
            parts.append(f"  - VAE: {vae_score:.4f} (threshold: {self.vae_threshold:.4f})")
            parts.append(f"  - SVDD: {svdd_score:.4f} (threshold: {self.svdd_threshold:.4f})")
        else:
            parts.append("**NORMAL** - No anomalous patterns detected")
            parts.append(f"  - VAE score: {vae_score:.4f} (below threshold)")
            parts.append(f"  - SVDD score: {svdd_score:.4f} (below threshold)")

        return '\n'.join(parts)

    def _save_models(self):
        """Save trained models to disk"""
        try:
            # Save VAE
            if self.vae is not None:
                torch.save({
                    'model_state_dict': self.vae.state_dict(),
                    'input_dim': self.vae.input_dim,
                    'latent_dim': self.vae.latent_dim
                }, self.model_dir / 'vae_model.pt')

            # Save Deep SVDD
            if self.deep_svdd is not None:
                torch.save({
                    'model_state_dict': self.deep_svdd.network.state_dict(),
                    'center': self.deep_svdd.center,
                    'radius': self.deep_svdd.radius,
                    'input_dim': self.deep_svdd.input_dim,
                    'output_dim': self.deep_svdd.output_dim
                }, self.model_dir / 'deep_svdd_model.pt')

            # Save scaler and thresholds
            with open(self.model_dir / 'preprocessing.pkl', 'wb') as f:
                pickle.dump({
                    'scaler': self.scaler,
                    'vae_threshold': self.vae_threshold,
                    'svdd_threshold': self.svdd_threshold,
                    'feature_names': self.feature_names
                }, f)

            self.logger.info(f"Models saved to {self.model_dir}")

        except Exception as e:
            self.logger.error(f"Failed to save models: {e}")

    def _load_models(self):
        """Load trained models from disk"""
        try:
            # Load preprocessing
            preproc_path = self.model_dir / 'preprocessing.pkl'
            if preproc_path.exists():
                with open(preproc_path, 'rb') as f:
                    data = pickle.load(f)
                    self.scaler = data['scaler']
                    self.vae_threshold = data['vae_threshold']
                    self.svdd_threshold = data['svdd_threshold']
                    self.feature_names = data['feature_names']

            # Load VAE
            vae_path = self.model_dir / 'vae_model.pt'
            if vae_path.exists():
                checkpoint = torch.load(vae_path, map_location=self.device)
                self.vae = VariationalAutoencoder(
                    input_dim=checkpoint['input_dim'],
                    latent_dim=checkpoint['latent_dim']
                ).to(self.device)
                self.vae.load_state_dict(checkpoint['model_state_dict'])
                self.vae.eval()

            # Load Deep SVDD
            svdd_path = self.model_dir / 'deep_svdd_model.pt'
            if svdd_path.exists():
                checkpoint = torch.load(svdd_path, map_location=self.device)
                self.deep_svdd = DeepSVDD(
                    input_dim=checkpoint['input_dim'],
                    output_dim=checkpoint['output_dim']
                )
                self.deep_svdd.network.load_state_dict(checkpoint['model_state_dict'])
                self.deep_svdd.network.to(self.device)
                self.deep_svdd.center = checkpoint['center'].to(self.device)
                self.deep_svdd.radius = checkpoint['radius']
                self.deep_svdd.network.eval()

            if self.vae is not None and self.deep_svdd is not None:
                self.logger.info("Loaded existing VAE + Deep SVDD models")

        except Exception as e:
            self.logger.debug(f"No existing models found: {e}")

    def _save_training_history(self):
        """Save training history"""
        try:
            with open(self.model_dir / 'training_history.json', 'w') as f:
                json.dump(self.training_history, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save training history: {e}")

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about current models"""
        return {
            'vae_trained': self.vae is not None,
            'svdd_trained': self.deep_svdd is not None,
            'vae_threshold': self.vae_threshold,
            'svdd_threshold': self.svdd_threshold,
            'device': str(self.device),
            'training_runs': len(self.training_history),
            'latest_training': self.training_history[-1] if self.training_history else None
        }


# =============================================================================
# INTEGRATION HELPER
# =============================================================================

def create_advanced_detector(model_dir: str = "./models/advanced_unsupervised"):
    """Factory function to create AdvancedUnsupervisedDetector"""
    try:
        return AdvancedUnsupervisedDetector(model_dir)
    except ImportError as e:
        logging.warning(f"Could not create AdvancedUnsupervisedDetector: {e}")
        return None
