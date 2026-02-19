"""
ML Model Persistence Module
Handles saving, loading, versioning, and management of ML models

Features:
- Model serialization (pickle, joblib, TensorFlow SavedModel)
- Version control with metadata
- Model registry with lineage tracking
- Automatic backup and rollback
- Compression for storage optimization
- Integrity verification with checksums
"""

import pickle
import joblib
import json
import hashlib
import gzip
import shutil
import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# Suppress TensorFlow verbose messages BEFORE import
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # 0=all, 1=info, 2=warning, 3=error
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'  # Disable oneDNN messages

try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

try:
    import torch
    PYTORCH_AVAILABLE = True
except ImportError:
    PYTORCH_AVAILABLE = False


class ModelFormat(Enum):
    """Supported model serialization formats"""
    PICKLE = "pickle"
    JOBLIB = "joblib"
    TENSORFLOW = "tensorflow"
    PYTORCH = "pytorch"
    ONNX = "onnx"


class ModelStatus(Enum):
    """Model lifecycle status"""
    TRAINING = "training"
    VALIDATED = "validated"
    DEPLOYED = "deployed"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"


@dataclass
class ModelMetadata:
    """Comprehensive model metadata"""
    model_id: str
    model_name: str
    version: str
    model_type: str  # e.g., "IsolationForest", "LSTM", "XGBoost"
    format: str
    created_at: datetime
    created_by: str
    file_path: str
    file_size_bytes: int
    checksum: str
    status: str

    # Training metadata
    training_dataset_size: Optional[int] = None
    training_duration_seconds: Optional[float] = None
    hyperparameters: Optional[Dict[str, Any]] = None

    # Performance metrics
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    roc_auc: Optional[float] = None
    custom_metrics: Optional[Dict[str, float]] = None

    # Deployment metadata
    deployed_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    prediction_count: int = 0

    # Lineage
    parent_version: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with datetime serialization"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        if self.deployed_at:
            data['deployed_at'] = self.deployed_at.isoformat()
        if self.last_used:
            data['last_used'] = self.last_used.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModelMetadata':
        """Create from dictionary with datetime deserialization"""
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        if data.get('deployed_at'):
            data['deployed_at'] = datetime.fromisoformat(data['deployed_at'])
        if data.get('last_used'):
            data['last_used'] = datetime.fromisoformat(data['last_used'])
        return cls(**data)


class MLModelPersistence:
    """
    Comprehensive ML model persistence manager

    Features:
    - Multi-format model serialization
    - Version control and lineage tracking
    - Automatic compression
    - Integrity verification
    - Model registry
    - Backup and rollback
    """

    def __init__(self, base_path: str = "models", compress: bool = True):
        """
        Initialize model persistence manager

        Args:
            base_path: Base directory for model storage
            compress: Enable gzip compression for models
        """
        self.base_path = Path(base_path)
        self.compress = compress
        self.logger = logging.getLogger(__name__)

        # Create directory structure
        self.models_dir = self.base_path / "models"
        self.metadata_dir = self.base_path / "metadata"
        self.backups_dir = self.base_path / "backups"
        self.registry_file = self.metadata_dir / "registry.json"

        for directory in [self.models_dir, self.metadata_dir, self.backups_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        # Load or create registry
        self.registry = self._load_registry()

    def save_model(
        self,
        model: Any,
        model_name: str,
        version: str,
        model_type: str,
        format: ModelFormat = ModelFormat.JOBLIB,
        metadata: Optional[Dict[str, Any]] = None,
        overwrite: bool = False
    ) -> ModelMetadata:
        """
        Save model with metadata

        Args:
            model: Model object to save
            model_name: Name of the model
            version: Version identifier (e.g., "1.0.0", "2024-01-10")
            model_type: Type of model (e.g., "IsolationForest")
            format: Serialization format
            metadata: Additional metadata
            overwrite: Allow overwriting existing version

        Returns:
            ModelMetadata object
        """
        model_id = f"{model_name}_{version}"

        # Check if version exists
        if model_id in self.registry and not overwrite:
            raise ValueError(f"Model version {model_id} already exists. Use overwrite=True to replace.")

        # Determine file extension
        ext = self._get_file_extension(format)
        filename = f"{model_id}{ext}"
        if self.compress and format != ModelFormat.TENSORFLOW:
            filename += ".gz"

        model_path = self.models_dir / filename

        start_time = datetime.now()

        # Save model based on format
        try:
            if format == ModelFormat.PICKLE:
                self._save_pickle(model, model_path)
            elif format == ModelFormat.JOBLIB:
                self._save_joblib(model, model_path)
            elif format == ModelFormat.TENSORFLOW:
                self._save_tensorflow(model, model_path)
            elif format == ModelFormat.PYTORCH:
                self._save_pytorch(model, model_path)
            else:
                raise ValueError(f"Unsupported format: {format}")
        except Exception as e:
            self.logger.error(f"Failed to save model {model_id}: {e}")
            if model_path.exists():
                model_path.unlink()
            raise

        duration = (datetime.now() - start_time).total_seconds()

        # Calculate checksum
        checksum = self._calculate_checksum(model_path)

        # Get file size
        file_size = model_path.stat().st_size

        # Create metadata - merge user metadata with defaults
        metadata_dict = metadata or {}

        # Set defaults that shouldn't be overwritten
        final_metadata = {
            'model_id': model_id,
            'model_name': model_name,
            'version': version,
            'model_type': model_type,
            'format': format.value,
            'created_at': datetime.now(),
            'created_by': "system",
            'file_path': str(model_path),
            'file_size_bytes': file_size,
            'checksum': checksum,
            'status': ModelStatus.VALIDATED.value,
        }

        # Add training duration if not provided by user
        if 'training_duration_seconds' not in metadata_dict:
            final_metadata['training_duration_seconds'] = duration

        # Merge user metadata
        final_metadata.update(metadata_dict)

        # Create metadata object
        model_metadata = ModelMetadata(**final_metadata)

        # Save metadata
        self._save_metadata(model_metadata)

        # Update registry
        self.registry[model_id] = model_metadata
        self._save_registry()

        self.logger.info(f"Model saved: {model_id} ({file_size / 1024:.2f} KB)")

        return model_metadata

    def load_model(
        self,
        model_name: str,
        version: Optional[str] = None,
        verify_checksum: bool = True
    ) -> Tuple[Any, ModelMetadata]:
        """
        Load model with metadata

        Args:
            model_name: Name of the model
            version: Specific version to load (None = latest)
            verify_checksum: Verify file integrity

        Returns:
            Tuple of (model, metadata)
        """
        # Get model metadata
        if version:
            model_id = f"{model_name}_{version}"
        else:
            # Get latest version
            model_id = self._get_latest_version(model_name)
            if not model_id:
                raise ValueError(f"No models found for {model_name}")

        if model_id not in self.registry:
            raise ValueError(f"Model {model_id} not found in registry")

        metadata = self.registry[model_id]
        model_path = Path(metadata.file_path)

        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        # Verify checksum
        if verify_checksum:
            current_checksum = self._calculate_checksum(model_path)
            if current_checksum != metadata.checksum:
                raise ValueError(f"Checksum mismatch for {model_id}. File may be corrupted.")

        # Load model based on format
        try:
            format_enum = ModelFormat(metadata.format)

            if format_enum == ModelFormat.PICKLE:
                model = self._load_pickle(model_path)
            elif format_enum == ModelFormat.JOBLIB:
                model = self._load_joblib(model_path)
            elif format_enum == ModelFormat.TENSORFLOW:
                model = self._load_tensorflow(model_path)
            elif format_enum == ModelFormat.PYTORCH:
                model = self._load_pytorch(model_path)
            else:
                raise ValueError(f"Unsupported format: {format_enum}")

            # Update usage statistics
            metadata.last_used = datetime.now()
            metadata.prediction_count += 1
            self._save_metadata(metadata)
            self._save_registry()

            self.logger.info(f"Model loaded: {model_id}")

            return model, metadata

        except Exception as e:
            self.logger.error(f"Failed to load model {model_id}: {e}")
            raise

    def list_models(
        self,
        model_name: Optional[str] = None,
        status: Optional[ModelStatus] = None
    ) -> List[ModelMetadata]:
        """
        List models in registry

        Args:
            model_name: Filter by model name
            status: Filter by status

        Returns:
            List of ModelMetadata objects
        """
        models = list(self.registry.values())

        if model_name:
            models = [m for m in models if m.model_name == model_name]

        if status:
            models = [m for m in models if m.status == status.value]

        # Sort by creation date (newest first)
        models.sort(key=lambda m: m.created_at, reverse=True)

        return models

    def delete_model(self, model_name: str, version: str, backup: bool = True) -> None:
        """
        Delete a model version

        Args:
            model_name: Name of the model
            version: Version to delete
            backup: Create backup before deletion
        """
        model_id = f"{model_name}_{version}"

        if model_id not in self.registry:
            raise ValueError(f"Model {model_id} not found")

        metadata = self.registry[model_id]
        model_path = Path(metadata.file_path)

        # Create backup
        if backup and model_path.exists():
            backup_path = self.backups_dir / f"{model_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(model_path, backup_path)
            self.logger.info(f"Backup created: {backup_path}")

        # Delete model file
        if model_path.exists():
            model_path.unlink()

        # Delete metadata file
        metadata_path = self.metadata_dir / f"{model_id}.json"
        if metadata_path.exists():
            metadata_path.unlink()

        # Remove from registry
        del self.registry[model_id]
        self._save_registry()

        self.logger.info(f"Model deleted: {model_id}")

    def update_metadata(self, model_name: str, version: str, updates: Dict[str, Any]) -> ModelMetadata:
        """Update model metadata"""
        model_id = f"{model_name}_{version}"

        if model_id not in self.registry:
            raise ValueError(f"Model {model_id} not found")

        metadata = self.registry[model_id]

        # Update allowed fields
        for key, value in updates.items():
            if hasattr(metadata, key):
                setattr(metadata, key, value)

        self._save_metadata(metadata)
        self._save_registry()

        return metadata

    def promote_to_production(self, model_name: str, version: str) -> ModelMetadata:
        """Promote model to production status"""
        updates = {
            'status': ModelStatus.DEPLOYED.value,
            'deployed_at': datetime.now()
        }
        return self.update_metadata(model_name, version, updates)

    def get_model_lineage(self, model_name: str, version: str) -> List[ModelMetadata]:
        """Get model version history"""
        lineage = []
        current_id = f"{model_name}_{version}"

        while current_id in self.registry:
            metadata = self.registry[current_id]
            lineage.append(metadata)

            if not metadata.parent_version:
                break

            current_id = f"{model_name}_{metadata.parent_version}"

        return lineage

    # Private helper methods

    def _get_file_extension(self, format: ModelFormat) -> str:
        """Get file extension for format"""
        extensions = {
            ModelFormat.PICKLE: ".pkl",
            ModelFormat.JOBLIB: ".joblib",
            ModelFormat.TENSORFLOW: "",  # SavedModel is a directory
            ModelFormat.PYTORCH: ".pt",
            ModelFormat.ONNX: ".onnx"
        }
        return extensions.get(format, ".dat")

    def _save_pickle(self, model: Any, path: Path) -> None:
        """Save model using pickle"""
        if self.compress:
            with gzip.open(path, 'wb') as f:
                pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)
        else:
            with open(path, 'wb') as f:
                pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)

    def _load_pickle(self, path: Path) -> Any:
        """Load model using pickle"""
        if str(path).endswith('.gz'):
            with gzip.open(path, 'rb') as f:
                return pickle.load(f)
        else:
            with open(path, 'rb') as f:
                return pickle.load(f)

    def _save_joblib(self, model: Any, path: Path) -> None:
        """Save model using joblib"""
        if self.compress:
            with gzip.open(path, 'wb') as f:
                joblib.dump(model, f, compress=3)
        else:
            joblib.dump(model, path, compress=3)

    def _load_joblib(self, path: Path) -> Any:
        """Load model using joblib"""
        if str(path).endswith('.gz'):
            with gzip.open(path, 'rb') as f:
                return joblib.load(f)
        else:
            return joblib.load(path)

    def _save_tensorflow(self, model: Any, path: Path) -> None:
        """Save TensorFlow model"""
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow not available")
        model.save(str(path))

    def _load_tensorflow(self, path: Path) -> Any:
        """Load TensorFlow model"""
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow not available")
        return tf.keras.models.load_model(str(path))

    def _save_pytorch(self, model: Any, path: Path) -> None:
        """Save PyTorch model"""
        if not PYTORCH_AVAILABLE:
            raise ImportError("PyTorch not available")

        if self.compress:
            with gzip.open(path, 'wb') as f:
                torch.save(model.state_dict(), f)
        else:
            torch.save(model.state_dict(), path)

    def _load_pytorch(self, path: Path) -> Any:
        """Load PyTorch model"""
        if not PYTORCH_AVAILABLE:
            raise ImportError("PyTorch not available")

        if str(path).endswith('.gz'):
            with gzip.open(path, 'rb') as f:
                return torch.load(f)
        else:
            return torch.load(path)

    def _calculate_checksum(self, path: Path) -> str:
        """Calculate SHA256 checksum of file"""
        sha256 = hashlib.sha256()

        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    def _save_metadata(self, metadata: ModelMetadata) -> None:
        """Save metadata to JSON file"""
        metadata_path = self.metadata_dir / f"{metadata.model_id}.json"

        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata.to_dict(), f, indent=2)

    def _load_registry(self) -> Dict[str, ModelMetadata]:
        """Load model registry"""
        if not self.registry_file.exists():
            return {}

        try:
            with open(self.registry_file, 'r', encoding='utf-8') as f:
                registry_data = json.load(f)

            registry = {}
            for model_id, metadata_dict in registry_data.items():
                registry[model_id] = ModelMetadata.from_dict(metadata_dict)

            return registry
        except Exception as e:
            self.logger.error(f"Failed to load registry: {e}")
            return {}

    def _save_registry(self) -> None:
        """Save model registry"""
        registry_data = {
            model_id: metadata.to_dict()
            for model_id, metadata in self.registry.items()
        }

        with open(self.registry_file, 'w', encoding='utf-8') as f:
            json.dump(registry_data, f, indent=2)

    def _get_latest_version(self, model_name: str) -> Optional[str]:
        """Get latest version of a model"""
        versions = [
            (model_id, metadata.created_at)
            for model_id, metadata in self.registry.items()
            if metadata.model_name == model_name and metadata.status != ModelStatus.DEPRECATED.value
        ]

        if not versions:
            return None

        # Sort by creation date and return latest
        versions.sort(key=lambda x: x[1], reverse=True)
        return versions[0][0]
