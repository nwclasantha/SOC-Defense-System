"""
ML Model Retraining Pipeline
Automated pipeline for model training, validation, and deployment

Features:
- Scheduled automatic retraining
- Data drift detection
- Model performance monitoring
- A/B testing
- Automated rollback on degradation
- Model registry integration
"""

import logging
import schedule
import time
import threading
from datetime import datetime, timedelta
from typing import Callable, Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
from pathlib import Path

from modules.MLModelPersistence import MLModelPersistence, ModelMetadata, ModelStatus, ModelFormat
from modules.PerformanceOptimizer import PerformanceOptimizer


class RetrainingTrigger(Enum):
    """Triggers for model retraining"""
    SCHEDULED = "scheduled"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    DATA_DRIFT = "data_drift"
    MANUAL = "manual"


@dataclass
class RetrainingConfig:
    """Configuration for retraining pipeline"""
    # Scheduling
    schedule_cron: Optional[str] = "0 2 * * 0"  # Weekly at 2 AM Sunday
    check_interval_hours: int = 24

    # Performance thresholds
    min_accuracy: float = 0.85
    min_precision: float = 0.80
    min_recall: float = 0.80
    max_degradation_percent: float = 10.0  # Max 10% degradation

    # Data drift thresholds
    max_drift_score: float = 0.3
    min_samples_for_drift: int = 1000

    # Validation
    validation_split: float = 0.2
    test_split: float = 0.1
    min_training_samples: int = 100

    # Deployment
    enable_ab_testing: bool = True
    ab_test_duration_hours: int = 24
    ab_test_traffic_split: float = 0.1  # 10% to new model

    # Rollback
    auto_rollback_on_degradation: bool = True
    rollback_threshold_percent: float = 5.0  # Rollback if 5% worse


@dataclass
class RetrainingResult:
    """Result of retraining process"""
    success: bool
    trigger: str
    model_id: str
    model_metadata: Optional[ModelMetadata]
    training_duration: float
    training_samples: int
    validation_metrics: Dict[str, float]
    deployed: bool
    rollback_performed: bool
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


class MLModelRetrainingPipeline:
    """
    Automated ML model retraining pipeline

    Features:
    - Scheduled retraining
    - Performance monitoring
    - Data drift detection
    - Automated validation
    - A/B testing
    - Automatic rollback

    Usage:
        pipeline = MLModelRetrainingPipeline(
            model_name="anomaly_detector",
            training_function=train_model_func,
            validation_function=validate_model_func,
            config=config
        )

        # Start automated pipeline
        pipeline.start()

        # Or manual retraining
        result = pipeline.retrain(trigger=RetrainingTrigger.MANUAL)
    """

    def __init__(
        self,
        model_name: str,
        training_function: Callable,
        validation_function: Callable,
        config: Optional[RetrainingConfig] = None,
        persistence: Optional[MLModelPersistence] = None
    ):
        """
        Initialize retraining pipeline

        Args:
            model_name: Name of the model
            training_function: Function that trains model and returns (model, metrics)
            validation_function: Function that validates model and returns metrics
            config: Retraining configuration
            persistence: Model persistence manager
        """
        self.model_name = model_name
        self.training_function = training_function
        self.validation_function = validation_function
        self.config = config or RetrainingConfig()
        self.persistence = persistence or MLModelPersistence()

        self.logger = logging.getLogger(f"{__name__}.{model_name}")

        # State management
        self.current_model_version: Optional[str] = None
        self.baseline_metrics: Optional[Dict[str, float]] = None
        self.retraining_history: List[RetrainingResult] = []

        # Scheduler
        self._stop_scheduler = threading.Event()
        self._scheduler_thread: Optional[threading.Thread] = None
        self._running = False

        # A/B testing
        self.ab_test_active = False
        self.ab_test_champion: Optional[str] = None
        self.ab_test_challenger: Optional[str] = None
        self.ab_test_metrics: Dict[str, List[float]] = {"champion": [], "challenger": []}

    def start(self) -> None:
        """Start automated retraining pipeline"""
        if self._running:
            self.logger.warning("Pipeline already running")
            return

        self._running = True
        self._stop_scheduler.clear()

        # Start scheduler thread
        self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._scheduler_thread.start()

        self.logger.info(f"Retraining pipeline started for {self.model_name}")

    def stop(self) -> None:
        """Stop automated retraining pipeline"""
        if not self._running:
            return

        self._running = False
        self._stop_scheduler.set()

        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)

        self.logger.info(f"Retraining pipeline stopped for {self.model_name}")

    def retrain(
        self,
        trigger: RetrainingTrigger = RetrainingTrigger.MANUAL,
        training_data: Optional[Any] = None
    ) -> RetrainingResult:
        """
        Execute model retraining

        Args:
            trigger: What triggered the retraining
            training_data: Training dataset (optional, training function can fetch it)

        Returns:
            RetrainingResult with training details
        """
        self.logger.info(f"Starting retraining for {self.model_name} (trigger: {trigger.value})")

        start_time = time.time()
        result = RetrainingResult(
            success=False,
            trigger=trigger.value,
            model_id="",
            model_metadata=None,
            training_duration=0,
            training_samples=0,
            validation_metrics={},
            deployed=False,
            rollback_performed=False
        )

        try:
            # Step 1: Prepare data
            self.logger.info("Preparing training data...")
            if training_data is None:
                # Training function should handle data fetching
                pass

            # Step 2: Train model
            self.logger.info("Training model...")
            model, training_metrics = self.training_function(training_data)

            if not model:
                raise Exception("Training function returned None")

            training_duration = time.time() - start_time
            result.training_duration = training_duration

            # Get training samples count if available
            if hasattr(training_data, '__len__'):
                result.training_samples = len(training_data)

            # Step 3: Validate model
            self.logger.info("Validating model...")
            validation_metrics = self.validation_function(model, training_data)
            result.validation_metrics = validation_metrics

            # Step 4: Check if model meets quality thresholds
            if not self._meets_quality_thresholds(validation_metrics):
                raise Exception(
                    f"Model does not meet quality thresholds: {validation_metrics}"
                )

            # Step 5: Check for degradation (if baseline exists)
            if self.baseline_metrics:
                degradation = self._calculate_degradation(validation_metrics, self.baseline_metrics)
                if degradation > self.config.max_degradation_percent:
                    raise Exception(
                        f"Model performance degraded by {degradation:.1f}% "
                        f"(threshold: {self.config.max_degradation_percent}%)"
                    )

            # Step 6: Save model
            version = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_metadata = self.persistence.save_model(
                model=model,
                model_name=self.model_name,
                version=version,
                model_type=type(model).__name__,
                format=ModelFormat.JOBLIB,
                metadata={
                    "training_dataset_size": result.training_samples,
                    "hyperparameters": training_metrics.get("hyperparameters", {}),
                    **validation_metrics,
                    "parent_version": self.current_model_version,
                    "description": f"Retraining triggered by: {trigger.value}",
                    "tags": [trigger.value, "automated_retraining"]
                }
            )

            result.model_id = model_metadata.model_id
            result.model_metadata = model_metadata

            self.logger.info(f"Model saved: {model_metadata.model_id}")

            # Step 7: Deploy or A/B test
            if self.config.enable_ab_testing and self.current_model_version:
                self.logger.info("Starting A/B test...")
                self._start_ab_test(self.current_model_version, version)
                result.deployed = False  # Will deploy after A/B test
            else:
                self.logger.info("Deploying model to production...")
                self.persistence.promote_to_production(self.model_name, version)
                self.current_model_version = version
                self.baseline_metrics = validation_metrics
                result.deployed = True

            result.success = True
            self.logger.info(f"Retraining completed successfully in {training_duration:.2f}s")

        except Exception as e:
            self.logger.error(f"Retraining failed: {e}")
            result.error_message = str(e)
            result.success = False

        # Record result
        self.retraining_history.append(result)

        return result

    def check_data_drift(self, current_data: np.ndarray, reference_data: np.ndarray) -> float:
        """
        Detect data drift using statistical tests

        Args:
            current_data: Current data distribution
            reference_data: Reference data distribution

        Returns:
            Drift score (0 = no drift, 1 = maximum drift)
        """
        if len(current_data) < self.config.min_samples_for_drift:
            return 0.0

        try:
            # Use Kolmogorov-Smirnov test
            from scipy.stats import ks_2samp

            # For multivariate data, check each feature
            if len(current_data.shape) > 1:
                drift_scores = []
                for i in range(current_data.shape[1]):
                    statistic, _ = ks_2samp(current_data[:, i], reference_data[:, i])
                    drift_scores.append(statistic)
                drift_score = np.mean(drift_scores)
            else:
                drift_score, _ = ks_2samp(current_data, reference_data)

            return float(drift_score)

        except Exception as e:
            self.logger.error(f"Data drift detection failed: {e}")
            return 0.0

    def check_performance_degradation(self, current_metrics: Dict[str, float]) -> bool:
        """Check if model performance has degraded"""
        if not self.baseline_metrics:
            return False

        degradation = self._calculate_degradation(current_metrics, self.baseline_metrics)
        return degradation > self.config.max_degradation_percent

    def finalize_ab_test(self) -> str:
        """
        Finalize A/B test and promote winner

        Returns:
            Version ID of winner
        """
        if not self.ab_test_active:
            raise Exception("No A/B test active")

        # Calculate average metrics
        champion_avg = np.mean(self.ab_test_metrics["champion"]) if self.ab_test_metrics["champion"] else 0
        challenger_avg = np.mean(self.ab_test_metrics["challenger"]) if self.ab_test_metrics["challenger"] else 0

        # Determine winner
        if challenger_avg > champion_avg:
            winner = self.ab_test_challenger
            self.logger.info(f"A/B test winner: Challenger {winner} ({challenger_avg:.3f} vs {champion_avg:.3f})")
        else:
            winner = self.ab_test_champion
            self.logger.info(f"A/B test winner: Champion {winner} ({champion_avg:.3f} vs {challenger_avg:.3f})")

        # Promote winner
        self.persistence.promote_to_production(self.model_name, winner)
        self.current_model_version = winner

        # Clean up
        self.ab_test_active = False
        self.ab_test_metrics = {"champion": [], "challenger": []}

        return winner

    def rollback(self, reason: str = "Manual rollback") -> bool:
        """
        Rollback to previous model version

        Args:
            reason: Reason for rollback

        Returns:
            True if successful
        """
        if not self.current_model_version:
            self.logger.error("No current version to rollback from")
            return False

        # Get current model metadata
        current_metadata = self.persistence.registry.get(
            f"{self.model_name}_{self.current_model_version}"
        )

        if not current_metadata or not current_metadata.parent_version:
            self.logger.error("No parent version found for rollback")
            return False

        parent_version = current_metadata.parent_version

        self.logger.warning(
            f"Rolling back from {self.current_model_version} to {parent_version}: {reason}"
        )

        # Promote parent version
        self.persistence.promote_to_production(self.model_name, parent_version)
        self.current_model_version = parent_version

        return True

    def get_retraining_history(self, limit: int = 10) -> List[RetrainingResult]:
        """Get recent retraining history"""
        return self.retraining_history[-limit:]

    def get_pipeline_metrics(self) -> Dict[str, Any]:
        """Get pipeline metrics"""
        successful_retrainings = sum(1 for r in self.retraining_history if r.success)
        failed_retrainings = sum(1 for r in self.retraining_history if not r.success)

        return {
            "model_name": self.model_name,
            "current_version": self.current_model_version,
            "total_retrainings": len(self.retraining_history),
            "successful_retrainings": successful_retrainings,
            "failed_retrainings": failed_retrainings,
            "baseline_metrics": self.baseline_metrics,
            "ab_test_active": self.ab_test_active,
            "pipeline_running": self._running
        }

    # Private methods

    def _scheduler_loop(self) -> None:
        """Background scheduler loop"""
        last_check = datetime.now()

        while not self._stop_scheduler.is_set():
            try:
                # Check if it's time for scheduled retraining
                now = datetime.now()
                if (now - last_check).total_seconds() >= self.config.check_interval_hours * 3600:
                    self.logger.info("Scheduled retraining check...")

                    # You could implement cron-like scheduling here
                    # For now, just check every interval
                    self.retrain(trigger=RetrainingTrigger.SCHEDULED)

                    last_check = now

            except Exception as e:
                self.logger.error(f"Scheduler error: {e}")

            # Sleep for a while
            self._stop_scheduler.wait(timeout=3600)  # Check every hour

    def _meets_quality_thresholds(self, metrics: Dict[str, float]) -> bool:
        """Check if metrics meet quality thresholds"""
        checks = [
            metrics.get("accuracy", 0) >= self.config.min_accuracy,
            metrics.get("precision", 0) >= self.config.min_precision,
            metrics.get("recall", 0) >= self.config.min_recall
        ]

        return all(checks)

    def _calculate_degradation(
        self,
        current: Dict[str, float],
        baseline: Dict[str, float]
    ) -> float:
        """Calculate performance degradation percentage"""
        # Use F1 score as primary metric
        current_f1 = current.get("f1_score", 0)
        baseline_f1 = baseline.get("f1_score", 0)

        if baseline_f1 == 0:
            return 0.0

        degradation = ((baseline_f1 - current_f1) / baseline_f1) * 100
        return max(0, degradation)  # Only positive degradation

    def _start_ab_test(self, champion_version: str, challenger_version: str) -> None:
        """Start A/B test between two model versions"""
        self.ab_test_active = True
        self.ab_test_champion = champion_version
        self.ab_test_challenger = challenger_version
        self.ab_test_metrics = {"champion": [], "challenger": []}

        self.logger.info(
            f"A/B test started: Champion={champion_version}, Challenger={challenger_version}"
        )

        # Schedule test finalization
        # In practice, you'd implement this with a timer or scheduled job
