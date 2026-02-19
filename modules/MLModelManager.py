"""
ML Model Management with MLflow Integration
Handles model versioning, A/B testing, deployment, and retraining
"""

import json
import pickle
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
import hashlib
import shutil

try:
    import mlflow
    import mlflow.sklearn
    import mlflow.tensorflow
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False

class MLModelManager:
    """
    Comprehensive ML Model Management System
    - Model versioning and rollback
    - A/B testing framework
    - Model performance tracking
    - Automated retraining pipeline
    - Model deployment management
    """

    def __init__(self, experiment_name: str = "soc-defense", tracking_uri: str = "./mlruns"):
        self.experiment_name = experiment_name
        self.tracking_uri = tracking_uri
        self.model_registry = Path("./models/registry")
        self.model_registry.mkdir(parents=True, exist_ok=True)

        if MLFLOW_AVAILABLE:
            mlflow.set_tracking_uri(tracking_uri)
            mlflow.set_experiment(experiment_name)

        # Model versions database
        self.versions_db = self.model_registry / "versions.json"
        self.versions = self._load_versions()

        # A/B testing config
        self.ab_tests = {}

    def register_model(self,
                      model,
                      model_name: str,
                      model_type: str,
                      metrics: Dict[str, float],
                      parameters: Dict[str, Any] = None,
                      tags: Dict[str, str] = None) -> str:
        """
        Register a new model version with MLflow

        Args:
            model: Trained model object
            model_name: Name of the model
            model_type: Type (sklearn, tensorflow, xgboost, etc.)
            metrics: Model performance metrics
            parameters: Training parameters
            tags: Additional tags

        Returns:
            Model version ID
        """
        version_id = self._generate_version_id(model_name)

        if MLFLOW_AVAILABLE:
            with mlflow.start_run(run_name=f"{model_name}_v{version_id}"):
                # Log parameters
                if parameters:
                    mlflow.log_params(parameters)

                # Log metrics
                mlflow.log_metrics(metrics)

                # Log model
                if model_type == "sklearn":
                    mlflow.sklearn.log_model(model, model_name)
                elif model_type == "tensorflow":
                    mlflow.tensorflow.log_model(model, model_name)

                # Log tags
                if tags:
                    mlflow.set_tags(tags)

                run_id = mlflow.active_run().info.run_id
        else:
            # Fallback: Save locally
            run_id = version_id

        # Save model metadata
        model_info = {
            "version_id": version_id,
            "model_name": model_name,
            "model_type": model_type,
            "metrics": metrics,
            "parameters": parameters or {},
            "tags": tags or {},
            "created_at": datetime.utcnow().isoformat(),
            "run_id": run_id,
            "status": "registered"
        }

        # Save model locally
        model_path = self.model_registry / f"{model_name}_v{version_id}.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)

        # Update versions database
        if model_name not in self.versions:
            self.versions[model_name] = []

        self.versions[model_name].append(model_info)
        self._save_versions()

        return version_id

    def get_model(self, model_name: str, version_id: str = None) -> Any:
        """
        Load a specific model version

        Args:
            model_name: Name of the model
            version_id: Version ID (None for latest)

        Returns:
            Loaded model
        """
        if version_id is None:
            # Get latest version
            versions = self.versions.get(model_name, [])
            if not versions:
                raise ValueError(f"No versions found for model {model_name}")

            version_id = versions[-1]["version_id"]

        model_path = self.model_registry / f"{model_name}_v{version_id}.pkl"

        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        with open(model_path, 'rb') as f:
            model = pickle.load(f)

        return model

    def compare_models(self, model_name: str, version_ids: List[str]) -> Dict[str, Any]:
        """
        Compare performance of different model versions

        Args:
            model_name: Name of the model
            version_ids: List of version IDs to compare

        Returns:
            Comparison results
        """
        versions = self.versions.get(model_name, [])

        comparison = {
            "model_name": model_name,
            "versions": []
        }

        for vid in version_ids:
            version_info = next((v for v in versions if v["version_id"] == vid), None)
            if version_info:
                comparison["versions"].append({
                    "version_id": vid,
                    "metrics": version_info["metrics"],
                    "created_at": version_info["created_at"]
                })

        # Determine best version
        if comparison["versions"]:
            # Assume higher accuracy is better (customize based on your metric)
            best = max(comparison["versions"],
                      key=lambda x: x["metrics"].get("accuracy", 0))
            comparison["best_version"] = best["version_id"]

        return comparison

    def rollback_model(self, model_name: str, target_version: str) -> Dict[str, Any]:
        """
        Rollback to a previous model version

        Args:
            model_name: Name of the model
            target_version: Version ID to rollback to

        Returns:
            Rollback confirmation
        """
        versions = self.versions.get(model_name, [])

        # Find target version
        target = next((v for v in versions if v["version_id"] == target_version), None)

        if not target:
            return {
                "status": "error",
                "message": f"Version {target_version} not found"
            }

        # Mark as production
        target["status"] = "production"
        target["promoted_at"] = datetime.utcnow().isoformat()

        # Demote other versions
        for v in versions:
            if v["version_id"] != target_version and v.get("status") == "production":
                v["status"] = "archived"

        self._save_versions()

        return {
            "status": "success",
            "model_name": model_name,
            "version": target_version,
            "message": f"Rolled back to version {target_version}"
        }

    def setup_ab_test(self,
                     model_name: str,
                     version_a: str,
                     version_b: str,
                     traffic_split: float = 0.5) -> str:
        """
        Setup A/B test between two model versions

        Args:
            model_name: Name of the model
            version_a: First version ID
            version_b: Second version ID
            traffic_split: Percentage of traffic to version A (0-1)

        Returns:
            A/B test ID
        """
        test_id = hashlib.md5(
            f"{model_name}{version_a}{version_b}{datetime.utcnow()}".encode()
        ).hexdigest()[:12]

        self.ab_tests[test_id] = {
            "test_id": test_id,
            "model_name": model_name,
            "version_a": version_a,
            "version_b": version_b,
            "traffic_split": traffic_split,
            "created_at": datetime.utcnow().isoformat(),
            "status": "active",
            "results": {
                "version_a": {"requests": 0, "successes": 0, "avg_latency": 0},
                "version_b": {"requests": 0, "successes": 0, "avg_latency": 0}
            }
        }

        return test_id

    def route_ab_test(self, test_id: str, request_id: str) -> str:
        """
        Route request to appropriate model version in A/B test

        Args:
            test_id: A/B test ID
            request_id: Unique request identifier

        Returns:
            Version to use ("version_a" or "version_b")
        """
        test = self.ab_tests.get(test_id)

        if not test or test["status"] != "active":
            return "version_a"  # Default

        # Use hash-based routing for consistency
        hash_val = int(hashlib.md5(request_id.encode()).hexdigest()[:8], 16)
        threshold = int(test["traffic_split"] * 0xFFFFFFFF)

        return "version_a" if hash_val < threshold else "version_b"

    def record_ab_result(self,
                        test_id: str,
                        version: str,
                        success: bool,
                        latency_ms: float):
        """
        Record A/B test result

        Args:
            test_id: A/B test ID
            version: Which version was used
            success: Whether request succeeded
            latency_ms: Request latency in milliseconds
        """
        test = self.ab_tests.get(test_id)

        if not test:
            return

        results = test["results"][version]
        results["requests"] += 1

        if success:
            results["successes"] += 1

        # Update avg latency (incremental average)
        n = results["requests"]
        results["avg_latency"] = (
            results["avg_latency"] * (n - 1) + latency_ms
        ) / n

    def evaluate_ab_test(self, test_id: str) -> Dict[str, Any]:
        """
        Evaluate A/B test results

        Args:
            test_id: A/B test ID

        Returns:
            Evaluation results with winner
        """
        test = self.ab_tests.get(test_id)

        if not test:
            return {"error": "Test not found"}

        results_a = test["results"]["version_a"]
        results_b = test["results"]["version_b"]

        # Calculate success rates
        success_rate_a = (results_a["successes"] / results_a["requests"]
                         if results_a["requests"] > 0 else 0)
        success_rate_b = (results_b["successes"] / results_b["requests"]
                         if results_b["requests"] > 0 else 0)

        # Determine winner
        if success_rate_a > success_rate_b:
            winner = "version_a"
            improvement = ((success_rate_a - success_rate_b) / success_rate_b * 100
                          if success_rate_b > 0 else 100.0)
        elif success_rate_b > success_rate_a:
            winner = "version_b"
            improvement = ((success_rate_b - success_rate_a) / success_rate_a * 100
                          if success_rate_a > 0 else 100.0)
        else:
            winner = "tie"
            improvement = 0

        return {
            "test_id": test_id,
            "model_name": test["model_name"],
            "version_a": {
                "id": test["version_a"],
                "requests": results_a["requests"],
                "success_rate": round(success_rate_a * 100, 2),
                "avg_latency_ms": round(results_a["avg_latency"], 2)
            },
            "version_b": {
                "id": test["version_b"],
                "requests": results_b["requests"],
                "success_rate": round(success_rate_b * 100, 2),
                "avg_latency_ms": round(results_b["avg_latency"], 2)
            },
            "winner": winner,
            "improvement_percent": round(improvement, 2),
            "recommendation": f"Deploy {winner}" if winner != "tie" else "Continue testing"
        }

    def schedule_retraining(self,
                           model_name: str,
                           trigger: str = "schedule",
                           frequency: str = "weekly") -> Dict[str, Any]:
        """
        Schedule automated model retraining

        Args:
            model_name: Name of the model to retrain
            trigger: Trigger type (schedule, performance, data_drift)
            frequency: Retraining frequency

        Returns:
            Schedule configuration
        """
        schedule = {
            "model_name": model_name,
            "trigger": trigger,
            "frequency": frequency,
            "last_trained": datetime.utcnow().isoformat(),
            "next_training": self._calculate_next_training(frequency),
            "status": "scheduled"
        }

        # Save schedule
        schedule_file = self.model_registry / f"{model_name}_schedule.json"
        with open(schedule_file, 'w', encoding='utf-8') as f:
            json.dump(schedule, f, indent=2)

        return schedule

    def trigger_retraining(self, model_name: str, new_data: Any) -> Dict[str, Any]:
        """
        Trigger model retraining with new data

        Args:
            model_name: Model to retrain
            new_data: New training data

        Returns:
            Retraining result
        """
        # Load current model
        try:
            current_model = self.get_model(model_name)
        except (KeyError, FileNotFoundError, Exception):
            return {"status": "error", "message": "Current model not found"}

        # This would trigger actual retraining
        # Implementation depends on model type
        return {
            "status": "triggered",
            "model_name": model_name,
            "data_samples": len(new_data) if hasattr(new_data, '__len__') else "unknown",
            "message": "Retraining job queued"
        }

    def _generate_version_id(self, model_name: str) -> str:
        """Generate unique version ID"""
        existing = self.versions.get(model_name, [])
        return f"{len(existing) + 1:03d}"

    def _calculate_next_training(self, frequency: str) -> str:
        """Calculate next training date"""
        from datetime import timedelta

        now = datetime.utcnow()

        if frequency == "daily":
            next_date = now + timedelta(days=1)
        elif frequency == "weekly":
            next_date = now + timedelta(weeks=1)
        elif frequency == "monthly":
            next_date = now + timedelta(days=30)
        else:
            next_date = now + timedelta(days=7)

        return next_date.isoformat()

    def _load_versions(self) -> Dict:
        """Load versions database"""
        if self.versions_db.exists():
            with open(self.versions_db, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    def _save_versions(self):
        """Save versions database"""
        with open(self.versions_db, 'w', encoding='utf-8') as f:
            json.dump(self.versions, f, indent=2)

    def get_model_stats(self) -> Dict[str, Any]:
        """Get overall model management statistics"""
        total_models = len(self.versions)
        total_versions = sum(len(versions) for versions in self.versions.values())
        active_tests = len([t for t in self.ab_tests.values() if t["status"] == "active"])

        return {
            "total_models": total_models,
            "total_versions": total_versions,
            "active_ab_tests": active_tests,
            "models": list(self.versions.keys())
        }
