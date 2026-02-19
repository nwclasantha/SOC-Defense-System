"""
Time-Series Forecasting Module
Implements Prophet-like and ARIMA-style forecasting for attack prediction
Predicts future attack volumes, patterns, and trends
"""

import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from collections import defaultdict
from dataclasses import dataclass

@dataclass
class Forecast:
    """Forecast result"""
    timestamps: List[datetime]
    predictions: List[float]
    lower_bound: List[float]
    upper_bound: List[float]
    confidence: float
    model_type: str

class TimeSeriesForecaster:
    """
    Time-series forecasting engine
    Implements simplified Prophet and ARIMA methodologies
    """

    def __init__(self):
        self.models = {}
        self.training_data = defaultdict(list)

    def add_data_point(self, series_name: str, timestamp: datetime, value: float):
        """
        Add data point to time series

        Args:
            series_name: Name of the series
            timestamp: Timestamp of observation
            value: Observed value
        """
        self.training_data[series_name].append({
            "timestamp": timestamp,
            "value": value
        })

    def forecast_prophet_style(self,
                               series_name: str,
                               periods: int = 24,
                               frequency: str = "hourly") -> Forecast:
        """
        Prophet-style forecasting with trend and seasonality

        Args:
            series_name: Name of series to forecast
            periods: Number of periods to forecast
            frequency: hourly, daily, weekly

        Returns:
            Forecast object
        """
        data = self.training_data.get(series_name, [])

        if len(data) < 10:
            raise ValueError("Need at least 10 data points for forecasting")

        # Sort by timestamp
        data = sorted(data, key=lambda x: x["timestamp"])

        # Extract values
        timestamps = [d["timestamp"] for d in data]
        values = np.array([d["value"] for d in data])

        # Decompose into trend, seasonality, and noise
        trend = self._extract_trend(values)
        seasonality = self._extract_seasonality(values, self._get_period(frequency))

        # Forecast future values
        last_timestamp = timestamps[-1]
        future_timestamps = []
        predictions = []
        lower_bounds = []
        upper_bounds = []

        for i in range(1, periods + 1):
            # Calculate future timestamp
            if frequency == "hourly":
                future_ts = last_timestamp + timedelta(hours=i)
            elif frequency == "daily":
                future_ts = last_timestamp + timedelta(days=i)
            else:
                future_ts = last_timestamp + timedelta(hours=i)

            future_timestamps.append(future_ts)

            # Extrapolate trend
            trend_value = trend[-1] + (trend[-1] - trend[-2]) * i

            # Get seasonality component
            season_idx = i % len(seasonality)
            season_value = seasonality[season_idx]

            # Combine
            prediction = trend_value + season_value

            # Add uncertainty
            std = np.std(values)
            lower_bound = prediction - 1.96 * std
            upper_bound = prediction + 1.96 * std

            predictions.append(max(0, prediction))
            lower_bounds.append(max(0, lower_bound))
            upper_bounds.append(max(0, upper_bound))

        return Forecast(
            timestamps=future_timestamps,
            predictions=predictions,
            lower_bound=lower_bounds,
            upper_bound=upper_bounds,
            confidence=0.95,
            model_type="prophet_style"
        )

    def forecast_arima_style(self,
                            series_name: str,
                            periods: int = 24,
                            p: int = 2,
                            d: int = 1,
                            q: int = 2) -> Forecast:
        """
        ARIMA-style forecasting

        Args:
            series_name: Name of series
            periods: Forecast horizon
            p: Autoregressive order
            d: Differencing order
            q: Moving average order

        Returns:
            Forecast object
        """
        data = self.training_data.get(series_name, [])

        if len(data) < max(p, q) + d + 10:
            raise ValueError(f"Need at least {max(p, q) + d + 10} data points")

        # Sort and extract values
        data = sorted(data, key=lambda x: x["timestamp"])
        timestamps = [d["timestamp"] for d in data]
        values = np.array([d["value"] for d in data])

        # Differencing to make stationary
        diff_values = values.copy()
        for _ in range(d):
            diff_values = np.diff(diff_values)

        # Autoregressive component (AR)
        ar_coeffs = self._estimate_ar_coefficients(diff_values, p)

        # Moving average component (MA)
        ma_coeffs = self._estimate_ma_coefficients(diff_values, q)

        # Forecast
        last_values = list(diff_values[-p:])
        last_errors = [0] * q

        future_timestamps = []
        predictions = []
        last_timestamp = timestamps[-1]

        for i in range(periods):
            # AR component
            ar_component = sum(ar_coeffs[j] * last_values[-(j+1)]
                             for j in range(min(p, len(last_values))))

            # MA component
            ma_component = sum(ma_coeffs[j] * last_errors[-(j+1)]
                             for j in range(min(q, len(last_errors))))

            # Forecast
            forecast_diff = ar_component + ma_component

            # Integrate back
            forecast_value = values[-1] + forecast_diff

            # Update
            last_values.append(forecast_diff)
            last_errors.append(0)  # Simplified

            future_timestamps.append(last_timestamp + timedelta(hours=i+1))
            predictions.append(max(0, forecast_value))

        # Calculate confidence intervals
        std = np.std(values)
        lower_bounds = [max(0, p - 1.96 * std) for p in predictions]
        upper_bounds = [p + 1.96 * std for p in predictions]

        return Forecast(
            timestamps=future_timestamps,
            predictions=predictions,
            lower_bound=lower_bounds,
            upper_bound=upper_bounds,
            confidence=0.95,
            model_type="arima_style"
        )

    def forecast_exponential_smoothing(self,
                                      series_name: str,
                                      periods: int = 24,
                                      alpha: float = 0.3,
                                      beta: float = 0.1,
                                      gamma: float = 0.1) -> Forecast:
        """
        Exponential smoothing (Holt-Winters) forecast

        Args:
            series_name: Series name
            periods: Forecast periods
            alpha: Level smoothing parameter
            beta: Trend smoothing parameter
            gamma: Seasonal smoothing parameter

        Returns:
            Forecast object
        """
        data = self.training_data.get(series_name, [])

        if len(data) < 24:
            raise ValueError("Need at least 24 data points")

        data = sorted(data, key=lambda x: x["timestamp"])
        timestamps = [d["timestamp"] for d in data]
        values = np.array([d["value"] for d in data])

        # Initialize components
        level = values[0]
        trend = (values[1] - values[0])
        season_length = min(24, len(values) // 2)
        seasonal = values[:season_length] - level

        # Apply Holt-Winters
        for i in range(len(values)):
            old_level = level

            # Update level
            level = alpha * (values[i] - seasonal[i % season_length]) + (1 - alpha) * (level + trend)

            # Update trend
            trend = beta * (level - old_level) + (1 - beta) * trend

            # Update seasonality
            seasonal[i % season_length] = gamma * (values[i] - level) + (1 - gamma) * seasonal[i % season_length]

        # Forecast
        future_timestamps = []
        predictions = []
        last_timestamp = timestamps[-1]

        for i in range(periods):
            forecast = (level + (i + 1) * trend) + seasonal[i % season_length]

            future_timestamps.append(last_timestamp + timedelta(hours=i+1))
            predictions.append(max(0, forecast))

        # Confidence intervals
        std = np.std(values)
        lower_bounds = [max(0, p - 1.96 * std) for p in predictions]
        upper_bounds = [p + 1.96 * std for p in predictions]

        return Forecast(
            timestamps=future_timestamps,
            predictions=predictions,
            lower_bound=lower_bounds,
            upper_bound=upper_bounds,
            confidence=0.95,
            model_type="exponential_smoothing"
        )

    def detect_anomalies_in_forecast(self,
                                    series_name: str,
                                    current_value: float) -> Dict[str, Any]:
        """
        Detect if current value is anomalous compared to forecast

        Args:
            series_name: Series name
            current_value: Current observed value

        Returns:
            Anomaly detection result
        """
        try:
            # Get forecast for current time
            forecast = self.forecast_prophet_style(series_name, periods=1)

            predicted = forecast.predictions[0]
            lower = forecast.lower_bound[0]
            upper = forecast.upper_bound[0]

            # Check if current value is outside confidence interval
            is_anomaly = current_value < lower or current_value > upper

            deviation = abs(current_value - predicted) / max(predicted, 1)

            return {
                "is_anomaly": is_anomaly,
                "current_value": current_value,
                "predicted_value": predicted,
                "lower_bound": lower,
                "upper_bound": upper,
                "deviation_percent": deviation * 100,
                "severity": "critical" if deviation > 2 else "high" if deviation > 1 else "medium"
            }
        except (IndexError, ValueError, ZeroDivisionError):
            return {"is_anomaly": False, "error": "Insufficient data"}

    def _extract_trend(self, values: np.ndarray) -> np.ndarray:
        """Extract trend using moving average"""
        window = min(24, len(values) // 4)
        trend = np.convolve(values, np.ones(window)/window, mode='same')
        return trend

    def _extract_seasonality(self, values: np.ndarray, period: int) -> np.ndarray:
        """Extract seasonal component"""
        if len(values) < period:
            return np.zeros(period)

        # Calculate average for each seasonal position
        seasonal = np.zeros(period)

        for i in range(period):
            seasonal_values = values[i::period]
            seasonal[i] = np.mean(seasonal_values) if len(seasonal_values) > 0 else 0

        # Normalize
        seasonal = seasonal - np.mean(seasonal)

        return seasonal

    def _get_period(self, frequency: str) -> int:
        """Get period length for seasonality"""
        if frequency == "hourly":
            return 24  # Daily seasonality
        elif frequency == "daily":
            return 7  # Weekly seasonality
        else:
            return 24

    def _estimate_ar_coefficients(self, values: np.ndarray, p: int) -> np.ndarray:
        """Estimate AR coefficients using Yule-Walker equations"""
        if len(values) < p + 1:
            return np.zeros(p)

        # Simple least squares estimation
        X = []
        y = []

        for i in range(p, len(values)):
            X.append(values[i-p:i][::-1])
            y.append(values[i])

        X = np.array(X)
        y = np.array(y)

        # Solve least squares
        try:
            coeffs = np.linalg.lstsq(X, y, rcond=None)[0]
        except (np.linalg.LinAlgError, ValueError):
            coeffs = np.zeros(p)

        return coeffs

    def _estimate_ma_coefficients(self, values: np.ndarray, q: int) -> np.ndarray:
        """Estimate MA coefficients"""
        # Simplified: use zeros (in practice would use innovations algorithm)
        return np.zeros(q)

    def get_forecast_accuracy(self, series_name: str, test_periods: int = 24) -> Dict[str, float]:
        """
        Evaluate forecast accuracy using last N periods as test set

        Args:
            series_name: Series name
            test_periods: Number of periods to use for testing

        Returns:
            Accuracy metrics
        """
        data = self.training_data.get(series_name, [])

        if len(data) < test_periods + 24:
            return {"error": "Insufficient data"}

        # Split into train/test
        train_data = data[:-test_periods]
        test_data = data[-test_periods:]

        # Temporarily use only training data
        original_data = self.training_data[series_name]
        self.training_data[series_name] = train_data

        # Forecast
        try:
            forecast = self.forecast_prophet_style(series_name, periods=test_periods)

            # Calculate errors
            actuals = [d["value"] for d in test_data]
            predictions = forecast.predictions

            mae = np.mean(np.abs(np.array(actuals) - np.array(predictions)))
            rmse = np.sqrt(np.mean((np.array(actuals) - np.array(predictions)) ** 2))
            # Avoid division by zero in MAPE calculation
            actuals_arr = np.array(actuals)
            actuals_safe = np.where(actuals_arr == 0, 1, actuals_arr)  # Replace zeros with 1 to avoid div by zero
            mape = np.mean(np.abs((actuals_arr - np.array(predictions)) / actuals_safe)) * 100

            # Restore data
            self.training_data[series_name] = original_data

            return {
                "mae": float(mae),
                "rmse": float(rmse),
                "mape": float(mape),
                "accuracy": max(0, 100 - mape)
            }
        except Exception as e:
            self.training_data[series_name] = original_data
            return {"error": str(e)}
