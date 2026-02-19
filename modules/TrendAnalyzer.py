"""
Trend Analysis Module
Implements statistical trend analysis with seasonal decomposition
Detects trends, change points, and anomalies in security metrics
"""

import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass
from scipy import stats
from scipy.signal import find_peaks
import warnings
warnings.filterwarnings('ignore')

@dataclass
class TrendResult:
    """Trend analysis result"""
    trend: np.ndarray
    seasonal: np.ndarray
    residual: np.ndarray
    strength: float
    direction: str  # increasing, decreasing, stable
    change_points: List[int]
    anomalies: List[int]
    confidence: float

@dataclass
class ChangePoint:
    """Detected change point"""
    index: int
    timestamp: datetime
    value_before: float
    value_after: float
    magnitude: float
    significance: float

class TrendAnalyzer:
    """
    Statistical trend analysis engine
    Implements seasonal decomposition, change point detection, and trend forecasting
    """

    def __init__(self):
        self.historical_data = defaultdict(list)
        self.trend_cache = {}

    def add_data_point(self, series_name: str, timestamp: datetime, value: float):
        """
        Add data point to time series

        Args:
            series_name: Name of the series
            timestamp: Timestamp of observation
            value: Observed value
        """
        self.historical_data[series_name].append({
            "timestamp": timestamp,
            "value": value
        })

    def decompose_series(self,
                        series_name: str,
                        period: int = 24,
                        model: str = "additive") -> TrendResult:
        """
        Perform seasonal decomposition

        Args:
            series_name: Name of series to decompose
            period: Seasonal period (24 for daily in hourly data)
            model: "additive" or "multiplicative"

        Returns:
            TrendResult with decomposed components
        """
        data = self.historical_data.get(series_name, [])

        if len(data) < period * 2:
            raise ValueError(f"Need at least {period * 2} data points for decomposition")

        # Sort and extract values
        data = sorted(data, key=lambda x: x["timestamp"])
        values = np.array([d["value"] for d in data])

        # Decompose
        trend = self._extract_trend(values, window=period)
        seasonal = self._extract_seasonal(values, period, model)

        if model == "additive":
            residual = values - trend - seasonal
        else:
            residual = values / (trend * seasonal + 1e-10)

        # Calculate trend strength
        trend_strength = 1 - (np.var(residual) / np.var(trend + residual + 1e-10))
        trend_strength = max(0, min(1, trend_strength))

        # Detect trend direction
        direction = self._detect_trend_direction(trend)

        # Find change points
        change_points = self._detect_change_points(values)

        # Find anomalies
        anomalies = self._detect_anomalies_from_residual(residual)

        # Calculate confidence
        confidence = self._calculate_confidence(values, residual, trend_strength)

        return TrendResult(
            trend=trend,
            seasonal=seasonal,
            residual=residual,
            strength=trend_strength,
            direction=direction,
            change_points=change_points,
            anomalies=anomalies,
            confidence=confidence
        )

    def detect_change_points(self, series_name: str, sensitivity: float = 2.0) -> List[ChangePoint]:
        """
        Detect significant change points in time series

        Args:
            series_name: Series name
            sensitivity: Detection sensitivity (lower = more sensitive)

        Returns:
            List of detected change points
        """
        data = self.historical_data.get(series_name, [])

        if len(data) < 10:
            return []

        data = sorted(data, key=lambda x: x["timestamp"])
        values = np.array([d["value"] for d in data])

        change_points = []

        # Use CUSUM (Cumulative Sum) algorithm
        cusum_pos = np.zeros(len(values))
        cusum_neg = np.zeros(len(values))

        mean = np.mean(values)
        std = np.std(values)

        threshold = sensitivity * std

        for i in range(1, len(values)):
            cusum_pos[i] = max(0, cusum_pos[i-1] + values[i] - mean - threshold)
            cusum_neg[i] = max(0, cusum_neg[i-1] - values[i] + mean - threshold)

            # Check for change point
            if cusum_pos[i] > threshold or cusum_neg[i] > threshold:
                # Calculate values before and after
                window = 5
                start = max(0, i - window)
                end = min(len(values), i + window)

                value_before = np.mean(values[start:i])
                value_after = np.mean(values[i:end])

                magnitude = abs(value_after - value_before)

                # Statistical significance (t-test)
                if i > window and i < len(values) - window:
                    t_stat, p_value = stats.ttest_ind(
                        values[i-window:i],
                        values[i:i+window]
                    )
                    significance = 1 - p_value
                else:
                    significance = 0.5

                change_points.append(ChangePoint(
                    index=i,
                    timestamp=data[i]["timestamp"],
                    value_before=value_before,
                    value_after=value_after,
                    magnitude=magnitude,
                    significance=significance
                ))

                # Reset CUSUM after detection
                cusum_pos[i] = 0
                cusum_neg[i] = 0

        return change_points

    def calculate_correlation(self,
                            series1_name: str,
                            series2_name: str,
                            method: str = "pearson") -> Dict[str, Any]:
        """
        Calculate correlation between two time series

        Args:
            series1_name: First series
            series2_name: Second series
            method: pearson, spearman, or kendall

        Returns:
            Correlation analysis results
        """
        data1 = self.historical_data.get(series1_name, [])
        data2 = self.historical_data.get(series2_name, [])

        if not data1 or not data2:
            return {"error": "Insufficient data"}

        # Align time series
        values1, values2 = self._align_time_series(data1, data2)

        if len(values1) < 3:
            return {"error": "Not enough aligned data points"}

        # Calculate correlation
        if method == "pearson":
            corr, p_value = stats.pearsonr(values1, values2)
        elif method == "spearman":
            corr, p_value = stats.spearmanr(values1, values2)
        elif method == "kendall":
            corr, p_value = stats.kendalltau(values1, values2)
        else:
            return {"error": "Invalid method"}

        # Calculate lag correlation
        lag_correlations = self._calculate_lag_correlation(values1, values2, max_lag=10)

        # Determine relationship strength
        if abs(corr) > 0.7:
            strength = "strong"
        elif abs(corr) > 0.4:
            strength = "moderate"
        elif abs(corr) > 0.2:
            strength = "weak"
        else:
            strength = "negligible"

        return {
            "correlation": float(corr),
            "p_value": float(p_value),
            "method": method,
            "strength": strength,
            "significant": p_value < 0.05,
            "lag_correlations": lag_correlations,
            "sample_size": len(values1)
        }

    def detect_periodic_patterns(self, series_name: str) -> Dict[str, Any]:
        """
        Detect periodic patterns using FFT

        Args:
            series_name: Series name

        Returns:
            Detected periods and their strengths
        """
        data = self.historical_data.get(series_name, [])

        if len(data) < 50:
            return {"error": "Need at least 50 data points"}

        values = np.array([d["value"] for d in sorted(data, key=lambda x: x["timestamp"])])

        # Remove trend
        detrended = values - self._extract_trend(values, window=min(24, len(values)//4))

        # Apply FFT
        fft = np.fft.fft(detrended)
        freqs = np.fft.fftfreq(len(values))

        # Get positive frequencies
        pos_mask = freqs > 0
        freqs = freqs[pos_mask]
        power = np.abs(fft[pos_mask]) ** 2

        # Find peaks
        peaks, properties = find_peaks(power, height=np.mean(power))

        # Convert to periods
        periods = []
        for peak in peaks:
            period = 1 / freqs[peak]
            strength = power[peak] / np.sum(power)

            periods.append({
                "period": float(period),
                "strength": float(strength),
                "frequency": float(freqs[peak])
            })

        # Sort by strength
        periods = sorted(periods, key=lambda x: x["strength"], reverse=True)

        return {
            "detected_periods": periods[:5],  # Top 5
            "dominant_period": periods[0]["period"] if periods else None,
            "has_periodicity": len(periods) > 0 and periods[0]["strength"] > 0.1
        }

    def calculate_trend_forecast(self,
                                series_name: str,
                                periods: int = 24) -> Dict[str, Any]:
        """
        Simple trend-based forecast

        Args:
            series_name: Series name
            periods: Number of periods to forecast

        Returns:
            Forecast based on trend
        """
        result = self.decompose_series(series_name)

        # Extrapolate trend
        trend = result.trend
        trend_slope = (trend[-1] - trend[-10]) / 10 if len(trend) > 10 else 0

        forecasts = []
        for i in range(1, periods + 1):
            forecast = trend[-1] + trend_slope * i

            # Add seasonal component if strong
            if result.strength > 0.5:
                seasonal_idx = (len(result.seasonal) + i - 1) % len(result.seasonal)
                forecast += result.seasonal[seasonal_idx]

            forecasts.append(max(0, forecast))

        return {
            "forecasts": forecasts,
            "trend_direction": result.direction,
            "confidence": result.confidence,
            "based_on_samples": len(self.historical_data[series_name])
        }

    def _extract_trend(self, values: np.ndarray, window: int) -> np.ndarray:
        """Extract trend using moving average"""
        if len(values) < window:
            return values

        # Apply centered moving average
        trend = np.convolve(values, np.ones(window)/window, mode='same')

        # Fix edges
        for i in range(window // 2):
            trend[i] = np.mean(values[:i+window//2+1])
            trend[-(i+1)] = np.mean(values[-(i+window//2+1):])

        return trend

    def _extract_seasonal(self, values: np.ndarray, period: int, model: str) -> np.ndarray:
        """Extract seasonal component"""
        if len(values) < period:
            return np.zeros(len(values))

        seasonal = np.zeros(period)

        # Calculate average for each seasonal position
        for i in range(period):
            seasonal_values = values[i::period]
            seasonal[i] = np.mean(seasonal_values)

        if model == "additive":
            # Center around 0
            seasonal = seasonal - np.mean(seasonal)
        else:
            # Center around 1
            seasonal = seasonal / np.mean(seasonal)

        # Repeat for full length
        full_seasonal = np.tile(seasonal, len(values) // period + 1)[:len(values)]

        return full_seasonal

    def _detect_trend_direction(self, trend: np.ndarray) -> str:
        """Detect overall trend direction"""
        if len(trend) < 2:
            return "stable"

        # Linear regression
        x = np.arange(len(trend))
        slope, _, _, p_value, _ = stats.linregress(x, trend)

        if p_value > 0.05:
            return "stable"
        elif slope > 0:
            return "increasing"
        else:
            return "decreasing"

    def _detect_change_points(self, values: np.ndarray) -> List[int]:
        """Detect change points using simple threshold"""
        if len(values) < 10:
            return []

        change_points = []
        window = 5

        for i in range(window, len(values) - window):
            before = values[i-window:i]
            after = values[i:i+window]

            # t-test
            t_stat, p_value = stats.ttest_ind(before, after)

            if p_value < 0.01:  # Significant change
                change_points.append(i)

        return change_points

    def _detect_anomalies_from_residual(self, residual: np.ndarray) -> List[int]:
        """Detect anomalies from residual component"""
        if len(residual) < 3:
            return []

        # Use IQR method
        q1 = np.percentile(residual, 25)
        q3 = np.percentile(residual, 75)
        iqr = q3 - q1

        lower_bound = q1 - 3 * iqr
        upper_bound = q3 + 3 * iqr

        anomalies = []
        for i, r in enumerate(residual):
            if r < lower_bound or r > upper_bound:
                anomalies.append(i)

        return anomalies

    def _calculate_confidence(self, values: np.ndarray, residual: np.ndarray, trend_strength: float) -> float:
        """Calculate confidence in trend analysis"""
        if len(values) < 10:
            return 0.3

        # Base confidence on multiple factors
        confidence = 0.5

        # Factor 1: Trend strength
        confidence += trend_strength * 0.2

        # Factor 2: Residual magnitude
        residual_ratio = np.std(residual) / (np.std(values) + 1e-10)
        confidence += (1 - residual_ratio) * 0.2

        # Factor 3: Data quantity
        data_factor = min(len(values) / 100, 0.1)
        confidence += data_factor

        return min(confidence, 1.0)

    def _align_time_series(self, data1: List[Dict], data2: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Align two time series by timestamp"""
        # Create timestamp maps
        map1 = {d["timestamp"]: d["value"] for d in data1}
        map2 = {d["timestamp"]: d["value"] for d in data2}

        # Find common timestamps
        common_timestamps = set(map1.keys()) & set(map2.keys())

        if not common_timestamps:
            return np.array([]), np.array([])

        # Extract aligned values
        common_timestamps = sorted(common_timestamps)
        values1 = np.array([map1[ts] for ts in common_timestamps])
        values2 = np.array([map2[ts] for ts in common_timestamps])

        return values1, values2

    def _calculate_lag_correlation(self, series1: np.ndarray, series2: np.ndarray, max_lag: int = 10) -> List[Dict]:
        """Calculate correlation at different lags"""
        lag_results = []

        for lag in range(-max_lag, max_lag + 1):
            if lag < 0:
                # series1 leads series2
                s1 = series1[:lag]
                s2 = series2[-lag:]
            elif lag > 0:
                # series2 leads series1
                s1 = series1[lag:]
                s2 = series2[:-lag]
            else:
                s1 = series1
                s2 = series2

            if len(s1) > 2:
                corr, _ = stats.pearsonr(s1, s2)
                lag_results.append({
                    "lag": lag,
                    "correlation": float(corr)
                })

        return lag_results

    def get_series_summary(self, series_name: str) -> Dict[str, Any]:
        """Get comprehensive summary of time series"""
        data = self.historical_data.get(series_name, [])

        if not data:
            return {"error": "No data"}

        values = np.array([d["value"] for d in data])

        try:
            result = self.decompose_series(series_name)

            return {
                "series_name": series_name,
                "data_points": len(data),
                "mean": float(np.mean(values)),
                "std": float(np.std(values)),
                "min": float(np.min(values)),
                "max": float(np.max(values)),
                "trend_direction": result.direction,
                "trend_strength": float(result.strength),
                "change_points_detected": len(result.change_points),
                "anomalies_detected": len(result.anomalies),
                "confidence": float(result.confidence)
            }
        except (ValueError, TypeError, AttributeError, IndexError):
            return {
                "series_name": series_name,
                "data_points": len(data),
                "mean": float(np.mean(values)),
                "std": float(np.std(values)),
                "error": "Insufficient data for full analysis"
            }
