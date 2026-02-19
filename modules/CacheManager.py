import logging
import hashlib
import pickle
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Any

# Cache Manager
class CacheManager:
    """Manages caching for various data types."""

    def __init__(self, cache_dir: str, ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
        self.logger = logging.getLogger(self.__class__.__name__)

    def _get_cache_path(self, key: str) -> Path:
        """Generate cache file path from key."""
        hash_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{hash_key}.cache"

    def get(self, key: str) -> Optional[Any]:
        """Retrieve item from cache if valid."""
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            return None

        try:
            with open(str(cache_path), 'rb') as f:
                cached_data = pickle.load(f)

            # Check TTL - use custom ttl_seconds if stored, otherwise default
            custom_ttl = cached_data.get('ttl_seconds')
            if custom_ttl:
                ttl_delta = timedelta(seconds=custom_ttl)
            else:
                ttl_delta = self.ttl

            if datetime.now() - cached_data['timestamp'] > ttl_delta:
                cache_path.unlink()
                return None

            self.logger.debug(f"Cache hit for key: {key}")
            return cached_data['data']

        except Exception as e:
            self.logger.error(f"Error reading cache: {e}")
            return None

    def set(self, key: str, data: Any, ttl: int = None) -> bool:
        """Store item in cache.

        Args:
            key: Cache key
            data: Data to cache
            ttl: Optional TTL in seconds (overrides default ttl_hours)
        """
        cache_path = self._get_cache_path(key)

        try:
            cached_data = {
                'timestamp': datetime.now(),
                'data': data,
                'ttl_seconds': ttl  # Store custom TTL if provided
            }

            with open(str(cache_path), 'wb') as f:
                pickle.dump(cached_data, f)

            self.logger.debug(f"Cached data for key: {key}")
            return True

        except Exception as e:
            self.logger.error(f"Error writing cache: {e}")
            return False
