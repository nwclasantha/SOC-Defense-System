"""
Performance Optimization Module
Implements caching, connection pooling, compression, and optimization strategies
"""

import time
import gzip
import json
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Callable
from functools import wraps
from collections import OrderedDict
import threading

class LRUCache:
    """
    Least Recently Used (LRU) Cache implementation
    Thread-safe with TTL support
    """

    def __init__(self, capacity: int = 1000, ttl_seconds: int = 3600):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key not in self.cache:
                self.misses += 1
                return None

            value, timestamp = self.cache[key]

            # Check if expired
            if time.time() - timestamp > self.ttl_seconds:
                del self.cache[key]
                self.misses += 1
                return None

            # Move to end (most recently used)
            self.cache.move_to_end(key)
            self.hits += 1
            return value

    def put(self, key: str, value: Any):
        """Put value in cache"""
        with self.lock:
            if key in self.cache:
                # Update existing
                self.cache[key] = (value, time.time())
                self.cache.move_to_end(key)
            else:
                # Add new
                if len(self.cache) >= self.capacity:
                    # Evict oldest
                    self.cache.popitem(last=False)
                    self.evictions += 1

                self.cache[key] = (value, time.time())

    def invalidate(self, key: str):
        """Invalidate specific cache entry"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]

    def invalidate_pattern(self, pattern: str):
        """Invalidate all keys matching pattern"""
        with self.lock:
            keys_to_delete = [k for k in self.cache.keys() if pattern in k]
            for key in keys_to_delete:
                del self.cache[key]

    def clear(self):
        """Clear entire cache"""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0
            self.evictions = 0

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

            return {
                "size": len(self.cache),
                "capacity": self.capacity,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "hit_rate": round(hit_rate, 2),
                "total_requests": total_requests
            }

class PerformanceOptimizer:
    """
    Comprehensive performance optimization utilities
    """

    def __init__(self):
        self.query_cache = LRUCache(capacity=500, ttl_seconds=300)  # 5 min TTL
        self.data_cache = LRUCache(capacity=1000, ttl_seconds=3600)  # 1 hour TTL
        self.api_cache = LRUCache(capacity=200, ttl_seconds=1800)  # 30 min TTL

    @staticmethod
    def cache_result(cache_key_prefix: str = "", ttl: int = 3600):
        """
        Decorator to cache function results

        Usage:
            @cache_result(cache_key_prefix="attacker_", ttl=300)
            def expensive_function(ip_address):
                # ... expensive operation
                return result
        """
        def decorator(func: Callable):
            cache = LRUCache(capacity=100, ttl_seconds=ttl)

            @wraps(func)
            def wrapper(*args, **kwargs):
                # Generate cache key from function name and arguments
                key_parts = [cache_key_prefix, func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = hashlib.md5("_".join(key_parts).encode()).hexdigest()

                # Try to get from cache
                cached_result = cache.get(cache_key)
                if cached_result is not None:
                    return cached_result

                # Execute function
                result = func(*args, **kwargs)

                # Store in cache
                cache.put(cache_key, result)

                return result

            # Add cache stats method
            wrapper.cache_stats = cache.get_stats
            wrapper.clear_cache = cache.clear

            return wrapper
        return decorator

    @staticmethod
    def compress_data(data: str, level: int = 6) -> bytes:
        """
        Compress data using gzip

        Args:
            data: String data to compress
            level: Compression level (1-9, higher = better compression)

        Returns:
            Compressed bytes
        """
        return gzip.compress(data.encode('utf-8'), compresslevel=level)

    @staticmethod
    def decompress_data(compressed_data: bytes) -> str:
        """
        Decompress gzip data

        Args:
            compressed_data: Compressed bytes

        Returns:
            Decompressed string
        """
        return gzip.decompress(compressed_data).decode('utf-8')

    @staticmethod
    def batch_process(items: list, batch_size: int = 100, process_func: Callable = None):
        """
        Process items in batches for better performance

        Args:
            items: List of items to process
            batch_size: Size of each batch
            process_func: Function to process each batch

        Yields:
            Processed results
        """
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            if process_func:
                yield process_func(batch)
            else:
                yield batch

    @staticmethod
    def lazy_load(data_source: Callable, chunk_size: int = 50):
        """
        Lazy load data in chunks

        Args:
            data_source: Function that returns data
            chunk_size: Size of each chunk

        Yields:
            Data chunks
        """
        offset = 0
        while True:
            chunk = data_source(offset=offset, limit=chunk_size)
            if not chunk:
                break
            yield chunk
            offset += chunk_size

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get statistics for all caches"""
        return {
            "query_cache": self.query_cache.get_stats(),
            "data_cache": self.data_cache.get_stats(),
            "api_cache": self.api_cache.get_stats(),
            "total_memory_estimate_mb": self._estimate_cache_memory()
        }

    def _estimate_cache_memory(self) -> float:
        """Estimate memory usage of caches (rough estimate)"""
        # Rough estimate: 1KB per cache entry average
        total_entries = (
            self.query_cache.get_stats()["size"] +
            self.data_cache.get_stats()["size"] +
            self.api_cache.get_stats()["size"]
        )
        return round(total_entries * 1024 / 1024 / 1024, 2)  # Convert to MB

    def invalidate_all_caches(self):
        """Clear all caches"""
        self.query_cache.clear()
        self.data_cache.clear()
        self.api_cache.clear()

    @staticmethod
    def optimize_query_filter(filters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Optimize query filters for better performance

        Args:
            filters: Query filter dictionary

        Returns:
            Optimized filters
        """
        optimized = {}

        for key, value in filters.items():
            # Skip None values
            if value is None:
                continue

            # Optimize string filters
            if isinstance(value, str) and len(value) > 100:
                # Truncate very long strings
                optimized[key] = value[:100]
            else:
                optimized[key] = value

        return optimized

    @staticmethod
    def create_pagination(total_items: int, page: int = 1, page_size: int = 50) -> Dict[str, Any]:
        """
        Create pagination metadata

        Args:
            total_items: Total number of items
            page: Current page number (1-indexed)
            page_size: Items per page

        Returns:
            Pagination info
        """
        total_pages = (total_items + page_size - 1) // page_size
        has_next = page < total_pages
        has_prev = page > 1

        return {
            "page": page,
            "page_size": page_size,
            "total_items": total_items,
            "total_pages": total_pages,
            "has_next": has_next,
            "has_prev": has_prev,
            "start_index": (page - 1) * page_size,
            "end_index": min(page * page_size, total_items)
        }

    @staticmethod
    def measure_performance(func: Callable):
        """
        Decorator to measure function performance

        Usage:
            @measure_performance
            def slow_function():
                # ... slow operation
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()

            execution_time = end_time - start_time
            print(f"{func.__name__} executed in {execution_time:.4f} seconds")

            return result
        return wrapper

    @staticmethod
    def compress_json(data: Dict) -> bytes:
        """Compress JSON data"""
        json_str = json.dumps(data)
        return gzip.compress(json_str.encode('utf-8'))

    @staticmethod
    def decompress_json(compressed_data: bytes) -> Dict:
        """Decompress JSON data"""
        json_str = gzip.decompress(compressed_data).decode('utf-8')
        return json.loads(json_str)


# Global performance optimizer instance
performance_optimizer = PerformanceOptimizer()
