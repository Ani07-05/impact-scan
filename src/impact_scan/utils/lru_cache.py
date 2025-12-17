"""
LRU (Least Recently Used) cache implementation for caching HTTP responses and other data.
"""

from collections import OrderedDict
from typing import Any, Optional


class LRUCache:
    """Thread-safe LRU cache with automatic eviction of oldest items."""

    def __init__(self, max_size: int = 1000):
        """Initialize LRU cache.
        
        Args:
            max_size: Maximum number of items to store in cache
        """
        self.max_size = max_size
        self.cache: OrderedDict[str, Any] = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache, moving to end (most recently used).
        
        Args:
            key: Cache key
            
        Returns:
            Value if found, None otherwise
        """
        if key not in self.cache:
            return None
        
        # Move to end (mark as recently used)
        self.cache.move_to_end(key)
        return self.cache[key]

    def put(self, key: str, value: Any) -> None:
        """Put value in cache, evicting LRU item if needed.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        if key in self.cache:
            # Update existing key and move to end
            self.cache.move_to_end(key)
            self.cache[key] = value
        else:
            # Add new key
            self.cache[key] = value
            
            # Evict least recently used (first) item if cache is full
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

    def __contains__(self, key: str) -> bool:
        """Check if key exists in cache."""
        return key in self.cache

    def __len__(self) -> int:
        """Get cache size."""
        return len(self.cache)

    def clear(self) -> None:
        """Clear all items from cache."""
        self.cache.clear()

    @property
    def size(self) -> int:
        """Get current cache size."""
        return len(self.cache)

    @property
    def max_capacity(self) -> int:
        """Get maximum cache capacity."""
        return self.max_size


__all__ = ["LRUCache"]
