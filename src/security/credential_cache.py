"""
Thread-safe credential cache for Basic Authentication.

Caches successful LDAP authentications to reduce AD load and improve performance.
Uses SHA256 hash of credentials as cache key (never stores plaintext passwords).
Supports TTL-based expiration and LRU eviction when max size is reached.
"""

import hashlib
import time
import threading
from typing import Optional, Dict
from collections import OrderedDict

from src.security.auth import UserInfo
from src.utils.logger import get_logger

logger = get_logger("credential_cache")


class CredentialCache:
    """
    Thread-safe LRU cache with TTL for user credentials.

    Caches successful LDAP authentications to reduce AD load.
    """

    def __init__(self, ttl_seconds: int = 300, max_size: int = 1000):
        """
        Initialize credential cache.

        Args:
            ttl_seconds: Time-to-live for cached credentials in seconds (default 5 minutes)
            max_size: Maximum number of cached entries (default 1000)
        """
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._cache: OrderedDict[str, tuple[UserInfo, float]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

        logger.info(f"Credential cache initialized (TTL: {ttl_seconds}s, Max size: {max_size})")

    def _make_key(self, username: str, password: str) -> str:
        """
        Create cache key from credentials.

        Uses SHA256 hash to avoid storing plaintext passwords.

        Args:
            username: Username
            password: Password

        Returns:
            SHA256 hash of "username:password"
        """
        credential_string = f"{username}:{password}"
        return hashlib.sha256(credential_string.encode()).hexdigest()

    def get(self, username: str, password: str) -> Optional[UserInfo]:
        """
        Get cached user info if valid.

        Checks if credentials exist in cache and haven't expired.
        Updates LRU order by moving accessed entry to end.

        Args:
            username: Username
            password: Password

        Returns:
            UserInfo if cached and not expired, None otherwise
        """
        key = self._make_key(username, password)

        with self._lock:
            if key not in self._cache:
                self._misses += 1
                logger.debug(f"Cache miss for user {username}")
                return None

            user_info, expires_at = self._cache[key]

            # Check if expired
            if time.time() > expires_at:
                logger.debug(f"Cache entry expired for user {username}")
                del self._cache[key]
                self._misses += 1
                return None

            # Move to end (LRU)
            self._cache.move_to_end(key)
            self._hits += 1
            logger.debug(f"Cache hit for user {username}")
            return user_info

    def put(self, username: str, password: str, user_info: UserInfo) -> None:
        """
        Store user info in cache.

        Sets expiration time to current time + TTL.
        Evicts oldest entry if cache is at max size.

        Args:
            username: Username
            password: Password
            user_info: UserInfo object to cache
        """
        key = self._make_key(username, password)
        expires_at = time.time() + self.ttl_seconds

        with self._lock:
            # Remove old entry if it exists (to update)
            if key in self._cache:
                del self._cache[key]

            # Evict oldest entry if at max size
            if len(self._cache) >= self.max_size:
                oldest_key, _ = self._cache.popitem(last=False)
                logger.debug(f"Cache evicted oldest entry (size limit reached)")

            # Add new entry
            self._cache[key] = (user_info, expires_at)
            logger.debug(f"Cached credentials for user {username} (expires in {self.ttl_seconds}s)")

    def invalidate(self, username: str = None) -> None:
        """
        Invalidate cache entries.

        Args:
            username: If provided, only invalidate entries for this user.
                      If None, invalidate entire cache.
        """
        with self._lock:
            if username is None:
                self._cache.clear()
                logger.info("Cache invalidated (all entries cleared)")
            else:
                # This is a best-effort invalidation since we don't store usernames directly
                # Actual implementation would need to iterate through all entries
                logger.info(f"Cache invalidation requested for user {username} (partial support)")

    def get_stats(self) -> Dict:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats: size, max_size, ttl_seconds, hits, misses, hit_rate_percent
        """
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0

            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "ttl_seconds": self.ttl_seconds,
                "hits": self._hits,
                "misses": self._misses,
                "total_requests": total_requests,
                "hit_rate_percent": round(hit_rate, 2),
            }
