"""
Shared HTTP client utilities with connection pooling and reuse.
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Singleton instances
_async_client: Optional[httpx.AsyncClient] = None
_sync_client: Optional[httpx.Client] = None


def get_async_client(
    timeout: float = 30.0,
    max_keepalive_connections: int = 5,
    max_connections: int = 20,
) -> httpx.AsyncClient:
    """Get a shared async HTTP client with connection pooling.
    
    Reuses the same client instance across the application to benefit from
    connection pooling and avoid creating unnecessary connections.
    
    Args:
        timeout: Request timeout in seconds
        max_keepalive_connections: Max keep-alive connections per host
        max_connections: Max total connections
        
    Returns:
        Shared AsyncClient instance
    """
    global _async_client
    
    if _async_client is None:
        limits = httpx.Limits(
            max_keepalive_connections=max_keepalive_connections,
            max_connections=max_connections,
        )
        _async_client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            verify=True,
        )
        logger.debug("Created new async HTTP client with connection pooling")
    
    return _async_client


def get_sync_client(
    timeout: float = 30.0,
    max_keepalive_connections: int = 5,
    max_connections: int = 20,
) -> httpx.Client:
    """Get a shared sync HTTP client with connection pooling.
    
    Reuses the same client instance across the application to benefit from
    connection pooling and avoid creating unnecessary connections.
    
    Args:
        timeout: Request timeout in seconds
        max_keepalive_connections: Max keep-alive connections per host
        max_connections: Max total connections
        
    Returns:
        Shared Client instance
    """
    global _sync_client
    
    if _sync_client is None:
        limits = httpx.Limits(
            max_keepalive_connections=max_keepalive_connections,
            max_connections=max_connections,
        )
        _sync_client = httpx.Client(
            timeout=timeout,
            limits=limits,
            verify=True,
        )
        logger.debug("Created new sync HTTP client with connection pooling")
    
    return _sync_client


async def close_async_client() -> None:
    """Close the shared async client to release resources."""
    global _async_client
    if _async_client is not None:
        await _async_client.aclose()
        _async_client = None
        logger.debug("Closed async HTTP client")


def close_sync_client() -> None:
    """Close the shared sync client to release resources."""
    global _sync_client
    if _sync_client is not None:
        _sync_client.close()
        _sync_client = None
        logger.debug("Closed sync HTTP client")


__all__ = [
    "get_async_client",
    "get_sync_client",
    "close_async_client",
    "close_sync_client",
]
