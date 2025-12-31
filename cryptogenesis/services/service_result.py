"""
Service Result

Result type for service operations.
"""

from typing import Any, Optional


class ServiceResult:
    """
    Result type for service operations.

    Fields:
        success: bool - Whether the operation succeeded
        data: Any (optional) - Result data if successful
        error: str (optional) - Error message if failed
    """

    def __init__(self, success: bool, data: Any = None, error: Optional[str] = None):
        self.success = success
        self.data = data
        self.error = error
