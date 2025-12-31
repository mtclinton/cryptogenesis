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

    def __bool__(self) -> bool:
        """
        Make ServiceResult truthy/falsy based on success.

        Returns:
            True if success, False otherwise
        """
        return self.success

    def __repr__(self) -> str:
        """
        String representation for debugging.

        Returns:
            String representation of the result
        """
        if self.success:
            return f"ServiceResult(success=True, data={repr(self.data)})"
        else:
            return f"ServiceResult(success=False, error={repr(self.error)})"

    def is_success(self) -> bool:
        """
        Check if the operation was successful.

        Returns:
            True if successful, False otherwise
        """
        return self.success

    def is_error(self) -> bool:
        """
        Check if the operation failed.

        Returns:
            True if failed, False otherwise
        """
        return not self.success
