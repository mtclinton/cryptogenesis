"""
Event Type Definitions

Base event class and event type definitions.
"""

from typing import Any, Optional
from cryptogenesis.util import get_time


class Event:
    """
    Base event class.
    
    All events inherit from this class.
    Contains timestamp and data fields.
    """
    
    def __init__(self, data: Optional[Any] = None):
        """
        Initialize event.
        
        Args:
            data: Optional event data
        """
        self.timestamp = get_time()
        self.data = data
    
    def __repr__(self) -> str:
        """String representation for debugging"""
        return f"{self.__class__.__name__}(timestamp={self.timestamp}, data={repr(self.data)})"

