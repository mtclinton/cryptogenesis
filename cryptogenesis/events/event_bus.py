"""
Event Bus

Central event dispatcher for decoupled communication.
"""

from typing import Callable, Dict, List, Optional

from cryptogenesis.events.events import Event


class EventBus:
    """
    Event bus for publishing and subscribing to events.
    
    Provides decoupled communication between components.
    """
    
    def __init__(self):
        """Initialize event bus"""
        # Map of event type to list of subscribers
        self._subscribers: Dict[type, List[Callable]] = {}
    
    def subscribe(self, event_type: type, handler: Callable):
        """
        Subscribe to events of a specific type.
        
        Args:
            event_type: Event class to subscribe to
            handler: Callback function to call when event is published
        """
        pass
    
    def publish(self, event: Event):
        """
        Publish an event to all subscribers.
        
        Args:
            event: Event instance to publish
        """
        pass

