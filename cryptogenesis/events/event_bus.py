"""
Event Bus

Central event dispatcher for decoupled communication.
"""

import threading
from collections import defaultdict
from typing import Callable, List, Type

from cryptogenesis.events.events import Event


class EventBus:
    """
    Event bus for publishing and subscribing to events.
    
    Provides decoupled communication between components.
    Thread-safe implementation using RLock.
    """
    
    def __init__(self):
        """Initialize event bus"""
        # Thread lock for thread-safe operations
        self._lock = threading.RLock()
        # Map of event type to list of subscribers (defaultdict for convenience)
        self._subscribers: defaultdict[Type[Event], List[Callable]] = defaultdict(list)
    
    def subscribe(self, event_type: Type[Event], handler: Callable) -> None:
        """
        Subscribe to events of a specific type.
        
        Thread-safe operation that adds handler to subscribers list.
        
        Args:
            event_type: Event class to subscribe to
            handler: Callback function to call when event is published
        """
        with self._lock:
            # Add handler if not already subscribed (avoid duplicates)
            if handler not in self._subscribers[event_type]:
                self._subscribers[event_type].append(handler)
    
    def unsubscribe(self, event_type: Type[Event], handler: Callable) -> None:
        """
        Unsubscribe from events of a specific type.
        
        Thread-safe operation that removes handler from subscribers.
        
        Args:
            event_type: Event class to unsubscribe from
            handler: Callback function to remove
        """
        with self._lock:
            if event_type in self._subscribers and handler in self._subscribers[event_type]:
                self._subscribers[event_type].remove(handler)
                # Clean up empty lists (optional, but good practice)
                if not self._subscribers[event_type]:
                    del self._subscribers[event_type]
    
    def publish(self, event: Event) -> None:
        """
        Publish an event to all subscribers.
        
        Thread-safe operation that calls all handlers for the event type.
        Errors in handlers are logged but don't crash the event bus.
        
        Args:
            event: Event instance to publish
        """
        # Get handlers for this event type (thread-safe copy)
        handlers = []
        with self._lock:
            # Get handlers for exact event type
            handlers.extend(self._subscribers[type(event)])
            # Also get handlers for base Event class (if any)
            if Event in self._subscribers and Event not in (type(event),):
                handlers.extend(self._subscribers[Event])
        
        # Call handlers outside of lock to avoid deadlocks
        # and allow handlers to publish events if needed
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                # Log error but don't crash
                # Using print for now, can be replaced with proper logging
                print(f"Error in event handler {handler.__name__ if hasattr(handler, '__name__') else handler}: {e}")
                import traceback
                traceback.print_exc()

