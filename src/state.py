"""
Entity State Tracking System

Maintains per-entity attack progression state across multiple stages.
Enforces stage order and time window constraints.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from models import Event, Incident
import config


class EntityState:
    """
    Tracks attack chain progression for a single entity.
    
    Attributes:
        entity_id: User or host identifier
        current_stage: Current attack stage (1, 2, or 3)
        stage_events: Events collected for each stage
        score: Accumulated confidence score
        first_signal_time: Timestamp of first signal in chain
        last_signal_time: Timestamp of most recent signal
    """
    
    def __init__(self, entity_id: str):
        self.entity_id = entity_id
        self.current_stage = 0  # No stage active yet
        self.stage_events: Dict[int, List[Event]] = {1: [], 2: [], 3: []}
        self.score = 0.0
        self.first_signal_time: Optional[datetime] = None
        self.last_signal_time: Optional[datetime] = None
    
    def reset(self):
        """Reset entity state after incident or timeout."""
        self.current_stage = 0
        self.stage_events = {1: [], 2: [], 3: []}
        self.score = 0.0
        self.first_signal_time = None
        self.last_signal_time = None
    
    def is_chain_expired(self, current_time: datetime) -> bool:
        """
        Check if attack chain has expired based on time window.
        
        Args:
            current_time: Current timestamp
            
        Returns:
            True if chain has exceeded maximum duration
        """
        if self.first_signal_time is None:
            return False
        
        duration = current_time - self.first_signal_time
        return duration > config.MAX_CHAIN_DURATION
    
    def can_accept_stage(self, stage: int) -> bool:
        """
        Check if entity can accept an event for the given stage.
        
        Enforces sequential stage progression: 1 → 2 → 3
        
        Args:
            stage: Proposed stage number
            
        Returns:
            True if stage is next in sequence
        """
        # First signal can be stage 1
        if self.current_stage == 0:
            return stage == 1
        
        # Otherwise, must be current stage or next stage
        return stage == self.current_stage or stage == self.current_stage + 1
    
    def add_event(self, event: Event):
        """
        Add event to entity state and update progression.
        
        Args:
            event: Event to add
        """
        stage = event.stage
        
        # Initialize first signal time
        if self.first_signal_time is None:
            self.first_signal_time = event.timestamp
        
        # Update last signal time
        self.last_signal_time = event.timestamp
        
        # Add to stage events
        self.stage_events[stage].append(event)
        
        # Update score
        signal_weight = config.SIGNAL_WEIGHTS.get(event.signal_type, 0.0)
        self.score += signal_weight
        
        # Advance stage if moving to new stage
        if stage > self.current_stage:
            self.current_stage = stage
    
    def is_chain_complete(self) -> bool:
        """
        Check if all three stages have been completed.
        
        Returns:
            True if stages 1, 2, and 3 all have events
        """
        return all(len(self.stage_events[s]) > 0 for s in [1, 2, 3])
    
    def get_timeline(self) -> List[Event]:
        """
        Get chronologically ordered timeline of all events.
        
        Returns:
            Sorted list of all events in chain
        """
        all_events = []
        for stage_list in self.stage_events.values():
            all_events.extend(stage_list)
        
        # Sort by timestamp
        all_events.sort(key=lambda e: e.timestamp)
        return all_events
    
    def create_incident(self) -> Incident:
        """
        Create an Incident object from current state.
        
        Returns:
            Incident with full timeline and confidence score
        """
        timeline = self.get_timeline()
        
        return Incident(
            entity_id=self.entity_id,
            start_time=timeline[0].timestamp,
            end_time=timeline[-1].timestamp,
            confidence=min(self.score, 100.0),  # Cap at 100%
            timeline=timeline
        )


class StateTracker:
    """
    Manages state for all entities in the system.
    """
    
    def __init__(self):
        self.entities: Dict[str, EntityState] = {}
    
    def get_or_create_state(self, entity_id: str) -> EntityState:
        """
        Get existing entity state or create new one.
        
        Args:
            entity_id: Entity identifier
            
        Returns:
            EntityState object
        """
        if entity_id not in self.entities:
            self.entities[entity_id] = EntityState(entity_id)
        return self.entities[entity_id]
    
    def process_event(self, event: Event) -> Optional[Incident]:
        """
        Process a single event and update entity state.
        
        Returns:
            Incident if attack chain completes, None otherwise
        """
        entity_id = event.entity_id
        state = self.get_or_create_state(entity_id)
        
        # Check if chain has expired
        if state.is_chain_expired(event.timestamp):
            state.reset()
        
        # Check if we can accept this stage
        if not state.can_accept_stage(event.stage):
            # Out of order signal - could reset or ignore
            # For now, we ignore out-of-order signals
            return None
        
        # Add event to state
        state.add_event(event)
        
        # Check if chain is complete and confidence threshold met
        if state.is_chain_complete() and state.score >= config.CONFIDENCE_THRESHOLD:
            incident = state.create_incident()
            state.reset()  # Reset for future detection
            return incident
        
        return None
    
    def reset_entity(self, entity_id: str):
        """
        Reset state for a specific entity.
        
        Args:
            entity_id: Entity to reset
        """
        if entity_id in self.entities:
            self.entities[entity_id].reset()
    
    def get_active_entities(self) -> List[str]:
        """
        Get list of entities with active attack chains.
        
        Returns:
            List of entity IDs
        """
        return [
            entity_id 
            for entity_id, state in self.entities.items() 
            if state.current_stage > 0
        ]
