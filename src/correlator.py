"""
Attack Chain Correlation Engine

Orchestrates the complete detection pipeline:
1. Processes events chronologically
2. Runs beacon detection
3. Updates entity state
4. Generates incidents when chains complete
"""

from typing import List
from models import Event, Incident
from beacon_detector import detect_beacons
from state import StateTracker
import config


class AttackChainCorrelator:
    """
    Main correlation engine that combines beacon detection with
    multi-stage attack chain correlation.
    """
    
    def __init__(self):
        self.state_tracker = StateTracker()
    
    def correlate_events(self, events: List[Event]) -> List[Incident]:
        """
        Process all events and generate incidents for complete attack chains.
        
        Pipeline:
        1. Sort events chronologically (realistic processing)
        2. Detect beacon patterns in network events
        3. Process all events (normal + beacon) through state tracker
        4. Return generated incidents
        
        Args:
            events: All events to process
            
        Returns:
            List of detected incidents
        """
        incidents = []
        
        # Step 1: Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Step 2: Run beacon detection on network events
        beacon_events = detect_beacons(sorted_events)
        
        # Create a set of beacon event identifiers for quick lookup
        # We'll use (entity_id, timestamp, dest_ip) as unique identifier
        beacon_signatures = {
            (be.entity_id, be.timestamp, be.metadata.get('destination_ip'))
            for be in beacon_events
        }
        
        # Step 3: Process all events, replacing network events with beacon events where detected
        for event in sorted_events:
            # Determine if this event should be treated as a beacon
            event_signature = (
                event.entity_id, 
                event.timestamp, 
                event.metadata.get('destination_ip')
            )
            
            # If this network event was detected as a beacon, use the beacon version
            if event_signature in beacon_signatures:
                # Find the corresponding beacon event
                beacon_event = next(
                    be for be in beacon_events 
                    if (be.entity_id, be.timestamp, be.metadata.get('destination_ip')) == event_signature
                )
                process_event = beacon_event
            else:
                process_event = event
            
            # Only process events that map to attack stages
            if process_event.stage not in [1, 2, 3]:
                continue
            
            # Process through state tracker
            incident = self.state_tracker.process_event(process_event)
            
            if incident:
                incidents.append(incident)
        
        return incidents
    
    def get_active_entities(self) -> List[str]:
        """
        Get entities with active (incomplete) attack chains.
        
        Returns:
            List of entity IDs
        """
        return self.state_tracker.get_active_entities()


def correlate_simple(events: List[Event]) -> List[Incident]:
    """
    Simple convenience function for correlation.
    
    Args:
        events: Events to correlate
        
    Returns:
        List of incidents
    """
    correlator = AttackChainCorrelator()
    return correlator.correlate_events(events)
