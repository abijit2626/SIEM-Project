"""
C2 Beacon Detection Engine

Identifies Command & Control (C2) beacon-like network behavior by analyzing
periodic connection patterns to external IPs.
"""

from collections import defaultdict
from typing import List, Dict, Tuple
from datetime import datetime
from models import Event
import config


def calculate_interval_regularity(intervals: List[float]) -> Tuple[float, float]:
    """
    Calculate mean and variance of time intervals.
    
    Args:
        intervals: List of time intervals in seconds
        
    Returns:
        Tuple of (mean_interval, variance)
    """
    if not intervals:
        return 0.0, 0.0
    
    mean = sum(intervals) / len(intervals)
    
    # Calculate variance
    if len(intervals) == 1:
        variance = 0.0
    else:
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    
    return mean, variance


def detect_beacons(events: List[Event]) -> List[Event]:
    """
    Detect C2 beacon patterns in network events.
    
    Algorithm:
    1. Group network events by (entity_id, destination_ip)
    2. Calculate time intervals between consecutive connections
    3. Check for regularity:
       - Low variance in intervals (within tolerance)
       - Minimum connection count met
       - Interval not too short (avoid flagging bursts)
    4. Tag matches as 'beacon_detected' events
    
    Args:
        events: List of all events to analyze
        
    Returns:
        List of beacon_detected events (subset of input with updated signal_type)
    """
    # Filter to network events only
    network_events = [e for e in events if e.signal_type == 'network']
    
    # Group by (entity_id, destination_ip)
    connections: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    
    for event in network_events:
        entity_id = event.entity_id
        dest_ip = event.metadata.get('destination_ip', '')
        
        if dest_ip:
            connections[(entity_id, dest_ip)].append(event)
    
    beacon_events = []
    
    # Analyze each connection group
    for (entity_id, dest_ip), conn_events in connections.items():
        # Need minimum connections to establish pattern
        if len(conn_events) < config.MIN_BEACON_CONNECTIONS:
            continue
        
        # Sort by timestamp
        conn_events.sort(key=lambda e: e.timestamp)
        
        # Calculate intervals between consecutive connections
        intervals = []
        for i in range(1, len(conn_events)):
            time_diff = (conn_events[i].timestamp - conn_events[i-1].timestamp).total_seconds()
            intervals.append(time_diff)
        
        if not intervals:
            continue
        
        # Check for interval regularity
        mean_interval, variance = calculate_interval_regularity(intervals)
        
        # Skip if intervals too short (likely a burst, not beacon)
        if mean_interval < config.MIN_BEACON_INTERVAL:
            continue
        
        # Check if variance is within acceptable tolerance
        # Using standard deviation for easier interpretation
        std_dev = variance ** 0.5
        
        # Beacon detected if intervals are regular (low variance)
        if std_dev <= config.BEACON_INTERVAL_TOLERANCE:
            # Create beacon_detected events for this pattern
            for event in conn_events:
                # Create new event with updated signal type
                beacon_event = Event(
                    timestamp=event.timestamp,
                    entity_id=event.entity_id,
                    signal_type='beacon_detected',
                    stage=2,  # Beacons are Stage 2 (C2 communication)
                    metadata={
                        **event.metadata,
                        'beacon_pattern': True,
                        'mean_interval': round(mean_interval, 2),
                        'interval_variance': round(variance, 2),
                        'connection_count': len(conn_events),
                        'destination_ip': dest_ip
                    }
                )
                beacon_events.append(beacon_event)
    
    return beacon_events


def format_beacon_summary(beacon_events: List[Event]) -> str:
    """
    Generate human-readable summary of detected beacons.
    
    Args:
        beacon_events: List of beacon_detected events
        
    Returns:
        Formatted summary string
    """
    if not beacon_events:
        return "No beacons detected."
    
    # Group by entity and destination
    beacons_by_entity: Dict[str, List[Event]] = defaultdict(list)
    for event in beacon_events:
        beacons_by_entity[event.entity_id].append(event)
    
    lines = [f"\n{'='*60}", "BEACON DETECTION SUMMARY", f"{'='*60}"]
    
    for entity_id, events in beacons_by_entity.items():
        # Get unique destinations
        destinations = set(e.metadata.get('destination_ip', '') for e in events)
        
        for dest_ip in destinations:
            dest_events = [e for e in events if e.metadata.get('destination_ip') == dest_ip]
            if not dest_events:
                continue
            
            sample = dest_events[0]
            mean_interval = sample.metadata.get('mean_interval', 0)
            count = sample.metadata.get('connection_count', 0)
            
            lines.append(f"\nEntity: {entity_id}")
            lines.append(f"  → Destination: {dest_ip}")
            lines.append(f"  → Connections: {count}")
            lines.append(f"  → Avg Interval: {mean_interval}s")
            lines.append(f"  → Pattern: Regular beacon detected")
    
    lines.append(f"{'='*60}\n")
    return "\n".join(lines)
