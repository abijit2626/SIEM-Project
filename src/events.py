"""
Synthetic event generation for testing the SIEM system.

Generates realistic attack chains and normal background traffic.
"""

import random
from datetime import datetime, timedelta
from typing import List
from models import Event


def generate_normal_events(count: int, entity_id: str, base_time: datetime) -> List[Event]:
    """
    Generate benign background network traffic.
    
    Args:
        count: Number of normal events to generate
        entity_id: Entity generating the traffic
        base_time: Starting timestamp
        
    Returns:
        List of normal network events
    """
    events = []
    current_time = base_time
    
    # Common legitimate destinations
    legitimate_ips = [
        '8.8.8.8',           # Google DNS
        '1.1.1.1',           # Cloudflare DNS
        '93.184.216.34',     # Example.com
        '142.250.185.46',    # Google
        '13.107.42.14'       # Microsoft
    ]
    
    for _ in range(count):
        # Random time increment (1-300 seconds)
        current_time += timedelta(seconds=random.randint(1, 300))
        
        event = Event(
            timestamp=current_time,
            entity_id=entity_id,
            signal_type='network',
            stage=2,
            metadata={
                'destination_ip': random.choice(legitimate_ips),
                'port': random.choice([80, 443, 53]),
                'bytes': random.randint(100, 5000),
                'protocol': 'TCP'
            }
        )
        events.append(event)
    
    return events


def generate_attack_chain(entity_id: str, base_time: datetime) -> List[Event]:
    """
    Generate a complete 3-stage attack chain.
    
    Stage 1: Access Anomaly (off-hours login, unusual location)
    Stage 2: C2 Beacon (regular 60s intervals to attacker IP)
    Stage 3: Objective (data exfiltration)
    
    Args:
        entity_id: Compromised entity
        base_time: Attack start time
        
    Returns:
        List of events forming complete attack chain
    """
    events = []
    current_time = base_time
    
    # Stage 1: Access Anomaly
    access_event = Event(
        timestamp=current_time,
        entity_id=entity_id,
        signal_type='access_anomaly',
        stage=1,
        metadata={
            'reason': 'Off-hours login from unusual location',
            'source_ip': '185.220.101.47',  # Known Tor exit node range
            'time_of_day': '03:42',
            'geo_location': 'Unknown/Proxy',
            'user_agent': 'curl/7.68.0'
        }
    )
    events.append(access_event)
    
    # Stage 2: C2 Beacon Pattern (5 connections at 60s intervals)
    # This creates a detectable beacon signature
    attacker_c2 = '45.142.212.61'  # Simulated C2 server
    beacon_interval = 60  # seconds
    
    for i in range(5):
        current_time += timedelta(seconds=beacon_interval)
        beacon_event = Event(
            timestamp=current_time,
            entity_id=entity_id,
            signal_type='network',
            stage=2,
            metadata={
                'destination_ip': attacker_c2,
                'port': 443,
                'bytes': random.randint(200, 500),  # Small beacon payloads
                'protocol': 'TCP',
                'connection_type': 'HTTPS'
            }
        )
        events.append(beacon_event)
    
    # Stage 3: Objective (data exfiltration)
    current_time += timedelta(seconds=120)
    objective_event = Event(
        timestamp=current_time,
        entity_id=entity_id,
        signal_type='objective',
        stage=3,
        metadata={
            'action': 'Large data transfer',
            'destination_ip': attacker_c2,
            'bytes': 524288000,  # 500 MB exfiltration
            'file_accessed': '/var/db/customer_data.db',
            'port': 443
        }
    )
    events.append(objective_event)
    
    return events


def generate_beacon_only(entity_id: str, base_time: datetime) -> List[Event]:
    """
    Generate isolated beacon behavior WITHOUT access anomaly or objective.
    
    This should NOT trigger an incident (partial chain).
    
    Args:
        entity_id: Entity with beacon behavior
        base_time: Beacon start time
        
    Returns:
        List of beacon events only
    """
    events = []
    current_time = base_time
    
    # Beacon pattern to legitimate-looking IP (could be compromised server)
    suspicious_ip = '104.21.45.78'
    beacon_interval = 90  # 90-second beacons
    
    for i in range(6):
        current_time += timedelta(seconds=beacon_interval)
        beacon_event = Event(
            timestamp=current_time,
            entity_id=entity_id,
            signal_type='network',
            stage=2,
            metadata={
                'destination_ip': suspicious_ip,
                'port': 8080,
                'bytes': random.randint(150, 400),
                'protocol': 'TCP'
            }
        )
        events.append(beacon_event)
    
    return events


def generate_access_and_objective_only(entity_id: str, base_time: datetime) -> List[Event]:
    """
    Generate access anomaly + objective WITHOUT beacon.
    
    This should NOT trigger an incident (missing Stage 2).
    
    Args:
        entity_id: Entity identifier
        base_time: Event start time
        
    Returns:
        List of events (access + objective, no beacon)
    """
    events = []
    
    # Stage 1: Access anomaly
    access_event = Event(
        timestamp=base_time,
        entity_id=entity_id,
        signal_type='access_anomaly',
        stage=1,
        metadata={
            'reason': 'Failed login attempts',
            'source_ip': '192.168.1.100',
            'attempts': 5
        }
    )
    events.append(access_event)
    
    # Stage 3: Objective (no Stage 2 beacon)
    objective_event = Event(
        timestamp=base_time + timedelta(minutes=10),
        entity_id=entity_id,
        signal_type='objective',
        stage=3,
        metadata={
            'action': 'Privilege escalation attempt',
            'command': 'sudo su -',
            'result': 'failed'
        }
    )
    events.append(objective_event)
    
    return events


def generate_test_dataset() -> List[Event]:
    """
    Generate complete test dataset with normal and malicious events.
    
    Returns:
        Combined list of all events (shuffled by timestamp)
    """
    base_time = datetime(2026, 2, 12, 10, 0, 0)  # Start at 10 AM
    all_events = []
    
    # Normal background traffic from multiple entities
    all_events.extend(generate_normal_events(50, 'user_normal_1', base_time))
    all_events.extend(generate_normal_events(50, 'user_normal_2', base_time))
    
    # Complete attack chain (should trigger incident)
    all_events.extend(generate_attack_chain('user_compromised', base_time + timedelta(hours=1)))
    
    # Partial chains (should NOT trigger incidents)
    all_events.extend(generate_beacon_only('user_beacon_only', base_time + timedelta(hours=2)))
    all_events.extend(generate_access_and_objective_only('user_partial', base_time + timedelta(hours=3)))
    
    # Sort all events by timestamp (realistic processing order)
    all_events.sort(key=lambda e: e.timestamp)
    
    return all_events
