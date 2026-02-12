"""
Comprehensive test suite for Attack Chain SIEM.

Tests critical scenarios to ensure correlation logic works correctly.
"""

import unittest
import sys
import os
from datetime import datetime, timedelta

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from models import Event, Incident
from events import generate_attack_chain, generate_beacon_only, generate_access_and_objective_only
from correlator import AttackChainCorrelator
from beacon_detector import detect_beacons
import config


class TestFullChain(unittest.TestCase):
    """Test complete attack chain detection."""
    
    def setUp(self):
        """Initialize correlator for each test."""
        self.correlator = AttackChainCorrelator()
        self.base_time = datetime(2026, 2, 12, 10, 0, 0)
    
    def test_full_chain_generates_incident(self):
        """
        CRITICAL: Full attack chain (access → beacon → objective) MUST generate incident.
        """
        events = generate_attack_chain('user_test', self.base_time)
        incidents = self.correlator.correlate_events(events)
        
        # Should detect exactly 1 incident
        self.assertEqual(len(incidents), 1, "Full attack chain should generate exactly 1 incident")
        
        incident = incidents[0]
        self.assertEqual(incident.entity_id, 'user_test')
        self.assertGreaterEqual(incident.confidence, config.CONFIDENCE_THRESHOLD)
        
        # Check that all 3 stages are present in timeline
        stages = set(e.stage for e in incident.timeline)
        self.assertEqual(stages, {1, 2, 3}, "Incident should contain all 3 stages")
    
    def test_beacon_only_no_incident(self):
        """
        CRITICAL: Beacon pattern alone (no access anomaly) should NOT generate incident.
        """
        events = generate_beacon_only('user_beacon', self.base_time)
        incidents = self.correlator.correlate_events(events)
        
        # Should NOT generate any incidents
        self.assertEqual(len(incidents), 0, "Beacon-only pattern should NOT generate incident")
    
    def test_access_objective_no_beacon_no_incident(self):
        """
        CRITICAL: Access + Objective without beacon should NOT generate incident.
        """
        events = generate_access_and_objective_only('user_partial', self.base_time)
        incidents = self.correlator.correlate_events(events)
        
        # Should NOT generate any incidents (missing Stage 2)
        self.assertEqual(len(incidents), 0, "Partial chain (no beacon) should NOT generate incident")
    
    def test_multiple_entities_independent(self):
        """
        Test that multiple entities are tracked independently.
        """
        # Create attack chains for 2 different entities
        events1 = generate_attack_chain('user_1', self.base_time)
        events2 = generate_attack_chain('user_2', self.base_time + timedelta(hours=1))
        
        all_events = events1 + events2
        incidents = self.correlator.correlate_events(all_events)
        
        # Should detect 2 separate incidents
        self.assertEqual(len(incidents), 2, "Should detect incident for each entity")
        
        entity_ids = {inc.entity_id for inc in incidents}
        self.assertEqual(entity_ids, {'user_1', 'user_2'})
    
    def test_time_window_expiration(self):
        """
        Test that attack chain resets if time window expires.
        """
        events = []
        
        # Stage 1: Access anomaly
        events.append(Event(
            timestamp=self.base_time,
            entity_id='user_timeout',
            signal_type='access_anomaly',
            stage=1,
            metadata={'reason': 'test'}
        ))
        
        # Stage 2: Beacon - but AFTER time window expires (> 2 hours later)
        events.append(Event(
            timestamp=self.base_time + timedelta(hours=3),
            entity_id='user_timeout',
            signal_type='beacon_detected',
            stage=2,
            metadata={'destination_ip': '1.2.3.4'}
        ))
        
        incidents = self.correlator.correlate_events(events)
        
        # Should NOT generate incident (chain expired)
        self.assertEqual(len(incidents), 0, "Expired chain should NOT generate incident")


class TestBeaconDetection(unittest.TestCase):
    """Test beacon detection algorithm."""
    
    def setUp(self):
        self.base_time = datetime(2026, 2, 12, 10, 0, 0)
    
    def test_regular_interval_detected(self):
        """Test that regular 60s intervals are detected as beacons."""
        events = []
        dest_ip = '45.142.212.61'
        
        # Create 5 connections at exactly 60s intervals
        for i in range(5):
            events.append(Event(
                timestamp=self.base_time + timedelta(seconds=i * 60),
                entity_id='user_beacon',
                signal_type='network',
                stage=2,
                metadata={'destination_ip': dest_ip, 'port': 443}
            ))
        
        beacons = detect_beacons(events)
        
        # Should detect all 5 as beacon connections
        self.assertEqual(len(beacons), 5, "Should detect 5 beacon connections")
        self.assertTrue(all(b.signal_type == 'beacon_detected' for b in beacons))
    
    def test_irregular_interval_not_detected(self):
        """Test that irregular intervals are NOT flagged as beacons."""
        events = []
        dest_ip = '8.8.8.8'
        
        # Create connections with very irregular intervals
        intervals = [10, 300, 5, 600, 2]
        current_time = self.base_time
        
        for interval in intervals:
            events.append(Event(
                timestamp=current_time,
                entity_id='user_normal',
                signal_type='network',
                stage=2,
                metadata={'destination_ip': dest_ip, 'port': 80}
            ))
            current_time += timedelta(seconds=interval)
        
        beacons = detect_beacons(events)
        
        # Should NOT detect as beacon (too irregular)
        self.assertEqual(len(beacons), 0, "Irregular traffic should NOT be detected as beacon")
    
    def test_minimum_connection_threshold(self):
        """Test that minimum connection count is enforced."""
        events = []
        dest_ip = '1.2.3.4'
        
        # Create only 3 connections (below MIN_BEACON_CONNECTIONS = 4)
        for i in range(3):
            events.append(Event(
                timestamp=self.base_time + timedelta(seconds=i * 60),
                entity_id='user_test',
                signal_type='network',
                stage=2,
                metadata={'destination_ip': dest_ip, 'port': 443}
            ))
        
        beacons = detect_beacons(events)
        
        # Should NOT detect (below threshold)
        self.assertEqual(len(beacons), 0, "Should not detect beacon with too few connections")


class TestStateTracking(unittest.TestCase):
    """Test entity state tracking."""
    
    def test_stage_ordering_enforced(self):
        """Test that stages must occur in order (1 → 2 → 3)."""
        from state import StateTracker
        
        tracker = StateTracker()
        base_time = datetime(2026, 2, 12, 10, 0, 0)
        
        # Try to send Stage 3 before Stage 1
        event_stage_3 = Event(
            timestamp=base_time,
            entity_id='user_test',
            signal_type='objective',
            stage=3,
            metadata={}
        )
        
        incident = tracker.process_event(event_stage_3)
        
        # Should NOT accept out-of-order stage
        self.assertIsNone(incident, "Out-of-order stage should be rejected")
        
        # Entity should still be at stage 0
        state = tracker.get_or_create_state('user_test')
        self.assertEqual(state.current_stage, 0, "Stage should not advance for out-of-order signal")


if __name__ == '__main__':
    unittest.main(verbosity=2)
