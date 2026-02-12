
import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from datetime import datetime, timedelta
from models import Event
import beacon_detector
import config

class TestBeaconDetector(unittest.TestCase):
    
    def setUp(self):
        self.base_time = datetime(2026, 2, 12, 10, 0, 0)
        
    def test_calculate_interval_metrics(self):
        # Regular intervals: 60s, 60s, 60s
        intervals = [60.0, 60.0, 60.0]
        mean, variance, jitter = beacon_detector.calculate_interval_metrics(intervals)
        
        self.assertEqual(mean, 60.0)
        self.assertEqual(variance, 0.0)
        self.assertEqual(jitter, 0.0)
        
    def test_calculate_interval_metrics_irregular(self):
        # Irregular: 10s, 100s, 50s
        intervals = [10.0, 100.0, 50.0]
        # Mean = 53.33
        # Variance will be high
        mean, variance, jitter = beacon_detector.calculate_interval_metrics(intervals)
        
        self.assertAlmostEqual(mean, 53.33, places=2)
        self.assertGreater(jitter, 0.5)  # High jitter for irregular traffic

    def test_detect_beacons_with_metadata(self):
        events = []
        dest_ip = '10.0.0.99'
        
        # Create 5 connections at exactly 60s intervals
        for i in range(5):
            events.append(Event(
                timestamp=self.base_time + timedelta(seconds=i * 60),
                entity_id='user_beacon',
                signal_type='network',
                stage=2,
                metadata={'destination_ip': dest_ip}
            ))
            
        beacons = beacon_detector.detect_beacons(events)
        self.assertEqual(len(beacons), 5)
        
        # Check metadata
        first_beacon = beacons[0]
        self.assertEqual(first_beacon.metadata['mean_interval'], 60.0)
        self.assertEqual(first_beacon.metadata['jitter'], 0.0)

if __name__ == '__main__':
    unittest.main()
