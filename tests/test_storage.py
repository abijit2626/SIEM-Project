import sys
import unittest
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import json
import sqlite3
from datetime import datetime
from models import Event, Incident
import storage
import config

class TestStorage(unittest.TestCase):
    
    def setUp(self):
        self.test_db = 'test_siem.db'
        # Ensure clean state
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
            
        storage.init_db(self.test_db)
        self.base_time = datetime(2026, 2, 12, 10, 0, 0)
        
    def tearDown(self):
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
            
    def test_store_and_retrieve_event(self):
        event = Event(
            timestamp=self.base_time,
            entity_id='user_test',
            signal_type='network',
            stage=2,
            metadata={'ip': '1.2.3.4'}
        )
        
        storage.store_event(event, self.test_db)
        
        events = storage.get_events_for_entity('user_test', self.test_db)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['entity_id'], 'user_test')
        self.assertEqual(events[0]['metadata']['ip'], '1.2.3.4')
        
    def test_store_and_retrieve_incident(self):
        incident = Incident(
            incident_id='inc_123',
            entity_id='user_victim',
            start_time=self.base_time,
            end_time=self.base_time,
            confidence=85.0,
            timeline=[]
        )
        
        storage.store_incident(incident, self.test_db)
        
        incidents = storage.get_incidents(self.test_db)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]['incident_id'], 'inc_123')
        self.assertEqual(incidents[0]['confidence'], 85.0)

if __name__ == '__main__':
    unittest.main()
