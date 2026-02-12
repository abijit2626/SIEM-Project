"""
SQLite Storage Layer

Provides persistence for events and incidents.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Optional
from models import Event, Incident
import config


from contextlib import closing

def get_db_connection(db_path: str = config.DATABASE_PATH):
    """
    Get a database connection with row factory.
    
    Args:
        db_path: Path to database file
        
    Returns:
        sqlite3.Connection
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = config.DATABASE_PATH):
    """
    Initialize SQLite database with required schema.
    
    Args:
        db_path: Path to database file
    """
    try:
        with closing(get_db_connection(db_path)) as conn:
            cursor = conn.cursor()
            
            # Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    signal_type TEXT NOT NULL,
                    stage INTEGER NOT NULL,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for query performance
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_entity 
                ON events(entity_id, timestamp)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_signal 
                ON events(signal_type)
            ''')
            
            # Incidents table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE NOT NULL,
                    entity_id TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    timeline TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_incidents_entity 
                ON incidents(entity_id)
            ''')
            
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
        raise


def store_event(event: Event, db_path: str = config.DATABASE_PATH):
    """
    Store a single event in the database.
    
    Args:
        event: Event to store
        db_path: Path to database file
    """
    try:
        with closing(get_db_connection(db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO events (timestamp, entity_id, signal_type, stage, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                event.timestamp.isoformat(),
                event.entity_id,
                event.signal_type,
                event.stage,
                json.dumps(event.metadata)
            ))
            
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error storing event: {e}")
        # Build robust logging in detection systems, but re-raise for now to fail tests
        raise


def store_events_batch(events: List[Event], db_path: str = config.DATABASE_PATH):
    """
    Store multiple events efficiently.
    
    Args:
        events: List of events to store
        db_path: Path to database file
    """
    if not events:
        return

    try:
        with closing(get_db_connection(db_path)) as conn:
            cursor = conn.cursor()
            
            data = [
                (
                    e.timestamp.isoformat(),
                    e.entity_id,
                    e.signal_type,
                    e.stage,
                    json.dumps(e.metadata)
                )
                for e in events
            ]
            
            cursor.executemany('''
                INSERT INTO events (timestamp, entity_id, signal_type, stage, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', data)
            
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error storing event batch: {e}")
        raise


def store_incident(incident: Incident, db_path: str = config.DATABASE_PATH):
    """
    Store an incident with full timeline.
    
    Args:
        incident: Incident to store
        db_path: Path to database file
    """
    try:
        with closing(get_db_connection(db_path)) as conn:
            cursor = conn.cursor()
            
            # Convert incident to dict for JSON storage
            incident_dict = incident.to_dict()
            
            cursor.execute('''
                INSERT INTO incidents (incident_id, entity_id, start_time, end_time, confidence, timeline)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                incident.incident_id,
                incident.entity_id,
                incident.start_time.isoformat(),
                incident.end_time.isoformat(),
                incident.confidence,
                json.dumps(incident_dict['timeline'])
            ))
            
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error storing incident: {e}")
        raise


def get_incidents(db_path: str = config.DATABASE_PATH) -> List[dict]:
    """
    Retrieve all incidents from database.
    
    Args:
        db_path: Path to database file
        
    Returns:
        List of incident dictionaries
    """
    try:
        with closing(get_db_connection(db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT incident_id, entity_id, start_time, end_time, confidence, timeline, created_at
                FROM incidents
                ORDER BY start_time DESC
            ''')
            
            incidents = []
            for row in cursor.fetchall():
                incidents.append({
                    'incident_id': row['incident_id'],
                    'entity_id': row['entity_id'],
                    'start_time': row['start_time'],
                    'end_time': row['end_time'],
                    'confidence': row['confidence'],
                    'timeline': json.loads(row['timeline']),
                    'created_at': row['created_at']
                })
            
            return incidents
    except sqlite3.Error as e:
        print(f"Error retrieving incidents: {e}")
        return []


def get_events_for_entity(entity_id: str, db_path: str = config.DATABASE_PATH) -> List[dict]:
    """
    Get all events for a specific entity.
    
    Args:
        entity_id: Entity identifier
        db_path: Path to database file
        
    Returns:
        List of event dictionaries
    """
    try:
        with closing(get_db_connection(db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, entity_id, signal_type, stage, metadata
                FROM events
                WHERE entity_id = ?
                ORDER BY timestamp
            ''', (entity_id,))
            
            events = []
            for row in cursor.fetchall():
                events.append({
                    'timestamp': row['timestamp'],
                    'entity_id': row['entity_id'],
                    'signal_type': row['signal_type'],
                    'stage': row['stage'],
                    'metadata': json.loads(row['metadata'])
                })
            
            return events
    except sqlite3.Error as e:
        print(f"Error retrieving events: {e}")
        return []


def clear_database(db_path: str = config.DATABASE_PATH):
    """
    Clear all data from database (for testing).
    
    Args:
        db_path: Path to database file
    """
    try:
        with closing(get_db_connection(db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM events')
            cursor.execute('DELETE FROM incidents')
            
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error clearing database: {e}")
        raise
