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


def init_db(db_path: str = config.DATABASE_PATH):
    """
    Initialize SQLite database with required schema.
    
    Args:
        db_path: Path to database file
    """
    conn = sqlite3.connect(db_path)
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
    conn.close()


def store_event(event: Event, db_path: str = config.DATABASE_PATH):
    """
    Store a single event in the database.
    
    Args:
        event: Event to store
        db_path: Path to database file
    """
    conn = sqlite3.connect(db_path)
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
    conn.close()


def store_events_batch(events: List[Event], db_path: str = config.DATABASE_PATH):
    """
    Store multiple events efficiently.
    
    Args:
        events: List of events to store
        db_path: Path to database file
    """
    conn = sqlite3.connect(db_path)
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
    conn.close()


def store_incident(incident: Incident, db_path: str = config.DATABASE_PATH):
    """
    Store an incident with full timeline.
    
    Args:
        incident: Incident to store
        db_path: Path to database file
    """
    conn = sqlite3.connect(db_path)
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
    conn.close()


def get_incidents(db_path: str = config.DATABASE_PATH) -> List[dict]:
    """
    Retrieve all incidents from database.
    
    Args:
        db_path: Path to database file
        
    Returns:
        List of incident dictionaries
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT incident_id, entity_id, start_time, end_time, confidence, timeline, created_at
        FROM incidents
        ORDER BY start_time DESC
    ''')
    
    incidents = []
    for row in cursor.fetchall():
        incidents.append({
            'incident_id': row[0],
            'entity_id': row[1],
            'start_time': row[2],
            'end_time': row[3],
            'confidence': row[4],
            'timeline': json.loads(row[5]),
            'created_at': row[6]
        })
    
    conn.close()
    return incidents


def get_events_for_entity(entity_id: str, db_path: str = config.DATABASE_PATH) -> List[dict]:
    """
    Get all events for a specific entity.
    
    Args:
        entity_id: Entity identifier
        db_path: Path to database file
        
    Returns:
        List of event dictionaries
    """
    conn = sqlite3.connect(db_path)
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
            'timestamp': row[0],
            'entity_id': row[1],
            'signal_type': row[2],
            'stage': row[3],
            'metadata': json.loads(row[4])
        })
    
    conn.close()
    return events


def clear_database(db_path: str = config.DATABASE_PATH):
    """
    Clear all data from database (for testing).
    
    Args:
        db_path: Path to database file
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM events')
    cursor.execute('DELETE FROM incidents')
    
    conn.commit()
    conn.close()
