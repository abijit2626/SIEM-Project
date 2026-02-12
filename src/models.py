"""
Core data models for the Attack Chain SIEM system.

Defines Event and Incident dataclasses with clear semantic meaning.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional


@dataclass
class Event:
    """
    Represents a single security event in the system.
    
    Attributes:
        timestamp: When the event occurred
        entity_id: The user or host identifier (e.g., 'user_123', 'host_456')
        signal_type: Type of signal ('access_anomaly', 'network', 'objective', 'beacon_detected')
        stage: Attack chain stage (1=Access, 2=C2/Network, 3=Objective)
        metadata: Additional context (source_ip, destination_ip, action, etc.)
    """
    timestamp: datetime
    entity_id: str
    signal_type: str
    stage: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __repr__(self) -> str:
        return (f"Event(timestamp={self.timestamp.isoformat()}, "
                f"entity_id={self.entity_id}, signal_type={self.signal_type}, "
                f"stage={self.stage})")


@dataclass
class Incident:
    """
    Represents a correlated attack chain with high confidence.
    
    Only generated when all stages complete in correct order within time window.
    
    Attributes:
        entity_id: The compromised user/host
        start_time: Timestamp of first signal in chain
        end_time: Timestamp of final signal in chain
        confidence: Confidence score (0-100)
        timeline: Ordered list of events forming the attack chain
        incident_id: Unique identifier (auto-generated)
    """
    entity_id: str
    start_time: datetime
    end_time: datetime
    confidence: float
    timeline: List[Event]
    incident_id: Optional[str] = None
    
    def __post_init__(self):
        """Generate incident ID if not provided."""
        if self.incident_id is None:
            self.incident_id = f"INC_{self.entity_id}_{int(self.start_time.timestamp())}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert incident to dictionary for storage."""
        return {
            'incident_id': self.incident_id,
            'entity_id': self.entity_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'confidence': self.confidence,
            'timeline': [
                {
                    'timestamp': e.timestamp.isoformat(),
                    'entity_id': e.entity_id,
                    'signal_type': e.signal_type,
                    'stage': e.stage,
                    'metadata': e.metadata
                }
                for e in self.timeline
            ]
        }
    
    def duration_seconds(self) -> float:
        """Calculate attack chain duration in seconds."""
        return (self.end_time - self.start_time).total_seconds()
    
    def format_report(self) -> str:
        """Generate human-readable incident report."""
        lines = [
            "=" * 80,
            f"INCIDENT DETECTED: {self.incident_id}",
            "=" * 80,
            f"Entity: {self.entity_id}",
            f"Confidence: {self.confidence:.1f}%",
            f"Duration: {self.duration_seconds():.0f} seconds",
            f"Time Range: {self.start_time.isoformat()} → {self.end_time.isoformat()}",
            "",
            "ATTACK TIMELINE:",
            "-" * 80,
        ]
        
        for i, event in enumerate(self.timeline, 1):
            stage_name = {1: "ACCESS ANOMALY", 2: "C2 BEACON", 3: "OBJECTIVE"}.get(
                event.stage, "UNKNOWN"
            )
            lines.append(f"{i}. [{event.timestamp.isoformat()}] Stage {event.stage}: {stage_name}")
            lines.append(f"   Signal: {event.signal_type}")
            
            # Format metadata
            if event.metadata:
                for key, value in event.metadata.items():
                    lines.append(f"   {key}: {value}")
            lines.append("")
        
        lines.append("=" * 80)
        return "\n".join(lines)
