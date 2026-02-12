"""
Main Pipeline for Attack Chain SIEM

Orchestrates the complete detection workflow:
1. Generate synthetic events
2. Run beacon detection
3. Perform attack chain correlation
4. Store results
5. Generate incident reports
"""

import os
from datetime import datetime
from models import Event, Incident
from events import generate_test_dataset
from beacon_detector import detect_beacons, format_beacon_summary
from correlator import AttackChainCorrelator
from storage import init_db, store_events_batch, store_incident, clear_database
import config


def print_header(title: str):
    """Print formatted section header."""
    print(f"\n{'='*80}")
    print(f"{title:^80}")
    print(f"{'='*80}\n")


def main():
    """
    Execute the complete SIEM pipeline.
    """
    print_header("ATTACK CHAIN SIEM - Starting Pipeline")
    
    # Step 1: Initialize database
    print("📦 Initializing database...")
    if os.path.exists(config.DATABASE_PATH):
        clear_database()
    init_db()
    print(f"   ✓ Database initialized: {config.DATABASE_PATH}\n")
    
    # Step 2: Generate synthetic events
    print("🔄 Generating synthetic events...")
    events = generate_test_dataset()
    print(f"   ✓ Generated {len(events)} events")
    print(f"   ✓ Events span: {events[0].timestamp} to {events[-1].timestamp}\n")
    
    # Step 3: Store events
    print("💾 Storing events in database...")
    store_events_batch(events)
    print(f"   ✓ Stored {len(events)} events\n")
    
    # Step 4: Detect beacons
    print("🔍 Running beacon detection...")
    beacon_events = detect_beacons(events)
    print(f"   ✓ Detected {len(beacon_events)} beacon connections")
    
    # Print beacon summary
    if beacon_events:
        print(format_beacon_summary(beacon_events))
    
    # Step 5: Run correlation engine
    print("🧠 Running attack chain correlation...")
    correlator = AttackChainCorrelator()
    incidents = correlator.correlate_events(events)
    print(f"   ✓ Detected {len(incidents)} complete attack chain(s)\n")
    
    # Step 6: Store and display incidents
    if incidents:
        print_header("INCIDENTS DETECTED")
        
        for incident in incidents:
            # Store in database
            store_incident(incident)
            
            # Print formatted report
            print(incident.format_report())
            print()
        
        # Save to output file
        output_dir = 'outputs'
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, 'sample_incident_output.txt')
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("ATTACK CHAIN SIEM - Incident Report\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            
            for incident in incidents:
                f.write(incident.format_report())
                f.write("\n\n")
        
        print(f"📄 Full report saved to: {output_file}\n")
    else:
        print("✓ No incidents detected (all events were normal or partial chains)\n")
    
    # Step 7: Summary statistics
    print_header("PIPELINE SUMMARY")
    print(f"Total Events Processed:     {len(events)}")
    print(f"Beacon Connections Detected: {len(beacon_events)}")
    print(f"Incidents Generated:        {len(incidents)}")
    
    # Show active entities (incomplete chains)
    active = correlator.get_active_entities()
    if active:
        print(f"\nEntities with Partial Chains: {', '.join(active)}")
        print("(Not enough evidence for incident generation)")
    
    print(f"\n{'='*80}\n")
    print("✅ Pipeline completed successfully!")
    print(f"📊 Database: {config.DATABASE_PATH}")
    print(f"📄 Report:   outputs/sample_incident_output.txt\n")


if __name__ == '__main__':
    main()
