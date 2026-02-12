"""
Configuration settings for the Attack Chain SIEM.

All thresholds and parameters are defined here for easy tuning.
"""

from datetime import timedelta


# Time Window Settings
# ---------------------
# Maximum time allowed between stages for correlation
STAGE_WINDOW_SECONDS = 3600  # 1 hour per stage
FULL_CHAIN_WINDOW_SECONDS = 7200  # 2 hours for complete attack chain

# If time between events exceeds this, entity state resets
MAX_CHAIN_DURATION = timedelta(seconds=FULL_CHAIN_WINDOW_SECONDS)


# Beacon Detection Settings
# --------------------------
# Minimum number of connections to same destination to consider as beacon
MIN_BEACON_CONNECTIONS = 4

# Maximum allowed variance in interval (seconds) to be considered "regular"
# E.g., for 60s beacon with 5s tolerance: intervals like 58s, 61s, 59s are OK
BEACON_INTERVAL_TOLERANCE = 5

# Minimum interval to avoid flagging rapid bursts as beacons
MIN_BEACON_INTERVAL = 30  # seconds


# Scoring and Confidence
# ----------------------
# Weights for each signal type (0-100 scale)
SIGNAL_WEIGHTS = {
    'access_anomaly': 30.0,
    'beacon_detected': 40.0,
    'objective': 30.0
}

# Minimum confidence score to generate incident
CONFIDENCE_THRESHOLD = 70.0


# Stage Definitions
# -----------------
STAGE_MAPPINGS = {
    'access_anomaly': 1,
    'network': 2,
    'beacon_detected': 2,
    'objective': 3
}


# Storage Settings
# ----------------
DATABASE_PATH = 'siem_data.db'


# Event Generation Settings (for testing)
# ----------------------------------------
NORMAL_EVENT_COUNT = 100  # Background noise events
ATTACK_CHAIN_COUNT = 1    # Number of full attack chains to generate
BEACON_ONLY_COUNT = 1     # Partial chains for negative testing


def get_stage_for_signal(signal_type: str) -> int:
    """
    Map signal type to attack chain stage.
    
    Args:
        signal_type: Type of signal detected
        
    Returns:
        Stage number (1, 2, or 3)
    """
    return STAGE_MAPPINGS.get(signal_type, 0)
