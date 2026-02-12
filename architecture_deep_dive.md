# SIEM Architecture Deep Dive

This document details the internal logic of the Attack Chain SIEM, focusing on the detection algorithms and data persistence mechanisms.

## 1. C2 Beacon Detection Algorithm (`src/beacon_detector.py`)

The core of the system is differentiating between normal web traffic (bursty, irregular) and Command & Control (C2) beacons (periodic, machine-like).

### The Math: Interval Analysis

We analyze the **time intervals** ($t$) between consecutive network connections to the same destination.

$$ \Delta t_i = Timestamp_{i+1} - Timestamp_i $$

For a set of intervals, we calculate three key metrics:

1.  **Mean Interval ($\mu$)**: The average time between phone-homes.
    $$ \mu = \frac{\sum \Delta t}{N} $$
2.  **Variance ($\sigma^2$)**: How much the intervals differ from the average.
    $$ \sigma^2 = \frac{\sum (\Delta t_i - \mu)^2}{N} $$
3.  **Jitter (Coefficient of Variation)**: A normalized measure of irregularity.
    $$ CV = \frac{\sigma}{\mu} $$

### Detection Logic

A "Beacon" is flagged if:
- **Count > Threshold**: Enough data points exist (default: 4+ connections).
- **Mean > Threshold**: Not just a rapid burst of packets (default: >30s).
- **Jitter $\approx$ 0**: The connection is highly regular (machine-like).

By calculating Jitter (CV), we can distinguish between:
- **Perfect Beacon**: 60s, 60s, 60s $\rightarrow$ $CV = 0.0$ (High Danger)
- **Jittered Beacon**: 58s, 62s, 59s $\rightarrow$ $CV \approx 0.05$ (Suspicious)
- **User Browsing**: 10s, 300s, 5s $\rightarrow$ $CV > 1.0$ (Benign)

## 2. Attack Chain Correlation (`src/correlator.py`)

The system uses a **Stateful Correlation Engine** to link individual events into a narrative.

### State Machine

Each entity (user/host) has a `State` object tracking their progress:

- **Stage 0 (Clean)**: No suspicious activity.
- **Stage 1 (Access)**: `access_anomaly` detected (e.g., VPN from new location).
    - *Timer starts*.
- **Stage 2 (Beacon)**: `beacon_detected` (from component #1) occurs targeting external IP.
    - *Must happen within 1 hour of Stage 1*.
- **Stage 3 (Objective)**: `objective` event detected (e.g., Data Exfiltration).
    - *Must happen within 2 hours of chain start*.

### Incident Generation

An `Incident` is ONLY generated if:
1.  Entity reaches **Stage 3**.
2.  Total accumulated **Confidence Score > 70**.
    - $Score = \sum (Signal Weight \times Severity)$

## 3. Robust Storage (`src/storage.py`)

Data persistence is handled via SQLite with strict safety mechanisms.

### Schema
- **Events Table**: Stores raw signals with JSON metadata.
- **Incidents Table**: Stores completed attack chains.

### Safety Mechanisms
- **Context Management**: All DB operations use `contextlib.closing` to safe-guard connections.
    ```python
    with closing(get_db_connection(db_path)) as conn:
        # Connection automatically closes even if errors occur
        cursor = conn.cursor()
        ...
    ```
- **Error Handling**: Wrapped in `try/except sqlite3.Error` to prevent the detection pipeline from crashing due to disk I/O issues.
