# Attack Chain SIEM

A **stateful, event-driven SIEM system** that detects Command & Control (C2) beacon behavior and correlates it with multi-stage attack patterns to generate high-confidence security incidents.

## 🎯 What This Project Does

This SIEM combines two advanced detection techniques:

1. **C2 Beacon Detection**: Identifies periodic network communication patterns that resemble command-and-control channels
2. **Attack Chain Correlation**: Tracks multi-stage attack progression across entities with temporal constraints

**Key Insight**: Beacon detection alone generates many false positives. This system only triggers incidents when beacons appear as part of a complete attack chain (access anomaly → C2 beacon → objective behavior).

_For a technical deep dive into the algorithms, see [architecture_deep_dive.md](architecture_deep_dive.md)._

---

## 🏗️ Architecture

### Attack Chain Model

The system enforces a **3-stage attack progression model**:

```
Stage 1: Access Anomaly
   ↓
Stage 2: C2 Beacon Communication  
   ↓
Stage 3: Objective Behavior (exfiltration, privilege escalation, etc.)
   ↓
High-Confidence Incident (only if all stages present + time constraints met)
```

**Why this matters**: 
- A beacon alone might be legitimate software
- An access anomaly alone might be a false alarm
- But all three in sequence = actionable threat

### Data Flow

```
Events → Beacon Detector → State Tracker → Correlator → Incidents
                                 ↓
                            SQLite Storage
```

### Core Components

| Component | Responsibility |
|-----------|---------------|
| **models.py** | Data structures (Event, Incident) |
| **config.py** | Tunable parameters (time windows, thresholds) |
| **events.py** | Synthetic event generation for testing |
| **beacon_detector.py** | C2 pattern detection via interval analysis |
| **state.py** | Per-entity attack progression tracking |
| **correlator.py** | Multi-stage correlation engine |
| **storage.py** | SQLite persistence layer |
| **main.py** | End-to-end pipeline orchestration |

---

## 🚀 How to Run

### Prerequisites
- Python 3.8+ (standard library only, no external dependencies)

### Quick Start

```bash
# Run the complete pipeline
cd c:\Users\user\Desktop\Projects\SIEM
python src/main.py
```

**Expected Output**:
- Event generation summary
- Beacon detection results
- Incident report (1 incident detected from attack chain)
- Database and output file creation

### Run Tests

```bash
# Execute test suite
python -m unittest tests.test_full_chain -v
```

**Test Coverage**:
- ✅ Full chain generates incident
- ❌ Beacon only (no incident)
- ❌ Access + Objective without beacon (no incident)
- ✅ Multiple independent entities
- ✅ Time window expiration

---

## 📊 Example Output

See `outputs/sample_incident_output.txt` for a complete incident report showing:
- Entity ID and confidence score
- Full attack timeline with timestamps
- Individual signal details (access anomaly → beacons → exfiltration)

---

## 🧠 Key Design Decisions

### 1. Stateful vs Stateless Detection

**Most SIEMs use stateless alerts**: Each event is evaluated independently.

**This system is stateful**: It maintains per-entity state across events, tracking:
- Current attack stage
- Timeline of signals
- Accumulated confidence score

**Benefit**: Dramatically reduces false positives by requiring complete attack chains.

### 2. Temporal Correlation

Attack stages must occur in **correct order** within a **time window** (configurable in `config.py`):
- Max 1 hour between stages
- Max 2 hours for full chain
- Chain resets if window expires

**Real-world relevance**: Attackers typically execute phases sequentially within hours, not days.

### 3. Explainable Beacon Detection

Uses **interval regularity analysis** instead of ML:
1. Group network events by (entity, destination IP)
2. Calculate time intervals between connections
3. Check variance against threshold
4. Require minimum connection count

**Interview advantage**: You can explain exactly why something was flagged as a beacon.

### 4. No False Confidence

**What this is NOT**:
- ❌ Not a production-ready enterprise SIEM
- ❌ Not an "APT detection system" (requires real threat intel)
- ❌ Not packet-level analysis (works with logs)
- ❌ Not machine learning (explainable rules)

**What this IS**:
- ✅ Demonstrates advanced correlation concepts
- ✅ Shows understanding of attack patterns
- ✅ Clean, maintainable code
- ✅ Interview-ready talking points

---

## 🔍 How This Differs from Simple Alert-Based SIEMs

| Simple SIEM | This Correlation Engine |
|-------------|------------------------|
| Each event evaluated in isolation | Events linked by entity and time |
| High false positive rate | Requires multi-stage confirmation |
| No attack progression tracking | Stateful stage advancement |
| Alert fatigue | High-confidence incidents only |
| Rules fire independently | Temporal correlation enforced |

**Example**: A simple SIEM might alert on:
- 1000 "unusual login" alerts
- 500 "external connection" alerts
- 200 "large data transfer" alerts

This system generates **1 incident** when all three correlate for the same entity in sequence.

---

## 📈 Future Extensions

### Near-term (complexity++)
- Real log ingestion (syslog, Windows Event Logs)
- MITRE ATT&CK technique tagging
- Alert tuning UI
- REST API for integration

### Production path
- **ELK Stack Integration**:
  - **Logstash**: Replace `events.py` with real log ingestion pipelines
  - **Elasticsearch**: Replace SQLite with ES for scalability
  - **Kibana**: Add dashboards for incident visualization
- **Stream Processing**: Migrate to Apache Kafka + Flink for real-time processing
- **Threat Intel**: Integrate IOC feeds for destination IP enrichment

---

## 🎓 Interview Talking Points

### When discussing this project:

1. **"Why stateful correlation?"**
   - Reduces false positives by requiring full attack context
   - Mirrors real attacker kill chains
   - Demonstrates understanding of temporal relationships in security

2. **"How does beacon detection work?"**
   - Analyzes connection intervals for regularity (low variance)
   - Configurable thresholds avoid ML black box
   - Can walk through exact algorithm with pseudocode

3. **"Why SQLite?"**
   - Sufficient for prototype/learning
   - Easy migration path to Elasticsearch
   - Demonstrates SQL schema design

4. **"What would you do differently in production?"**
   - Stream processing (Kafka)
   - Distributed storage (Elasticsearch)
   - Machine learning for anomaly scoring (after explainable baseline)
   - Horizontal scaling for multi-tenant environments

5. **"How do you prevent alert fatigue?"**
   - High confidence threshold (70%+ required)
   - Multi-stage validation (not single-indicator alerts)
   - Clear incident timelines for analyst review

---

## 🛠️ Customization

Edit `src/config.py` to tune:
- Time windows (stage and chain duration)
- Beacon detection thresholds (interval tolerance, min connections)
- Scoring weights (how much each signal contributes)
- Confidence threshold (minimum for incident generation)

---

## 📝 Limitations

- **Synthetic data only**: Real environments require log parsers
- **No network capture**: Works with metadata, not packet payloads
- **Single-host execution**: Not distributed
- **Basic storage**: SQLite not suitable for high-volume production

---

## 📂 Project Structure

```
attack_chain_siem/
│
├── README.md                      ← You are here
│
├── src/
│   ├── main.py                    ← Pipeline orchestration
│   ├── models.py                  ← Event/Incident data models
│   ├── events.py                  ← Synthetic event generation
│   ├── beacon_detector.py         ← C2 pattern detection
│   ├── state.py                   ← Entity state tracking
│   ├── correlator.py              ← Attack chain correlation
│   ├── storage.py                 ← SQLite persistence
│   └── config.py                  ← Configuration parameters
│
├── tests/
│   └── test_full_chain.py         ← Comprehensive test suite
│
└── outputs/
    └── sample_incident_output.txt ← Example incident report
```

---

## 🎯 Learning Outcomes

By building this project, you demonstrate:
- ✅ Understanding of attack progression (cyber kill chain)
- ✅ Stateful system design
- ✅ Temporal correlation logic
- ✅ Database schema design
- ✅ Testing complex systems
- ✅ False positive reduction strategies
- ✅ Clean Python architecture

---

## 📚 References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- Cyber Kill Chain: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- C2 Beacon Detection: https://www.sans.org/white-papers/

---

**Built with Python 🐍 | Interview-Ready 💼 | Production-Minded 🚀**
