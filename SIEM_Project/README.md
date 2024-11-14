# SIEM Detection and Prevention System

A Security Information and Event Management (SIEM) system for monitoring, detecting, and preventing security threats in real-time.

## Features

- **Log Collection**: Collects and processes Windows Event logs and other system logs
- **Threat Detection**: Analyzes events using configurable detection rules
- **Automated Response**: Implements preventive measures based on detected threats
- **Real-time Monitoring**: Continuous monitoring and analysis of security events

## Components

1. **Log Collector** (`log_collector.py`)
   - Collects Windows Event logs
   - Processes system and application logs
   - Provides structured event data for analysis

2. **Threat Analyzer** (`analyzer.py`)
   - Implements detection rules
   - Analyzes events for potential threats
   - Generates security alerts

3. **Threat Prevention** (`prevention.py`)
   - Implements automated response actions
   - Handles security alerts
   - Executes preventive measures

4. **SIEM Orchestrator** (`siem_main.py`)
   - Coordinates all SIEM components
   - Manages the event processing pipeline
   - Handles system startup and shutdown

## Setup

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure logging directories in `log_collector.py`

3. Review and customize detection rules in `analyzer.py`

4. Configure response actions in `prevention.py`

## Usage

Run the SIEM system:
```bash
python siem_main.py
```

The system will:
- Start collecting logs from configured sources
- Analyze events using detection rules
- Generate alerts for detected threats
- Execute automated response actions

## Detection Rules

Current implementation includes rules for:
- Brute force attack detection
- Privilege escalation attempts

Add custom rules by modifying the `load_detection_rules()` method in `analyzer.py`.

## Response Actions

Available automated responses:
- IP blocking
- Account disabling
- Session termination
- Admin alerts

Configure response actions in the `load_response_actions()` method in `prevention.py`.

## Logging

All components generate logs in their respective log files:
- `siem.log`: Main system logs
- `siem_analyzer.log`: Threat analysis logs
- `siem_prevention.log`: Response action logs

## Requirements

- Python 3.8+
- Windows OS (for Windows Event log collection)
- Administrative privileges (for some response actions)

## Security Considerations

- Run with appropriate permissions
- Regularly review and update detection rules
- Monitor false positives and adjust thresholds
- Backup system before implementing automated responses

## Contributing

Feel free to contribute by:
- Adding new detection rules
- Implementing additional response actions
- Improving log collection mechanisms
- Enhancing analysis capabilities
