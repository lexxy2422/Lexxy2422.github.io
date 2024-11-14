import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import re

class ThreatAnalyzer:
    def __init__(self):
        self.setup_logging()
        self.rules = self.load_detection_rules()
        self.event_cache = defaultdict(list)
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('siem_analyzer.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('SIEM_Analyzer')

    def load_detection_rules(self):
        """Load detection rules from configuration"""
        # Example rules - in production, these should be loaded from a config file
        return {
            'brute_force': {
                'event_id': 4625,  # Failed login attempt
                'threshold': 5,
                'timeframe': 300,  # 5 minutes
                'severity': 'high',
                'description': 'Multiple failed login attempts detected'
            },
            'privilege_escalation': {
                'event_id': 4672,  # Special privileges assigned to new logon
                'threshold': 1,
                'timeframe': 60,
                'severity': 'critical',
                'description': 'Suspicious privilege escalation detected'
            },
            'suspicious_powershell': {
                'event_id': 4104,  # PowerShell script block logging
                'threshold': 1,
                'timeframe': 300,
                'severity': 'high',
                'patterns': [
                    r'(?i)invoke-mimikatz',
                    r'(?i)bypass|encodedcommand|-enc|-e',
                    r'(?i)downloadstring|downloadfile|invoke-webrequest',
                    r'(?i)hidden|vbscript|bitsadmin'
                ],
                'description': 'Suspicious PowerShell command detected'
            },
            'admin_brute_force': {
                'event_id': 4625,
                'threshold': 3,
                'timeframe': 300,
                'target_account_type': 'Administrator',
                'severity': 'critical',
                'description': 'Multiple failed administrator login attempts'
            },
            'suspicious_process': {
                'event_id': 4688,  # Process creation
                'threshold': 1,
                'timeframe': 300,
                'severity': 'medium',
                'suspicious_paths': [
                    r'\\temp\\',
                    r'\\downloads\\',
                    r'\\appdata\\',
                ],
                'suspicious_names': [
                    'cmd.exe',
                    'powershell.exe',
                    'psexec.exe',
                    'mimikatz',
                    'procdump'
                ],
                'description': 'Suspicious process creation detected'
            },
            'data_exfiltration': {
                'event_id': 5156,  # Network connection
                'threshold': 100,
                'timeframe': 300,
                'severity': 'high',
                'suspicious_ports': [21, 22, 23, 25, 445, 3389, 4444, 4445],
                'min_data_size': 10000000,  # 10MB
                'description': 'Potential data exfiltration detected'
            },
            'unusual_network': {
                'event_id': 5156,
                'threshold': 50,
                'timeframe': 300,
                'severity': 'medium',
                'unusual_hours': [0, 1, 2, 3, 4, 5],  # Midnight to 5 AM
                'description': 'Unusual network activity detected'
            }
        }

    def analyze_event(self, event):
        """Analyze a single event for potential threats"""
        try:
            event_id = event.get('event_id')
            timestamp = datetime.fromisoformat(event.get('timestamp'))
            
            # Check event against rules
            for rule_name, rule in self.rules.items():
                if event_id == rule['event_id']:
                    if rule_name == 'suspicious_powershell':
                        self._analyze_powershell(rule_name, rule, event, timestamp)
                    elif rule_name == 'admin_brute_force':
                        self._analyze_admin_login(rule_name, rule, event, timestamp)
                    elif rule_name == 'suspicious_process':
                        self._analyze_process(rule_name, rule, event, timestamp)
                    elif rule_name in ['data_exfiltration', 'unusual_network']:
                        self._analyze_network(rule_name, rule, event, timestamp)
                    else:
                        self._check_rule_violation(rule_name, rule, event, timestamp)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing event: {str(e)}")

    def _analyze_powershell(self, rule_name, rule, event, timestamp):
        """Analyze PowerShell commands for suspicious patterns"""
        command = event.get('command_line', '').lower()
        for pattern in rule['patterns']:
            if re.search(pattern, command):
                self._generate_alert(rule_name, rule, [{
                    'timestamp': timestamp,
                    'event': event,
                    'matched_pattern': pattern
                }])

    def _analyze_admin_login(self, rule_name, rule, event, timestamp):
        """Analyze failed administrator login attempts"""
        if event.get('target_account_type') == rule['target_account_type']:
            self._check_rule_violation(rule_name, rule, event, timestamp)

    def _analyze_process(self, rule_name, rule, event, timestamp):
        """Analyze process creation events"""
        process_path = event.get('process_path', '').lower()
        process_name = event.get('process_name', '').lower()
        
        is_suspicious = False
        for path in rule['suspicious_paths']:
            if re.search(path.lower(), process_path):
                is_suspicious = True
                break
                
        if process_name in [name.lower() for name in rule['suspicious_names']]:
            is_suspicious = True
            
        if is_suspicious:
            self._generate_alert(rule_name, rule, [{
                'timestamp': timestamp,
                'event': event
            }])

    def _analyze_network(self, rule_name, rule, event, timestamp):
        """Analyze network connection events"""
        if rule_name == 'data_exfiltration':
            if (event.get('destination_port') in rule['suspicious_ports'] and
                event.get('data_size', 0) >= rule['min_data_size']):
                self._check_rule_violation(rule_name, rule, event, timestamp)
        
        elif rule_name == 'unusual_network':
            event_hour = timestamp.hour
            if event_hour in rule['unusual_hours']:
                self._check_rule_violation(rule_name, rule, event, timestamp)

    def _check_rule_violation(self, rule_name, rule, event, timestamp):
        """Check if an event violates a specific rule"""
        # Clean old events from cache
        self._clean_event_cache(rule['timeframe'])
        
        # Add current event to cache
        self.event_cache[rule_name].append({
            'timestamp': timestamp,
            'event': event
        })
        
        # Check if rule threshold is exceeded
        if len(self.event_cache[rule_name]) >= rule['threshold']:
            self._generate_alert(rule_name, rule, self.event_cache[rule_name])

    def _clean_event_cache(self, timeframe):
        """Remove old events from cache"""
        current_time = datetime.now()
        for rule_name in list(self.event_cache.keys()):
            self.event_cache[rule_name] = [
                e for e in self.event_cache[rule_name]
                if (current_time - e['timestamp']).total_seconds() <= timeframe
            ]

    def _generate_alert(self, rule_name, rule, events):
        """Generate security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'rule_name': rule_name,
            'severity': rule['severity'],
            'event_count': len(events),
            'events': events
        }
        
        self.logger.warning(f"Security Alert: {json.dumps(alert, default=str)}")
        # In production, send alert to SIEM dashboard or security team

if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
