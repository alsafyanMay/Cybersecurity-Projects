"""
Parser for Linux log files to extract IP addresses, threats, and security events
"""
import re
import gzip
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import ipaddress


class LogParser:
    def __init__(self):
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        self.threat_patterns = {
            'failed_login': [
                r'Failed password',
                r'authentication failure',
                r'Invalid user',
                r'Connection closed',
                r'Connection refused'
            ],
            'brute_force': [
                r'multiple authentication failures',
                r'too many authentication failures',
                r'blocked.*attempts'
            ],
            'suspicious_activity': [
                r'POSSIBLE BREAK-IN',
                r'possible break-in',
                r'suspicious',
                r'anomalous'
            ],
            'malware': [
                r'malware',
                r'virus',
                r'trojan',
                r'exploit'
            ],
            'spam': [
                r'spam',
                r'SPAM',
                r'rejected.*spam'
            ],
            'ddos': [
                r'flood',
                r'DDoS',
                r'too many connections',
                r'connection limit'
            ]
        }
        
    def is_private_ip(self, ip_str):
        """Check if IP is private/local"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except:
            return False
    
    def parse_secure_log(self, log_path, max_lines=None):
        """Parse /var/log/secure for authentication and security events
        
        Args:
            log_path: Path to secure log file
            max_lines: Maximum number of lines to parse (None for all, useful for large files)
        """
        events = []
        ip_events = defaultdict(lambda: {
            'count': 0,
            'threats': defaultdict(int),
            'first_seen': None,
            'last_seen': None,
            'services': set(),
            'failed_logins': 0,
            'successful_logins': 0
        })
        
        def read_file(filepath):
            if filepath.suffix == '.gz':
                return gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
            else:
                return open(filepath, 'r', encoding='utf-8', errors='ignore')
        
        log_file = Path(log_path)
        if not log_file.exists():
            return events, ip_events
        
        # Optimized reading for large files - use tail approach
        try:
            if max_lines and log_file.stat().st_size > 5 * 1024 * 1024:  # > 5MB
                # For large files, read from end using efficient method
                import subprocess
                try:
                    # Use tail command for efficiency
                    result = subprocess.run(
                        ['tail', '-n', str(max_lines), str(log_file)],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        lines = result.stdout.splitlines()
                    else:
                        # Fallback: read normally but limit
                        with read_file(log_file) as f:
                            lines = list(f)[-max_lines:]
                except:
                    # Fallback: read normally
                    with read_file(log_file) as f:
                        lines = list(f)[-max_lines:] if max_lines else list(f)
            else:
                # Small files: read normally
                with read_file(log_file) as f:
                    lines = list(f)
            
            # Process lines efficiently
            for line in lines:
                if not line or not line.strip():
                    continue
                
                line = line.strip()
                
                # Extract IP addresses first (fast check)
                ips = self.ip_pattern.findall(line)
                if not ips:
                    continue
                
                public_ips = [ip for ip in ips if not self.is_private_ip(ip)]
                if not public_ips:
                    continue
                
                # Extract timestamp
                timestamp_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
                timestamp = None
                if timestamp_match:
                    try:
                        timestamp = datetime.strptime(
                            f"{datetime.now().year} {timestamp_match.group(1)}",
                            "%Y %b %d %H:%M:%S"
                        )
                    except:
                        pass
                
                # Determine threat type
                threat_type = None
                threat_level = 'low'
                
                line_lower = line.lower()
                
                if any(re.search(pattern, line_lower) for pattern in self.threat_patterns['brute_force']):
                    threat_type = 'brute_force'
                    threat_level = 'high'
                elif any(re.search(pattern, line_lower) for pattern in self.threat_patterns['failed_login']):
                    threat_type = 'failed_login'
                    threat_level = 'medium'
                elif any(re.search(pattern, line_lower) for pattern in self.threat_patterns['suspicious_activity']):
                    threat_type = 'suspicious_activity'
                    threat_level = 'high'
                elif any(re.search(pattern, line_lower) for pattern in self.threat_patterns['malware']):
                    threat_type = 'malware'
                    threat_level = 'critical'
                elif any(re.search(pattern, line_lower) for pattern in self.threat_patterns['spam']):
                    threat_type = 'spam'
                    threat_level = 'medium'
                elif any(re.search(pattern, line_lower) for pattern in self.threat_patterns['ddos']):
                    threat_type = 'ddos'
                    threat_level = 'critical'
                
                # Extract service
                service = None
                if 'ssh' in line_lower:
                    service = 'SSH'
                elif 'ftp' in line_lower:
                    service = 'FTP'
                elif 'http' in line_lower or 'apache' in line_lower:
                    service = 'HTTP'
                elif 'mysql' in line_lower or 'mariadb' in line_lower:
                    service = 'MySQL'
                elif 'exim' in line_lower:
                    service = 'Email'
                
                for ip in public_ips:
                    ip_data = ip_events[ip]
                    ip_data['count'] += 1
                    
                    if timestamp:
                        if ip_data['first_seen'] is None or timestamp < ip_data['first_seen']:
                            ip_data['first_seen'] = timestamp
                        if ip_data['last_seen'] is None or timestamp > ip_data['last_seen']:
                            ip_data['last_seen'] = timestamp
                    
                    if threat_type:
                        ip_data['threats'][threat_type] += 1
                    
                    if service:
                        ip_data['services'].add(service)
                    
                    if 'failed' in line_lower or 'failure' in line_lower:
                        ip_data['failed_logins'] += 1
                    elif 'accepted' in line_lower or 'success' in line_lower:
                        ip_data['successful_logins'] += 1
                    
                    events.append({
                        'timestamp': timestamp.isoformat() if timestamp else None,
                        'ip': ip,
                        'threat_type': threat_type,
                        'threat_level': threat_level,
                        'service': service,
                        'log_line': line[:200]  # Truncate long lines
                    })
        
        except Exception as e:
            print(f"Error parsing {log_path}: {e}")
            import traceback
            traceback.print_exc()
        
        # Convert sets to lists for JSON serialization
        for ip_data in ip_events.values():
            ip_data['services'] = list(ip_data['services'])
            if ip_data['first_seen']:
                ip_data['first_seen'] = ip_data['first_seen'].isoformat()
            if ip_data['last_seen']:
                ip_data['last_seen'] = ip_data['last_seen'].isoformat()
        
        return events, dict(ip_events)
    
    def parse_messages_log(self, log_path, max_lines=None):
        """Parse /var/log/messages for system events - Optimized"""
        events = []
        ip_events = defaultdict(lambda: {
            'count': 0,
            'threats': defaultdict(int),
            'first_seen': None,
            'last_seen': None,
            'services': set()
        })
        
        def read_file(filepath):
            if filepath.suffix == '.gz':
                return gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
            else:
                return open(filepath, 'r', encoding='utf-8', errors='ignore')
        
        log_file = Path(log_path)
        if not log_file.exists():
            return events, ip_events
        
        # Optimized reading for large files
        try:
            if max_lines and log_file.stat().st_size > 5 * 1024 * 1024:  # > 5MB
                import subprocess
                try:
                    result = subprocess.run(
                        ['tail', '-n', str(max_lines), str(log_file)],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        lines = result.stdout.splitlines()
                    else:
                        with read_file(log_file) as f:
                            lines = list(f)[-max_lines:]
                except:
                    with read_file(log_file) as f:
                        lines = list(f)[-max_lines:] if max_lines else list(f)
            else:
                with read_file(log_file) as f:
                    lines = list(f)
            
            for line in lines:
                if not line or not line.strip():
                    continue
                
                line = line.strip()
                
                ips = self.ip_pattern.findall(line)
                public_ips = [ip for ip in ips if not self.is_private_ip(ip)]
                
                if not public_ips:
                    continue
                
                line_lower = line.lower()
                threat_type = None
                threat_level = 'low'
                
                if any(re.search(pattern, line_lower) for pattern in self.threat_patterns['ddos']):
                    threat_type = 'ddos'
                    threat_level = 'critical'
                elif any(re.search(pattern, line_lower) for pattern in self.threat_patterns['suspicious_activity']):
                    threat_type = 'suspicious_activity'
                    threat_level = 'high'
                
                for ip in public_ips:
                    ip_events[ip]['count'] += 1
                    if threat_type:
                        ip_events[ip]['threats'][threat_type] += 1
                    
                    events.append({
                        'ip': ip,
                        'threat_type': threat_type,
                        'threat_level': threat_level,
                        'log_line': line[:200]
                    })
        
        except Exception as e:
            print(f"Error parsing {log_path}: {e}")
            import traceback
            traceback.print_exc()
        
        for ip_data in ip_events.values():
            ip_data['services'] = list(ip_data['services'])
        
        return events, dict(ip_events)
    
    def parse_exim_log(self, log_path):
        """Parse Exim mail logs for spam and email threats"""
        events = []
        ip_events = defaultdict(lambda: {
            'count': 0,
            'threats': defaultdict(int),
            'first_seen': None,
            'last_seen': None,
            'services': ['Email']
        })
        
        def read_file(filepath):
            if filepath.suffix == '.gz':
                return gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
            else:
                return open(filepath, 'r', encoding='utf-8', errors='ignore')
        
        log_file = Path(log_path)
        if not log_file.exists():
            return events, ip_events
        
        try:
            with read_file(log_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    ips = self.ip_pattern.findall(line)
                    public_ips = [ip for ip in ips if not self.is_private_ip(ip)]
                    
                    if not public_ips:
                        continue
                    
                    line_lower = line.lower()
                    threat_type = None
                    threat_level = 'low'
                    
                    if 'rejected' in line_lower or 'reject' in line_lower:
                        threat_type = 'spam'
                        threat_level = 'medium'
                    
                    for ip in public_ips:
                        ip_events[ip]['count'] += 1
                        if threat_type:
                            ip_events[ip]['threats'][threat_type] += 1
                        
                        events.append({
                            'ip': ip,
                            'threat_type': threat_type,
                            'threat_level': threat_level,
                            'service': 'Email',
                            'log_line': line[:200]
                        })
        
        except Exception as e:
            print(f"Error parsing {log_path}: {e}")
        
        for ip_data in ip_events.values():
            ip_data['services'] = list(ip_data['services'])
        
        return events, dict(ip_events)
    
    def parse_all_logs(self, log_dir='/var/log', max_lines_per_file=None):
        """Parse all relevant log files
        
        Args:
            log_dir: Directory containing log files
            max_lines_per_file: Maximum lines to parse per file (None for all)
                              Useful for large files like messages (35MB+)
        """
        log_dir = Path(log_dir)
        all_events = []
        all_ip_events = defaultdict(lambda: {
            'count': 0,
            'threats': defaultdict(int),
            'first_seen': None,
            'last_seen': None,
            'services': set(),
            'failed_logins': 0,
            'successful_logins': 0
        })
        
        # Parse secure log
        secure_log = log_dir / 'secure'
        if secure_log.exists():
            # For secure log, use more lines (it's usually smaller and more important)
            secure_max = max_lines_per_file * 2 if max_lines_per_file else None
            events, ip_events = self.parse_secure_log(secure_log, max_lines=secure_max)
            all_events.extend(events)
            for ip, data in ip_events.items():
                for key, value in data.items():
                    if key == 'services':
                        all_ip_events[ip]['services'].update(value)
                    elif key in ['threats']:
                        for threat, count in value.items():
                            all_ip_events[ip]['threats'][threat] += count
                    elif key == 'count':
                        all_ip_events[ip]['count'] += value
                    elif key in ['failed_logins', 'successful_logins']:
                        all_ip_events[ip][key] += value
                    elif key in ['first_seen', 'last_seen']:
                        if value:
                            if all_ip_events[ip][key] is None:
                                all_ip_events[ip][key] = value
                            else:
                                if key == 'first_seen':
                                    if value < all_ip_events[ip][key]:
                                        all_ip_events[ip][key] = value
                                else:
                                    if value > all_ip_events[ip][key]:
                                        all_ip_events[ip][key] = value
        
        # Parse messages log (with max_lines for performance)
        messages_log = log_dir / 'messages'
        if messages_log.exists():
            events, ip_events = self.parse_messages_log(messages_log, max_lines=max_lines_per_file)
            all_events.extend(events)
            for ip, data in ip_events.items():
                all_ip_events[ip]['count'] += data['count']
                for threat, count in data['threats'].items():
                    all_ip_events[ip]['threats'][threat] += count
                all_ip_events[ip]['services'].update(data.get('services', []))
        
        # Parse exim logs
        exim_log = log_dir / 'exim_rejectlog'
        if exim_log.exists():
            events, ip_events = self.parse_exim_log(exim_log)
            all_events.extend(events)
            for ip, data in ip_events.items():
                all_ip_events[ip]['count'] += data['count']
                for threat, count in data['threats'].items():
                    all_ip_events[ip]['threats'][threat] += count
                all_ip_events[ip]['services'].update(data.get('services', []))
        
        # Convert sets to lists
        for ip_data in all_ip_events.values():
            ip_data['services'] = list(ip_data['services'])
        
        return all_events, dict(all_ip_events)
