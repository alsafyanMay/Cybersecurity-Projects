"""
Behavior Analysis Module for IP addresses
"""
from collections import defaultdict
from datetime import datetime, timedelta
import statistics


class BehaviorAnalyzer:
    def __init__(self):
        pass
    
    def analyze_ip_behavior(self, ip_data, events):
        """Analyze behavior patterns for an IP address"""
        ip_events = [e for e in events if e.get('ip') == ip_data['ip']]
        
        if not ip_events:
            return {
                'pattern': 'no_activity',
                'risk_level': 'low',
                'characteristics': []
            }
        
        behavior = {
            'pattern': 'normal',
            'risk_level': 'low',
            'characteristics': [],
            'timing_pattern': {},
            'service_targeting': {},
            'attack_pattern': {}
        }
        
        # Analyze timing patterns
        timestamps = []
        for event in ip_events:
            if event.get('timestamp'):
                try:
                    ts = datetime.fromisoformat(event['timestamp'])
                    timestamps.append(ts)
                except:
                    pass
        
        if timestamps:
            timestamps.sort()
            behavior['timing_pattern'] = {
                'first_seen': timestamps[0].isoformat(),
                'last_seen': timestamps[-1].isoformat(),
                'duration_hours': (timestamps[-1] - timestamps[0]).total_seconds() / 3600,
                'total_events': len(timestamps),
                'events_per_hour': len(timestamps) / max((timestamps[-1] - timestamps[0]).total_seconds() / 3600, 1)
            }
            
            # Check for rapid-fire attacks
            if len(timestamps) > 10:
                intervals = []
                for i in range(1, len(timestamps)):
                    interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                    intervals.append(interval)
                
                avg_interval = statistics.mean(intervals) if intervals else 0
                if avg_interval < 5:  # Less than 5 seconds between attempts
                    behavior['characteristics'].append('rapid_fire_attack')
                    behavior['risk_level'] = 'high'
                    behavior['pattern'] = 'automated_attack'
        
        # Analyze service targeting
        services = defaultdict(int)
        for event in ip_events:
            if event.get('service'):
                services[event['service']] += 1
        
        behavior['service_targeting'] = dict(services)
        
        if len(services) > 3:
            behavior['characteristics'].append('multi_service_targeting')
            behavior['risk_level'] = 'high'
        
        # Analyze attack patterns
        threat_types = defaultdict(int)
        for event in ip_events:
            if event.get('threat_type'):
                threat_types[event['threat_type']] += 1
        
        behavior['attack_pattern'] = dict(threat_types)
        
        # Determine overall pattern
        if 'brute_force' in threat_types or 'failed_login' in threat_types:
            if threat_types.get('brute_force', 0) + threat_types.get('failed_login', 0) > 10:
                behavior['pattern'] = 'brute_force_attack'
                behavior['risk_level'] = 'high'
                behavior['characteristics'].append('persistent_brute_force')
        
        if 'ddos' in threat_types:
            behavior['pattern'] = 'ddos_attack'
            behavior['risk_level'] = 'critical'
            behavior['characteristics'].append('distributed_denial_of_service')
        
        if 'malware' in threat_types:
            behavior['pattern'] = 'malware_distribution'
            behavior['risk_level'] = 'critical'
            behavior['characteristics'].append('malware_related')
        
        # Geographic analysis (if location data available)
        if ip_data.get('location'):
            country = ip_data['location'].get('country', 'Unknown')
            behavior['characteristics'].append(f'origin_country_{country}')
        
        # ISP analysis
        if ip_data.get('isp'):
            isp = ip_data['isp'].lower()
            if any(keyword in isp for keyword in ['vpn', 'proxy', 'tor', 'hosting', 'datacenter']):
                behavior['characteristics'].append('suspicious_isp')
                if behavior['risk_level'] == 'low':
                    behavior['risk_level'] = 'medium'
        
        return behavior
    
    def generate_behavior_summary(self, all_behaviors):
        """Generate summary of all IP behaviors"""
        summary = {
            'total_ips': len(all_behaviors),
            'high_risk_count': 0,
            'critical_risk_count': 0,
            'common_patterns': defaultdict(int),
            'top_countries': defaultdict(int),
            'top_services_targeted': defaultdict(int)
        }
        
        for ip, behavior in all_behaviors.items():
            if behavior.get('risk_level') == 'high':
                summary['high_risk_count'] += 1
            elif behavior.get('risk_level') == 'critical':
                summary['critical_risk_count'] += 1
            
            pattern = behavior.get('pattern', 'unknown')
            summary['common_patterns'][pattern] += 1
        
        return summary
