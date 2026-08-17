"""
OSINT Security Dashboard - Main Application
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
from log_parser import LogParser
from osint_module import OSINTCollector
from behavior_analyzer import BehaviorAnalyzer
import json
from pathlib import Path

app = Flask(__name__)
CORS(app)

# Initialize modules
log_parser = LogParser()
osint_collector = OSINTCollector()
behavior_analyzer = BehaviorAnalyzer()

# Global data cache
cached_data = {
    'events': [],
    'ip_data': {},
    'enriched_data': {},
    'behaviors': {},
    'last_update': None
}


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'message': 'OSINT Dashboard API is running'})


@app.route('/api/parse-logs', methods=['POST'])
def parse_logs():
    """Parse log files and extract IP data - Optimized"""
    global cached_data
    
    try:
        log_dir = request.json.get('log_dir', '/var/log')
        max_lines = request.json.get('max_lines', 50000)  # Default: parse last 50k lines per file
        
        # Parse logs (this is fast)
        events, ip_data = log_parser.parse_all_logs(log_dir, max_lines_per_file=max_lines)
        
        # Limit IPs for OSINT enrichment to avoid timeout (top 500 most active)
        ip_items = list(ip_data.items())
        ip_items.sort(key=lambda x: x[1].get('count', 0), reverse=True)
        top_ips = dict(ip_items[:500])  # Only enrich top 500 IPs
        
        # Enrich with OSINT data (only top IPs for performance)
        enriched_data = osint_collector.enrich_ip_data(top_ips)
        
        # Add non-enriched IPs with basic data
        for ip, data in ip_data.items():
            if ip not in enriched_data:
                enriched_data[ip] = {
                    **data,
                    'location': {},
                    'isp': 'Unknown',
                    'asn': {},
                    'threat_score': min(data.get('count', 0) * 2, 100),
                    'threat_level': 'low' if data.get('count', 0) < 10 else 'medium'
                }
        
        # Analyze behaviors (only for enriched IPs to save time)
        behaviors = {}
        for ip, data in enriched_data.items():
            if ip in top_ips:
                behaviors[ip] = behavior_analyzer.analyze_ip_behavior(data, events)
        
        cached_data = {
            'events': events,
            'ip_data': ip_data,
            'enriched_data': enriched_data,
            'behaviors': behaviors,
            'last_update': str(Path(log_dir))
        }
        
        return jsonify({
            'status': 'success',
            'message': f'Parsed {len(events)} events from {len(ip_data)} unique IPs',
            'data': {
                'total_events': len(events),
                'total_ips': len(ip_data),
                'enriched_ips': len(top_ips)
            }
        })
    
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': error_msg}), 500


@app.route('/api/dashboard-data', methods=['GET'])
def get_dashboard_data():
    """Get all dashboard data"""
    global cached_data
    
    if not cached_data.get('enriched_data'):
        return jsonify({
            'status': 'error',
            'message': 'No data available. Please parse logs first.'
        }), 404
    
    # Prepare summary statistics
    enriched = cached_data['enriched_data']
    behaviors = cached_data['behaviors']
    
    # Threat statistics
    threat_stats = {
        'by_type': {},
        'by_level': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
        'total_attempts': 0
    }
    
    # Location data for map
    locations = []
    
    # IP details
    ip_details = []
    
    for ip, data in enriched.items():
        # Threat statistics
        for threat_type, count in data.get('threats', {}).items():
            threat_stats['by_type'][threat_type] = threat_stats['by_type'].get(threat_type, 0) + count
        
        threat_level = data.get('threat_level', 'info')
        threat_stats['by_level'][threat_level] = threat_stats['by_level'].get(threat_level, 0) + 1
        
        threat_stats['total_attempts'] += data.get('count', 0)
        
        # Location data
        if data.get('location') and data['location'].get('latitude'):
            locations.append({
                'ip': ip,
                'lat': data['location']['latitude'],
                'lon': data['location']['longitude'],
                'country': data['location'].get('country', 'Unknown'),
                'city': data['location'].get('city', 'Unknown'),
                'threat_level': threat_level,
                'threat_score': data.get('threat_score', 0),
                'attempts': data.get('count', 0)
            })
        
        # IP details
        behavior = behaviors.get(ip, {})
        ip_details.append({
            'ip': ip,
            'location': data.get('location', {}),
            'isp': data.get('isp', 'Unknown'),
            'asn': data.get('asn', {}),
            'threat_level': threat_level,
            'threat_score': data.get('threat_score', 0),
            'threat_types': list(data.get('threats', {}).keys()),
            'attempts': data.get('count', 0),
            'failed_logins': data.get('failed_logins', 0),
            'successful_logins': data.get('successful_logins', 0),
            'services': data.get('services', []),
            'behavior': behavior,
            'first_seen': data.get('first_seen'),
            'last_seen': data.get('last_seen')
        })
    
    # Sort IPs by threat score
    ip_details.sort(key=lambda x: x['threat_score'], reverse=True)
    
    # Service distribution
    service_dist = {}
    for ip_data in enriched.values():
        for service in ip_data.get('services', []):
            service_dist[service] = service_dist.get(service, 0) + 1
    
    # Behavior summary
    behavior_summary = behavior_analyzer.generate_behavior_summary(behaviors)
    
    return jsonify({
        'status': 'success',
        'data': {
            'threat_statistics': threat_stats,
            'locations': locations,
            'ip_details': ip_details[:100],  # Limit to top 100
            'service_distribution': service_dist,
            'behavior_summary': behavior_summary,
            'total_ips': len(enriched),
            'total_events': len(cached_data['events'])
        }
    })


@app.route('/api/ip-details/<ip>', methods=['GET'])
def get_ip_details(ip):
    """Get detailed information about a specific IP"""
    global cached_data
    
    enriched = cached_data.get('enriched_data', {})
    behaviors = cached_data.get('behaviors', {})
    events = cached_data.get('events', [])
    
    if ip not in enriched:
        return jsonify({'status': 'error', 'message': 'IP not found'}), 404
    
    ip_data = enriched[ip]
    behavior = behaviors.get(ip, {})
    ip_events = [e for e in events if e.get('ip') == ip]
    
    return jsonify({
        'status': 'success',
        'data': {
            'ip': ip,
            'osint': {
                'location': ip_data.get('location', {}),
                'isp': ip_data.get('isp', 'Unknown'),
                'asn': ip_data.get('asn', {}),
            },
            'threats': {
                'level': ip_data.get('threat_level', 'info'),
                'score': ip_data.get('threat_score', 0),
                'types': ip_data.get('threats', {}),
                'total_attempts': ip_data.get('count', 0),
                'failed_logins': ip_data.get('failed_logins', 0),
                'successful_logins': ip_data.get('successful_logins', 0)
            },
            'services': ip_data.get('services', []),
            'behavior': behavior,
            'timeline': {
                'first_seen': ip_data.get('first_seen'),
                'last_seen': ip_data.get('last_seen'),
                'recent_events': ip_events[-20:]  # Last 20 events
            }
        }
    })


@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get threat analysis"""
    global cached_data
    
    enriched = cached_data.get('enriched_data', {})
    
    threats_by_level = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': []
    }
    
    for ip, data in enriched.items():
        level = data.get('threat_level', 'low')
        if level in threats_by_level:
            threats_by_level[level].append({
                'ip': ip,
                'score': data.get('threat_score', 0),
                'attempts': data.get('count', 0),
                'threat_types': list(data.get('threats', {}).keys()),
                'location': data.get('location', {}).get('country', 'Unknown')
            })
    
    # Sort by score
    for level in threats_by_level:
        threats_by_level[level].sort(key=lambda x: x['score'], reverse=True)
    
    return jsonify({
        'status': 'success',
        'data': threats_by_level
    })


if __name__ == '__main__':
    print("Starting OSINT Security Dashboard API...")
    print("API will be available at http://localhost:3321")
    app.run(debug=False, host='0.0.0.0', port=3321)
