"""
OSINT Module for gathering intelligence about IP addresses
"""
import requests
import time
from collections import defaultdict
from datetime import datetime


class OSINTCollector:
    def __init__(self):
        self.api_cache = {}
        self.rate_limit_delay = 0.5  # Delay between API calls
        
    def get_ip_info(self, ip_address):
        """Get comprehensive OSINT information about an IP address"""
        if ip_address in self.api_cache:
            return self.api_cache[ip_address]
        
        info = {
            'ip': ip_address,
            'location': {},
            'threat_intel': {},
            'asn': {},
            'isp': None,
            'last_updated': datetime.now().isoformat()
        }
        
        try:
            # Get geolocation and basic info from ip-api.com (free, no API key needed)
            geo_response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5,
                params={'fields': 'status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,asname,query'}
            )
            
            if geo_response.status_code == 200:
                geo_data = geo_response.json()
                if geo_data.get('status') == 'success':
                    info['location'] = {
                        'country': geo_data.get('country', 'Unknown'),
                        'country_code': geo_data.get('countryCode', ''),
                        'region': geo_data.get('regionName', 'Unknown'),
                        'city': geo_data.get('city', 'Unknown'),
                        'latitude': geo_data.get('lat'),
                        'longitude': geo_data.get('lon'),
                        'timezone': geo_data.get('timezone', 'Unknown')
                    }
                    info['isp'] = geo_data.get('isp', 'Unknown')
                    info['asn'] = {
                        'number': geo_data.get('as', '').split()[0] if geo_data.get('as') else '',
                        'name': geo_data.get('asname', 'Unknown'),
                        'org': geo_data.get('org', 'Unknown')
                    }
            
            time.sleep(self.rate_limit_delay)
            
            # Get threat intelligence from AbuseIPDB (requires API key, optional)
            # For now, we'll use a simple scoring system based on log analysis
            
        except Exception as e:
            print(f"Error fetching OSINT for {ip_address}: {e}")
        
        self.api_cache[ip_address] = info
        return info
    
    def enrich_ip_data(self, ip_data_dict):
        """Enrich IP data with OSINT information - Optimized"""
        enriched_data = {}
        total_ips = len(ip_data_dict)
        
        print(f"Enriching {total_ips} IPs...")
        
        for idx, (ip, data) in enumerate(ip_data_dict.items(), 1):
            # Show progress every 50 IPs
            if idx % 50 == 0:
                print(f"Progress: {idx}/{total_ips} IPs enriched...")
            
            try:
                osint_info = self.get_ip_info(ip)
                
                # Calculate threat score
                threat_score = self.calculate_threat_score(data)
                
                enriched_data[ip] = {
                    **data,
                    **osint_info,
                    'threat_score': threat_score,
                    'threat_level': self.get_threat_level(threat_score)
                }
            except Exception as e:
                # If OSINT fails, use basic data
                threat_score = self.calculate_threat_score(data)
                enriched_data[ip] = {
                    **data,
                    'location': {},
                    'isp': 'Unknown',
                    'asn': {},
                    'threat_score': threat_score,
                    'threat_level': self.get_threat_level(threat_score)
                }
        
        print(f"✅ Enriched {len(enriched_data)} IPs")
        return enriched_data
    
    def calculate_threat_score(self, ip_data):
        """Calculate threat score based on activity"""
        score = 0
        
        # Base score from number of events
        score += min(ip_data.get('count', 0) * 2, 50)
        
        # Threat type multipliers
        threat_multipliers = {
            'critical': {'malware': 50, 'ddos': 40},
            'high': {'brute_force': 30, 'suspicious_activity': 25},
            'medium': {'failed_login': 15, 'spam': 10},
            'low': {'other': 5}
        }
        
        threats = ip_data.get('threats', {})
        for threat_type, count in threats.items():
            if threat_type in ['malware', 'ddos']:
                score += count * 50
            elif threat_type in ['brute_force', 'suspicious_activity']:
                score += count * 30
            elif threat_type in ['failed_login']:
                score += count * 15
            elif threat_type in ['spam']:
                score += count * 10
        
        # Failed login attempts
        failed_logins = ip_data.get('failed_logins', 0)
        score += min(failed_logins * 2, 40)
        
        # Multiple services targeted
        services_count = len(ip_data.get('services', []))
        if services_count > 1:
            score += services_count * 5
        
        return min(score, 100)  # Cap at 100
    
    def get_threat_level(self, score):
        """Determine threat level from score"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'info'
    
    def batch_enrich(self, ip_list, delay=0.5):
        """Enrich multiple IPs with rate limiting"""
        enriched = {}
        for ip in ip_list:
            enriched[ip] = self.get_ip_info(ip)
            time.sleep(delay)
        return enriched
