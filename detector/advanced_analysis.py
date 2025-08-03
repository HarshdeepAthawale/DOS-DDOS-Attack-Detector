import time
from collections import defaultdict, deque
import re
from datetime import datetime, timedelta

class AdvancedThreatDetector:
    def __init__(self):
        # Port scanning detection
        self.port_scan_tracker = defaultdict(lambda: {
            'ports': set(),
            'timestamps': deque(maxlen=100),
            'last_reset': time.time()
        })
        
        # Brute force detection
        self.auth_failure_tracker = defaultdict(lambda: {
            'failures': deque(maxlen=50),
            'protocols': set()
        })
        
        # DNS amplification detection
        self.dns_tracker = defaultdict(lambda: {
            'queries': deque(maxlen=100),
            'response_sizes': deque(maxlen=100),
            'query_types': defaultdict(int)
        })
        
        # Advanced SYN flood detection
        self.syn_flood_tracker = defaultdict(lambda: {
            'syn_packets': deque(maxlen=200),
            'ports_targeted': set(),
            'packet_sizes': deque(maxlen=100)
        })
        
        # HTTP flood detection
        self.http_flood_tracker = defaultdict(lambda: {
            'requests': deque(maxlen=200),
            'user_agents': set(),
            'request_methods': defaultdict(int),
            'urls': defaultdict(int)
        })
        
        # Botnet detection
        self.botnet_tracker = {
            'coordinated_ips': defaultdict(lambda: {
                'timestamps': deque(maxlen=100),
                'targets': set(),
                'attack_types': set()
            }),
            'similar_patterns': defaultdict(list)
        }
        
        # Configuration thresholds
        self.thresholds = {
            'port_scan': {
                'ports_per_minute': 20,
                'time_window': 60
            },
            'brute_force': {
                'failures_per_minute': 10,
                'time_window': 300
            },
            'dns_amplification': {
                'amplification_ratio': 10,
                'queries_per_second': 50
            },
            'syn_flood': {
                'syns_per_second': 100,
                'unique_ports': 10
            },
            'http_flood': {
                'requests_per_second': 50,
                'time_window': 60
            },
            'botnet': {
                'coordinated_ips': 5,
                'time_correlation': 30
            }
        }
    
    def detect_port_scanning(self, src_ip, dst_port, timestamp):
        """Detect port scanning activities"""
        tracker = self.port_scan_tracker[src_ip]
        current_time = time.time()
        
        # Clean old entries
        while tracker['timestamps'] and current_time - tracker['timestamps'][0] > self.thresholds['port_scan']['time_window']:
            tracker['timestamps'].popleft()
        
        # Add new port and timestamp
        tracker['ports'].add(dst_port)
        tracker['timestamps'].append(current_time)
        
        # Check for port scanning
        if len(tracker['ports']) >= self.thresholds['port_scan']['ports_per_minute']:
            if len(tracker['timestamps']) >= self.thresholds['port_scan']['ports_per_minute']:
                return {
                    'type': 'port_scan',
                    'severity': 'high',
                    'message': f"Port scan detected from {src_ip}: {len(tracker['ports'])} ports in {len(tracker['timestamps'])} attempts",
                    'details': {
                        'ports_scanned': len(tracker['ports']),
                        'attempts': len(tracker['timestamps']),
                        'time_window': self.thresholds['port_scan']['time_window']
                    }
                }
        return None
    
    def detect_brute_force(self, src_ip, protocol, auth_failed=True):
        """Detect brute force authentication attempts"""
        if not auth_failed:
            return None
            
        tracker = self.auth_failure_tracker[src_ip]
        current_time = time.time()
        
        # Clean old entries
        while tracker['failures'] and current_time - tracker['failures'][0] > self.thresholds['brute_force']['time_window']:
            tracker['failures'].popleft()
        
        # Add new failure
        tracker['failures'].append(current_time)
        tracker['protocols'].add(protocol)
        
        # Check for brute force
        if len(tracker['failures']) >= self.thresholds['brute_force']['failures_per_minute']:
            return {
                'type': 'brute_force',
                'severity': 'high',
                'message': f"Brute force attack detected from {src_ip}: {len(tracker['failures'])} failed attempts across {len(tracker['protocols'])} protocols",
                'details': {
                    'failed_attempts': len(tracker['failures']),
                    'protocols': list(tracker['protocols']),
                    'time_window': self.thresholds['brute_force']['time_window']
                }
            }
        return None
    
    def detect_dns_amplification(self, src_ip, query_size, response_size, query_type):
        """Detect DNS amplification attacks"""
        tracker = self.dns_tracker[src_ip]
        current_time = time.time()
        
        # Clean old entries (1 minute window)
        while tracker['queries'] and current_time - tracker['queries'][0]['timestamp'] > 60:
            old_query = tracker['queries'].popleft()
            if tracker['response_sizes']:
                tracker['response_sizes'].popleft()
        
        # Add new query
        tracker['queries'].append({
            'timestamp': current_time,
            'size': query_size
        })
        tracker['response_sizes'].append(response_size)
        tracker['query_types'][query_type] += 1
        
        # Calculate amplification ratio
        if len(tracker['queries']) >= 10 and len(tracker['response_sizes']) >= 10:
            avg_query_size = sum(q['size'] for q in tracker['queries']) / len(tracker['queries'])
            avg_response_size = sum(tracker['response_sizes']) / len(tracker['response_sizes'])
            
            if avg_response_size > 0 and avg_query_size > 0:
                amplification_ratio = avg_response_size / avg_query_size
                queries_per_second = len(tracker['queries']) / 60
                
                if (amplification_ratio >= self.thresholds['dns_amplification']['amplification_ratio'] and 
                    queries_per_second >= self.thresholds['dns_amplification']['queries_per_second']):
                    return {
                        'type': 'dns_amplification',
                        'severity': 'critical',
                        'message': f"DNS amplification attack detected from {src_ip}: {amplification_ratio:.1f}x amplification, {queries_per_second:.1f} queries/sec",
                        'details': {
                            'amplification_ratio': round(amplification_ratio, 2),
                            'queries_per_second': round(queries_per_second, 2),
                            'query_types': dict(tracker['query_types'])
                        }
                    }
        return None
    
    def detect_advanced_syn_flood(self, src_ip, dst_port, packet_size):
        """Detect advanced SYN flood attacks"""
        tracker = self.syn_flood_tracker[src_ip]
        current_time = time.time()
        
        # Clean old entries (1 second window)
        while tracker['syn_packets'] and current_time - tracker['syn_packets'][0] > 1:
            tracker['syn_packets'].popleft()
        
        # Add new SYN packet
        tracker['syn_packets'].append(current_time)
        tracker['ports_targeted'].add(dst_port)
        tracker['packet_sizes'].append(packet_size)
        
        # Check for SYN flood
        syns_per_second = len(tracker['syn_packets'])
        unique_ports = len(tracker['ports_targeted'])
        
        if (syns_per_second >= self.thresholds['syn_flood']['syns_per_second'] or
            unique_ports >= self.thresholds['syn_flood']['unique_ports']):
            
            # Analyze packet size patterns
            avg_packet_size = sum(tracker['packet_sizes'][-50:]) / min(50, len(tracker['packet_sizes']))
            size_variance = len(set(tracker['packet_sizes'][-20:]))
            
            return {
                'type': 'advanced_syn_flood',
                'severity': 'critical',
                'message': f"Advanced SYN flood detected from {src_ip}: {syns_per_second} SYNs/sec targeting {unique_ports} ports",
                'details': {
                    'syns_per_second': syns_per_second,
                    'unique_ports_targeted': unique_ports,
                    'avg_packet_size': round(avg_packet_size, 2),
                    'size_variance': size_variance
                }
            }
        return None
    
    def detect_http_flood(self, src_ip, method, url, user_agent):
        """Detect HTTP flood and application layer attacks"""
        tracker = self.http_flood_tracker[src_ip]
        current_time = time.time()
        
        # Clean old entries
        while tracker['requests'] and current_time - tracker['requests'][0] > self.thresholds['http_flood']['time_window']:
            tracker['requests'].popleft()
        
        # Add new request
        tracker['requests'].append(current_time)
        tracker['user_agents'].add(user_agent)
        tracker['request_methods'][method] += 1
        tracker['urls'][url] += 1
        
        # Check for HTTP flood
        requests_per_second = len(tracker['requests']) / self.thresholds['http_flood']['time_window']
        
        if requests_per_second >= self.thresholds['http_flood']['requests_per_second']:
            # Analyze attack patterns
            most_common_method = max(tracker['request_methods'], key=tracker['request_methods'].get)
            most_targeted_url = max(tracker['urls'], key=tracker['urls'].get)
            unique_user_agents = len(tracker['user_agents'])
            
            # Detect Slowloris variation (few user agents, repetitive patterns)
            attack_subtype = "http_flood"
            if unique_user_agents <= 3 and len(tracker['urls']) <= 5:
                attack_subtype = "slowloris_variant"
            
            return {
                'type': attack_subtype,
                'severity': 'high',
                'message': f"HTTP flood detected from {src_ip}: {requests_per_second:.1f} requests/sec, method: {most_common_method}",
                'details': {
                    'requests_per_second': round(requests_per_second, 2),
                    'most_common_method': most_common_method,
                    'most_targeted_url': most_targeted_url,
                    'unique_user_agents': unique_user_agents,
                    'total_requests': len(tracker['requests'])
                }
            }
        return None
    
    def detect_botnet_activity(self, attack_data):
        """Detect coordinated botnet attacks"""
        current_time = time.time()
        alerts = []
        
        # Group recent attacks by type and time
        recent_attacks = defaultdict(list)
        for ip, data in attack_data.items():
            if 'last_attack_time' in data and current_time - data['last_attack_time'] <= self.thresholds['botnet']['time_correlation']:
                recent_attacks[data.get('attack_type', 'unknown')].append({
                    'ip': ip,
                    'time': data['last_attack_time'],
                    'target': data.get('target', 'unknown')
                })
        
        # Check for coordinated attacks
        for attack_type, attacks in recent_attacks.items():
            if len(attacks) >= self.thresholds['botnet']['coordinated_ips']:
                # Check time correlation
                attack_times = [a['time'] for a in attacks]
                time_spread = max(attack_times) - min(attack_times)
                
                if time_spread <= self.thresholds['botnet']['time_correlation']:
                    unique_targets = len(set(a['target'] for a in attacks))
                    attacking_ips = [a['ip'] for a in attacks]
                    
                    alerts.append({
                        'type': 'botnet_coordination',
                        'severity': 'critical',
                        'message': f"Botnet activity detected: {len(attacks)} IPs coordinating {attack_type} attacks within {time_spread:.1f}s",
                        'details': {
                            'attack_type': attack_type,
                            'coordinated_ips': len(attacks),
                            'time_spread': round(time_spread, 2),
                            'unique_targets': unique_targets,
                            'attacking_ips': attacking_ips[:10]  # Limit to first 10 IPs
                        }
                    })
        
        return alerts
    
    def cleanup_old_data(self):
        """Clean up old tracking data to prevent memory leaks"""
        current_time = time.time()
        cleanup_threshold = 3600  # 1 hour
        
        # Clean port scan data
        for ip in list(self.port_scan_tracker.keys()):
            if current_time - self.port_scan_tracker[ip]['last_reset'] > cleanup_threshold:
                del self.port_scan_tracker[ip]
        
        # Clean other trackers similarly
        for tracker in [self.auth_failure_tracker, self.dns_tracker, 
                       self.syn_flood_tracker, self.http_flood_tracker]:
            for ip in list(tracker.keys()):
                # Remove IPs with no recent activity
                if not hasattr(tracker[ip], 'get') or len(str(tracker[ip])) < 10:
                    continue
