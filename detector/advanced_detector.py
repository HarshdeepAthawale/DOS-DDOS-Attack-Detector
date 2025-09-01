"""
Advanced threat detection module for DoS/DDoS attack detection
"""
import time
from collections import defaultdict, deque
import re

class AdvancedDetector:
    def __init__(self):
        # Port scanning detection
        self.port_scan_data = defaultdict(lambda: {'ports': set(), 'timestamps': deque(), 'last_scan': 0})
        self.port_scan_threshold = 10  # ports per minute
        self.port_scan_window = 60  # seconds
        
        # SYN flood detection
        self.syn_flood_data = defaultdict(lambda: {'count': 0, 'last_reset': time.time()})
        self.syn_flood_threshold = 50  # SYN packets per second
        self.syn_flood_window = 1  # seconds
        
        # HTTP flood detection
        self.http_flood_data = defaultdict(lambda: {'requests': deque(), 'user_agents': set()})
        self.http_flood_threshold = 30  # requests per minute
        self.http_flood_window = 60  # seconds
        
        # DNS amplification detection
        self.dns_data = defaultdict(lambda: {'queries': 0, 'responses': 0, 'query_sizes': deque(), 'response_sizes': deque()})
        self.dns_amplification_threshold = 100  # queries per minute
        self.dns_amplification_ratio = 3  # response/query size ratio
        
        # Brute force detection
        self.brute_force_data = defaultdict(lambda: {'attempts': 0, 'last_attempt': 0, 'protocols': set()})
        self.brute_force_threshold = 20  # attempts per minute
        self.brute_force_window = 60  # seconds
        
        # Botnet detection
        self.botnet_data = defaultdict(lambda: {'attack_times': deque(), 'attack_types': set(), 'targets': set()})
        self.botnet_threshold = 5  # coordinated attacks
        self.botnet_window = 300  # 5 minutes
        
        # Cleanup interval
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes

    def detect_port_scanning(self, src_ip, dst_port, timestamp):
        """Detect port scanning attempts"""
        data = self.port_scan_data[src_ip]
        
        # Add new port and timestamp
        data['ports'].add(dst_port)
        data['timestamps'].append(timestamp)
        
        # Remove old timestamps
        while data['timestamps'] and timestamp - data['timestamps'][0] > self.port_scan_window:
            data['timestamps'].popleft()
        
        # Check if this is a port scan
        if len(data['ports']) >= self.port_scan_threshold:
            # Reset to prevent spam
            if timestamp - data['last_scan'] > self.port_scan_window:
                data['last_scan'] = timestamp
                return {
                    'type': 'port_scan',
                    'severity': 'high',
                    'message': f'Port scan detected from {src_ip}: {len(data["ports"])} ports in {self.port_scan_window}s',
                    'timestamp': timestamp,
                    'source_ip': src_ip,
                    'ports_scanned': len(data['ports'])
                }
        
        return None

    def detect_advanced_syn_flood(self, src_ip, dst_port, packet_size):
        """Detect advanced SYN flood attacks"""
        current_time = time.time()
        data = self.syn_flood_data[src_ip]
        
        # Reset counter if window has passed
        if current_time - data['last_reset'] > self.syn_flood_window:
            data['count'] = 0
            data['last_reset'] = current_time
        
        data['count'] += 1
        
        # Check for SYN flood
        if data['count'] >= self.syn_flood_threshold:
            return {
                'type': 'syn_flood',
                'severity': 'critical',
                'message': f'SYN flood detected from {src_ip} to port {dst_port}: {data["count"]} SYN packets/sec',
                'timestamp': current_time,
                'source_ip': src_ip,
                'target_port': dst_port,
                'packet_count': data['count']
            }
        
        return None

    def detect_http_flood(self, src_ip, method, url, user_agent):
        """Detect HTTP flood attacks"""
        current_time = time.time()
        data = self.http_flood_data[src_ip]
        
        # Add request data
        data['requests'].append(current_time)
        data['user_agents'].add(user_agent)
        
        # Remove old requests
        while data['requests'] and current_time - data['requests'][0] > self.http_flood_window:
            data['requests'].popleft()
        
        # Check for HTTP flood
        if len(data['requests']) >= self.http_flood_threshold:
            # Check for suspicious patterns
            suspicious_patterns = [
                len(data['user_agents']) == 1,  # Single user agent
                any(pattern in url.lower() for pattern in ['admin', 'login', 'wp-admin', 'phpmyadmin']),  # Admin pages
                method in ['POST', 'PUT', 'DELETE']  # Write operations
            ]
            
            severity = 'high' if any(suspicious_patterns) else 'medium'
            
            return {
                'type': 'http_flood',
                'severity': severity,
                'message': f'HTTP flood detected from {src_ip}: {len(data["requests"])} requests/min to {url}',
                'timestamp': current_time,
                'source_ip': src_ip,
                'target_url': url,
                'method': method,
                'request_count': len(data['requests']),
                'user_agents': len(data['user_agents'])
            }
        
        return None

    def detect_dns_amplification(self, src_ip, query_size, response_size, query_type):
        """Detect DNS amplification attacks"""
        current_time = time.time()
        data = self.dns_data[src_ip]
        
        if query_size > 0:
            data['queries'] += 1
            data['query_sizes'].append(query_size)
        elif response_size > 0:
            data['responses'] += 1
            data['response_sizes'].append(response_size)
        
        # Remove old data
        while data['query_sizes'] and current_time - data['query_sizes'][0] > self.dns_amplification_window:
            data['query_sizes'].popleft()
        while data['response_sizes'] and current_time - data['response_sizes'][0] > self.dns_amplification_window:
            data['response_sizes'].popleft()
        
        # Check for DNS amplification
        if data['queries'] >= self.dns_amplification_threshold:
            avg_query_size = sum(data['query_sizes']) / len(data['query_sizes']) if data['query_sizes'] else 0
            avg_response_size = sum(data['response_sizes']) / len(data['response_sizes']) if data['response_sizes'] else 0
            
            if avg_response_size > 0 and avg_query_size > 0:
                amplification_ratio = avg_response_size / avg_query_size
                
                if amplification_ratio >= self.dns_amplification_ratio:
                    return {
                        'type': 'dns_amplification',
                        'severity': 'high',
                        'message': f'DNS amplification detected from {src_ip}: {amplification_ratio:.1f}x amplification ratio',
                        'timestamp': current_time,
                        'source_ip': src_ip,
                        'amplification_ratio': amplification_ratio,
                        'query_count': data['queries'],
                        'response_count': data['responses']
                    }
        
        return None

    def detect_brute_force(self, src_ip, protocol, is_failure):
        """Detect brute force attacks"""
        current_time = time.time()
        data = self.brute_force_data[src_ip]
        
        if is_failure:
            data['attempts'] += 1
            data['last_attempt'] = current_time
            data['protocols'].add(protocol)
        
        # Check for brute force
        if data['attempts'] >= self.brute_force_threshold:
            return {
                'type': 'brute_force',
                'severity': 'high',
                'message': f'Brute force attack detected from {src_ip} against {protocol}: {data["attempts"]} attempts',
                'timestamp': current_time,
                'source_ip': src_ip,
                'target_protocol': protocol,
                'attempt_count': data['attempts'],
                'protocols_targeted': list(data['protocols'])
            }
        
        return None

    def detect_botnet_activity(self, attack_data):
        """Detect coordinated botnet activity"""
        current_time = time.time()
        alerts = []
        
        # Analyze attack patterns
        for ip, attack_info in attack_data.items():
            data = self.botnet_data[ip]
            
            # Add attack data
            data['attack_times'].append(current_time)
            data['attack_types'].add(attack_info.get('attack_type', 'unknown'))
            data['targets'].add(attack_info.get('target', 'unknown'))
            
            # Remove old data
            while data['attack_times'] and current_time - data['attack_times'][0] > self.botnet_window:
                data['attack_times'].popleft()
            
            # Check for botnet activity
            if len(data['attack_times']) >= self.botnet_threshold:
                alerts.append({
                    'type': 'botnet_activity',
                    'severity': 'critical',
                    'message': f'Botnet activity detected from {ip}: {len(data["attack_times"])} coordinated attacks',
                    'timestamp': current_time,
                    'source_ip': ip,
                    'attack_count': len(data['attack_times']),
                    'attack_types': list(data['attack_types']),
                    'targets': list(data['targets'])
                })
        
        return alerts

    def cleanup_old_data(self):
        """Clean up old detection data to prevent memory leaks"""
        current_time = time.time()
        
        # Only cleanup every 5 minutes
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        self.last_cleanup = current_time
        
        # Clean up old data from all detectors
        cutoff_time = current_time - 3600  # 1 hour ago
        
        # Clean port scan data
        for ip in list(self.port_scan_data.keys()):
            data = self.port_scan_data[ip]
            while data['timestamps'] and data['timestamps'][0] < cutoff_time:
                data['timestamps'].popleft()
            if not data['timestamps'] and current_time - data['last_scan'] > 3600:
                del self.port_scan_data[ip]
        
        # Clean SYN flood data
        for ip in list(self.syn_flood_data.keys()):
            if current_time - self.syn_flood_data[ip]['last_reset'] > 3600:
                del self.syn_flood_data[ip]
        
        # Clean HTTP flood data
        for ip in list(self.http_flood_data.keys()):
            data = self.http_flood_data[ip]
            while data['requests'] and data['requests'][0] < cutoff_time:
                data['requests'].popleft()
            if not data['requests']:
                del self.http_flood_data[ip]
        
        # Clean DNS data
        for ip in list(self.dns_data.keys()):
            data = self.dns_data[ip]
            while data['query_sizes'] and data['query_sizes'][0] < cutoff_time:
                data['query_sizes'].popleft()
            while data['response_sizes'] and data['response_sizes'][0] < cutoff_time:
                data['response_sizes'].popleft()
            if not data['query_sizes'] and not data['response_sizes']:
                del self.dns_data[ip]
        
        # Clean brute force data
        for ip in list(self.brute_force_data.keys()):
            if current_time - self.brute_force_data[ip]['last_attempt'] > 3600:
                del self.brute_force_data[ip]
        
        # Clean botnet data
        for ip in list(self.botnet_data.keys()):
            data = self.botnet_data[ip]
            while data['attack_times'] and data['attack_times'][0] < cutoff_time:
                data['attack_times'].popleft()
            if not data['attack_times']:
                del self.botnet_data[ip]

# Global instance
advanced_detector = AdvancedDetector()
