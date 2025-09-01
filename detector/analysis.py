def check_for_dos(stats):
    alerts = []
    
    # Traditional DoS/DDoS detection
    unique_ip_count = len(stats.get('ip_counter', {}))
    total_packet_rate = stats.get('packets_per_second', 0)
    
    if total_packet_rate > 500 and unique_ip_count > 50:
        alerts.append(f" DDoS CRITICAL: {unique_ip_count} IPs, {total_packet_rate} packets/sec")
    elif total_packet_rate > 100:
        alerts.append(f" DoS WARNING: High traffic rate ({total_packet_rate} packets/sec)")
    
    # Traditional flood detections
    if stats.get('udp_packets', 0) > 80:
        alerts.append(f" UDP Flood: {stats.get('udp_packets', 0)} UDP packets/sec")
    
    if stats.get('icmp_packets', 0) > 50:
        alerts.append(f" ICMP Flood: {stats.get('icmp_packets', 0)} ICMP packets/sec")
    
    # TCP flood detection
    tcp_packets = stats.get('tcp_packets', 0)
    if tcp_packets > 100:
        alerts.append(f" TCP Flood: {tcp_packets} TCP packets/sec")
    
    # TCP SYN flood detection (enhanced)
    tcp_syn_packets = stats.get('tcp_syn', 0)
    if tcp_syn_packets > 50:
        alerts.append(f" TCP SYN Flood: {tcp_syn_packets} SYN packets/sec")
    
    # TCP connection state analysis
    tcp_connections = stats.get('tcp_connections', {})
    if tcp_connections:
        # Check for unusual connection patterns
        established_connections = tcp_connections.get('ESTABLISHED', 0)
        time_wait_connections = tcp_connections.get('TIME_WAIT', 0)
        fin_wait_connections = tcp_connections.get('FIN_WAIT', 0)
        
        if time_wait_connections > 200:
            alerts.append(f" TCP Connection Exhaustion: {time_wait_connections} TIME_WAIT connections")
        
        if fin_wait_connections > 100:
            alerts.append(f" TCP Connection Issues: {fin_wait_connections} FIN_WAIT connections")
    
    # TCP port-based attack detection
    tcp_port_attacks = stats.get('tcp_port_attacks', {})
    for port, count in tcp_port_attacks.items():
        if count > 30:  # High connection attempts to specific port
            port_name = get_port_name(port)
            alerts.append(f" TCP Port Attack: {count} attempts to {port_name} (port {port})")
    
    # HTTP packet analysis
    http_packets = stats.get('http_packets', 0)
    if http_packets > 50:
        alerts.append(f" HTTP Traffic Spike: {http_packets} HTTP packets/sec")
    
    # HTTP request method analysis
    http_requests = stats.get('http_requests', {})
    total_requests = sum(http_requests.values())
    if total_requests > 30:
        # Check for suspicious request patterns
        post_requests = http_requests.get('POST', 0)
        put_requests = http_requests.get('PUT', 0)
        delete_requests = http_requests.get('DELETE', 0)
        
        if post_requests > 20:
            alerts.append(f" HTTP POST Flood: {post_requests} POST requests/sec")
        
        if put_requests > 10:
            alerts.append(f" HTTP PUT Flood: {put_requests} PUT requests/sec")
        
        if delete_requests > 5:
            alerts.append(f" HTTP DELETE Flood: {delete_requests} DELETE requests/sec")
    
    # HTTP response code analysis
    http_responses = stats.get('http_responses', {})
    error_responses = sum(count for code, count in http_responses.items() if code.startswith(('4', '5')))
    if error_responses > 20:
        alerts.append(f" HTTP Error Spike: {error_responses} error responses/sec")
    
    # HTTP User-Agent analysis
    http_user_agents = stats.get('http_user_agents', {})
    if len(http_user_agents) == 1 and total_requests > 20:
        # Single user agent with high request volume
        ua = list(http_user_agents.keys())[0]
        if 'bot' in ua.lower() or 'crawler' in ua.lower() or 'spider' in ua.lower():
            alerts.append(f" Bot Traffic Detected: {total_requests} requests from {ua[:50]}...")
    
    # HTTP URL analysis
    http_urls = stats.get('http_urls', {})
    if http_urls:
        # Check for directory traversal attempts
        suspicious_urls = [url for url in http_urls.keys() if '../' in url or '..\\' in url]
        if suspicious_urls:
            alerts.append(f" Directory Traversal Attempt: {len(suspicious_urls)} suspicious URLs")
        
        # Check for admin panel access attempts
        admin_urls = [url for url in http_urls.keys() if any(pattern in url.lower() for pattern in ['admin', 'login', 'wp-admin', 'phpmyadmin'])]
        if admin_urls and sum(http_urls[url] for url in admin_urls) > 10:
            alerts.append(f" Admin Panel Access Attempt: {sum(http_urls[url] for url in admin_urls)} attempts")
    
    if any(count > 30 for count in stats.get('tcp_syn_no_ack', {}).values()):
        max_syn_ip = max(stats.get('tcp_syn_no_ack', {}), key=stats.get('tcp_syn_no_ack', {}).get, default='unknown')
        alerts.append(f" Slowloris Attack: {stats.get('tcp_syn_no_ack', {}).get(max_syn_ip, 0)} incomplete handshakes from {max_syn_ip}")
    
    # Advanced threat detection alerts
    advanced_alerts = stats.get('advanced_alerts', [])
    for alert in advanced_alerts[-5:]:  # Show last 5 advanced alerts
        severity_icon = get_severity_icon(alert.get('severity', 'medium'))
        alert_type = alert.get('type', 'unknown').replace('_', ' ').title()
        message = alert.get('message', 'Unknown threat detected')
        alerts.append(f"{severity_icon} {alert_type}: {message}")
    
    # Summary of advanced threats
    total_advanced = stats.get('total_advanced_threats', 0)
    if total_advanced > 0:
        threat_breakdown = []
        if stats.get('port_scans', 0) > 0:
            threat_breakdown.append(f"{stats.get('port_scans', 0)} port scans")
        if stats.get('brute_force_attempts', 0) > 0:
            threat_breakdown.append(f"{stats.get('brute_force_attempts', 0)} brute force")
        if stats.get('dns_amplification', 0) > 0:
            threat_breakdown.append(f"{stats.get('dns_amplification', 0)} DNS amplification")
        if stats.get('http_floods', 0) > 0:
            threat_breakdown.append(f"{stats.get('http_floods', 0)} HTTP floods")
        if stats.get('botnet_activity', 0) > 0:
            threat_breakdown.append(f"{stats.get('botnet_activity', 0)} botnet activities")
        
        if threat_breakdown:
            alerts.append(f" Advanced Threats Detected: {', '.join(threat_breakdown)}")
    
    return "\n".join(alerts)

def get_severity_icon(severity):
    """Get appropriate icon for alert severity"""
    icons = {
        'low': '',
        'medium': '', 
        'high': '',
        'critical': ''
    }
    return icons.get(severity.lower(), '')

def get_port_name(port):
    """Get common port names for better readability"""
    port_names = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
    }
    return port_names.get(port, f'Port-{port}')

def get_threat_summary(stats):
    """Generate a comprehensive threat summary"""
    summary = {
        'total_threats': 0,
        'threat_types': [],
        'severity_level': 'low',
        'top_attackers': [],
        'protocol_breakdown': stats.get('protocol_stats', {})
    }
    
    # Count traditional threats
    traditional_threats = 0
    if stats.get('packets_per_second', 0) > 100:
        traditional_threats += 1
        summary['threat_types'].append('DoS/DDoS')
    
    if stats.get('udp_packets', 0) > 80:
        traditional_threats += 1
        summary['threat_types'].append('UDP Flood')
    
    if stats.get('icmp_packets', 0) > 50:
        traditional_threats += 1
        summary['threat_types'].append('ICMP Flood')
    
    # TCP threat detection
    if stats.get('tcp_packets', 0) > 100:
        traditional_threats += 1
        summary['threat_types'].append('TCP Flood')
    
    if stats.get('tcp_syn', 0) > 50:
        traditional_threats += 1
        summary['threat_types'].append('TCP SYN Flood')
    
    # TCP connection exhaustion detection
    tcp_connections = stats.get('tcp_connections', {})
    if tcp_connections.get('TIME_WAIT', 0) > 200 or tcp_connections.get('FIN_WAIT', 0) > 100:
        traditional_threats += 1
        summary['threat_types'].append('TCP Connection Exhaustion')
    
    # HTTP threat detection
    http_packets = stats.get('http_packets', 0)
    if http_packets > 50:
        traditional_threats += 1
        summary['threat_types'].append('HTTP Traffic Spike')
    
    http_requests = stats.get('http_requests', {})
    total_requests = sum(http_requests.values())
    if total_requests > 30:
        post_requests = http_requests.get('POST', 0)
        if post_requests > 20:
            traditional_threats += 1
            summary['threat_types'].append('HTTP POST Flood')
    
    # HTTP error analysis
    http_responses = stats.get('http_responses', {})
    error_responses = sum(count for code, count in http_responses.items() if code.startswith(('4', '5')))
    if error_responses > 20:
        traditional_threats += 1
        summary['threat_types'].append('HTTP Error Spike')
    
    # Add advanced threats
    advanced_threats = stats.get('total_advanced_threats', 0)
    summary['total_threats'] = traditional_threats + advanced_threats
    
    # Determine severity
    if summary['total_threats'] >= 5:
        summary['severity_level'] = 'critical'
    elif summary['total_threats'] >= 3:
        summary['severity_level'] = 'high'
    elif summary['total_threats'] >= 1:
        summary['severity_level'] = 'medium'
    
    # Get top attackers
    ip_counter = stats.get('ip_counter', {})
    if ip_counter:
        sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
        summary['top_attackers'] = sorted_ips[:5]
    
    return summary