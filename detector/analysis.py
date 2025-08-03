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