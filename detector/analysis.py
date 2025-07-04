def check_for_dos(stats):
    alerts = []
    # DDoS detection: high packet rate from many unique IPs
    unique_ip_count = len(stats.get('ip_counter', {}))
    total_packet_rate = stats.get('packets_per_second', 0)
    if total_packet_rate > 500 and unique_ip_count > 50:
        alerts.append(f"DDoS detected! {unique_ip_count} IPs, {total_packet_rate} packets/sec.")
    # Generic high traffic
    if total_packet_rate > 100:
        alerts.append("Potential DoS attack detected! High traffic rate.")
    # UDP Flood
    if stats.get('udp_packets', 0) > 80:
        alerts.append("UDP Flood detected! High volume of UDP packets.")
    # ICMP Flood
    if stats.get('icmp_packets', 0) > 50:
        alerts.append("ICMP Flood detected! Excessive ICMP requests.")
    # Slowloris-style (many incomplete TCP handshakes)
    if any(count > 30 for count in stats.get('tcp_syn_no_ack', {}).values()):
        alerts.append("Possible Slowloris attack! Many incomplete TCP handshakes.")
    return "\n".join(alerts) 