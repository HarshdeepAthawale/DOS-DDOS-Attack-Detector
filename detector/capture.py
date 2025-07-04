from scapy.all import sniff
from collections import defaultdict
import time

traffic_stats = {
    'total_packets': 0,
    'packets_per_second': 0,
    'last_reset': time.time(),
    'ip_counter': defaultdict(int),
    'udp_packets': 0,
    'icmp_packets': 0,
    'tcp_syn': 0,
    'tcp_syn_no_ack': defaultdict(int),  # src_ip: count of SYNs without ACKs
}

def packet_callback(packet):
    traffic_stats['total_packets'] += 1
    src_ip = packet[0][1].src if packet.haslayer('IP') else 'unknown'
    traffic_stats['ip_counter'][src_ip] += 1

    # UDP Flood detection
    if packet.haslayer('UDP'):
        traffic_stats['udp_packets'] += 1

    # ICMP Flood detection
    if packet.haslayer('ICMP'):
        traffic_stats['icmp_packets'] += 1

    # TCP SYN/ACK tracking for Slowloris
    if packet.haslayer('TCP'):
        tcp = packet['TCP']
        if tcp.flags == 'S':  # SYN
            traffic_stats['tcp_syn'] += 1
            traffic_stats['tcp_syn_no_ack'][src_ip] += 1
        elif tcp.flags == 'A':  # ACK
            # Assume ACK means handshake completed, reset SYN count for this IP
            if src_ip in traffic_stats['tcp_syn_no_ack']:
                traffic_stats['tcp_syn_no_ack'][src_ip] = 0

def start_sniffing():
    sniff(prn=packet_callback, store=0)

def get_stats():
    now = time.time()
    elapsed = now - traffic_stats['last_reset']
    if elapsed >= 1:
        traffic_stats['packets_per_second'] = traffic_stats['total_packets']
        traffic_stats['total_packets'] = 0
        traffic_stats['last_reset'] = now
        traffic_stats['ip_counter'] = defaultdict(int)
        # Reset UDP, ICMP, TCP SYN counts each second
        traffic_stats['udp_packets'] = 0
        traffic_stats['icmp_packets'] = 0
        traffic_stats['tcp_syn'] = 0
        # Keep tcp_syn_no_ack for slowloris detection (do not reset every second)
    return {
        'packets_per_second': traffic_stats['packets_per_second'],
        'ip_counter': dict(traffic_stats['ip_counter']),
        'udp_packets': traffic_stats['udp_packets'],
        'icmp_packets': traffic_stats['icmp_packets'],
        'tcp_syn': traffic_stats['tcp_syn'],
        'tcp_syn_no_ack': dict(traffic_stats['tcp_syn_no_ack'])
    } 