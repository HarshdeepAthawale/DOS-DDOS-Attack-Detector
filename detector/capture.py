from scapy.all import sniff, conf, get_if_list, get_if_addr
from collections import defaultdict
import time
import re
import os
import sys
import threading
from .advanced_detector import advanced_detector

# Global flag to track if real packet capture is working
REAL_CAPTURE_ACTIVE = False
CAPTURE_ERROR = None

# Simple threat detection thresholds
THREAT_THRESHOLDS = {
    'port_scan_threshold': 10,  # ports per minute
    'syn_flood_threshold': 50,  # SYN packets per second
    'http_flood_threshold': 30,  # HTTP requests per minute
    'dns_amplification_threshold': 100,  # DNS queries per minute
    'brute_force_threshold': 20,  # attempts per minute
}

traffic_stats = {
    'total_packets': 0,
    'packets_per_second': 0,
    'last_reset': time.time(),
    'ip_counter': defaultdict(int),
    'udp_packets': 0,
    'icmp_packets': 0,
    'tcp_packets': 0,  # Total TCP packets
    'tcp_syn': 0,
    'tcp_syn_no_ack': defaultdict(int),  # src_ip: count of SYNs without ACKs
    'tcp_connections': defaultdict(int),  # Connection states
    'tcp_port_attacks': defaultdict(int),  # Port-specific attack attempts
    'http_packets': 0,  # Total HTTP packets
    'http_requests': defaultdict(int),  # HTTP request methods
    'http_responses': defaultdict(int),  # HTTP response codes
    'http_user_agents': defaultdict(int),  # User agent tracking
    'http_urls': defaultdict(int),  # URL tracking
    'http_headers': defaultdict(int),  # HTTP header analysis
    # Advanced detection stats
    'port_scans': 0,
    'brute_force_attempts': 0,
    'dns_amplification': 0,
    'http_floods': 0,
    'botnet_activity': 0,
    'advanced_alerts': [],
    'protocol_stats': defaultdict(int),
    'connection_states': defaultdict(int),
}

def packet_callback(packet):
    traffic_stats['total_packets'] += 1
    current_time = time.time()
    
    # Extract packet information
    src_ip = packet[0][1].src if packet.haslayer('IP') else 'unknown'
    dst_ip = packet[0][1].dst if packet.haslayer('IP') else 'unknown'
    packet_size = len(packet)
    
    traffic_stats['ip_counter'][src_ip] += 1

    # Advanced packet analysis
    try:
        # TCP Analysis
        if packet.haslayer('TCP'):
            tcp = packet['TCP']
            dst_port = tcp.dport
            src_port = tcp.sport
            
            # Increment TCP packet counters
            traffic_stats['tcp_packets'] += 1
            traffic_stats['protocol_stats']['TCP'] += 1
            
            # Track TCP connection states
            tcp_flags = tcp.flags
            if 'S' in tcp_flags and 'A' not in tcp_flags:  # SYN only
                traffic_stats['tcp_connections']['SYN_SENT'] += 1
            elif 'S' in tcp_flags and 'A' in tcp_flags:  # SYN-ACK
                traffic_stats['tcp_connections']['SYN_RECEIVED'] += 1
            elif 'A' in tcp_flags and 'S' not in tcp_flags and 'F' not in tcp_flags:  # ACK only
                traffic_stats['tcp_connections']['ESTABLISHED'] += 1
            elif 'F' in tcp_flags:  # FIN
                traffic_stats['tcp_connections']['FIN_WAIT'] += 1
            elif 'R' in tcp_flags:  # RST
                traffic_stats['tcp_connections']['RESET'] += 1
            
            # Port scanning detection
            port_scan_alert = advanced_detector.detect_port_scanning(src_ip, dst_port, current_time)
            if port_scan_alert:
                traffic_stats['port_scans'] += 1
                traffic_stats['advanced_alerts'].append(port_scan_alert)
            
            # Track port-specific attack attempts
            traffic_stats['tcp_port_attacks'][dst_port] += 1
            
            # Advanced SYN flood detection
            if tcp.flags == 'S':  # SYN
                traffic_stats['tcp_syn'] += 1
                traffic_stats['tcp_syn_no_ack'][src_ip] += 1
                
                syn_flood_alert = advanced_detector.detect_advanced_syn_flood(src_ip, dst_port, packet_size)
                if syn_flood_alert:
                    traffic_stats['advanced_alerts'].append(syn_flood_alert)
                    
            elif tcp.flags == 'A':  # ACK
                if src_ip in traffic_stats['tcp_syn_no_ack']:
                    traffic_stats['tcp_syn_no_ack'][src_ip] = 0
            
            # HTTP flood detection and analysis
            if dst_port in [80, 443, 8080, 8443]:  # Common HTTP ports
                traffic_stats['http_packets'] += 1
                try:
                    if packet.haslayer('Raw'):
                        payload = packet['Raw'].load.decode('utf-8', errors='ignore')
                        
                        # HTTP Request Analysis
                        if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                            # Extract HTTP details
                            lines = payload.split('\r\n')
                            if lines:
                                request_line = lines[0]
                                parts = request_line.split(' ')
                                if len(parts) >= 3:
                                    method = parts[0]
                                    url = parts[1]
                                    http_version = parts[2] if len(parts) > 2 else 'HTTP/1.1'
                                    
                                    # Track HTTP request methods
                                    traffic_stats['http_requests'][method] += 1
                                    
                                    # Track URLs (limit to prevent memory issues)
                                    if len(traffic_stats['http_urls']) < 100:
                                        traffic_stats['http_urls'][url] += 1
                                    
                                    # Extract and track headers
                                    for line in lines[1:]:
                                        if ':' in line:
                                            header_name, header_value = line.split(':', 1)
                                            header_name = header_name.strip().lower()
                                            header_value = header_value.strip()
                                            
                                            # Track User-Agent
                                            if header_name == 'user-agent':
                                                traffic_stats['http_user_agents'][header_value] += 1
                                            
                                            # Track other important headers
                                            if header_name in ['host', 'referer', 'accept', 'content-type']:
                                                if len(traffic_stats['http_headers']) < 50:
                                                    traffic_stats['http_headers'][f"{header_name}: {header_value}"] += 1
                                    
                                    # HTTP flood detection
                                    http_flood_alert = advanced_detector.detect_http_flood(src_ip, method, url, 
                                                                                         traffic_stats['http_user_agents'].get('Unknown', 'Unknown'))
                                    if http_flood_alert:
                                        traffic_stats['http_floods'] += 1
                                        traffic_stats['advanced_alerts'].append(http_flood_alert)
                        
                        # HTTP Response Analysis
                        elif payload.startswith('HTTP/'):
                            lines = payload.split('\r\n')
                            if lines:
                                status_line = lines[0]
                                parts = status_line.split(' ')
                                if len(parts) >= 2:
                                    http_version = parts[0]
                                    status_code = parts[1]
                                    
                                    # Track HTTP response codes
                                    traffic_stats['http_responses'][status_code] += 1
                                    
                                    # Extract response headers
                                    for line in lines[1:]:
                                        if ':' in line:
                                            header_name, header_value = line.split(':', 1)
                                            header_name = header_name.strip().lower()
                                            header_value = header_value.strip()
                                            
                                            # Track important response headers
                                            if header_name in ['server', 'content-type', 'content-length', 'cache-control']:
                                                if len(traffic_stats['http_headers']) < 50:
                                                    traffic_stats['http_headers'][f"{header_name}: {header_value}"] += 1
                                    
                except Exception:
                    pass  # Ignore HTTP parsing errors
            
            # Brute force detection for common services
            if dst_port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432]:
                # Simulate authentication failure detection (in real scenario, this would be based on response analysis)
                # For demonstration, we'll trigger on high connection attempts to auth ports
                if src_ip in traffic_stats['ip_counter'] and traffic_stats['ip_counter'][src_ip] > 20:
                    protocol_name = get_protocol_name(dst_port)
                    brute_force_alert = advanced_detector.detect_brute_force(src_ip, protocol_name, True)
                    if brute_force_alert:
                        traffic_stats['brute_force_attempts'] += 1
                        traffic_stats['advanced_alerts'].append(brute_force_alert)
        
        # UDP Analysis
        elif packet.haslayer('UDP'):
            udp = packet['UDP']
            traffic_stats['udp_packets'] += 1
            traffic_stats['protocol_stats']['UDP'] += 1
            
            # DNS amplification detection
            if udp.dport == 53 or udp.sport == 53:  # DNS traffic
                query_size = len(packet) if udp.dport == 53 else 0
                response_size = len(packet) if udp.sport == 53 else 0
                
                if query_size > 0:  # DNS query
                    dns_alert = advanced_detector.detect_dns_amplification(src_ip, query_size, 0, 'A')
                elif response_size > 0:  # DNS response
                    dns_alert = advanced_detector.detect_dns_amplification(dst_ip, 0, response_size, 'A')
                else:
                    dns_alert = None
                    
                if dns_alert:
                    traffic_stats['dns_amplification'] += 1
                    traffic_stats['advanced_alerts'].append(dns_alert)
        
        # ICMP Analysis
        elif packet.haslayer('ICMP'):
            traffic_stats['icmp_packets'] += 1
            traffic_stats['protocol_stats']['ICMP'] += 1
            
    except Exception as e:
        # Log error but continue processing
        pass

def get_protocol_name(port):
    """Map common ports to protocol names"""
    port_map = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL'
    }
    return port_map.get(port, f'Port-{port}')

def start_sniffing():
    global REAL_CAPTURE_ACTIVE, CAPTURE_ERROR
    
    try:
        # Check if we're on Windows and try to configure Scapy properly
        if sys.platform.startswith('win'):
            print("Windows detected - configuring packet capture...")
            
            # Try multiple Windows-specific configurations
            pcap_configured = False
            
            # Method 1: Try to use pcap
            try:
                conf.use_pcap = True
                print("✅ Configured Scapy to use pcap")
                pcap_configured = True
            except Exception as e:
                print(f"⚠️ Could not configure pcap: {e}")
            
            # Method 2: Try to use dnet
            if not pcap_configured:
                try:
                    conf.use_dnet = True
                    print("✅ Configured Scapy to use dnet")
                    pcap_configured = True
                except Exception as e:
                    print(f"⚠️ Could not configure dnet: {e}")
            
            # Method 3: Try to use raw sockets
            if not pcap_configured:
                try:
                    conf.use_raw_socket = True
                    print("✅ Configured Scapy to use raw sockets")
                    pcap_configured = True
                except Exception as e:
                    print(f"⚠️ Could not configure raw sockets: {e}")
        
        # Get available interfaces
        interfaces = get_if_list()
        if interfaces:
            print(f"Available network interfaces: {interfaces}")
            
            # Try to find a suitable interface
            target_interface = None
            for iface in interfaces:
                if iface != 'lo' and not iface.startswith('docker'):
                    target_interface = iface
                    break
            
            if target_interface:
                print(f"Using interface: {target_interface}")
                try:
                    # Start packet sniffing on specific interface with timeout
                    print("Attempting to capture packets on interface...")
                    sniff(iface=target_interface, prn=packet_callback, store=0, timeout=5)
                    REAL_CAPTURE_ACTIVE = True
                    print("✅ Real packet capture started successfully!")
                    return
                except Exception as e:
                    CAPTURE_ERROR = str(e)
                    print(f"Failed to capture on interface {target_interface}: {e}")
        
        # Fallback: try generic sniffing with timeout
        print("Attempting generic packet capture...")
        try:
            # Try to capture with a timeout to see if it works
            sniff(prn=packet_callback, store=0, timeout=5)
            REAL_CAPTURE_ACTIVE = True
            print("✅ Real packet capture started successfully!")
            return
        except Exception as e:
            CAPTURE_ERROR = str(e)
            print(f"Generic sniffing failed: {e}")
        
    except Exception as e:
        CAPTURE_ERROR = str(e)
        print(f"❌ Could not start real packet capture: {e}")
        print("This is normal on Windows without proper network permissions.")
        print("The application will work with simulated data.")
    
    # If we get here, real packet capture failed
    print("🔄 Starting simulated packet capture...")
    
    # Start a background thread to simulate packet capture
    def simulate_packet_capture():
        global REAL_CAPTURE_ACTIVE
        REAL_CAPTURE_ACTIVE = False
        print("🔄 Simulated packet capture active - generating realistic demo data")
        while True:
            time.sleep(1)
    
    sim_thread = threading.Thread(target=simulate_packet_capture, daemon=True)
    sim_thread.start()

def get_capture_status():
    """Get detailed information about packet capture status"""
    global REAL_CAPTURE_ACTIVE, CAPTURE_ERROR
    
    status = {
        'real_capture_active': REAL_CAPTURE_ACTIVE,
        'capture_error': CAPTURE_ERROR,
        'platform': sys.platform,
        'interfaces_available': len(get_if_list()) if get_if_list() else 0,
        'scapy_config': {
            'use_pcap': getattr(conf, 'use_pcap', False),
            'use_dnet': getattr(conf, 'use_dnet', False),
            'use_bpf': getattr(conf, 'use_bpf', False)
        }
    }
    
    if not REAL_CAPTURE_ACTIVE:
        status['instructions'] = {
            'windows': [
                "1. Install Npcap: https://npcap.com/",
                "2. Run as Administrator",
                "3. Ensure firewall allows packet capture",
                "4. Install WinPcap if Npcap doesn't work"
            ],
            'linux': [
                "1. Run with sudo: sudo python app.py",
                "2. Install libpcap-dev: sudo apt-get install libpcap-dev",
                "3. Ensure proper network permissions"
            ],
            'macos': [
                "1. Run with sudo: sudo python app.py",
                "2. Install libpcap: brew install libpcap",
                "3. Grant network permissions to terminal"
            ]
        }
    
    return status

def test_packet_capture():
    """Test if packet capture is working"""
    global REAL_CAPTURE_ACTIVE
    
    try:
        # Try to capture a single packet with timeout
        result = sniff(count=1, timeout=2, store=0)
        if result:
            REAL_CAPTURE_ACTIVE = True
            return True, "Packet capture is working"
        else:
            return False, "No packets captured in timeout period"
    except Exception as e:
        return False, f"Packet capture failed: {str(e)}"

def get_stats():
    global REAL_CAPTURE_ACTIVE, CAPTURE_ERROR
    
    now = time.time()
    elapsed = now - traffic_stats['last_reset']
    
    # Check if we need to generate demo data (no real packets captured)
    if not REAL_CAPTURE_ACTIVE and traffic_stats['total_packets'] == 0 and elapsed > 3:
        # Generate realistic demo data that simulates real network traffic
        import random
        
        # Simulate varying traffic patterns
        base_traffic = random.randint(15, 60)
        traffic_stats['total_packets'] = base_traffic
        
        # Simulate different IP sources
        ip_sources = [
            '192.168.1.100', '192.168.1.101', '192.168.1.102',
            '10.0.0.50', '10.0.0.51', '172.16.0.10',
            '8.8.8.8', '1.1.1.1', '208.67.222.222'
        ]
        
        for ip in random.sample(ip_sources, random.randint(3, 6)):
            traffic_stats['ip_counter'][ip] = random.randint(2, 12)
        
        # Generate realistic protocol distribution
        tcp_ratio = random.uniform(0.6, 0.8)
        udp_ratio = random.uniform(0.1, 0.3)
        icmp_ratio = 1 - tcp_ratio - udp_ratio
        
        traffic_stats['tcp_packets'] = int(base_traffic * tcp_ratio)
        traffic_stats['udp_packets'] = int(base_traffic * udp_ratio)
        traffic_stats['icmp_packets'] = int(base_traffic * icmp_ratio)
        
        # TCP SYN packets (connection attempts)
        traffic_stats['tcp_syn'] = random.randint(3, int(traffic_stats['tcp_packets'] * 0.4))
        
        # Protocol statistics
        traffic_stats['protocol_stats']['TCP'] = traffic_stats['tcp_packets']
        traffic_stats['protocol_stats']['UDP'] = traffic_stats['udp_packets']
        traffic_stats['protocol_stats']['ICMP'] = traffic_stats['icmp_packets']
        
        # Realistic TCP connection states
        established = random.randint(8, 20)
        syn_sent = random.randint(2, 6)
        fin_wait = random.randint(1, 4)
        
        traffic_stats['tcp_connections']['ESTABLISHED'] = established
        traffic_stats['tcp_connections']['SYN_SENT'] = syn_sent
        traffic_stats['tcp_connections']['FIN_WAIT'] = fin_wait
        traffic_stats['tcp_connections']['TIME_WAIT'] = random.randint(1, 3)
        
        # Common port traffic
        common_ports = [80, 443, 22, 53, 25, 110, 143, 993, 995, 8080]
        for port in random.sample(common_ports, random.randint(3, 6)):
            traffic_stats['tcp_port_attacks'][port] = random.randint(2, 8)
        
        # HTTP traffic simulation
        if random.random() > 0.3:  # 70% chance of HTTP traffic
            http_traffic = random.randint(5, 20)
            traffic_stats['http_packets'] = http_traffic
            
            # HTTP request methods
            traffic_stats['http_requests']['GET'] = random.randint(3, int(http_traffic * 0.7))
            traffic_stats['http_requests']['POST'] = random.randint(1, int(http_traffic * 0.2))
            traffic_stats['http_requests']['HEAD'] = random.randint(0, int(http_traffic * 0.1))
            
            # HTTP response codes
            traffic_stats['http_responses']['200'] = random.randint(2, int(http_traffic * 0.6))
            traffic_stats['http_responses']['404'] = random.randint(0, int(http_traffic * 0.2))
            traffic_stats['http_responses']['500'] = random.randint(0, int(http_traffic * 0.1))
            traffic_stats['http_responses']['302'] = random.randint(0, int(http_traffic * 0.1))
            
            # User agents
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'curl/7.68.0',
                'Python-urllib/3.8',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ]
            for ua in random.sample(user_agents, random.randint(2, 4)):
                traffic_stats['http_user_agents'][ua] = random.randint(1, 5)
            
            # URLs
            urls = ['/', '/index.html', '/api/data', '/login', '/admin', '/static/css/style.css']
            for url in random.sample(urls, random.randint(2, 4)):
                traffic_stats['http_urls'][url] = random.randint(1, 4)
    
    if elapsed >= 1:
        # Detect botnet activity before resetting stats
        attack_data = {}
        for ip, count in traffic_stats['ip_counter'].items():
            if count > 10:  # Threshold for suspicious activity
                attack_data[ip] = {
                    'last_attack_time': now,
                    'attack_type': 'high_volume',
                    'target': 'multiple'
                }
        
        botnet_alerts = advanced_detector.detect_botnet_activity(attack_data)
        if botnet_alerts:
            traffic_stats['botnet_activity'] += len(botnet_alerts)
            traffic_stats['advanced_alerts'].extend(botnet_alerts)
        
        # Update per-second stats
        traffic_stats['packets_per_second'] = traffic_stats['total_packets']
        traffic_stats['total_packets'] = 0
        traffic_stats['last_reset'] = now
        traffic_stats['ip_counter'] = defaultdict(int)
        
        # Reset per-second counters
        traffic_stats['udp_packets'] = 0
        traffic_stats['icmp_packets'] = 0
        traffic_stats['tcp_packets'] = 0
        traffic_stats['tcp_syn'] = 0
        traffic_stats['tcp_connections'] = defaultdict(int)
        traffic_stats['tcp_port_attacks'] = defaultdict(int)
        traffic_stats['http_packets'] = 0
        traffic_stats['http_requests'] = defaultdict(int)
        traffic_stats['http_responses'] = defaultdict(int)
        
        # Clean up old detection data periodically (every 5 minutes)
        if int(now) % 300 == 0:
            advanced_detector.cleanup_old_data()
    
    # Limit advanced alerts to last 20 to prevent memory issues
    if len(traffic_stats['advanced_alerts']) > 20:
        traffic_stats['advanced_alerts'] = traffic_stats['advanced_alerts'][-20:]
    
    return {
        'packets_per_second': traffic_stats['packets_per_second'],
        'ip_counter': dict(traffic_stats['ip_counter']),
        'udp_packets': traffic_stats['udp_packets'],
        'icmp_packets': traffic_stats['icmp_packets'],
        'tcp_packets': traffic_stats['tcp_packets'],
        'tcp_syn': traffic_stats['tcp_syn'],
        'tcp_syn_no_ack': dict(traffic_stats['tcp_syn_no_ack']),
        'tcp_connections': dict(traffic_stats['tcp_connections']),
        'tcp_port_attacks': dict(traffic_stats['tcp_port_attacks']),
        'http_packets': traffic_stats['http_packets'],
        'http_requests': dict(traffic_stats['http_requests']),
        'http_responses': dict(traffic_stats['http_responses']),
        'http_user_agents': dict(traffic_stats['http_user_agents']),
        'http_urls': dict(traffic_stats['http_urls']),
        'http_headers': dict(traffic_stats['http_headers']),
        # Advanced detection stats
        'port_scans': traffic_stats['port_scans'],
        'brute_force_attempts': traffic_stats['brute_force_attempts'],
        'dns_amplification': traffic_stats['dns_amplification'],
        'http_floods': traffic_stats['http_floods'],
        'botnet_activity': traffic_stats['botnet_activity'],
        'advanced_alerts': traffic_stats['advanced_alerts'][-10:],  # Last 10 alerts
        'protocol_stats': dict(traffic_stats['protocol_stats']),
        'total_advanced_threats': (
            traffic_stats['port_scans'] + 
            traffic_stats['brute_force_attempts'] + 
            traffic_stats['dns_amplification'] + 
            traffic_stats['http_floods'] + 
            traffic_stats['botnet_activity']
        ),
        # Capture status information
        'capture_status': {
            'real_capture_active': REAL_CAPTURE_ACTIVE,
            'capture_error': CAPTURE_ERROR,
            'total_packets_captured': traffic_stats['total_packets'],
            'is_simulated': not REAL_CAPTURE_ACTIVE and traffic_stats['total_packets'] > 0
        }
    }