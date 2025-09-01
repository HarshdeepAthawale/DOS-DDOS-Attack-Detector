"""
Configuration file for DoS/DDoS Attack Detector
"""

# Server Configuration
SERVER_CONFIG = {
    'host': '127.0.0.1',
    'port': 5000,
    'debug': True,
    'auto_reload': True,
    'threaded': True
}

# Detection Configuration
DETECTION_CONFIG = {
    'max_alerts': 100,
    'stats_cache_duration': 1,  # seconds
    'enable_email_alerts': True,
    'enable_advanced_detection': True,
    'enable_logging': True,
    'log_level': 'INFO',
    'log_file': 'detector.log'
}

# Threshold Configuration
THRESHOLDS = {
    'tcp_flood': 100,  # TCP packets per second
    'udp_flood': 80,   # UDP packets per second
    'http_flood': 50,  # HTTP packets per second
    'syn_flood': 50,   # SYN packets per second
    'icmp_flood': 50,  # ICMP packets per second
    'ddos_critical': 500,  # Total packets per second for DDoS
    'unique_ips_ddos': 50,  # Unique IPs for DDoS detection
    'port_scan': 10,   # Ports per minute
    'brute_force': 20,  # Attempts per minute
    'dns_amplification': 100,  # DNS queries per minute
    'http_requests': 30,  # HTTP requests per minute
}

# Email Configuration
EMAIL_CONFIG = {
    'enabled': True,
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'use_tls': True,
    'username': 'your_email@gmail.com',
    'password': 'your_app_password',
    'recipients': ['admin@example.com'],
    'subject_prefix': '[DoS/DDoS Alert]'
}

# Advanced Detection Configuration
ADVANCED_CONFIG = {
    'enable_port_scanning': True,
    'enable_syn_flood': True,
    'enable_http_flood': True,
    'enable_dns_amplification': True,
    'enable_brute_force': True,
    'enable_botnet_detection': True,
    'cleanup_interval': 300,  # 5 minutes
    'data_retention': 3600,   # 1 hour
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'detector.log',
    'max_size': 10 * 1024 * 1024,  # 10MB
    'backup_count': 5
}

# Development Configuration
DEV_CONFIG = {
    'enable_demo_data': True,
    'demo_data_interval': 5,  # seconds
    'enable_debug_endpoints': True,
    'enable_metrics': True
}
