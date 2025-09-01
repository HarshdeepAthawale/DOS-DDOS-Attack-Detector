from flask import Flask, render_template, jsonify, request
import threading
import time
import logging
from datetime import datetime
from detector.capture import start_sniffing, get_stats, get_capture_status, test_packet_capture
from detector.analysis import check_for_dos, get_threat_summary
from detector.alerts import get_alerts, add_alert

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('detector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
CONFIG = {
    'host': '127.0.0.1',
    'port': 5000,
    'debug': True,
    'auto_reload': True,
    'max_alerts': 100,
    'stats_cache_duration': 1,  # seconds
    'enable_email_alerts': True,
    'enable_advanced_detection': True
}

# Global variables for monitoring
app_start_time = time.time()
last_stats_time = 0
stats_cache = None
sniffing_active = False

# Start packet sniffing in a background thread
def start_background_sniffing():
    global sniffing_active
    try:
        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()
        sniffing_active = True
        logger.info("Packet sniffing started successfully")
    except Exception as e:
        logger.error(f"Failed to start packet sniffing: {e}")
        sniffing_active = False

# Initialize the application
def initialize_app():
    """Initialize the application and start background services"""
    logger.info("Initializing DoS/DDoS Attack Detector...")
    start_background_sniffing()
    logger.info(f"Application started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Initialize on startup
initialize_app()

@app.route('/')
def index():
    """Main dashboard page"""
    try:
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error rendering index page: {e}")
        return "Error loading dashboard", 500

@app.route('/stats')
def stats():
    """Get real-time statistics and threat data"""
    global last_stats_time, stats_cache
    
    try:
        current_time = time.time()
        
        # Use cached stats if within cache duration
        if (stats_cache and 
            current_time - last_stats_time < CONFIG['stats_cache_duration']):
            return jsonify(stats_cache)
        
        # Get fresh stats
        stats_data = get_stats()
        dos_alert = check_for_dos(stats_data)
        alerts = get_alerts()
        threat_summary = get_threat_summary(stats_data)
        
        # Add new alerts to the alert system if any threats detected
        if dos_alert and dos_alert.strip():
            for alert_line in dos_alert.split('\n'):
                if alert_line.strip():
                    add_alert(alert_line.strip())
                    logger.warning(f"Threat detected: {alert_line.strip()}")
        
        # Prepare response
        response_data = {
            'stats': stats_data, 
            'dos_alert': dos_alert, 
            'alerts': alerts,
            'threat_summary': threat_summary,
            'system_info': {
                'uptime': current_time - app_start_time,
                'sniffing_active': sniffing_active,
                'timestamp': datetime.now().isoformat()
            },
            'advanced_stats': {
                'port_scans': stats_data.get('port_scans', 0),
                'brute_force_attempts': stats_data.get('brute_force_attempts', 0),
                'dns_amplification': stats_data.get('dns_amplification', 0),
                'http_floods': stats_data.get('http_floods', 0),
                'botnet_activity': stats_data.get('botnet_activity', 0),
                'protocol_breakdown': stats_data.get('protocol_stats', {}),
                'total_advanced_threats': stats_data.get('total_advanced_threats', 0)
            }
        }
        
        # Cache the response
        stats_cache = response_data
        last_stats_time = current_time
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({
            'error': 'Failed to get statistics',
            'message': str(e)
        }), 500

@app.route('/advanced-alerts')
def advanced_alerts():
    """Get detailed advanced threat alerts"""
    try:
        stats_data = get_stats()
        advanced_alerts = stats_data.get('advanced_alerts', [])
        return jsonify({
            'alerts': advanced_alerts[-CONFIG['max_alerts']:],  # Last N alerts
            'total_count': len(advanced_alerts),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting advanced alerts: {e}")
        return jsonify({'error': 'Failed to get advanced alerts'}), 500

@app.route('/threat-dashboard')
def threat_dashboard():
    """Enhanced dashboard with advanced threat information"""
    try:
        stats_data = get_stats()
        threat_summary = get_threat_summary(stats_data)
        return jsonify(threat_summary)
    except Exception as e:
        logger.error(f"Error getting threat dashboard: {e}")
        return jsonify({'error': 'Failed to get threat dashboard'}), 500

@app.route('/system-status')
def system_status():
    """Get system status and health information"""
    try:
        current_time = time.time()
        return jsonify({
            'status': 'running',
            'uptime': current_time - app_start_time,
            'sniffing_active': sniffing_active,
            'start_time': datetime.fromtimestamp(app_start_time).isoformat(),
            'current_time': datetime.now().isoformat(),
            'version': '1.0.0',
            'config': CONFIG
        })
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({'error': 'Failed to get system status'}), 500

@app.route('/config', methods=['GET', 'POST'])
def config():
    """Get or update configuration"""
    global CONFIG
    
    if request.method == 'GET':
        return jsonify(CONFIG)
    
    elif request.method == 'POST':
        try:
            new_config = request.get_json()
            if new_config:
                CONFIG.update(new_config)
                logger.info(f"Configuration updated: {new_config}")
                return jsonify({'message': 'Configuration updated successfully', 'config': CONFIG})
            return jsonify({'error': 'No configuration data provided'}), 400
        except Exception as e:
            logger.error(f"Error updating configuration: {e}")
            return jsonify({'error': 'Failed to update configuration'}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'sniffing_active': sniffing_active
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/capture-status')
def capture_status():
    """Get detailed packet capture status and troubleshooting info"""
    try:
        status = get_capture_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting capture status: {e}")
        return jsonify({'error': 'Failed to get capture status'}), 500

@app.route('/test-capture')
def test_capture():
    """Test if packet capture is working"""
    try:
        success, message = test_packet_capture()
        return jsonify({
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error testing packet capture: {e}")
        return jsonify({'error': 'Failed to test packet capture'}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    try:
        logger.info(f"Starting DoS/DDoS Attack Detector on {CONFIG['host']}:{CONFIG['port']}")
        app.run(
            host=CONFIG['host'],
            port=CONFIG['port'],
            debug=CONFIG['debug'],
            use_reloader=CONFIG['auto_reload']
        )
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise