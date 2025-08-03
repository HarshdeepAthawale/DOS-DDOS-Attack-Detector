from flask import Flask, render_template, jsonify
import threading
from detector.capture import start_sniffing, get_stats
from detector.analysis import check_for_dos, get_threat_summary
from detector.alerts import get_alerts, add_alert

app = Flask(__name__)

# Start packet sniffing in a background thread
def start_background_sniffing():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

start_background_sniffing()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stats')
def stats():
    stats = get_stats()
    dos_alert = check_for_dos(stats)
    alerts = get_alerts()
    threat_summary = get_threat_summary(stats)
    
    # Add new alerts to the alert system if any threats detected
    if dos_alert and dos_alert.strip():
        for alert_line in dos_alert.split('\n'):
            if alert_line.strip():
                add_alert(alert_line.strip())
    
    return jsonify({
        'stats': stats, 
        'dos_alert': dos_alert, 
        'alerts': alerts,
        'threat_summary': threat_summary,
        'advanced_stats': {
            'port_scans': stats.get('port_scans', 0),
            'brute_force_attempts': stats.get('brute_force_attempts', 0),
            'dns_amplification': stats.get('dns_amplification', 0),
            'http_floods': stats.get('http_floods', 0),
            'botnet_activity': stats.get('botnet_activity', 0),
            'protocol_breakdown': stats.get('protocol_stats', {}),
            'total_advanced_threats': stats.get('total_advanced_threats', 0)
        }
    })

@app.route('/advanced-alerts')
def advanced_alerts():
    """Get detailed advanced threat alerts"""
    stats = get_stats()
    advanced_alerts = stats.get('advanced_alerts', [])
    return jsonify({
        'alerts': advanced_alerts[-20:],  # Last 20 alerts
        'total_count': len(advanced_alerts)
    })

@app.route('/threat-dashboard')
def threat_dashboard():
    """Enhanced dashboard with advanced threat information"""
    stats = get_stats()
    threat_summary = get_threat_summary(stats)
    return jsonify(threat_summary)

if __name__ == '__main__':
    app.run(debug=True)