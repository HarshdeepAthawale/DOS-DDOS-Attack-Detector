from flask import Flask, render_template, jsonify
import threading
from detector.capture import start_sniffing, get_stats
from detector.analysis import check_for_dos
from detector.alerts import get_alerts

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
    return jsonify({'stats': stats, 'dos_alert': dos_alert, 'alerts': alerts})

if __name__ == '__main__':
    app.run(debug=True) 