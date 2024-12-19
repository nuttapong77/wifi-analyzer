from flask import Flask, jsonify, render_template
from prometheus_client import start_http_server
import threading
import time
from metrics_collector import collect_metrics_data

app = Flask(__name__)

# Metrics data (shared across threads)
metrics_data = {}

# Collect metrics (reuse your functions here)
def collect_metrics_data():
    global metrics_data
    wifi_info = get_current_wifi_info()
    metrics_data['wifi_info'] = wifi_info

    download_speed, upload_speed = get_throughput()
    metrics_data['download_speed'] = download_speed / 1e6  # Mbps
    metrics_data['upload_speed'] = upload_speed / 1e6  # Mbps

    latency = get_latency()
    metrics_data['latency'] = latency

    packet_loss = get_packet_loss()
    metrics_data['packet_loss'] = packet_loss

    bytes_sent, bytes_recv = get_bandwidth_utilization()
    metrics_data['bytes_sent'] = bytes_sent / 1e6  # MB
    metrics_data['bytes_recv'] = bytes_recv / 1e6  # MB

    device_count = get_device_count()
    metrics_data['device_count'] = device_count

    metrics_data['wifi_by_channel'] = get_wifi_networks_by_channel()

# Endpoint to fetch metrics
@app.route('/api/metrics', methods=['GET'])
def api_metrics():
    return jsonify(metrics_data)

# Frontend route
@app.route('/')
def index():
    return render_template('index.html')

# Schedule data collection
def schedule_metrics_collection():
    while True:
        collect_metrics_data()
        time.sleep(300)  # Collect every 5 minutes

# Start Prometheus server in a separate thread
def start_prometheus_server():
    start_http_server(8000)

if __name__ == '__main__':
    # Start Prometheus server
    threading.Thread(target=start_prometheus_server, daemon=True).start()
    
    # Start metrics collection thread
    threading.Thread(target=schedule_metrics_collection, daemon=True).start()
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
