import psutil
import ping3
import speedtest
from scapy.all import sniff, ARP
import subprocess
import schedule
import time
from prometheus_client import start_http_server, Gauge, Info

# Prometheus metrics
signal_strength_gauge = Gauge('wifi_signal_strength', 'WiFi Signal Strength', ['frequency'])
download_speed_gauge = Gauge('download_speed', 'Download Speed')
upload_speed_gauge = Gauge('upload_speed', 'Upload Speed')
latency_gauge = Gauge('latency', 'Latency')
packet_loss_gauge = Gauge('packet_loss', 'Packet Loss')
bytes_sent_gauge = Gauge('bytes_sent', 'Bytes Sent')
bytes_recv_gauge = Gauge('bytes_recv', 'Bytes Received')
device_count_gauge = Gauge('device_count', 'Device Count')

# Info metrics for Wi-Fi channels
channel_info_metric = Info('wifi_channel_info', 'WiFi Info by Channel', ['channel', 'bssid', 'ssid'])

# Function to get current Wi-Fi information
def get_current_wifi_info():
    result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
    wifi_info = {}
    for line in result.stdout.split('\n'):
        if 'SSID' in line and 'BSSID' not in line:
            wifi_info['SSID'] = line.split(':')[1].strip()
        elif 'BSSID' in line:
            wifi_info['BSSID'] = line.split(':')[1].strip()
        elif 'Signal' in line:
            wifi_info['Signal'] = int(line.split(':')[1].strip().replace('%', ''))
        elif 'Radio type' in line:
            wifi_info['Frequency'] = line.split(':')[1].strip()
        elif 'Channel' in line:
            wifi_info['Channel'] = line.split(':')[1].strip()
    return wifi_info

# Function to get all Wi-Fi networks grouped by channel
def get_wifi_networks_by_channel():
    result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], capture_output=True, text=True)
    networks = {}
    current_network = {}

    for line in result.stdout.split('\n'):
        if 'SSID' in line and 'BSSID' not in line:
            if current_network:  # Save the previous network
                channel = current_network.get('Channel', 'unknown')
                if channel not in networks:
                    networks[channel] = []
                networks[channel].append(current_network)
                current_network = {}
            current_network['SSID'] = line.split(':')[1].strip()
        elif 'BSSID' in line:
            current_network['BSSID'] = line.split(':')[1].strip()
        elif 'Signal' in line:
            current_network['Signal'] = int(line.split(':')[1].strip().replace('%', ''))
        elif 'Radio type' in line:
            current_network['Frequency'] = line.split(':')[1].strip()
        elif 'Channel' in line:
            current_network['Channel'] = line.split(':')[1].strip()

    if current_network:  # Add the last network
        channel = current_network.get('Channel', 'unknown')
        if channel not in networks:
            networks[channel] = []
        networks[channel].append(current_network)

    return networks

# Function to measure throughput
def get_throughput():
    try:
        st = speedtest.Speedtest(secure=True)
        download_speed = st.download()
        upload_speed = st.upload()
        return download_speed, upload_speed
    except Exception as e:
        print(f"Error in throughput measurement: {e}")
        return 0, 0

# Function to measure latency
def get_latency(host='8.8.8.8'):
    try:
        return ping3.ping(host)
    except Exception as e:
        print(f"Error in latency measurement: {e}")
        return None

# Function to measure packet loss
def get_packet_loss(host='8.8.8.8', count=10):
    try:
        lost = 0
        for _ in range(count):
            if ping3.ping(host) is None:
                lost += 1
        return lost / count
    except Exception as e:
        print(f"Error in packet loss measurement: {e}")
        return 1

# Function to measure bandwidth utilization
def get_bandwidth_utilization():
    net_io = psutil.net_io_counters()
    return net_io.bytes_sent, net_io.bytes_recv

# Function to count devices on the network
def get_device_count():
    devices = set()

    def arp_display(pkt):
        if pkt[ARP].op == 1:  # who-has (request)
            devices.add(pkt[ARP].psrc)

    sniff(prn=arp_display, filter="arp", store=0, count=10, timeout=10)
    return len(devices)

# Collect metrics and print information
def collect_metrics():
    wifi_info = get_current_wifi_info()

    # Update current Wi-Fi signal strength
    if 'Signal' in wifi_info and 'Frequency' in wifi_info:
        signal_strength_gauge.labels(frequency=wifi_info['Frequency']).set(wifi_info['Signal'])
        print(f"SSID: {wifi_info.get('SSID', 'unknown')} | BSSID: {wifi_info.get('BSSID', 'unknown')} | Signal: {wifi_info.get('Signal')}% | Frequency: {wifi_info.get('Frequency')} | Channel: {wifi_info.get('Channel', 'unknown')}")

    # Update throughput
    download_speed, upload_speed = get_throughput()
    download_speed_gauge.set(download_speed)
    upload_speed_gauge.set(upload_speed)
    print(f"Download Speed: {download_speed / 1e6:.2f} Mbps")
    print(f"Upload Speed: {upload_speed / 1e6:.2f} Mbps")

    # Update latency
    latency = get_latency()
    if latency is not None:
        latency_gauge.set(latency)
        print(f"Latency: {latency:.2f} ms")

    # Update packet loss
    packet_loss = get_packet_loss()
    packet_loss_gauge.set(packet_loss)
    print(f"Packet Loss: {packet_loss:.2%}")

    # Update bandwidth utilization
    bytes_sent, bytes_recv = get_bandwidth_utilization()
    bytes_sent_gauge.set(bytes_sent)
    bytes_recv_gauge.set(bytes_recv)
    print(f"Bytes Sent: {bytes_sent / 1e6:.2f} MB")
    print(f"Bytes Received: {bytes_recv / 1e6:.2f} MB")

    # Update device count
    device_count = get_device_count()
    device_count_gauge.set(device_count)
    print(f"Device Count: {device_count}")

    # Display all available Wi-Fi networks by channel
    wifi_by_channel = get_wifi_networks_by_channel()
    print("\n--- Wi-Fi Networks by Channel ---")
    for channel, networks in wifi_by_channel.items():
        print(f"Channel: {channel}")
        for network in networks:
            print(f"  SSID: {network.get('SSID', 'unknown')} | BSSID: {network.get('BSSID', 'unknown')} | Signal: {network.get('Signal', 0)}% | Frequency: {network.get('Frequency', 'unknown')}")

        # Update Prometheus Info metric
        for network in networks:
            channel_info_metric.labels(
                channel=channel,
                bssid=network.get('BSSID', 'unknown'),
                ssid=network.get('SSID', 'unknown')
            )

# Start Prometheus server
start_http_server(8000)

# Schedule metrics collection every 5 minutes
schedule.every(5).minutes.do(collect_metrics)

try:
    while True:
        schedule.run_pending()
        time.sleep(1)
except KeyboardInterrupt:
    print("Program interrupted by user.")

