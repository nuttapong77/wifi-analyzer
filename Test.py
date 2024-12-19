import pyshark

def analyze_bandwidth(interface='Wi-Fi'):
    capture = pyshark.LiveCapture(interface=interface)
    app_usage = {}

    for packet in capture.sniff_continuously(packet_count=100):
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            length = int(packet.length)
            protocol = packet.transport_layer

            if protocol not in app_usage:
                app_usage[protocol] = 0
            app_usage[protocol] += length

    return app_usage

# Example usage
bandwidth_usage = analyze_bandwidth()
for app, usage in bandwidth_usage.items():
    print(f"Application: {app}, Bandwidth Usage: {usage} bytes")
