import pyshark
from collections import Counter, defaultdict

def analyze_packets(file_path, filters=None):
    cap = pyshark.FileCapture(file_path)

    protocol_counts = Counter()
    filtered_packets = []
    data_usage = defaultdict(int)

    for packet in cap:
        try:
            # Check if packet has IP layer
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            else:
                # Skip non-IP packets if we're filtering by IP
                if filters and (filters.get('ip_a') or filters.get('ip_b')):
                    continue
                src_ip = "N/A"
                dst_ip = "N/A"

            # Apply IP filters if specified
            if filters:
                if filters.get('ip_a') and filters.get('ip_b'):
                    # Filter for communication between two specific IPs
                    if not ((src_ip == filters['ip_a'] and dst_ip == filters['ip_b']) or
                            (src_ip == filters['ip_b'] and dst_ip == filters['ip_a'])):
                        continue
                elif filters.get('ip_a'):
                    # Filter for packets from or to a specific IP
                    if src_ip != filters['ip_a'] and dst_ip != filters['ip_a']:
                        continue
                elif filters.get('ip_b'):
                    # Filter for packets from or to a specific IP
                    if src_ip != filters['ip_b'] and dst_ip != filters['ip_b']:
                        continue

            # Get timestamp
            timestamp = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S")
            packet_size = int(packet.length) if hasattr(packet, 'length') else 0

            # Determine protocol - use the highest layer or transport layer
            protocol = packet.highest_layer

            # Get port information for TCP or UDP
            src_port = "N/A"
            dst_port = "N/A"
            payload = "N/A"

            # Get transport layer info if available
            if hasattr(packet, 'tcp'):
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport

                # Get TCP flags if available
                tcp_payload = []
                if hasattr(packet.tcp, 'flags'):
                    flags = []
                    flag_value = int(packet.tcp.flags, 16)
                    if flag_value & 0x01: flags.append("FIN")
                    if flag_value & 0x02: flags.append("SYN")
                    if flag_value & 0x04: flags.append("RST")
                    if flag_value & 0x08: flags.append("PSH")
                    if flag_value & 0x10: flags.append("ACK")
                    if flag_value & 0x20: flags.append("URG")
                    tcp_payload.append(f"[{','.join(flags)}]")

                # Get sequence and acknowledgment numbers
                if hasattr(packet.tcp, 'seq'):
                    tcp_payload.append(f"seq={packet.tcp.seq}")
                if hasattr(packet.tcp, 'ack'):
                    tcp_payload.append(f"ack={packet.tcp.ack}")
                if hasattr(packet.tcp, 'window_size'):
                    tcp_payload.append(f"win={packet.tcp.window_size}")

                payload = ', '.join(tcp_payload) if tcp_payload else "N/A"

            elif hasattr(packet, 'udp'):
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport

            # Specific protocol handling for better payload information
            if protocol == 'HTTP':
                if hasattr(packet, 'http'):
                    http_data = ""
                    if hasattr(packet.http, 'request_method'):
                        http_data += f"Method: {packet.http.request_method} "
                        if hasattr(packet.http, 'request_uri'):
                            http_data += f"URI: {packet.http.request_uri} "
                    if hasattr(packet.http, 'host'):
                        http_data += f"Host: {packet.http.host}"
                    payload = http_data if http_data else "N/A"

            # Try to get payload from data layer if available
            if payload == "N/A" and hasattr(packet, 'data'):
                try:
                    data_bytes = bytes.fromhex(packet.data.data)
                    printable_chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data_bytes)
                    payload = printable_chars[:30]
                except:
                    payload = "N/A"

            # Store packet information
            packet_info = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "size": packet_size,
                "payload": payload
            }

            filtered_packets.append(packet_info)
            protocol_counts[protocol] += 1
            data_usage[timestamp] += packet_size

        except Exception as e:
            print(f"Error processing packet: {e}")

    return {
        "protocol_counts": protocol_counts,
        "filtered_packets": filtered_packets,
        "data_usage": dict(data_usage)
    }