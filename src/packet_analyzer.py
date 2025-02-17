from scapy.all import *
from collections import Counter, defaultdict
from datetime import datetime
from port_protocol import get_protocol_by_port, get_protocol_by_ip_proto
def map_tcp_flags(flags):
    flag_mapping = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR"
    }
    return [flag_mapping.get(flag, flag) for flag in flags]

def analyze_packets(file_path, filters):
    packets = rdpcap(file_path)
    protocol_counts = Counter()
    filtered_packets = []
    data_usage = defaultdict(int)

    for packet in packets:
        try:
            src_ip = packet["IP"].src if packet.haslayer("IP") else None
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else None
            timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S")
            packet_size = len(packet)

            # Zistenie protokolu
            if packet.haslayer("IP"):
                # Protokol z IP hlavičky
                protocol = get_protocol_by_ip_proto(packet["IP"].proto)
            elif packet.haslayer("TCP") or packet.haslayer("UDP"):
                # Protokol na základe portu (pre TCP a UDP)
                port = packet["TCP"].dport if packet.haslayer("TCP") else packet["UDP"].dport
                protocol = get_protocol_by_port(port)
            else:
                protocol = "Unknown"

            # Store packet information
            packet_info = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": packet["TCP"].sport if packet.haslayer("TCP") else (
                    packet["UDP"].sport if packet.haslayer("UDP") else "N/A"),
                "dst_port": packet["TCP"].dport if packet.haslayer("TCP") else (
                    packet["UDP"].dport if packet.haslayer("UDP") else "N/A"),
                "size": packet_size,
                "payload": "N/A"
            }
            # Spracovanie protokolu HTTP
            if packet.haslayer("TCP") and packet["TCP"].dport == 80:
                packet_info["protocol"] = "HTTP"
                http_data = ""

                # Kontrola existencie RAW vrstvy
                if packet.haslayer("Raw"):
                    raw_data = packet["Raw"].load.decode(errors="ignore")

                    # Na základe nájdenia metód nájdené HTTP dáta
                    if raw_data.startswith("GET") or raw_data.startswith("POST"):
                        http_data += f"Method: {raw_data.split(' ')[0]} "
                        # Dáta hlavičky HTTP
                        lines = raw_data.split("\r\n")
                        for line in lines[1:]:
                            if line.startswith("Host"):
                                http_data += f"Host: {line.split(':')[1].strip()}"
                        packet_info["payload"] = http_data if http_data else "N/A"
                    else:
                        packet_info["payload"] = "N/A"
                else:
                    packet_info["payload"] = "Žiadne dáta"

            # Spracovanie protokolu TCP
            elif packet.haslayer("TCP"):
                tcp_layer = packet["TCP"]
                tcp_payload = []

                # Pridanie TCP vlajok
                if tcp_layer.flags:
                    flags = map_tcp_flags(tcp_layer.sprintf("%TCP.flags%"))
                    tcp_payload.append(f"[{','.join(flags)}]")

                # Sekvenčné číslo
                if tcp_layer.seq:
                    tcp_payload.append(f"seq={tcp_layer.seq}")

                # Číslo potvrdenia
                if tcp_layer.ack:
                    tcp_payload.append(f"ack={tcp_layer.ack}")

                # Veľkosť okna
                if tcp_layer.window:
                    tcp_payload.append(f"win={tcp_layer.window}")

                # Kombinácia dát do payload
                packet_info["payload"] = ', '.join(tcp_payload) if tcp_payload else "N/A"

            elif packet.haslayer("Raw"):
                raw_data = packet["Raw"].load.decode(errors="ignore")
                packet_info["payload"] = raw_data[:30] if raw_data else "N/A"

            # Store the packet
            filtered_packets.append(packet_info)

            # Update protocol usage count
            protocol_counts[packet_info["protocol"]] += 1

            # Aggregate data usage per second
            data_usage[timestamp] += packet_size

        except Exception as e:
            print(f"Error processing packet: {e}")

    return {
        "protocol_counts": protocol_counts,
        "filtered_packets": filtered_packets,
        "data_usage": dict(data_usage)  # Convert defaultdict to a normal dict
    }
def interface_analyzer(interface, packet_queue, stop_event):
    """
    Captures packets on the given interface and sends them to the queue.
    """
    protocol_counts = Counter()
    data_usage = defaultdict(int)

    def packet_handler(packet):
        """Processes a single packet and places it into the queue."""
        try:
            src_ip = packet["IP"].src if packet.haslayer("IP") else None
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else None
            timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S")
            packet_size = len(packet)

            # Determine protocol
            if packet.haslayer("IP"):
                protocol = get_protocol_by_ip_proto(packet["IP"].proto)
            elif packet.haslayer("TCP") or packet.haslayer("UDP"):
                port = packet["TCP"].dport if packet.haslayer("TCP") else packet["UDP"].dport
                protocol = get_protocol_by_port(port)
            else:
                protocol = "Unknown"

            # Create packet info dictionary
            packet_info = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": packet["TCP"].sport if packet.haslayer("TCP") else (
                    packet["UDP"].sport if packet.haslayer("UDP") else "N/A"),
                "dst_port": packet["TCP"].dport if packet.haslayer("TCP") else (
                    packet["UDP"].dport if packet.haslayer("UDP") else "N/A"),
                "size": packet_size,
                "payload": "N/A"
            }

            # Handle HTTP, TCP, and Raw packet layers
            if packet.haslayer("TCP") and packet["TCP"].dport == 80:
                packet_info["protocol"] = "HTTP"
                http_data = ""

                if packet.haslayer("Raw"):
                    raw_data = packet["Raw"].load.decode(errors="ignore")
                    if raw_data.startswith("GET") or raw_data.startswith("POST"):
                        http_data += f"Method: {raw_data.split(' ')[0]} "
                        lines = raw_data.split("\r\n")
                        for line in lines[1:]:
                            if line.startswith("Host"):
                                http_data += f"Host: {line.split(':')[1].strip()}"
                        packet_info["payload"] = http_data if http_data else "N/A"
                    else:
                        packet_info["payload"] = "N/A"
                else:
                    packet_info["payload"] = "No Data"

            elif packet.haslayer("TCP"):
                tcp_layer = packet["TCP"]
                tcp_payload = []
                if tcp_layer.flags:
                    flags = map_tcp_flags(tcp_layer.sprintf("%TCP.flags%"))
                    tcp_payload.append(f"[{','.join(flags)}]")
                if tcp_layer.seq:
                    tcp_payload.append(f"seq={tcp_layer.seq}")
                if tcp_layer.ack:
                    tcp_payload.append(f"ack={tcp_layer.ack}")
                if tcp_layer.window:
                    tcp_payload.append(f"win={tcp_layer.window}")
                packet_info["payload"] = ', '.join(tcp_payload) if tcp_payload else "N/A"

            elif packet.haslayer("Raw"):
                raw_data = packet["Raw"].load.decode(errors="ignore")
                packet_info["payload"] = raw_data[:30] if raw_data else "N/A"

            # Add packet info to queue for processing in main.py
            packet_queue.put(packet_info)

        except Exception as e:
            print(f"Error processing packet: {e}")

    # Sniff packets in real-time, stopping when `stop_event` is set
    sniff(iface=interface, store=False, prn=packet_handler, stop_filter=lambda _: stop_event.is_set())