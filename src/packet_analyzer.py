from scapy.all import rdpcap
from collections import Counter
from datetime import datetime
from filters import ip_filter
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

    for packet in packets:
        try:
            src_ip = packet["IP"].src if packet.haslayer("IP") else None
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else None

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

            # Uloženie informácií o pakete
            packet_info = {
                "timestamp": datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": packet["TCP"].sport if packet.haslayer("TCP") else (
                    packet["UDP"].sport if packet.haslayer("UDP") else "N/A"),
                "dst_port": packet["TCP"].dport if packet.haslayer("TCP") else (
                    packet["UDP"].dport if packet.haslayer("UDP") else "N/A"),
                "size": len(packet),
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

            # Spracovanie ostatných protokolov alebo paketov bez špecifikovaných pravidiel
            else:
                # Ak je dostupná vrstva Raw, pokúsime sa zobraziť aspoň 30 znakov
                if packet.haslayer("Raw"):
                    raw_data = packet["Raw"].load.decode(errors="ignore")
                    packet_info["payload"] = raw_data[:30] if raw_data else "N/A"
                else:
                    packet_info["payload"] = "Žiadne dáta"

            filtered_packets.append(packet_info)

            # Aktualizácia počtu protokolov
            protocol_counts[packet_info["protocol"]] += 1

        except Exception as e:
            print(e)

    return {
        "protocol_counts": protocol_counts,
        "filtered_packets": filtered_packets
    }
