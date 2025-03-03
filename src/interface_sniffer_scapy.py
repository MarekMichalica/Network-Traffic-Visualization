import argparse
import threading
import queue
import curses
import subprocess
import json
import os
from datetime import datetime
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from pcap_analyzer import clean_string, wrap_text


def write_packets_to_json(packets, json_file):
    # Create directory if it doesn't exist
    directory = os.path.dirname(json_file)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)

    data = {
        "packets": packets
    }
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=4)


def write_data_usage_to_json(data_usage, json_file):
    # Create directory if it doesn't exist
    directory = os.path.dirname(json_file)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)

    data_usage_list = [{"timestamp": str(timestamp), "data_usage": str(size)} for timestamp, size in data_usage.items()]

    with open(json_file, 'w') as f:
        json.dump(data_usage_list, f, indent=4)


def detect_protocol(packet):
    """Enhanced protocol detection logic"""
    # Start with a default protocol
    protocol = "Unknown"

    # Check for IP layer
    if IP in packet:
        # Common protocols by IP protocol number
        ip_proto = packet[IP].proto
        proto_map = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP",
            41: "IPv6",
            50: "ESP",
            51: "AH",
            58: "ICMPv6",
            89: "OSPF"
        }
        protocol = proto_map.get(ip_proto, "IP")

        # For TCP/UDP, try to determine higher-level protocol
        if TCP in packet:
            # Get source and destination ports
            sport, dport = packet[TCP].sport, packet[TCP].dport

            # Try to identify by well-known ports
            if dport == 80 or sport == 80:
                protocol = "HTTP"
            elif dport == 443 or sport == 443:
                protocol = "HTTPS"
            elif dport == 22 or sport == 22:
                protocol = "SSH"
            elif dport == 23 or sport == 23:
                protocol = "Telnet"
            elif dport == 21 or sport == 21 or dport == 20 or sport == 20:
                protocol = "FTP"
            elif dport == 25 or sport == 25:
                protocol = "SMTP"
            elif dport == 110 or sport == 110:
                protocol = "POP3"
            elif dport == 143 or sport == 143:
                protocol = "IMAP"
            elif dport == 53 or sport == 53:
                protocol = "DNS"
            elif dport == 3306 or sport == 3306:
                protocol = "MySQL"
            elif dport == 5432 or sport == 5432:
                protocol = "PostgreSQL"
            elif dport == 6379 or sport == 6379:
                protocol = "Redis"
            elif dport == 8080 or sport == 8080:
                protocol = "HTTP-Alt"

            # Try to detect HTTP based on payload content
            if protocol == "TCP" and Raw in packet:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if any(method in payload for method in ["GET ", "POST ", "HTTP/1.", "HTTP/2."]):
                        protocol = "HTTP"
                except:
                    pass

        elif UDP in packet:
            # Get source and destination ports
            sport, dport = packet[UDP].sport, packet[UDP].dport

            # Try to identify by well-known ports
            if dport == 53 or sport == 53:
                protocol = "DNS"
            elif dport == 67 or dport == 68 or sport == 67 or sport == 68:
                protocol = "DHCP"
            elif dport == 123 or sport == 123:
                protocol = "NTP"
            elif dport == 161 or sport == 161:
                protocol = "SNMP"
            elif dport == 514 or sport == 514:
                protocol = "Syslog"

        # Check for specific protocol layers
        if ICMP in packet:
            protocol = "ICMP"
        elif DNS in packet:
            protocol = "DNS"
        elif HTTPRequest in packet or HTTPResponse in packet or HTTP in packet:
            protocol = "HTTP"

    return protocol


def extract_payload(packet, protocol):
    """Extract meaningful payload based on protocol"""
    payload = "N/A"

    # Try to extract payload based on the protocol
    if TCP in packet:
        tcp_flags = []
        flags = packet[TCP].flags

        # Map TCP flags
        flag_mapping = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR'
        }

        for flag_char, flag_name in flag_mapping.items():
            if packet[TCP].flags & getattr(TCP, flag_char):
                tcp_flags.append(flag_name)

        if tcp_flags:
            payload = f"[{','.join(tcp_flags)}]"

        # Add sequence and acknowledgment if present
        if hasattr(packet[TCP], 'seq'):
            if payload != "N/A":
                payload += f", seq={packet[TCP].seq}"
            else:
                payload = f"seq={packet[TCP].seq}"

        if hasattr(packet[TCP], 'ack') and packet[TCP].ack:
            if payload != "N/A":
                payload += f", ack={packet[TCP].ack}"
            else:
                payload = f"ack={packet[TCP].ack}"

    # Protocol-specific payload extraction
    if protocol == "HTTP" and Raw in packet:
        try:
            http_data = packet[Raw].load.decode('utf-8', errors='ignore')

            # For HTTP requests
            if "GET " in http_data or "POST " in http_data or "PUT " in http_data:
                # Extract the first line (request line)
                first_line = http_data.split('\r\n')[0]
                payload = first_line

            # For HTTP responses
            elif "HTTP/1." in http_data or "HTTP/2." in http_data:
                # Extract the first line (status line)
                first_line = http_data.split('\r\n')[0]
                payload = first_line
        except:
            pass

    elif protocol == "DNS" and DNS in packet:
        dns_packet = packet[DNS]

        # For DNS queries
        if dns_packet.qr == 0:  # Query
            if dns_packet.qd and dns_packet.qd.qname:
                try:
                    query_name = dns_packet.qd.qname.decode('utf-8')
                    payload = f"Query: {query_name}"
                except:
                    payload = "DNS Query"

        # For DNS responses
        elif dns_packet.qr == 1:  # Response
            if dns_packet.an and dns_packet.an.rrname:
                try:
                    response_name = dns_packet.an.rrname.decode('utf-8')
                    payload = f"Response: {response_name}"
                except:
                    payload = "DNS Response"

    elif protocol == "ICMP" and ICMP in packet:
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded"
        }
        icmp_type = packet[ICMP].type
        payload = f"{icmp_types.get(icmp_type, f'Type {icmp_type}')}"

    # If we still don't have a meaningful payload but Raw data exists
    if (payload == "N/A" or payload == "") and Raw in packet:
        try:
            raw_data = packet[Raw].load
            if isinstance(raw_data, bytes):
                # Try to decode as text first
                try:
                    text = raw_data.decode('utf-8', errors='ignore')
                    # Only use text if it contains printable characters
                    if any(32 <= ord(c) <= 126 for c in text):
                        payload = text[:30]
                        if len(text) > 30:
                            payload += "..."
                except:
                    # Fallback to hex representation
                    payload = raw_data.hex()[:30]
                    if len(raw_data) > 15:
                        payload += "..."
        except:
            pass

    return payload


def process_packet(packet, packet_queue, sniffing_event, packets, data_usage, packets_json_file, data_usage_json_file):
    """Processes captured packets and adds them to the queue."""
    if not sniffing_event.is_set():
        return  # Ignore packets when sniffing is paused

    try:
        # Basic packet info
        timestamp = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S")
        size = len(packet)

        # IP layer info
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            src_ip = "Unknown"
            dst_ip = "Unknown"

        # Detect protocol with enhanced logic
        protocol = detect_protocol(packet)

        # Get port information
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = "-"
            dst_port = "-"

        # Extract meaningful payload
        payload = extract_payload(packet, protocol)

        # Clean and truncate the payload for display
        payload = clean_string(payload)
        if len(payload) > 40:  # Limit payload length for display
            payload = payload[:37] + "..."

        packet_info = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": size,
            "payload": payload
        }

        packet_queue.put(packet_info)
        packets.append(packet_info)

        # Track data usage by timestamp
        if timestamp in data_usage:
            data_usage[timestamp] += size
        else:
            data_usage[timestamp] = size

        # Periodically write to JSON files
        if len(packets) % 10 == 0:
            write_packets_to_json(packets, packets_json_file)
            write_data_usage_to_json(data_usage, data_usage_json_file)

    except Exception as e:
        print(f"Error processing packet: {e}")


def sniff_packets(interface, packet_queue, stop_event, sniffing_event, packets_json_file, data_usage_json_file):
    """Sniffs packets on the selected interface."""
    packets = []
    data_usage = {}

    # Make sure we load all needed layers
    from scapy.all import load_layer
    load_layer("http")

    sniff(
        prn=lambda packet: process_packet(packet, packet_queue, sniffing_event, packets, data_usage, packets_json_file,
                                          data_usage_json_file),
        iface=interface,
        store=False,
        stop_filter=lambda _: stop_event.is_set())  # Stop if event is set

    # Write final data when stopping
    write_packets_to_json(packets, packets_json_file)
    write_data_usage_to_json(data_usage, data_usage_json_file)


def display_packets(stdscr, interface, filters):
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    packet_queue = queue.Queue()
    stop_event = threading.Event()
    sniffing_event = threading.Event()
    sniffing_event.set()  # Initially start sniffing

    # Use os.path.join for platform independence
    packets_json_file = os.path.join('live_visualisations', 'captured_packets.json')
    data_usage_json_file = os.path.join('live_visualisations', 'data_usage.json')

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=sniff_packets,
                                    args=(interface, packet_queue, stop_event, sniffing_event, packets_json_file,
                                          data_usage_json_file),
                                    daemon=True)
    sniff_thread.start()

    # Store all packet lines for scrolling capability
    all_packet_lines = []
    # Current scroll position
    scroll_position = 0
    # Number of visible lines in the packet display area
    visible_lines = max_y - 12

    stdscr.addstr(0, 0, f"Sledovanie paketov na rozhraní: {interface}")
    stdscr.addstr(2, 0,
                  "| Čas      | Zdrojová IP     | Cieľová IP      | Protokol | Porty         | Veľkosť    | Dáta ")
    stdscr.addstr(3, 0, "-" * 120)

    stdscr.timeout(100)  # Non-blocking key input

    while True:
        # Process new packets
        packets_added = False
        while not packet_queue.empty():
            packet_info = packet_queue.get()
            packet_info_str = (f"| {packet_info['timestamp']} | "
                               f"{packet_info['src_ip']:<15} | {packet_info['dst_ip']:<15} | "
                               f"{packet_info['protocol']:<8} | {packet_info['src_port']:<5} -> {packet_info['dst_port']:<5} | "
                               f"{packet_info['size']:<5} bajtov | {packet_info['payload']}")

            wrapped_lines = wrap_text(packet_info_str, max_x - 2)

            for line in wrapped_lines:
                clean_line = clean_string(line)
                all_packet_lines.append(clean_line)
                packets_added = True

        # When sniffing and new packets arrive, auto-scroll to the bottom
        if packets_added and sniffing_event.is_set():
            scroll_position = max(0, len(all_packet_lines) - visible_lines)

        # Clear the packet display area
        for i in range(4, max_y - 8):
            stdscr.addstr(i, 0, " " * (max_x - 1))

        # Display the visible part of the packet lines based on scroll position
        visible_end = min(len(all_packet_lines), scroll_position + visible_lines)
        for i, line_idx in enumerate(range(scroll_position, visible_end), start=4):
            stdscr.addstr(i, 0, all_packet_lines[line_idx])

        # Display scroll indicator and instructions
        if len(all_packet_lines) > visible_lines:
            # Clear the scroll status line first to prevent overlapping text
            stdscr.addstr(max_y - 6, 0, " " * (max_x - 1))

            scroll_percent = int(scroll_position / (len(all_packet_lines) - visible_lines) * 100)
            scroll_status = f"Scroll: {scroll_percent}% (↑/↓ to scroll)"
            stdscr.addstr(max_y - 6, max_x - len(scroll_status) - 3, scroll_status)

        # Menu and status lines
        stdscr.addstr(max_y - 5, 0,
                      "MENU: A) Vizualizácia 2 zariadení podľa IP B) Filtrovanie C) Vizualizácia".center(max_x))
        stdscr.addstr(max_y - 4, 0, "D) Export (JSON/CSV) E) ŠTART/STOP zachytávania F) Ukončiť".center(max_x))

        # Status line
        if sniffing_event.is_set():
            status_msg = "Zachytávanie AKTÍVNE. Stlačte E pre zastavenie."
        else:
            status_msg = "Zachytávanie POZASTAVENÉ. Stlačte E pre obnovenie."

        stdscr.addstr(max_y - 3, 0, status_msg.center(max_x))

        # Handle key presses
        key = stdscr.getch()

        # Handle scrolling
        if key == curses.KEY_UP and scroll_position > 0:
            scroll_position -= 1
        elif key == curses.KEY_DOWN and scroll_position < len(all_packet_lines) - visible_lines:
            scroll_position += 1
        elif key == curses.KEY_PPAGE:  # Page Up
            scroll_position = max(0, scroll_position - visible_lines)
        elif key == curses.KEY_NPAGE:  # Page Down
            scroll_position = min(len(all_packet_lines) - visible_lines, scroll_position + visible_lines)
        elif key == ord('g'):  # Go to top
            scroll_position = 0
        elif key == ord('G'):  # Go to bottom
            scroll_position = max(0, len(all_packet_lines) - visible_lines)

        # Handle menu options
        elif key == ord('A') or key == ord('a'):
            stdscr.clear()
            stdscr.refresh()

            subprocess.run([
                "python", r"two_devices.py",
            ])
            return
        elif key == ord('C') or key == ord('c'):
            stdscr.clear()
            stdscr.refresh()

            stdscr.addstr(0, 0, f"Sledovanie paketov na rozhraní: {interface}")
            stdscr.addstr(2, 0,
                          "| Čas      | Zdrojová IP     | Cieľová IP      | Protokol | Porty         | Veľkosť    | Dáta ")
            stdscr.addstr(3, 0, "-" * 120)

            subprocess.Popen(
                ["python", "live_visualisations_selector.py", packets_json_file],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            stdscr.refresh()
        elif key == ord('E') or key == ord('e'):
            if sniffing_event.is_set():
                sniffing_event.clear()
            else:
                sniffing_event.set()
                # When resuming, scroll to the bottom to see new packets
                scroll_position = max(0, len(all_packet_lines) - visible_lines)
            stdscr.refresh()
        elif key == ord('f') or key == ord('F'):
            stop_event.set()
            sniff_thread.join()
            return

        stdscr.refresh()


def main():
    parser = argparse.ArgumentParser(description="Snímač paketov s rozhraním curses.")
    parser.add_argument("--interface", required=True, help="Sieťové rozhranie na zachytávanie")
    parser.add_argument("--pcap_file", help="PCAP súbor")
    args = parser.parse_args()

    # Enable arrow keys and other special keys
    curses.setupterm()

    curses.wrapper(display_packets, args.interface, args.pcap_file)


if __name__ == "__main__":
    main()