import argparse
import asyncio
import pyshark
import threading
import queue
import curses
import subprocess
import json
import os

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


def sniff_packets(interface, packet_queue, stop_event, sniffing_event, packets_json_file, data_usage_json_file):
    asyncio.set_event_loop(asyncio.new_event_loop())
    capture = pyshark.LiveCapture(interface=interface, display_filter="ip")
    packets = []
    data_usage = {}

    try:
        for packet in capture.sniff_continuously():
            if stop_event.is_set():
                break

            if not sniffing_event.is_set():
                continue

            try:
                timestamp = packet.sniff_time.strftime("%H:%M:%S")
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.highest_layer
                size = int(packet.length)
                src_port = packet[packet.transport_layer].srcport if hasattr(packet, "transport_layer") else "-"
                dst_port = packet[packet.transport_layer].dstport if hasattr(packet, "transport_layer") else "-"
                payload = "N/A"

                try:
                    # Try to get application layer data if available
                    if hasattr(packet, protocol.lower()):
                        protocol_layer = getattr(packet, protocol.lower())

                        # For HTTP protocol
                        if protocol == "HTTP":
                            if hasattr(protocol_layer, "request_uri"):
                                payload = f"HTTP {protocol_layer.request_method} {protocol_layer.request_uri}"
                            elif hasattr(protocol_layer, "response_code"):
                                payload = f"HTTP {protocol_layer.response_code} {protocol_layer.response_phrase}"

                        # For DNS protocol
                        elif protocol == "DNS":
                            if hasattr(protocol_layer, "qry_name"):
                                payload = f"DNS Query: {protocol_layer.qry_name}"

                        # For TLS/SSL
                        elif protocol == "TLS" or protocol == "SSL":
                            if hasattr(protocol_layer, "handshake_type"):
                                handshake_types = {
                                    "1": "Client Hello",
                                    "2": "Server Hello",
                                    "11": "Certificate",
                                    "16": "Client Key Exchange"
                                }
                                type_num = protocol_layer.handshake_type
                                payload = f"TLS {handshake_types.get(type_num, type_num)}"

                        # For ICMP
                        elif protocol == "ICMP":
                            if hasattr(protocol_layer, "type"):
                                icmp_types = {
                                    "0": "Echo Reply",
                                    "8": "Echo Request"
                                }
                                type_num = protocol_layer.type
                                payload = f"ICMP {icmp_types.get(type_num, type_num)}"

                        # For other protocols, try to extract some meaningful data
                        else:
                            # Try to get a field that might contain payload data
                            for field_name in dir(protocol_layer):
                                if not field_name.startswith('_') and field_name not in ['field_names', 'layer_name']:
                                    field_value = getattr(protocol_layer, field_name)
                                    if isinstance(field_value, str) and len(field_value) > 0:
                                        payload = f"{field_name}: {field_value}"
                                        break

                    # If no application layer data, try to get raw data
                    if payload == "N/A" and hasattr(packet, "frame_raw"):
                        raw_data = packet.frame_raw.value
                        # Convert bytes to ASCII, replacing non-printable chars
                        printable_chars = ''.join(
                            chr(byte) if 32 <= byte <= 126 else '.' for byte in bytes.fromhex(raw_data))
                        payload = printable_chars[:30] + "..." if len(printable_chars) > 30 else printable_chars

                except Exception as e:
                    payload = f"Error extracting payload: {str(e)[:20]}"

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

                if timestamp in data_usage:
                    data_usage[timestamp] += size
                else:
                    data_usage[timestamp] = size

                if len(packets) % 10 == 0:
                    write_packets_to_json(packets, packets_json_file)
                    write_data_usage_to_json(data_usage, data_usage_json_file)

            except AttributeError as e:
                continue
    finally:
        capture.close()
        write_packets_to_json(packets, packets_json_file)
        write_data_usage_to_json(data_usage, data_usage_json_file)


def display_packets(stdscr, interface, filters):
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    packet_queue = queue.Queue()
    stop_event = threading.Event()
    sniffing_event = threading.Event()
    sniffing_event.set()

    # Use os.path.join for platform independence
    packets_json_file = os.path.join('live_visualisations', 'captured_packets.json')
    data_usage_json_file = os.path.join('live_visualisations', 'data_usage.json')

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
                  "| Čas      | Zdrojová IP     | Cieľová IP      | Protokol | Porty          | Veľkosť      | Dáta ")
    stdscr.addstr(3, 0, "-" * 120)

    stdscr.timeout(100)

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

        if len(all_packet_lines) > visible_lines:
            # Clear the scroll status line first
            stdscr.addstr(max_y - 6, 0, " " * (max_x - 1))

            scroll_percent = int(scroll_position / (len(all_packet_lines) - visible_lines) * 100)
            scroll_status = f"Scroll: {scroll_percent}% (↑/↓ to scroll)"
            stdscr.addstr(max_y - 6, max_x - len(scroll_status) - 3, scroll_status)

        # Menu and status lines
        stdscr.addstr(max_y - 5, 0,
                      "MENU: A) Vizualizácia 2 zariadení podľa IP B) Filtrovanie C) Vizualizácia".center(max_x))
        stdscr.addstr(max_y - 4, 0, "D) Export (JSON/CSV) E) ŠTART/STOP zachytávania F) Ukončiť".center(max_x))

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
                          "| Čas      | Zdrojová IP     | Cieľová IP      | Protokol | Porty          | Veľkosť      | Dáta ")
            stdscr.addstr(3, 0, "-" * 120)

            subprocess.Popen(
                ["python", "live_visualisations_selector.py", packets_json_file],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            stdscr.refresh()
        elif key == ord('D') or key == ord('d'):
            stdscr.refresh()
        elif key == ord('E') or key == ord('e'):
            if sniffing_event.is_set():
                sniffing_event.clear()
                status_msg = "Zachytávanie pozastavené. Stlačte E na obnovenie. ↑/↓ pre posúvanie."
                stdscr.addstr(max_y - 3, 0, status_msg.center(max_x))
            else:
                sniffing_event.set()
                # When resuming, scroll to the bottom to see new packets
                scroll_position = max(0, len(all_packet_lines) - visible_lines)
                stdscr.addstr(max_y - 3, 0, "Zachytávanie obnovené. Stlačte E na pozastavenie.".center(max_x))
            stdscr.refresh()
        elif key == ord('f') or key == ord('F'):
            stop_event.set()
            sniff_thread.join()

            write_packets_to_json([], packets_json_file)
            write_data_usage_to_json({}, data_usage_json_file)

            stdscr.addstr(max_y - 3, 0, "Zachytávanie zastavené.".center(max_x))
            stdscr.refresh()
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