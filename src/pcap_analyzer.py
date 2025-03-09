import argparse
import time
import curses
import subprocess
import threading
import pyshark

from collections import Counter, defaultdict
from datetime import datetime, timedelta


def clean_string(input_str):
    return input_str.replace('\0', '')  # Odstráni null characters


def wrap_text(text, width):
    lines = []
    while len(text) > width:
        split_point = text.rfind(' ', 0, width)  # Nájdeme posledný medzeru do šírky
        if split_point == -1:  # Ak nie je medzera, orežeme na pevnú šírku
            split_point = width
        lines.append(text[:split_point])
        text = text[split_point:].lstrip()  # Orezanie textu a odstránenie medzier
    lines.append(text)  # Pridáme posledný riadok
    return lines


def analyze_packets(file_path, filters):
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


def main(stdscr):
    # Vyčistenie obrazovky
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    # Argumenty pre analýzu PCAP
    parser = argparse.ArgumentParser(description="Analýza PCAP súboru")
    parser.add_argument("pcap_file", type=str, help="Cesta k súboru PCAP")
    parser.add_argument("--ip_a", type=str, help="IP adresa prvého zariadenia (voliteľné)")
    parser.add_argument("--ip_b", type=str, help="IP adresa druhého zariadenia (voliteľné)")
    args = parser.parse_args()

    # Inicializácia filtrov
    filters = {}

    # Ak sú zadané, pridať ich ako filtre
    if args.ip_a:
        filters["ip_a"] = args.ip_a
    if args.ip_b:
        filters["ip_b"] = args.ip_b

    # Ak neexistujú žiadne filtre, odovzdáme None (aby analyzér použil všetky pakety)
    if not filters:
        filters = None

    # Analyzovanie súboru PCAP a aplikácia filtrov
    packets = analyze_packets(args.pcap_file, filters)

    # Počet paketov
    total_packets = len(packets["filtered_packets"])

    previous_timestamp = None
    pause_start_time = None  # Čas, kedy bolo pozastavené zachytávanie
    pause_total_duration = 0  # Celkový čas pozastavenia (pre kompenzáciu)

    progress_bar_width = 50  # Šírka progres baru
    current_value = 0  # Počiatočný progres
    packet_lines = []
    remaining_packets = total_packets
    protocol_counts = {protocol: 0 for protocol in packets["protocol_counts"].keys()}

    # Nastavenie timeoutu na 100 ms pre neblokujúce čítanie kláves
    stdscr.timeout(100)

    # Inicializácia event pre štart/stop zachytávania
    sniffing_event = threading.Event()
    sniffing_event.set()  # Začíname v režime zachytávania

    run_subprocess = False
    scroll_position = 0
    visible_lines = max_y - 13  # Počet viditeľných riadkov

    stdscr.addstr(0, 0, "Analýza PCAP súboru: " + args.pcap_file)
    status_msg = "Zachytávanie aktívne. Stlačte E na pozastavenie."

    packet_idx = 0
    real_start_time = time.time()  # Čas začiatku analýzy
    processing_complete = False

    while True:
        # Kontrola klávesy v každom cykle
        key = stdscr.getch()

        # Spracovanie kláves pre pause/resume a ďalšie menu akcie
        if key == ord('F') or key == ord('f'):
            return
        elif key == ord('A') or key == ord('a'):
            curses.endwin()  # End the curses mode
            try:
                subprocess.run(["python", r"two_devices.py"])
            except Exception as e:
                print(f"Error running two_devices.py: {e}")  # Print to console
            finally:
                stdscr = curses.initscr()  # Restart curses
                stdscr.clear()
                stdscr.refresh()
            return
        elif key == ord('C') or key == ord('c'):
            stdscr.clear()
            stdscr.refresh()
            subprocess.run([
                "python", r"static_visualisations_selector.py", args.pcap_file
            ])
            return
        elif key == curses.KEY_UP and scroll_position > 0:
            scroll_position -= 1
            update_display(stdscr, max_x, max_y, args.pcap_file, current_value, total_packets,
                           progress_bar_width, protocol_counts, packet_lines, scroll_position,
                           visible_lines, remaining_packets, status_msg)
            continue
        elif key == curses.KEY_DOWN and scroll_position < max(0, len(packet_lines) - visible_lines):
            scroll_position += 1
            update_display(stdscr, max_x, max_y, args.pcap_file, current_value, total_packets,
                           progress_bar_width, protocol_counts, packet_lines, scroll_position,
                           visible_lines, remaining_packets, status_msg)
            continue
        elif key == ord('E') or key == ord('e'):
            if not processing_complete:
                if sniffing_event.is_set():
                    sniffing_event.clear()
                    pause_start_time = time.time()  # Uložíme čas pozastavenia
                    status_msg = "Zachytávanie pozastavené. Stlačte E na obnovenie. ↑/↓ pre posúvanie."
                else:
                    sniffing_event.set()
                    # Vypočítame, ako dlho bolo zachytávanie pozastavené
                    if pause_start_time:
                        pause_duration = time.time() - pause_start_time
                        pause_total_duration += pause_duration
                        pause_start_time = None
                    status_msg = "Zachytávanie obnovené. Stlačte E na pozastavenie."
            stdscr.addstr(max_y - 2, 0, status_msg.center(max_x))
            stdscr.refresh()

        if processing_complete:
            time.sleep(0.1)
            continue

        # Ak je zachytávanie pozastavené, nespracúvam ďalšie pakety
        if not sniffing_event.is_set():
            time.sleep(0.1)
            continue

        if packet_idx < total_packets:
            # Spracovanie aktuálneho paketu
            packet_info = packets["filtered_packets"][packet_idx]
            current_timestamp = datetime.strptime(packet_info["timestamp"], "%Y-%m-%d %H:%M:%S")

            if previous_timestamp:
                # Vypočítame čas medzi paketmi
                delta_time = (current_timestamp - previous_timestamp).total_seconds()
                # Čakáme príslušný čas, ale berieme do úvahy čas pozastavenia
                time.sleep(max(0, delta_time))
            previous_timestamp = current_timestamp

            current_value += 1
            remaining_packets -= 1

            # Aktualizácia protokolov
            protocol = packet_info["protocol"]
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

            # Formátovanie informácií o pakete
            packet_info_str = (
                f"{packet_idx + 1:<2} | {packet_info['timestamp']} | {packet_info['src_ip']:<15} | {packet_info['dst_ip']:<15} | "
                f"{protocol:<8} | {packet_info['src_port']} -> {packet_info['dst_port']} | "
                f"{packet_info['size']:<5} bytes | {packet_info['payload']}")

            # Zabalenie textu na riadky
            wrapped_lines = wrap_text(packet_info_str, max_x - 2)

            # Pridanie riadkov paketov do záznamu
            for line in wrapped_lines:
                clean_line = clean_string(line)
                packet_lines.append(clean_line)

            # Ak už máme viac riadkov, ako je viditeľných, posunieme sa na koniec
            if len(packet_lines) > visible_lines:
                scroll_position = len(packet_lines) - visible_lines

            # Posun na ďalší paket
            packet_idx += 1

            # Check if we've processed all packets
            if packet_idx >= total_packets:
                processing_complete = True
                status_msg = "Zachytávanie dokončené. Použite menu možnosti alebo F pre koniec."

        # Aktualizácia displeja
        update_display(stdscr, max_x, max_y, args.pcap_file, current_value, total_packets,
                       progress_bar_width, protocol_counts, packet_lines, scroll_position,
                       visible_lines, remaining_packets, status_msg)


def update_display(stdscr, max_x, max_y, pcap_file, current_value, total_packets,
                   progress_bar_width, protocol_counts, packet_lines, scroll_position,
                   visible_lines, remaining_packets, status_msg):
    # Vyčistenie obrazovky
    stdscr.clear()

    # Hlavička
    stdscr.addstr(0, 0, "Analýza PCAP súboru: " + pcap_file)

    # Progress bar
    num_hashes = int((current_value / total_packets) * progress_bar_width)
    progress_bar = f"Progress: [{'#' * num_hashes}{' ' * (progress_bar_width - num_hashes)}] {current_value}/{total_packets}"
    stdscr.addstr(1, 0, progress_bar)

    # Get the top 3 protocols by count
    top_protocols = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:3]

    # Štatistiky protokolov - len top 3
    protocol_y_offset = 2
    for protocol, count in top_protocols:
        if count > 0:  # Only display protocols that have been seen
            protocol_percentage = (count / current_value) * 100 if current_value > 0 else 0
            num_hashes_protocol = int((protocol_percentage / 100) * progress_bar_width)
            protocol_bar = f"{protocol}: [{'#' * num_hashes_protocol}{' ' * (progress_bar_width - num_hashes_protocol)}] {protocol_percentage:.2f}%"
            stdscr.addstr(protocol_y_offset, 0, protocol_bar)
            protocol_y_offset += 1

    # Hlavička tabuľky paketov
    stdscr.addstr(protocol_y_offset, 0,
                  "# | Časová pečiatka      | Zdrojová IP     | Cieľová IP      | Protokol | Porty       | Veľkosť     | Dáta ")
    stdscr.addstr(protocol_y_offset + 1, 0, "-" * 120)

    # Zobrazenie viditeľných paketových riadkov
    visible_end = min(len(packet_lines), scroll_position + visible_lines)
    for i, line_idx in enumerate(range(scroll_position, visible_end), start=protocol_y_offset + 2):
        if line_idx < len(packet_lines):  # Kontrola rozsahu
            stdscr.addstr(i, 0, packet_lines[line_idx])

    # Menu a informácie v päte
    stdscr.addstr(max_y - 5, 0, f"Zostávajúce pakety: {remaining_packets}".center(max_x))
    stdscr.addstr(max_y - 4, 0,
                  "MENU: A) Vizualizácia 2 zariadení podľa IP B) Filtrovanie C) Vizualizácia".center(max_x))
    stdscr.addstr(max_y - 3, 0, "D) Export (JSON/CSV) E) ŠTART/STOP zachytávania F) Koniec".center(max_x))
    stdscr.addstr(max_y - 2, 0, status_msg.center(max_x))  # Status msg moved here, after menu items

    # Aktualizácia obrazovky
    stdscr.refresh()


if __name__ == "__main__":
    curses.wrapper(main)