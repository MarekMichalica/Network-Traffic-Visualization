import argparse
import queue
import time
import curses
import subprocess
import threading

from datetime import datetime
from scapy.interfaces import get_if_list, conf
from packet_analyzer import analyze_packets, interface_analyzer
from main import wrap_text, clean_string

def display_packets(stdscr, packet_queue, max_x, max_y, interface_hard):
    captured_packets = []

    while True:
        stdscr.clear()
        stdscr.addstr(1, 0, "# | Časová pečiatka      | Zdrojová IP     | Cieľová IP      | Protokol | Porty       | Veľkosť     | Dáta ")
        stdscr.addstr(2, 0, "-" * 120)

        # Process all packets in the queue
        while not packet_queue.empty():
            packet = packet_queue.get()
            captured_packets.append(packet)

        # Show only the most recent packets that fit the screen
        for idx, pkt in enumerate(captured_packets[-(max_y-4):], start=3):
            packet_str = (f"{idx-2:<3} | {pkt['timestamp']} | {pkt['src_ip']:<15} | {pkt['dst_ip']:<15} | "
                          f"{pkt['protocol']:<8} | {pkt['src_port']} -> {pkt['dst_port']} | "
                          f"{pkt['size']:<5} bytes | {pkt['payload']}")
            stdscr.addstr(idx, 0, packet_str)

        # Display navigation menu
        stdscr.addstr(max_y - 6, max_x // 2, interface_hard)
        stdscr.addstr(max_y - 5, max_x // 2, str(len(captured_packets)))
        stdscr.addstr(max_y - 4, 0, "MENU: A) Vizualizácia 2 zariadení podľa IP B) Filtrovanie C) Vizualizácia".center(max_x))
        stdscr.addstr(max_y - 3, 0, "D) Export (JSON/CSV) E) ŠTART/STOP zachytávania F) Koniec".center(max_x))

        stdscr.refresh()

        # Check for user input
        key = stdscr.getch()
        if key == ord('A') or key == ord('a'):
            stdscr.clear()
            stdscr.refresh()

            subprocess.run([
                "python", r"two_devices.py",
            ])
            return
        elif key == ord('f') or key == ord('F'):
            return

        stdscr.refresh()

        #time.sleep(0.1)  # Avoid high CPU usage

def get_interface_mapping():
    """ Maps raw interface names to human-readable names """
    iface_mapping = {}
    for iface in conf.ifaces.values():
        iface_mapping[iface.name] = iface.description  # Human-readable name
    return iface_mapping

def select_interface(stdscr):
    """ Allows user to select a network interface """
    stdscr.clear()
    stdscr.addstr(2, 0, "Dostupné sieťové rozhrania:")

    interfaces = get_if_list()  # Raw interface names
    iface_mapping = get_interface_mapping()  # Get human-readable names

    # Display interfaces with both names
    for i, iface in enumerate(interfaces, start=3):
        human_readable = iface_mapping.get(iface, "Neznáme rozhranie")  # Fallback if no description found
        stdscr.addstr(i, 0, f"{i-2}) {iface} ({human_readable})")

    stdscr.addstr(len(interfaces) + 4, 0, "Zadajte číslo rozhrania alebo názov:")
    stdscr.refresh()

    curses.echo()
    interface_input = stdscr.getstr(len(interfaces) + 5, 0, 100).decode("utf-8").strip()
    curses.noecho()

    # Validate selection (must match an item in `interfaces`)
    try:
        interface_index = int(interface_input) - 1
        if 0 <= interface_index < len(interfaces):
            return interfaces[interface_index]  # Return raw interface name
    except ValueError:
        if interface_input in interfaces:
            return interface_input  # Return raw interface name

    return None  # Invalid selection

def main(stdscr):
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    stop_event = threading.Event()
    packet_queue = queue.Queue()

    parser = argparse.ArgumentParser(description="Packet capture tool.")
    parser.add_argument("--pcap", type=str, help="Cesta k súboru PCAP")
    parser.add_argument("--interface", type=str, help="Sieťové rozhranie na real-time capture")
    parser.add_argument("--ip_a", type=str, help="IP Address A for filtering")
    parser.add_argument("--ip_b", type=str, help="IP Address B for filtering")
    args = parser.parse_args()

    if not args.pcap and not args.interface:
        stdscr.addstr(2, 0, "Vyberte režim:")
        stdscr.addstr(3, 0, "1 - Analyzovať PCAP súbor")
        stdscr.addstr(4, 0, "2 - Real-time zachytávanie paketov")
        stdscr.refresh()

        key = stdscr.getch()
        if key == ord('1'):
            stdscr.clear()
            stdscr.addstr(2, 0, "Zadajte cestu k PCAP súboru:")
            stdscr.refresh()
            curses.echo()
            args.pcap = stdscr.getstr(3, 0, 100).decode("utf-8").strip()
            curses.noecho()
        elif key == ord('2'):
            args.interface = select_interface(stdscr)
            if not args.interface:
                stdscr.addstr(10, 0, "Neplatná voľba. Stlačte ľubovoľnú klávesu na ukončenie.")
                stdscr.refresh()
                stdscr.getch()
                return
        else:
            return

    args.interface = r"\Device\NPF_{ED870D6D-CF56-4ACA-BDB0-4A69805E037A}"

    if args.interface:
        capture_thread = threading.Thread(target=interface_analyzer, args=(args.interface, packet_queue, stop_event),daemon=True)
        capture_thread.start()

        # Display captured packets in the UI
        display_packets(stdscr, packet_queue, max_x, max_y, interface_hard = args.interface)
        stop_event.set()
        capture_thread.join()

        # Stop the packet capture when UI exits
        stop_event.set()
        capture_thread.join()

    stdscr.refresh()

    if args.pcap:
        filters = {"ip_a": args.ip_a, "ip_b": args.ip_b} if args.ip_a or args.ip_b else None
        packets = analyze_packets(args.pcap, filters)
        total_packets = len(packets["filtered_packets"])

        previous_timestamp = None
        progress_bar_width = 50
        current_value = 1
        packet_lines = []
        remaining_packets = total_packets
        protocol_counts = {protocol: 0 for protocol in packets["protocol_counts"].keys()}

        stdscr.timeout(100)
        run_subprocess = False

        while remaining_packets and not run_subprocess:
            for idx, packet_info in enumerate(packets["filtered_packets"], 1):
                current_timestamp = datetime.strptime(packet_info["timestamp"], "%Y-%m-%d %H:%M:%S")

                if previous_timestamp:
                    delta_time = (current_timestamp - previous_timestamp).total_seconds()
                    time.sleep(delta_time)
                previous_timestamp = current_timestamp

                num_hashes = int((current_value / total_packets) * progress_bar_width)
                progress_bar = f"Progress: [{'#' * num_hashes}{' ' * (progress_bar_width - num_hashes)}] {current_value}/{total_packets}"

                stdscr.clear()

                stdscr.addstr(1, 0, progress_bar)
                protocol_counts[packet_info["protocol"]] += 1

                protocol_y_offset = 2
                for protocol, count in protocol_counts.items():
                    protocol_percentage = (count / total_packets) * 100
                    num_hashes_protocol = int((protocol_percentage / 100) * progress_bar_width)

                    protocol_bar = f"{protocol}: [{'#' * num_hashes_protocol}{' ' * (progress_bar_width - num_hashes_protocol)}] {protocol_percentage:.2f}%"
                    stdscr.addstr(protocol_y_offset, 0, protocol_bar)
                    protocol_y_offset += 1

                stdscr.addstr(protocol_y_offset, 0, "# | Časová pečiatka      | Zdrojová IP     | Cieľová IP      | Protokol | Porty       | Veľkosť     | Dáta ")
                stdscr.addstr(protocol_y_offset + 1, 0, "-" * 120)

                packet_info_str = (f"{idx:<2} | {packet_info['timestamp']} | {packet_info['src_ip']:<15} | {packet_info['dst_ip']:<15} | "
                                   f"{packet_info['protocol']:<8} | {packet_info['src_port']} -> {packet_info['dst_port']} | "
                                   f"{packet_info['size']:<5} bytes | {packet_info['payload']}")

                wrapped_lines = wrap_text(packet_info_str, max_x - 2)

                for line in wrapped_lines:
                    if len(packet_lines) >= max_y - protocol_y_offset - 4:
                        packet_lines.pop(0)

                    clean_line = clean_string(line)
                    packet_lines.append(clean_line)

                for i, line in enumerate(packet_lines, start=protocol_y_offset + 2):
                    stdscr.addstr(i, 0, line)

                # Aktualizácia hlášky o ukončení na spodku obrazovky
                stdscr.addstr(max_y - 5, 0, str(remaining_packets))
                stdscr.addstr(max_y - 4, 0, "MENU: A) Vizualizácia 2 zariadení podľa IP B) Filtrovanie C) Vizualizácia".center(max_x))
                stdscr.addstr(max_y - 3, 0, "D) Export (JSON/CSV) E) ŠTART/STOP zachytávania F) Koniec".center(max_x))

                current_value += 1
                remaining_packets -= 1


                # Kontrola na stlačenú klávesu (non-blocking)
                key = stdscr.getch()
                if key == ord('A') or key == ord('a'):
                    stdscr.clear()
                    stdscr.refresh()

                    subprocess.run([
                        "python", r"two_devices.py",
                    ])
                    return
                elif key == ord('C') or key == ord('c'):
                    stdscr.clear()
                    stdscr.refresh()

                    subprocess.run([
                        "python", r"visualizations.py", args.pcap_file
                    ])
                    return

                elif key == ord('f') or key == ord('F'):
                    return

                stdscr.refresh()

                if remaining_packets == 1:
                    stdscr.clear()
                    stdscr.addstr(max_y - 4, 0, "Vizualizácia paketov bola dokončená.".center(max_x))
                    stdscr.refresh()

                    key = stdscr.getstr(max_y, 0).decode('utf-8')
                    if key == ord('f') or key == ord('F'):
                        return
                    else: time.sleep(20)

    stdscr.refresh()

if __name__ == "__main__":
    curses.wrapper(main)
