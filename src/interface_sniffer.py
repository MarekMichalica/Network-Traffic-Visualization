import argparse
import asyncio
import pyshark
import threading
import queue
import curses
import subprocess

from pcap_analyzer import clean_string, wrap_text

def sniff_packets(interface, packet_queue, stop_event, sniffing_event):
    asyncio.set_event_loop(asyncio.new_event_loop())
    capture = pyshark.LiveCapture(interface=interface, display_filter="ip")

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
                size = packet.length
                payload = "N/A"  # Placeholder for payload
                src_port = packet[packet.transport_layer].srcport if hasattr(packet, "transport_layer") else "-"
                dst_port = packet[packet.transport_layer].dstport if hasattr(packet, "transport_layer") else "-"

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
            except AttributeError:
                continue
    finally:
        capture.close()

def display_packets(stdscr, interface, pcap_file):
    # Vyčistenie obrazovky
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    # Vytvorenie fronty pre pakety
    packet_queue = queue.Queue()
    stop_event = threading.Event()
    sniffing_event = threading.Event()  # Event to control sniffing
    sniffing_event.set()  # Start sniffing initially

    # Spustenie sniffingu paketov v samostatnom vlákne
    sniff_thread = threading.Thread(target=sniff_packets, args=(interface, packet_queue, stop_event, sniffing_event), daemon=True)
    sniff_thread.start()

    packet_lines = []

    # Nastavenie hlavičky
    stdscr.addstr(0, 0, f"Sledujem pakety na rozhraní: {interface}")
    stdscr.addstr(2, 0, "| Čas      | Zdrojová IP     | Cieľová IP      | Protokol | Porty          | Veľkosť     | Dáta ")
    stdscr.addstr(3, 0, "-" * 120)

    stdscr.timeout(100)  # Non-blocking čítanie pre klávesový vstup

    while True:
        # Zobrazenie zachytených paketov
        while not packet_queue.empty():
            packet_info = packet_queue.get()
            packet_info_str = (f"| {packet_info['timestamp']} | "
                               f"{packet_info['src_ip']:<15} | {packet_info['dst_ip']:<15} | "
                               f"{packet_info['protocol']:<8} | {packet_info['src_port']:<5} -> {packet_info['dst_port']:<5} | "
                               f"{packet_info['size']:<5} bytes | {packet_info['payload']}")

            wrapped_lines = wrap_text(packet_info_str, max_x - 2)

            for line in wrapped_lines:
                if len(packet_lines) >= max_y - 12:
                    packet_lines.pop(0)  # Udržiavať maximálny počet riadkov na obrazovke
                clean_line = clean_string(line)
                packet_lines.append(clean_line)

        # Zobrazenie riadkov paketov na obrazovke
        for i, line in enumerate(packet_lines, start=4):  # Start from line 4 to account for the header and status message
            stdscr.addstr(i, 0, line)

        stdscr.addstr(max_y - 5, 0, "MENU: A) Vizualizácia 2 zariadení podľa IP B) Filtrovanie C) Vizualizácia".center(max_x))
        stdscr.addstr(max_y - 4, 0, "D) Export (JSON/CSV) E) ŠTART/STOP zachytávania F) Koniec".center(max_x))

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
                "python", r"visualizations.py", pcap_file
            ])
            return
        elif key == ord('E') or key == ord('e'):
            # Toggle sniffing start/stop
            if sniffing_event.is_set():
                sniffing_event.clear()  # Stop sniffing
                stdscr.addstr(max_y - 3, 0, "Zachytávanie pozastavené. Stlačte E pre obnovenie.".center(max_x))
            else:
                sniffing_event.set()  # Resume sniffing
                stdscr.addstr(max_y - 3, 0, "Zachytávanie obnovené. Stlačte E pre pozastavenie.".center(max_x))
            stdscr.refresh()

        elif key == ord('f') or key == ord('F'):
            stop_event.set()  # Stop sniffing
            sniff_thread.join()
            return

        stdscr.refresh()

def main():
    parser = argparse.ArgumentParser(description="Sniffer paketov s curses rozhraním.")
    parser.add_argument("--interface", required=True, help="Sieťové rozhranie pre sniffing")
    parser.add_argument("--pcap_file", help="PCAP súbor")
    args = parser.parse_args()

    curses.wrapper(display_packets, args.interface, args.pcap_file)

if __name__ == "__main__":
    main()
