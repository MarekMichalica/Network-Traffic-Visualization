import argparse
import asyncio
import pyshark
import threading
import queue
import curses
import subprocess
import json
from pcap_analyzer import clean_string, wrap_text

def write_packets_to_json(packets, json_file):
    data = {
        "packets": packets
    }
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=4)

def write_data_usage_to_json(data_usage, json_file):
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
                payload = "N/A"
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
                packets.append(packet_info)

                if timestamp in data_usage:
                    data_usage[timestamp] += size
                else:
                    data_usage[timestamp] = size

                if len(packets) % 10 == 0:
                    write_packets_to_json(packets, packets_json_file)
                    write_data_usage_to_json(data_usage, data_usage_json_file)

            except AttributeError:
                continue
    finally:
        capture.close()
        write_packets_to_json(packets, packets_json_file)
        write_data_usage_to_json(data_usage, data_usage_json_file)

def display_packets(stdscr, interface):
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    packet_queue = queue.Queue()
    stop_event = threading.Event()
    sniffing_event = threading.Event()
    sniffing_event.set()

    packets_json_file = r'live_visualisations/captured_packets.json'
    data_usage_json_file = r'live_visualisations/data_usage.json'

    sniff_thread = threading.Thread(target=sniff_packets,
                                    args=(interface, packet_queue, stop_event, sniffing_event, packets_json_file,
                                          data_usage_json_file),
                                    daemon=True)
    sniff_thread.start()

    packet_lines = []

    stdscr.addstr(0, 0, f"Sledovanie paketov na rozhraní: {interface}")
    stdscr.addstr(2, 0, "| Čas    | Zdrojová IP     | Cieľová IP      | Protokol | Porty         | Veľkosť    | Dáta ")
    stdscr.addstr(3, 0, "-" * 120)

    stdscr.timeout(100)

    while True:
        while not packet_queue.empty():
            packet_info = packet_queue.get()
            packet_info_str = (f"| {packet_info['timestamp']} | "
                               f"{packet_info['src_ip']:<15} | {packet_info['dst_ip']:<15} | "
                               f"{packet_info['protocol']:<8} | {packet_info['src_port']:<5} -> {packet_info['dst_port']:<5} | "
                               f"{packet_info['size']:<5} bajtov | {packet_info['payload']}")

            wrapped_lines = wrap_text(packet_info_str, max_x - 2)

            for line in wrapped_lines:
                if len(packet_lines) >= max_y - 12:
                    packet_lines.pop(0)
                clean_line = clean_string(line)
                packet_lines.append(clean_line)

        for i, line in enumerate(packet_lines, start=4):
            stdscr.addstr(i, 0, line)

        stdscr.addstr(max_y - 5, 0,
                      "MENU: A) Vizualizácia 2 zariadení podľa IP B) Filtrovanie C) Vizualizácia".center(max_x))
        stdscr.addstr(max_y - 4, 0, "D) Export (JSON/CSV) E) ŠTART/STOP zachytávania F) Ukončiť".center(max_x))

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

            stdscr.addstr(0, 0, f"Sledovanie paketov na rozhraní: {interface}")
            stdscr.addstr(2, 0,
                          "| Čas    | Zdrojová IP     | Cieľová IP      | Protokol | Porty         | Veľkosť    | Dáta ")
            stdscr.addstr(3, 0, "-" * 120)

            subprocess.Popen(
                ["python", "live_visualisations_selector.py", packets_json_file],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            stdscr.refresh()
        elif key == ord('E') or key == ord('e'):
            if sniffing_event.is_set():
                sniffing_event.clear()
                stdscr.addstr(max_y - 3, 0, "Zachytávanie pozastavené. Stlačte E na obnovenie.".center(max_x))
            else:
                sniffing_event.set()
                stdscr.addstr(max_y - 3, 0, "Zachytávanie obnovené. Stlačte E na pozastavenie.".center(max_x))
            stdscr.refresh()

        elif key == ord('f') or key == ord('F'):
            stop_event.set()
            sniff_thread.join()
            stdscr.addstr(max_y - 3, 0, "Zachytávanie zastavené.".center(max_x))
            stdscr.refresh()
            return

        stdscr.refresh()

def main():
    parser = argparse.ArgumentParser(description="Snímač paketov s rozhraním curses.")
    parser.add_argument("--interface", required=True, help="Sieťové rozhranie na zachytávanie")
    parser.add_argument("--pcap_file", help="PCAP súbor")
    args = parser.parse_args()

    curses.wrapper(display_packets, args.interface, args.pcap_file)

if __name__ == "__main__":
    main()
