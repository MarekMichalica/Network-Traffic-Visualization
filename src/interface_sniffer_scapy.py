import argparse
import threading
import queue
import curses
import subprocess

from scapy.all import sniff
from pcap_analyzer import clean_string, wrap_text
from datetime import datetime
from port_protocol import get_protocol_by_port, get_protocol_by_ip_proto, map_tcp_flags

def process_packet(packet, packet_queue, sniffing_event):
    """Processes captured packets and adds them to the queue."""
    if not sniffing_event.is_set():
        return  # Ignore packets when sniffing is paused

    try:
        timestamp = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S")
        src_ip = packet["IP"].src if "IP" in packet else "Unknown"
        dst_ip = packet["IP"].dst if "IP" in packet else "Unknown"
        if packet.haslayer("IP"):
            # Protokol z IP hlavičky
            protocol = get_protocol_by_ip_proto(packet["IP"].proto)
        elif packet.haslayer("TCP") or packet.haslayer("UDP"):
            # Protokol na základe portu (pre TCP a UDP)
            port = packet["TCP"].dport if packet.haslayer("TCP") else packet["UDP"].dport
            protocol = get_protocol_by_port(port)
        else:
            protocol = "Unknown"
        size = len(packet)
        payload = "N/A"
        src_port = packet["TCP"].sport if "TCP" in packet else packet["UDP"].sport if "UDP" in packet else "-"
        dst_port = packet["TCP"].dport if "TCP" in packet else packet["UDP"].dport if "UDP" in packet else "-"

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

        if packet.haslayer("TCP"):
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

        packet_queue.put(packet_info)

    except Exception as e:
        print(f"Error processing packet: {e}")

def sniff_packets(interface, packet_queue, stop_event, sniffing_event):
    """Sniffs packets on the selected interface."""
    sniff(prn=lambda packet: process_packet(packet, packet_queue, sniffing_event),
          iface=interface,
          store=False,
          stop_filter=lambda _: stop_event.is_set())  # Stop if event is set

def display_packets(stdscr, interface, pcap_file):
    """Displays packets using a curses-based UI."""
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    packet_queue = queue.Queue()
    stop_event = threading.Event()
    sniffing_event = threading.Event()
    sniffing_event.set()  # Initially start sniffing

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=sniff_packets, args=(interface, packet_queue, stop_event, sniffing_event), daemon=True)
    sniff_thread.start()

    packet_lines = []
    status_msg = "Zachytávanie AKTÍVNE. Stlačte E pre zastavenie."

    stdscr.timeout(100)  # Non-blocking key input

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, f"Sledujem pakety na rozhraní: {interface}")
        stdscr.addstr(1, 0, status_msg.center(max_x))  # Display status
        stdscr.addstr(3, 0, "| Čas      | Zdrojová IP     | Cieľová IP      | Protokol | Porty          | Veľkosť     | Dáta ")
        stdscr.addstr(4, 0, "-" * 120)

        while not packet_queue.empty():
            packet_info = packet_queue.get()
            packet_info_str = (f"| {packet_info['timestamp']} | "
                               f"{packet_info['src_ip']:<15} | {packet_info['dst_ip']:<15} | "
                               f"{packet_info['protocol']:<8} | {packet_info['src_port']:<5} -> {packet_info['dst_port']:<5} | "
                               f"{packet_info['size']:<5} bytes | {packet_info['payload']}")

            wrapped_lines = wrap_text(packet_info_str, max_x - 2)

            for line in wrapped_lines:
                if len(packet_lines) >= max_y - 12:
                    packet_lines.pop(0)  # Maintain screen size
                clean_line = clean_string(line)
                packet_lines.append(clean_line)

        for i, line in enumerate(packet_lines, start=5):  # Start from line 5
            stdscr.addstr(i, 0, line)

        stdscr.addstr(max_y - 5, 0, "MENU: A) Vizualizácia 2 zariadení B) Filtrovanie C) Vizualizácia".center(max_x))
        stdscr.addstr(max_y - 4, 0, "D) Export (JSON/CSV) E) ŠTART/STOP zachytávania F) Koniec".center(max_x))

        key = stdscr.getch()
        if key == ord('A') or key == ord('a'):
            stdscr.clear()
            stdscr.refresh()
            subprocess.run(["python", r"two_devices.py"])
            return
        elif key == ord('C') or key == ord('c'):
            stdscr.clear()
            stdscr.refresh()
            subprocess.run(["python", r"static_visualisations_selector.py", pcap_file])
            return
        elif key == ord('E') or key == ord('e'):
            if sniffing_event.is_set():
                sniffing_event.clear()  # Pause sniffing
                status_msg = "Zachytávanie POZASTAVENÉ. Stlačte E pre obnovenie."
            else:
                sniffing_event.set()  # Resume sniffing
                status_msg = "Zachytávanie AKTÍVNE. Stlačte E pre zastavenie."
            stdscr.refresh()
        elif key == ord('F') or key == ord('f'):
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
