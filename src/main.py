import argparse
import curses
import subprocess
import pyshark.tshark.tshark as tshark
from scapy.arch.windows import get_windows_if_list

def list_interfaces():
    scapy_interfaces = get_windows_if_list()
    npf_interfaces = tshark.get_tshark_interfaces()

    interface_map = {}
    for iface in scapy_interfaces:
        npf_name = next((npf for npf in npf_interfaces if iface['guid'] in npf), None)
        if npf_name:
            interface_map[iface['name']] = npf_name

    return interface_map

def select_interface(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Vyber sieťové rozhranie:", curses.A_BOLD)

    interfaces = list_interfaces()
    if not interfaces:
        stdscr.addstr(2, 0, "Neboli nájdené žiadne dostupné sieťové rozhrania. Stlačte nejaké tlačidlo pre ukončenie...")
        stdscr.refresh()
        stdscr.getch()
        return None

    interface_list = list(interfaces.keys())
    current_selection = 0

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Vyber sieťové rozhranie:", curses.A_BOLD)

        for i, iface in enumerate(interface_list):
            if i == current_selection:
                stdscr.addstr(i + 2, 0, f"> {iface}", curses.A_REVERSE)
            else:
                stdscr.addstr(i + 2, 0, f"  {iface}")

        stdscr.refresh()
        key = stdscr.getch()

        if key == curses.KEY_UP and current_selection > 0:
            current_selection -= 1
        elif key == curses.KEY_DOWN and current_selection < len(interface_list) - 1:
            current_selection += 1
        elif key == ord('\n'):
            return interfaces[interface_list[current_selection]]

def main(stdscr):
    stdscr.clear()

    parser = argparse.ArgumentParser(description="Packet capture tool.")
    parser.add_argument("--pcap_file", type=str, help="Cesta k súboru PCAP")
    parser.add_argument("--interface", type=str, help="Sieťové rozhranie na real-time capture")
    parser.add_argument("--ip_a", type=str, help="IP adresa A")
    parser.add_argument("--ip_b", type=str, help="IP adresa B")
    args = parser.parse_args()

    if not args.pcap_file and not args.interface:
        # Add menu items
        stdscr.addstr(0, 0, "VIZUALIZÉR DÁTOVEJ KOMUNIKÁCIE")
        stdscr.addstr(1, 0, "1 - Analyzovať PCAP súbor")
        stdscr.addstr(2, 0, "2 - Real-time zachytávanie paketov")
        stdscr.refresh()

        key = stdscr.getch()
        if key == ord('1'):
            stdscr.clear()
            stdscr.addstr(2, 0, "Zadajte cestu k PCAP súboru:")
            stdscr.refresh()
            curses.echo()
            args.pcap_file = stdscr.getstr(3, 0, 100).decode("utf-8").strip()
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

    if args.interface:
        curses.endwin()
        subprocess.run(["python", "interface_sniffer.py", "--interface", args.interface])

    if args.pcap_file:
        subprocess.run(["python", "pcap_analyzer.py", args.pcap_file])

if __name__ == "__main__":
    curses.wrapper(main)
