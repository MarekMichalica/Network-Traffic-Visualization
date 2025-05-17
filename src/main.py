import argparse
import curses
import subprocess
import os
import sys
import pyshark.tshark.tshark as tshark


def list_interfaces():
    interface_map = {}

    # Get interfaces from tshark
    npf_interfaces = tshark.get_tshark_interfaces()

    if os.name == 'nt':  # Windows
        try:
            from scapy.arch.windows import get_windows_if_list
            scapy_interfaces = get_windows_if_list()

            # Map friendly names to tshark interface names
            for iface in scapy_interfaces:
                npf_name = next((npf for npf in npf_interfaces if iface.get('guid', '') in npf), None)
                if npf_name:
                    interface_map[iface['name']] = npf_name
        except ImportError:
            # Fallback if scapy's Windows-specific module isn't available
            for iface in npf_interfaces:
                # Extract a more readable name from the interface string
                name = iface.split('(')[-1].split(')')[0] if '(' in iface else iface
                interface_map[name] = iface
    else:  # Linux/Unix
        try:
            import netifaces
            # Get interfaces using netifaces
            for iface in netifaces.interfaces():
                # Find matching tshark interface
                npf_name = next((npf for npf in npf_interfaces if iface in npf), None)
                if npf_name:
                    interface_map[iface] = npf_name
                else:
                    # If no match, use the interface name directly (might work with tshark)
                    interface_map[iface] = iface
        except ImportError:
            # Fallback if netifaces isn't available
            try:
                # Try to get interfaces from /proc/net/dev on Linux
                with open('/proc/net/dev', 'r') as f:
                    for line in f:
                        if ':' in line:
                            iface = line.split(':')[0].strip()
                            if iface != 'lo':  # Skip loopback
                                interface_map[iface] = iface
            except:
                # Last resort: use tshark interfaces directly
                for iface in npf_interfaces:
                    name = iface.split('(')[-1].split(')')[0] if '(' in iface else iface
                    interface_map[name] = iface

    # If no interfaces found, try direct tshark output as last resort
    if not interface_map:
        for iface in npf_interfaces:
            name = iface.split('(')[-1].split(')')[0] if '(' in iface else iface
            interface_map[name] = iface

    return interface_map


def select_interface(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Vyber sieťové rozhranie:", curses.A_BOLD)

    interfaces = list_interfaces()
    if not interfaces:
        stdscr.addstr(2, 0,
                      "Neboli nájdené žiadne dostupné sieťové rozhrania. Stlačte nejaké tlačidlo pre ukončenie...")
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
    max_y, max_x = stdscr.getmaxyx()

    # Import filter only when needed to avoid import issues
    try:
        from filter import get_user_input
    except ImportError:
        # Simple fallback if filter module is not available
        def get_user_input(stdscr, prompt, max_y, max_x):
            curses.echo()
            stdscr.addstr(2, 0, prompt)
            input_str = ""
            stdscr.addstr(3, 0, "> ")
            stdscr.refresh()
            input_str = stdscr.getstr(3, 2, max_x - 3).decode('utf-8')
            curses.noecho()
            return input_str

    parser = argparse.ArgumentParser(description="Packet capture tool.")
    parser.add_argument("--pcap_file", type=str, help="Cesta k súboru PCAP")
    parser.add_argument("--interface", type=str, help="Sieťové rozhranie na real-time capture")
    parser.add_argument("--ip_a", type=str, help="IP adresa A")
    parser.add_argument("--ip_b", type=str, help="IP adresa B")
    args = parser.parse_args()

    if not args.pcap_file and not args.interface:
        # Set up curses for arrow key navigation
        curses.curs_set(0)  # Hide cursor
        curses.noecho()
        curses.cbreak()
        stdscr.keypad(True)  # Enable special keys like arrows

        menu_items = ["Analyzovať PCAP súbor", "Real-time zachytávanie paketov"]
        current_selection = 0

        # Function to draw the menu
        def draw_menu():
            stdscr.clear()
            stdscr.addstr(0, 0, "VIZUALIZÉR DÁTOVEJ KOMUNIKÁCIE")

            for i, item in enumerate(menu_items):
                if i == current_selection:
                    stdscr.attron(curses.A_REVERSE)  # Highlight selected item
                    stdscr.addstr(i + 1, 0, f"> {item}")
                    stdscr.attroff(curses.A_REVERSE)
                else:
                    stdscr.addstr(i + 1, 0, f"  {item}")

            stdscr.addstr(len(menu_items) + 2, 0, "Použite šípky hore/dole na navigáciu a Enter pre výber")
            stdscr.refresh()

        # Initial drawing of the menu
        draw_menu()

        # Main menu loop
        while True:
            key = stdscr.getch()

            if key == curses.KEY_UP and current_selection > 0:
                current_selection -= 1
            elif key == curses.KEY_DOWN and current_selection < len(menu_items) - 1:
                current_selection += 1
            elif key == curses.KEY_ENTER or key in [10, 13]:  # Enter key
                if current_selection == 0:  # PCAP file analysis
                    stdscr.clear()
                    header = f"Zadajte cestu k PCAP súboru"
                    stdscr.addstr(0, 0, header[:max_x - 1])
                    stdscr.addstr(1, 0, "=" * min(len(header), max_x - 1))
                    stdscr.addstr(3, 0, "Pre operačný systém Windows použite znak '\\' pre oddelenie priečinkov")
                    stdscr.addstr(4, 0, "Pre distribúcie Linux použite znak '/' pre oddelenie priečinkov")
                    stdscr.refresh()
                    curses.echo()
                    curses.curs_set(1)  # Show cursor for text input
                    args.pcap_file = get_user_input(stdscr, "", max_y, max_x)
                    stdscr.addstr(4, 0, "Pre potvrdenie stlačte ENTER")
                    break
                elif current_selection == 1:  # Real-time capture
                    args.interface = select_interface(stdscr)
                    if not args.interface:
                        stdscr.clear()
                        stdscr.addstr(2, 0, "Neplatná voľba. Stlačte Enter na návrat do menu.")
                        stdscr.refresh()
                        stdscr.getch()
                        draw_menu()
                        continue
                    break

            # For any other key press, just redraw the menu (essentially do nothing)
            draw_menu()

    python_cmd = sys.executable

    if args.interface:
        curses.endwin()
        subprocess.run([python_cmd, "interface_sniffer.py", "--interface", args.interface])

    if args.pcap_file:
        subprocess.run([python_cmd, "pcap_analyzer.py", args.pcap_file])


if __name__ == "__main__":
    curses.wrapper(main)