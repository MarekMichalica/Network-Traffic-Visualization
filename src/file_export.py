import curses
import json
import csv
import os
from datetime import datetime

def export_menu(stdscr, packet_lines, interface):
    # Save current state
    max_y, max_x = stdscr.getmaxyx()

    # Create a new window for the export menu
    menu_height = 14
    menu_width = 60
    menu_y = (max_y - menu_height) // 2
    menu_x = (max_x - menu_width) // 2

    menu_win = curses.newwin(menu_height, menu_width, menu_y, menu_x)
    menu_win.box()
    menu_win.keypad(True)

    # Export options
    options = [
        "Export všetkých paketov do JSON",
        "Export všetkých paketov do CSV",
        "Export len viditeľných paketov do JSON",
        "Export len viditeľných paketov do CSV",
        "Späť"
    ]

    current_option = 0

    # Display the menu
    while True:
        menu_win.clear()
        menu_win.box()

        # Title
        menu_win.addstr(1, 2, f"Export paketov z rozhrania {interface}")
        menu_win.addstr(2, 2, "=" * (menu_width - 4))

        # Options
        for i, option in enumerate(options):
            if i == current_option:
                menu_win.attron(curses.A_REVERSE)
                menu_win.addstr(4 + i, 3, f"> {option}")
                menu_win.attroff(curses.A_REVERSE)
            else:
                menu_win.addstr(4 + i, 3, f"  {option}")

        # Instructions
        menu_win.addstr(10, 2, "Použite šípky ↑/↓ na výber a Enter na potvrdenie")
        menu_win.addstr(11, 2, "ESC pre ukončenie")

        menu_win.refresh()

        # Handle key presses
        key = menu_win.getch()

        if key == curses.KEY_UP and current_option > 0:
            current_option -= 1
        elif key == curses.KEY_DOWN and current_option < len(options) - 1:
            current_option += 1
        elif key == 10:  # Enter key
            if current_option == len(options) - 1:  # Back option
                break
            else:
                # Handle export
                export_type = "JSON" if current_option % 2 == 0 else "CSV"
                all_packets = current_option < 2

                # Create exports directory if it doesn't exist
                export_dir = os.path.join("exports")
                if not os.path.exists(export_dir):
                    os.makedirs(export_dir)

                # Generate filename with timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                packet_type = "all" if all_packets else "visible"
                filename = f"packets_{interface}_{packet_type}_{timestamp}"

                # Process packet lines into structured data
                packet_data = process_packet_lines(packet_lines, all_packets)

                # Export based on selected option
                if export_type == "JSON":
                    file_path = os.path.join(export_dir, f"{filename}.json")
                    export_to_json(packet_data, file_path)
                else:  # CSV
                    file_path = os.path.join(export_dir, f"{filename}.csv")
                    export_to_csv(packet_data, file_path)

                # Show success message
                menu_win.clear()
                menu_win.box()
                menu_win.addstr(5, 2, f"Export úspešný! Súbor uložený ako:")
                menu_win.addstr(7, 2, file_path)
                menu_win.addstr(10, 2, "Stlačte ľubovoľný kláves pre návrat...")
                menu_win.refresh()
                menu_win.getch()

        elif key == 27:  # ESC key
            break

    # Clean up
    menu_win.keypad(False)
    del menu_win
    stdscr.clear()
    stdscr.refresh()


def process_packet_lines(packet_lines, all_packets=True):
    """Process packet lines from the display into structured data"""
    structured_packets = []

    for line in packet_lines:
        # Skip separator lines or header lines
        if line.startswith("-") or "Zdrojová IP" in line:
            continue

        # Try to parse the line into components
        try:
            # Lines should follow the format from the display_packets function
            parts = line.split("|")
            if len(parts) < 7:
                continue

            timestamp = parts[1].strip()
            src_ip = parts[2].strip()
            dst_ip = parts[3].strip()
            protocol = parts[4].strip()

            # Parse ports (format: "srcport -> dstport")
            ports = parts[5].strip()
            port_parts = ports.split("->")
            src_port = port_parts[0].strip() if len(port_parts) > 0 else "-"
            dst_port = port_parts[1].strip() if len(port_parts) > 1 else "-"

            # Get size (format: "X bajtov")
            size_part = parts[6].strip()
            size = size_part.split(" ")[0] if " " in size_part else size_part

            # Get payload data (everything after the size column)
            payload = parts[7].strip() if len(parts) > 7 else "N/A"

            packet = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "size": size,
                "payload": payload
            }

            structured_packets.append(packet)

        except Exception as e:
            # Skip lines that can't be parsed
            continue

    return structured_packets


def export_to_json(packet_data, file_path):
    """Export packet data to JSON file"""
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump({"packets": packet_data}, f, indent=4, ensure_ascii=False)


def export_to_csv(packet_data, file_path):
    """Export packet data to CSV file"""
    if not packet_data:
        # Handle empty data case
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "size", "payload"])
        return

    # Get field names from the first packet
    fieldnames = packet_data[0].keys()

    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(packet_data)