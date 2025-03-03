import argparse
import curses
import json
import os
from file_export import export_menu


def load_packets_from_json(json_file):
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        packet_lines = []
        for packet in data.get("packets", []):
            # Format each packet as it would appear in the main display
            line = (f"| {packet.get('timestamp', 'N/A')} | "
                    f"{packet.get('src_ip', 'N/A'):<15} | {packet.get('dst_ip', 'N/A'):<15} | "
                    f"{packet.get('protocol', 'N/A'):<8} | {packet.get('src_port', 'N/A'):<5} -> {packet.get('dst_port', 'N/A'):<5} | "
                    f"{packet.get('size', 'N/A'):<5} bajtov | {packet.get('payload', 'N/A')}")
            packet_lines.append(line)

        return packet_lines
    except Exception as e:
        print(f"Error loading packets: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="Export captured packets to JSON or CSV.")
    parser.add_argument("--json_file", help="JSON file with captured packets",
                        default="live_visualisations/captured_packets.json")
    parser.add_argument("--interface", help="Network interface name", default="unknown")
    args = parser.parse_args()

    # Check if the JSON file exists
    if not os.path.exists(args.json_file):
        print(f"Error: File {args.json_file} not found.")
        return

    # Load packets from the JSON file
    packet_lines = load_packets_from_json(args.json_file)

    if not packet_lines:
        print("No packets found in the JSON file.")
        return

    print(f"Loaded {len(packet_lines)} packets. Opening export menu...")

    # Launch the export menu with curses
    curses.wrapper(export_menu, packet_lines, args.interface)


if __name__ == "__main__":
    main()