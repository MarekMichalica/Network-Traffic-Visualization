import curses
import time
from datetime import datetime
from packet_analyzer import analyze_packets
from main import wrap_text, clean_string

def draw_box(stdscr, x, width, height, content, title=None):
    max_y, max_x = stdscr.getmaxyx()
    device_y = max_y // 7
    stdscr.addstr(device_y, x, "+" + "-" * (width - 2) + "+")
    for i in range(1, height - 1):
        stdscr.addstr(device_y + i, x, "|" + " " * (width - 2) + "|")
    stdscr.addstr(device_y + height - 1, x, "+" + "-" * (width - 2) + "+")

    # Pridanie obsahu a názvu
    if title:
        stdscr.addstr(device_y, x + 3, f"[{title}]")
    for i, line in enumerate(content[:height - 2]):
        stdscr.addstr(device_y + i + 1, x + 2, line[:width - 4])

def draw_box_protocol(stdscr, x, width, height, content, title=None):
    max_y, max_x = stdscr.getmaxyx()
    device_y = max_y // 7 + 1
    stdscr.addstr(device_y, x, "+" + "-" * (width - 2) + "+")
    for i in range(1, height - 1):
        stdscr.addstr(device_y + i, x, "|" + " " * (width - 2) + "|")
    stdscr.addstr(device_y + height - 1, x, "+" + "-" * (width - 2) + "+")

    # Pridanie obsahu a názvu
    if title:
        stdscr.addstr(device_y, x + 3, f"[{title}]")
    for i, line in enumerate(content[:height - 2]):
        stdscr.addstr(device_y + i + 1, x + 2, line[:width - 4])

def get_user_input(stdscr):
    curses.echo()
    stdscr.clear()
    stdscr.addstr(0, 0, "Zadajte parametre pre spustenie vizualizácie:")

    stdscr.addstr(2, 0, "Cesta k súboru PCAP: ")
    file_path = stdscr.getstr(2, 25).decode('utf-8')

    stdscr.addstr(3, 0, "IP adresa zariadenia A: ")
    ip_a = stdscr.getstr(3, 25).decode('utf-8')

    stdscr.addstr(4, 0, "IP adresa zariadenia B: ")
    ip_b = stdscr.getstr(4, 25).decode('utf-8')

    stdscr.addstr(5, 0, "Rýchlosť prehrávania (napr. 1, 2, 5): ")
    replay_speed = int(stdscr.getstr(5, 40).decode('utf-8'))

    curses.noecho()
    return file_path, ip_a, ip_b, replay_speed

def main(stdscr):
    # Vyčistenie obrazovky
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    # Získanie vstupov od používateľa
    file_path, ip_a, ip_b, replay_speed = get_user_input(stdscr)

    # Velkosti boxov
    device_box_width = 20
    device_box_height = 5
    protocol_height = 3
    protocol_width = 9

    # Pozíce boxov zariadení
    device_a_x = 2
    device_b_x = 45
    protocol_x = (device_a_x + device_b_x + device_box_width - protocol_width) // 2

    # Analyzovanie paketov a filtrovanie na základe IP adries
    try:
        packets = analyze_packets(file_path, {
            "src_ip": [ip_a, ip_b],
            "dst_ip": [ip_b, ip_a]
        })
    except FileNotFoundError:
        stdscr.addstr(max_y - 3, 0, f"Súbor {file_path} neexistuje. Stlačte tlačidlo pre ukončenie programu.")
        stdscr.getch()
        return

    # Získanie celkového počtu paketov pred začiatkom
    total_packets = len(packets["filtered_packets"])

    remaining_packets = total_packets
    protocol_counts = {protocol: 0 for protocol in packets["protocol_counts"].keys()}
    previous_timestamp = None
    progress_bar_width = 50  # Šírka progres baru
    current_value = 1
    packet_lines = []

    for idx, packet_info in enumerate(packets["filtered_packets"], 1):
        current_timestamp = datetime.strptime(packet_info["timestamp"], "%Y-%m-%d %H:%M:%S")

        # Výpočet pečiatky
        if previous_timestamp:
            delta_time = (current_timestamp - previous_timestamp).total_seconds()
            time.sleep(delta_time / replay_speed)
        previous_timestamp = current_timestamp

        current_timestamp_str = current_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        sliced_timestamp = current_timestamp_str[11:]

        # Progress bar
        num_hashes = int((current_value / total_packets) * progress_bar_width)
        progress_bar = f"Progress: [{'#' * num_hashes}{' ' * (progress_bar_width - num_hashes)}] {current_value}/{total_packets}"

        if packet_info["src_ip"] == ip_a or packet_info["src_ip"] == ip_b and packet_info["dst_ip"] == ip_a or packet_info["dst_ip"] == ip_b:
            device_a_content = [f"IP: {ip_a}", f"Port: {packet_info['src_port']}", f"Time: {sliced_timestamp}"]
            device_b_content = [f"IP: {ip_b}", f"Port: {packet_info['dst_port']}", f"Time: {sliced_timestamp}"]
            protocol_content = [f"{packet_info['protocol']}"]
        else:
            stdscr.addstr(max_y - 3, 0, "IP adresy neboli nájdené v zozname. Stlačte tlačidlo pre ukončenie programu")
            stdscr.getch()
            break

        # Vyčisti obrazovku pred novým zobrazením
        stdscr.clear()

        stdscr.addstr(1, 2, progress_bar)

        protocol_counts[packet_info["protocol"]] += 1

        protocol_y_offset = 2
        for protocol, count in protocol_counts.items():
            protocol_percentage = (count / total_packets) * 100  # Percento pre daný protokol
            num_hashes_protocol = int((protocol_percentage / 100) * progress_bar_width)  # Počet symbolov #

            protocol_bar = f"{protocol}: [{'#' * num_hashes_protocol}{' ' * (progress_bar_width - num_hashes_protocol)}] {protocol_percentage:.2f}%"
            stdscr.addstr(protocol_y_offset, 2, protocol_bar)
            protocol_y_offset += 1

        # Zobrazenie boxov
        draw_box(stdscr, device_a_x, device_box_width, device_box_height, device_a_content, title="Zariadenie A")
        draw_box(stdscr, device_b_x, device_box_width, device_box_height, device_b_content, title="Zariadenie B")
        draw_box_protocol(stdscr, protocol_x, protocol_width, protocol_height, protocol_content, title=None)

        if packet_info['src_ip'] == ip_a and packet_info['dst_ip'] == ip_b:
            stdscr.addstr(max_y // 7, protocol_x - 1, "<==========")
            stdscr.addstr(max_y // 7 + 2, protocol_x - 6, "--<--")
            stdscr.addstr(max_y // 7 + 2, protocol_x + 10, "--<--")
            stdscr.addstr(max_y // 7 + 4, protocol_x - 1, "<==========")
        elif packet_info['src_ip'] == ip_b and packet_info['dst_ip'] == ip_a:
            stdscr.addstr(max_y // 7, protocol_x - 1, "==========>")
            stdscr.addstr(max_y // 7 + 2, protocol_x - 6, "-->--")
            stdscr.addstr(max_y // 7 + 2, protocol_x + 10, "-->--")
            stdscr.addstr(max_y // 7 + 4, protocol_x - 1, "==========>")

        stdscr.addstr(max_y // 7 + 6, device_a_x, "# | Protokol | Dáta")
        stdscr.addstr(max_y // 7 + 7, device_a_x, "-" * 71)

        packet_info_str = (f"{idx:<2} | {packet_info['protocol']:<8}| {packet_info['payload']}")
        wrapped_lines = wrap_text(packet_info_str, max_x - 2)

        for line in wrapped_lines:
            if len(packet_lines) >= max_y - 24:  # Ak počet riadkov presahuje obrazovku, vymažeme najstaršie
                packet_lines.pop(0)

            clean_line = clean_string(line)
            packet_lines.append(clean_line)

        for i, line in enumerate(packet_lines):
            stdscr.addstr(max_y // 7 + 8 + i, device_a_x, line)

        current_value += 1
        remaining_packets -= 1

        if remaining_packets == 0:
            stdscr.addstr(max_y - 3, 2, "Vizualizácia ukončená. Stlačte tlačidlo pre ukončenie programu")
            stdscr.getch()

        # Aktualizovanie obrazovky
        stdscr.refresh()

if __name__ == "__main__":
    curses.wrapper(main)
