import argparse
import curses
import os

def main(stdscr):
    # Initialize curses
    curses.curs_set(0)  # Hide cursor initially
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Filter input")
    parser.add_argument("pcap_file", type=str, help="Path to PCAP file")
    args = parser.parse_args()

    # Check if PCAP file exists
    if not os.path.exists(args.pcap_file):
        display_message(stdscr, f"Error: File {args.pcap_file} does not exist", max_y, max_x)
        stdscr.getch()
        return

    # Display header
    header = f"Filter Input - {args.pcap_file}"
    stdscr.addstr(0, 0, header[:max_x - 1])
    stdscr.addstr(1, 0, "=" * min(len(header), max_x - 1))

    stdscr.addstr(3, 0, "Zadajte filter:")
    stdscr.addstr(4, 0, "(Príklady: 'tcp.port == 80', 'http', 'ip.src == 192.168.1.1 and tcp')")
    stdscr.refresh()

    # Get filter input from user
    filter_expression = get_user_input(stdscr, "", max_y, max_x)

    help_text = "Stlačte ENTER pre uloženie filtru | ESC pre zrušenie"
    stdscr.addstr(8, 2, help_text)

    if filter_expression:
        # Save the filter
        save_filter_to_file(filter_expression)
        display_message(stdscr, "Filter uložený úspešne!", max_y, max_x)
    else:
        display_message(stdscr, "Filter nebol zadaný", max_y, max_x)


def get_user_input(stdscr, prompt, max_y, max_x):
    # Create a textbox for user input
    input_height = 3
    input_width = min(max_x - 4, 80)
    input_y = 6
    input_x = 0

    # Draw input box
    input_win = curses.newwin(input_height, input_width, input_y, input_x)
    input_win.box()
    if prompt:
        input_win.addstr(0, 2, prompt[:input_width - 4])
    input_win.refresh()

    # Create editing subwindow
    edit_win = curses.newwin(1, input_width - 2, input_y + 1, input_x + 1)
    edit_win.refresh()

    # Enable echo and show cursor for input
    curses.echo()
    curses.curs_set(1)

    # Get input
    input_str = ""
    stdscr.refresh()

    while True:
        try:
            key = edit_win.getch()

            if key == 10 or key == 13:  # Enter key
                break
            elif key == 27:  # Escape key
                input_str = ""
                break
            elif key == curses.KEY_BACKSPACE or key == 127 or key == 8:  # Backspace
                if input_str:
                    input_str = input_str[:-1]
                    edit_win.clear()
                    edit_win.addstr(0, 0, input_str)
                    edit_win.refresh()
            elif 32 <= key <= 126:  # Printable characters
                if len(input_str) < input_width - 4:  # Prevent overflow
                    input_str += chr(key)
                    edit_win.clear()
                    edit_win.addstr(0, 0, input_str)
                    edit_win.refresh()
        except:
            pass

    # Disable echo and hide cursor
    curses.noecho()
    curses.curs_set(0)

    return input_str.strip()


def save_filter_to_file(filter_expression):
    output_dir = os.path.dirname(os.path.abspath(__file__))
    filter_file = os.path.join(output_dir, "filter.txt")

    with open(filter_file, "w") as f:
        f.write(filter_expression)


def display_message(stdscr, message, max_y, max_x):
    # Create a popup for messages
    popup_height = 5
    popup_width = min(len(message) + 10, max_x - 4)
    popup_y = max_y // 2 - popup_height // 2
    popup_x = max_x // 2 - popup_width // 2

    popup = curses.newwin(popup_height, popup_width, popup_y, popup_x)
    popup.box()
    popup.addstr(2, (popup_width - len(message)) // 2, message)
    popup.addstr(3, 2, "Stlačte ENTER")
    popup.refresh()

    popup.getch()


if __name__ == "__main__":
    curses.wrapper(main)