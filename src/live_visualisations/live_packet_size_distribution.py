import json
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.animation import FuncAnimation

def plot_packet_size_distribution(json_file):
    """
    Plot the distribution of packet sizes.

    Args:
        json_file (str): Path to the JSON file containing packet data
    """
    fig, ax = plt.subplots(figsize=(10, 6))

    def animate(i):
        ax.clear()

        # Load packet data
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                packets = data['packets']
        except Exception as e:
            print(f"Error loading JSON file: {e}")
            return

        # Extract packet sizes
        packet_sizes = [packet['size'] for packet in packets if 'size' in packet]

        if not packet_sizes:
            ax.text(0.5, 0.5, "Žiadne dáta k zobrazeniu", ha='center', va='center')
            return

        # Create histogram
        bins = np.linspace(min(packet_sizes), max(packet_sizes), 20)
        ax.hist(packet_sizes, bins=bins, alpha=0.7, color='skyblue', edgecolor='black')

        # Add labels and title
        ax.set_title('Distribúcia veľkosti paketov')
        ax.set_xlabel('Veľkosť paketu (bajty)')
        ax.set_ylabel('Počet paketov')

        # Add statistics
        avg_size = np.mean(packet_sizes)
        median_size = np.median(packet_sizes)
        max_size = max(packet_sizes)
        min_size = min(packet_sizes)

        stats_text = (f'Priemerná veľkosť: {avg_size:.2f} bajtov\n'
                      f'Mediánová veľkosť: {median_size:.2f} bajtov\n'
                      f'Min: {min_size} bajtov, Max: {max_size} bajtov')

        ax.text(0.95, 0.95, stats_text, transform=ax.transAxes,
                verticalalignment='top', horizontalalignment='right',
                bbox=dict(boxstyle='round', facecolor='white', alpha=0.7))

        plt.tight_layout()

    # Create animation
    ani = FuncAnimation(fig, animate, interval=1000)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Distribúcia veľkosti paketov")
    parser.add_argument("json_file", type=str, help="Cesta k súboru JSON s paketmi")
    args = parser.parse_args()

    plot_packet_size_distribution(args.json_file)