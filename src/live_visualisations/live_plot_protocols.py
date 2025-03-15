import json
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import os

def plot_protocols(json_file):
    # Create figure with two subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 7))

    def animate(i):
        # Clear previous plots
        ax1.clear()
        ax2.clear()

        # Load and parse JSON data
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            # Extract packets from the data structure
            packets = data.get('packets', [])

            # Count protocols
            protocol_counts = {}
            for packet in packets:
                protocol = packet.get('protocol', 'Unknown')
                if protocol in protocol_counts:
                    protocol_counts[protocol] += 1
                else:
                    protocol_counts[protocol] = 1

            # Sort protocols by count in descending order
            sorted_protocols = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)

            # Take top 5 protocols and group the rest as "Others"
            if len(sorted_protocols) > 5:
                other_count = sum(count for protocol, count in sorted_protocols[5:])
                sorted_protocols = sorted_protocols[:5]
                if other_count > 0:
                    sorted_protocols.append(('Ostatné', other_count))

            # Prepare data for plotting
            labels = [protocol for protocol, _ in sorted_protocols]
            counts = [count for _, count in sorted_protocols]

            # Calculate percentages
            total = sum(counts)
            percentages = [(count / total) * 100 for count in counts]

            # Create bar chart
            ax1.bar(labels, counts, color='steelblue')
            ax1.set_title('Distribúcia protokolov')
            ax1.set_xlabel('Protokol')
            ax1.set_ylabel('Počet paketov')
            plt.setp(ax1.get_xticklabels(), rotation=45, ha='right')

            # Add count labels on top of each bar
            for i, count in enumerate(counts):
                ax1.text(i, count + (max(counts) * 0.01), str(count), ha='center')

            # Create pie chart
            colors = plt.cm.tab10.colors
            if len(sorted_protocols) > 5:
                colors = list(colors[:5]) + ['gray']  # Add color for 'Ostatné'

            ax2.pie(counts, labels=[f"{label} ({percentage:.1f}%)" for label, percentage in zip(labels, percentages)],
                    autopct='', startangle=90, colors=colors)
            ax2.set_title('Distribúcia protokolov (%)')
            ax2.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle

            # Add file name to the overall title
            file_name = os.path.basename(json_file)
            plt.suptitle(f"Analýza protokolov - {file_name}", fontsize=16)

            plt.tight_layout()
            plt.subplots_adjust(top=0.9)

        except Exception as e:
            print(f"Error pri aktualizácii grafu: {e}")

    # Create animation that updates every second
    ani = FuncAnimation(fig, animate, interval=1000)

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Distribúcia protokolov - vizualizácia")
    parser.add_argument("json_file", type=str, help="Cesta k súboru JSON s paketmi")
    args = parser.parse_args()

    plot_protocols(args.json_file)