import json
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
from matplotlib.animation import FuncAnimation
from datetime import datetime


def plot_data_usage(file_path):
    # Initialize figure and axis
    fig, ax = plt.subplots(figsize=(12, 6))

    # Initialize lists to hold the data
    timestamps = []
    data_usage = []

    # Function to animate the plot
    def animate(i):
        nonlocal timestamps, data_usage  # Use the outer variable

        # Load JSON data from the file
        with open(file_path, 'r') as file:
            data = json.load(file)

        # Update timestamps and data_usage lists
        timestamps = [datetime.strptime(entry["timestamp"], "%H:%M:%S") for entry in data]
        data_usage = [int(entry["data_usage"]) for entry in data]

        # Calculate data in KB for easier reading
        data_usage_kb = [size / 1024 for size in data_usage]

        ax.clear()  # Clear the current axes

        # Plot the data with improved styling
        ax.plot(timestamps, data_usage_kb, 'b-', linewidth=1.5, marker='o', markersize=4)
        ax.fill_between(timestamps, [0] * len(timestamps), data_usage_kb,
                        color='skyblue', alpha=0.4)

        # Add grid and styling
        ax.grid(True, linestyle='--', alpha=0.7)

        # Format x-axis to show time properly
        formatter = mdates.DateFormatter('%H:%M:%S')
        ax.xaxis.set_major_formatter(formatter)
        plt.xticks(rotation=45)

        # Set labels and title
        ax.set_xlabel('Časová pečiatka')
        ax.set_ylabel('Využitie dát (KB)')
        ax.set_title('Využitie dát v čase')

        # Calculate and display statistics
        if data_usage:
            total_data = sum(data_usage) / (1024 * 1024)  # Convert to MB
            time_span = max(timestamps) - min(timestamps)
            seconds = time_span.total_seconds()

            if seconds > 0:
                avg_rate = (total_data * 8) / (seconds / 60)  # Mbps
                stats_text = (f"Celkové dáta: {total_data:.2f} MB\n"
                              f"Priemerná rýchlosť: {avg_rate:.2f} Mbps\n"
                              f"Trvanie: {time_span}")

                ax.text(0.02, 0.95, stats_text, transform=ax.transAxes,
                        verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

        # Set the x-axis limits to the current min and max timestamps
        if timestamps:
            ax.set_xlim(min(timestamps), max(timestamps))

            # Set y-axis limit with a bit of padding
            max_usage = max(data_usage_kb) if data_usage_kb else 0
            ax.set_ylim(0, max_usage * 1.1)

        fig.tight_layout()

    # Create the animation
    ani = FuncAnimation(fig, animate, interval=1000, cache_frame_data=False)  # Update every 1 second

    # Show the plot
    plt.tight_layout()
    plt.show()

    return ani  # Return animation object to prevent garbage collection