import json
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from datetime import datetime

def plot_data_usage(file_path):
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

        plt.cla()  # Clear the current axes

        # Plot the data
        plt.plot(timestamps, data_usage, label='Data Usage', marker='o', linestyle='-')

        # Formatting the x-axis to show time
        plt.gcf().autofmt_xdate()  # Automatically format date for better visibility
        plt.xlabel('Timestamp')
        plt.ylabel('Data Usage (bytes)')
        plt.title('Data Usage Over Time')
        plt.legend(loc='upper left')

        # Set the x-axis limits to the current min and max timestamps
        if timestamps:
            plt.xlim(min(timestamps), max(timestamps))

        plt.tight_layout()

    # Create the animation
    ani = FuncAnimation(plt.gcf(), animate, interval=1000)  # Update every 1000 milliseconds (1 second)

    # Show the plot
    plt.tight_layout()
    plt.show()
