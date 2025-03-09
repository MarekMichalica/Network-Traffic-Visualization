import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import os
import numpy as np

from datetime import datetime

def plot_data_usage(filtered_packets, pcap_file):
    data_usage = filtered_packets["data_usage"]

    # Convert timestamps to datetime objects and sort
    timestamps = []
    sizes = []

    for timestamp_str, size in sorted(data_usage.items()):
        try:
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            timestamps.append(dt)
            sizes.append(size)
        except ValueError:
            continue  # Skip invalid timestamps

    # Check if we have data to plot
    if not timestamps:
        plt.figure(figsize=(10, 6))
        plt.text(0.5, 0.5, "No data available for the selected time period",
                 horizontalalignment='center', fontsize=14)
        plt.tight_layout()
        plt.show()
        return

    # Create figure with two subplots: line chart and cumulative
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), sharex=True)

    # Line chart of data usage over time
    ax1.plot(timestamps, [size / 1024 for size in sizes], 'b-', linewidth=1.5)
    ax1.fill_between(timestamps, [0] * len(timestamps), [size / 1024 for size in sizes],
                     color='skyblue', alpha=0.4)
    ax1.set_title('Data Usage Over Time')
    ax1.set_ylabel('Data Size (KB)')
    ax1.grid(True, linestyle='--', alpha=0.7)

    # Cumulative data usage over time
    cumulative_sizes = np.cumsum([size / 1024 for size in sizes])
    ax2.plot(timestamps, cumulative_sizes, 'g-', linewidth=1.5)
    ax2.fill_between(timestamps, [0] * len(timestamps), cumulative_sizes,
                     color='lightgreen', alpha=0.4)
    ax2.set_title('Cumulative Data Usage')
    ax2.set_ylabel('Cumulative Data (KB)')
    ax2.set_xlabel('Time')
    ax2.grid(True, linestyle='--', alpha=0.7)

    # Format x-axis to show appropriate time units
    time_span = max(timestamps) - min(timestamps)
    if time_span.total_seconds() < 3600:  # Less than an hour
        date_format = '%H:%M:%S'
    elif time_span.total_seconds() < 86400:  # Less than a day
        date_format = '%H:%M'
    else:  # More than a day
        date_format = '%Y-%m-%d %H:%M'

    formatter = mdates.DateFormatter(date_format)
    ax2.xaxis.set_major_formatter(formatter)

    # Add appropriate locators based on the time span
    if time_span.total_seconds() < 300:  # Less than 5 minutes
        locator = mdates.SecondLocator(interval=30)
    elif time_span.total_seconds() < 3600:  # Less than an hour
        locator = mdates.MinuteLocator(interval=5)
    elif time_span.total_seconds() < 86400:  # Less than a day
        locator = mdates.HourLocator(interval=1)
    else:  # More than a day
        locator = mdates.DayLocator(interval=1)

    ax2.xaxis.set_major_locator(locator)
    plt.xticks(rotation=45)

    # Add summary statistics
    total_data = sum(sizes) / (1024 * 1024)  # Convert to MB
    avg_rate = (total_data * 8) / (time_span.total_seconds() / 60)  # Mbps

    stats_text = (f"Total Data: {total_data:.2f} MB\n"
                  f"Average Rate: {avg_rate:.2f} Mbps\n"
                  f"Duration: {time_span}")

    ax1.text(0.02, 0.95, stats_text, transform=ax1.transAxes,
             verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

    # Add file name to the overall title
    file_name = os.path.basename(pcap_file)
    plt.suptitle(f"Data Usage Analysis - {file_name}", fontsize=16)

    plt.tight_layout()
    plt.subplots_adjust(top=0.93)
    plt.show()