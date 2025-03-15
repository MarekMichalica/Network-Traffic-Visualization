import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import os

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
        plt.text(0.5, 0.5, "Žiadne údaje nie sú k dispozícii pre zvolené časové obdobie",
                 horizontalalignment='center', fontsize=14)
        plt.tight_layout()
        plt.show()
        return

    # Create figure with a single plot for data usage over time
    fig, ax = plt.subplots(figsize=(12, 6))

    # Line chart of data usage over time
    ax.plot(timestamps, [size / 1024 for size in sizes], 'b-', linewidth=1.5)
    ax.fill_between(timestamps, [0] * len(timestamps), [size / 1024 for size in sizes],
                    color='skyblue', alpha=0.4)
    ax.set_title('Využitie dát v priebehu času')
    ax.set_ylabel('Veľkosť dát (KB)')
    ax.set_xlabel('Čas')
    ax.grid(True, linestyle='--', alpha=0.7)

    # Format x-axis to show appropriate time units
    time_span = max(timestamps) - min(timestamps)
    if time_span.total_seconds() < 3600:  # Less than an hour
        date_format = '%H:%M:%S'
    elif time_span.total_seconds() < 86400:  # Less than a day
        date_format = '%H:%M'
    else:  # More than a day
        date_format = '%Y-%m-%d %H:%M'

    formatter = mdates.DateFormatter(date_format)
    ax.xaxis.set_major_formatter(formatter)

    # Add appropriate locators based on the time span
    if time_span.total_seconds() < 300:  # Less than 5 minutes
        locator = mdates.SecondLocator(interval=30)
    elif time_span.total_seconds() < 3600:  # Less than an hour
        locator = mdates.MinuteLocator(interval=5)
    elif time_span.total_seconds() < 86400:  # Less than a day
        locator = mdates.HourLocator(interval=1)
    else:  # More than a day
        locator = mdates.DayLocator(interval=1)

    ax.xaxis.set_major_locator(locator)
    plt.xticks(rotation=45)

    # Add summary statistics
    total_data = sum(sizes) / (1024 * 1024)  # Convert to MB
    avg_rate = (total_data * 8) / (time_span.total_seconds() / 60)  # Mbps

    stats_text = (f"Celkové dáta: {total_data:.2f} MB\n"
                  f"Priemerná rýchlosť: {avg_rate:.2f} Mbps\n"
                  f"Trvanie: {time_span}")

    ax.text(0.02, 0.95, stats_text, transform=ax.transAxes,
            verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

    # Add file name to the title
    file_name = os.path.basename(pcap_file)
    plt.title(f"Analýza využitia dát - {file_name}", fontsize=16)

    plt.tight_layout()
    plt.show()