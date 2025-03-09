import matplotlib.pyplot as plt
import numpy as np
import os
from collections import defaultdict

def plot_packet_size_distribution(filtered_packets, pcap_file):
    # Extract packet data
    packets = filtered_packets["filtered_packets"]

    # Extract packet sizes and protocols
    sizes = [packet["size"] for packet in packets]
    protocols = [packet["protocol"] for packet in packets]

    # Create figure with multiple plots
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 15))

    # 1. Histogram of packet sizes
    if sizes:
        # Create bins with more granularity for smaller packets
        max_size = max(sizes)
        if max_size <= 1500:  # If all packets are within typical MTU
            bins = np.linspace(0, max_size, 30)
        else:
            # Create custom bins with focus on typical packet sizes
            small_bins = np.linspace(0, 1500, 20)  # More bins for typical packet sizes
            large_bins = np.linspace(1500, max_size, 10)  # Fewer bins for larger packets
            bins = np.unique(np.concatenate([small_bins, large_bins]))

        # Plot histogram
        ax1.hist(sizes, bins=bins, color='royalblue', alpha=0.7, edgecolor='black', linewidth=0.5)
        ax1.set_title('Packet Size Distribution')
        ax1.set_xlabel('Packet Size (bytes)')
        ax1.set_ylabel('Frequency')
        ax1.grid(axis='y', linestyle='--', alpha=0.7)

        # Add statistical information
        stats_text = (f"Min: {min(sizes)} bytes\n"
                      f"Max: {max(sizes)} bytes\n"
                      f"Mean: {np.mean(sizes):.2f} bytes\n"
                      f"Median: {np.median(sizes):.2f} bytes\n"
                      f"Std Dev: {np.std(sizes):.2f} bytes")

        ax1.text(0.95, 0.95, stats_text, transform=ax1.transAxes,
                 verticalalignment='top', horizontalalignment='right',
                 bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    else:
        ax1.text(0.5, 0.5, "No packet size data available",
                 horizontalalignment='center', fontsize=14)

    # 2. CDF of packet sizes
    if sizes:
        sorted_sizes = np.sort(sizes)
        cumulative_prob = np.arange(1, len(sorted_sizes) + 1) / len(sorted_sizes)

        ax2.step(sorted_sizes, cumulative_prob, where='post', color='forestgreen', linewidth=2)
        ax2.grid(True, linestyle='--', alpha=0.7)
        ax2.set_title('Cumulative Distribution Function (CDF) of Packet Sizes')
        ax2.set_xlabel('Packet Size (bytes)')
        ax2.set_ylabel('Cumulative Probability')

        # Add percentile markers
        percentiles = [25, 50, 75, 90]
        for p in percentiles:
            percentile_val = np.percentile(sizes, p)
            ax2.axvline(x=percentile_val, color='red', linestyle='--', alpha=0.5)
            ax2.text(percentile_val, 0.05, f"{p}%", color='red', ha='center')
    else:
        ax2.text(0.5, 0.5, "No packet size data available",
                 horizontalalignment='center', fontsize=14)

    # 3. Average packet size by protocol
    if sizes and protocols:
        # Calculate average size by protocol
        protocol_sizes = defaultdict(list)
        for packet in packets:
            protocol_sizes[packet["protocol"]].append(packet["size"])

        # Calculate average size for each protocol
        protocol_avg_sizes = {proto: np.mean(sizes) for proto, sizes in protocol_sizes.items()}

        # Sort by average size
        sorted_protocols = sorted(protocol_avg_sizes.items(), key=lambda x: x[1], reverse=True)

        # Take top 15 protocols
        if len(sorted_protocols) > 15:
            sorted_protocols = sorted_protocols[:15]

        # Prepare data for plotting
        protocol_labels = [proto for proto, _ in sorted_protocols]
        avg_sizes = [size for _, size in sorted_protocols]

        # Plot bar chart
        bars = ax3.bar(protocol_labels, avg_sizes, color='mediumorchid', alpha=0.7)
        ax3.set_title('Average Packet Size by Protocol')
        ax3.set_xlabel('Protocol')
        ax3.set_ylabel('Average Size (bytes)')
        plt.setp(ax3.get_xticklabels(), rotation=45, ha='right')
        ax3.grid(axis='y', linestyle='--', alpha=0.7)

        # Add value labels on top of each bar
        for bar in bars:
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width() / 2., height + 5,
                     f"{height:.1f}",
                     ha='center', va='bottom', rotation=0)
    else:
        ax3.text(0.5, 0.5, "No protocol data available",
                 horizontalalignment='center', fontsize=14)

    # Add file name to the overall title
    file_name = os.path.basename(pcap_file)
    plt.suptitle(f"Packet Size Analysis - {file_name}", fontsize=16)

    plt.tight_layout()
    plt.subplots_adjust(top=0.95)
    plt.show()