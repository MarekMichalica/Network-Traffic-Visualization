import matplotlib.pyplot as plt
from collections import Counter
import os

def plot_top_senders_receivers(filtered_packets, pcap_file):
    # Extract packet data
    packets = filtered_packets["filtered_packets"]

    # Count packets and data volume by source and destination IP
    src_packet_count = Counter()
    dst_packet_count = Counter()
    src_data_volume = Counter()
    dst_data_volume = Counter()

    for packet in packets:
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        size = packet["size"]

        src_packet_count[src_ip] += 1
        dst_packet_count[dst_ip] += 1
        src_data_volume[src_ip] += size
        dst_data_volume[dst_ip] += size

    # Get top 10 senders and receivers by packet count
    top_senders_packets = src_packet_count.most_common(10)
    top_receivers_packets = dst_packet_count.most_common(10)

    # Get top 10 senders and receivers by data volume
    top_senders_volume = src_data_volume.most_common(10)
    top_receivers_volume = dst_data_volume.most_common(10)

    # Create figure with 2x2 subplots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))

    # Plot top senders by packet count
    sender_ips_packets = [ip for ip, _ in top_senders_packets]
    sender_counts_packets = [count for _, count in top_senders_packets]

    ax1.barh(sender_ips_packets[::-1], sender_counts_packets[::-1], color='cornflowerblue')
    ax1.set_title('Top Senders (by Packet Count)')
    ax1.set_xlabel('Number of Packets')
    ax1.set_ylabel('IP Address')

    # Add count labels
    for i, count in enumerate(sender_counts_packets[::-1]):
        ax1.text(count + (max(sender_counts_packets) * 0.01), i, str(count), va='center')

    # Plot top receivers by packet count
    receiver_ips_packets = [ip for ip, _ in top_receivers_packets]
    receiver_counts_packets = [count for _, count in top_receivers_packets]

    ax2.barh(receiver_ips_packets[::-1], receiver_counts_packets[::-1], color='lightcoral')
    ax2.set_title('Top Receivers (by Packet Count)')
    ax2.set_xlabel('Number of Packets')
    ax2.set_ylabel('IP Address')

    # Add count labels
    for i, count in enumerate(receiver_counts_packets[::-1]):
        ax2.text(count + (max(receiver_counts_packets) * 0.01), i, str(count), va='center')

    # Plot top senders by data volume
    sender_ips_volume = [ip for ip, _ in top_senders_volume]
    sender_volumes = [volume / 1024 for _, volume in top_senders_volume]  # Convert to KB

    ax3.barh(sender_ips_volume[::-1], sender_volumes[::-1], color='mediumseagreen')
    ax3.set_title('Top Senders (by Data Volume)')
    ax3.set_xlabel('Data Volume (KB)')
    ax3.set_ylabel('IP Address')

    # Add volume labels
    for i, volume in enumerate(sender_volumes[::-1]):
        ax3.text(volume + (max(sender_volumes) * 0.01), i, f"{volume:.1f} KB", va='center')

    # Plot top receivers by data volume
    receiver_ips_volume = [ip for ip, _ in top_receivers_volume]
    receiver_volumes = [volume / 1024 for _, volume in top_receivers_volume]  # Convert to KB

    ax4.barh(receiver_ips_volume[::-1], receiver_volumes[::-1], color='darkorange')
    ax4.set_title('Top Receivers (by Data Volume)')
    ax4.set_xlabel('Data Volume (KB)')
    ax4.set_ylabel('IP Address')

    # Add volume labels
    for i, volume in enumerate(receiver_volumes[::-1]):
        ax4.text(volume + (max(receiver_volumes) * 0.01), i, f"{volume:.1f} KB", va='center')

    # Add file name to the overall title
    file_name = os.path.basename(pcap_file)
    plt.suptitle(f"Top Senders and Receivers Analysis - {file_name}", fontsize=16)

    plt.tight_layout()
    plt.subplots_adjust(top=0.93)
    plt.show()